/*
 * services/tsig_server.c - address->TSIG-key runtime lookup table.
 *
 * Copyright (c) 2026, SAP SE. All rights reserved.
 *
 * See LICENSE for the license.
 */

/**
 * \file
 *
 * See services/tsig_server.h for the API contract and doc/tsig.md
 * for the overall design.
 *
 * Two rb-trees hang off tsig_server_table:
 *   - keys_by_name: char* -> struct tsig_key*, owned.
 *   - map_by_addr: struct sockaddr_storage -> struct tsig_key*,
 *                  non-owning ref into keys_by_name.
 * The address key is normalized before storage/lookup: port and
 * IPv6 scope are zeroed out; address family is the discriminator.
 * The table is built once and read-only for its lifetime, so no
 * locking is needed on lookup.
 */

#include "config.h"
#include "services/tsig_server.h"
#include "util/config_file.h"
#include "util/log.h"
#include "util/net_help.h"
#include "util/rbtree.h"
#include "util/tsig.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <netinet/in.h>

/* ------------------------------------------------------------------ */
/* Internals                                                          */
/* ------------------------------------------------------------------ */

struct tsig_key_node {
	rbnode_type node;
	char* name;          /* owned; lower-cased, no trailing dot */
	struct tsig_key* key;/* owned */
};

struct tsig_addr_node {
	rbnode_type node;
	struct sockaddr_storage addr; /* normalized: port and v6 scope zero */
	socklen_t addrlen;
	const struct tsig_key* key;   /* borrowed from keys_by_name */
};

struct tsig_server_table {
	rbtree_type keys_by_name;
	rbtree_type map_by_addr;
};

/** Fold a key name to lower case, strip any trailing dot. Returns a
 * malloc'd copy or NULL on OOM. */
static char*
tsig_norm_name(const char* in)
{
	size_t len, i;
	char* out;
	if(!in) return NULL;
	len = strlen(in);
	if(len > 0 && in[len-1] == '.')
		len--;
	out = (char*)malloc(len+1);
	if(!out) return NULL;
	for(i = 0; i < len; i++) {
		char c = in[i];
		if(c >= 'A' && c <= 'Z') c = (char)(c + ('a' - 'A'));
		out[i] = c;
	}
	out[len] = '\0';
	return out;
}

/** Compare normalized name strings. Exposed for fptr_wlist. */
int
tsig_name_cmp(const void* a, const void* b)
{
	return strcmp((const char*)a, (const char*)b);
}

/**
 * Normalize a sockaddr_storage for TSIG address lookup: zero out the
 * port and IPv6 scope/flowinfo so that keys are compared on address
 * family + address only.
 */
static void
tsig_normalize_addr(struct sockaddr_storage* addr)
{
	if(addr->ss_family == AF_INET) {
		struct sockaddr_in* sa = (struct sockaddr_in*)addr;
		sa->sin_port = 0;
	} else if(addr->ss_family == AF_INET6) {
		struct sockaddr_in6* sa = (struct sockaddr_in6*)addr;
		sa->sin6_port = 0;
		sa->sin6_flowinfo = 0;
		sa->sin6_scope_id = 0;
	}
}

/** Compare two normalized sockaddr_storage keys. Exposed for fptr_wlist. */
int
tsig_addr_cmp(const void* a, const void* b)
{
	const struct sockaddr_storage* aa = (const struct sockaddr_storage*)a;
	const struct sockaddr_storage* bb = (const struct sockaddr_storage*)b;
	if(aa->ss_family != bb->ss_family)
		return aa->ss_family < bb->ss_family ? -1 : 1;
	if(aa->ss_family == AF_INET) {
		const struct sockaddr_in* sa = (const struct sockaddr_in*)aa;
		const struct sockaddr_in* sb = (const struct sockaddr_in*)bb;
		return memcmp(&sa->sin_addr, &sb->sin_addr,
			sizeof(sa->sin_addr));
	}
	if(aa->ss_family == AF_INET6) {
		const struct sockaddr_in6* sa = (const struct sockaddr_in6*)aa;
		const struct sockaddr_in6* sb = (const struct sockaddr_in6*)bb;
		return memcmp(&sa->sin6_addr, &sb->sin6_addr,
			sizeof(sa->sin6_addr));
	}
	/* unknown family: byte-compare the whole thing */
	return memcmp(aa, bb, sizeof(*aa));
}

/* ------------------------------------------------------------------ */
/* Public API                                                         */
/* ------------------------------------------------------------------ */

struct tsig_server_table*
tsig_server_table_create(void)
{
	struct tsig_server_table* t =
		(struct tsig_server_table*)calloc(1, sizeof(*t));
	if(!t) return NULL;
	rbtree_init(&t->keys_by_name, &tsig_name_cmp);
	rbtree_init(&t->map_by_addr, &tsig_addr_cmp);
	return t;
}

/** Look up a key by its (already-normalized) name. */
static const struct tsig_key*
tsig_server_table_get_by_name(const struct tsig_server_table* t,
	const char* norm_name)
{
	rbnode_type* n;
	if(!t || !norm_name) return NULL;
	n = rbtree_search((rbtree_type*)&t->keys_by_name, norm_name);
	if(!n) return NULL;
	return ((struct tsig_key_node*)n)->key;
}

/** Format err from a printf-like source. */
static void
tsig_set_err(char** err, const char* fmt, ...)
{
	char buf[512];
	va_list ap;
	if(!err || *err) return;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	*err = strdup(buf);
}

/** Load all tsig-key entries into keys_by_name. */
static int
load_keys(struct tsig_server_table* t, struct config_file* cfg, char** err)
{
	struct config_tsig_key* k;
	for(k = cfg->tsig_keys; k; k = k->next) {
		char* norm;
		struct tsig_key* key;
		struct tsig_key_node* node;
		char* file_err = NULL;

		if(!k->name || !*k->name) {
			tsig_set_err(err, "tsig-key: name is required");
			return 0;
		}
		if(!k->key_file || !*k->key_file) {
			tsig_set_err(err, "tsig-key '%s': key-file is required",
				k->name);
			return 0;
		}
		norm = tsig_norm_name(k->name);
		if(!norm) {
			tsig_set_err(err, "out of memory");
			return 0;
		}
		if(tsig_server_table_get_by_name(t, norm) != NULL) {
			tsig_set_err(err,
				"duplicate tsig-key name '%s'", k->name);
			free(norm);
			return 0;
		}
		key = tsig_key_load_bind_file(k->key_file, k->name, &file_err);
		if(!key) {
			tsig_set_err(err, "tsig-key '%s': %s", k->name,
				file_err ? file_err : "load failed");
			free(file_err);
			free(norm);
			return 0;
		}
		free(file_err);
		node = (struct tsig_key_node*)calloc(1, sizeof(*node));
		if(!node) {
			tsig_key_delete(key);
			free(norm);
			tsig_set_err(err, "out of memory");
			return 0;
		}
		node->name = norm;
		node->key = key;
		node->node.key = norm;
		if(!rbtree_insert(&t->keys_by_name, &node->node)) {
			/* impossible: we checked for duplicate above */
			tsig_key_delete(key);
			free(norm);
			free(node);
			tsig_set_err(err, "internal: rbtree_insert failed");
			return 0;
		}
	}
	return 1;
}

/** Populate map_by_addr from server-tsig entries. */
static int
load_bindings(struct tsig_server_table* t, struct config_file* cfg,
	char** err)
{
	struct config_server_tsig* s;
	for(s = cfg->server_tsigs; s; s = s->next) {
		struct sockaddr_storage addr;
		socklen_t addrlen = 0;
		const struct tsig_key* key;
		struct tsig_addr_node* node;
		char* norm_key;

		if(!s->address || !*s->address) {
			tsig_set_err(err, "server-tsig: address is required");
			return 0;
		}
		if(!s->key_name || !*s->key_name) {
			tsig_set_err(err, "server-tsig '%s': key is required",
				s->address);
			return 0;
		}
		if(!ipstrtoaddr(s->address, UNBOUND_DNS_PORT, &addr,
			&addrlen)) {
			tsig_set_err(err,
				"server-tsig: cannot parse address '%s'",
				s->address);
			return 0;
		}
		tsig_normalize_addr(&addr);
		norm_key = tsig_norm_name(s->key_name);
		if(!norm_key) {
			tsig_set_err(err, "out of memory");
			return 0;
		}
		key = tsig_server_table_get_by_name(t, norm_key);
		free(norm_key);
		if(!key) {
			tsig_set_err(err,
				"server-tsig '%s' references undefined "
				"tsig-key '%s'", s->address, s->key_name);
			return 0;
		}
		if(rbtree_search(&t->map_by_addr, &addr) != NULL) {
			tsig_set_err(err,
				"duplicate server-tsig address '%s'",
				s->address);
			return 0;
		}
		node = (struct tsig_addr_node*)calloc(1, sizeof(*node));
		if(!node) {
			tsig_set_err(err, "out of memory");
			return 0;
		}
		node->addr = addr;
		node->addrlen = addrlen;
		node->key = key;
		node->node.key = &node->addr;
		if(!rbtree_insert(&t->map_by_addr, &node->node)) {
			free(node);
			tsig_set_err(err, "internal: rbtree_insert failed");
			return 0;
		}
	}
	return 1;
}

int
tsig_server_table_apply_cfg(struct tsig_server_table* table,
	struct config_file* cfg, char** err)
{
	if(err) *err = NULL;
	if(!table || !cfg) {
		tsig_set_err(err, "null argument");
		return 0;
	}
	/* Table must be empty. */
	if(table->keys_by_name.count != 0 || table->map_by_addr.count != 0) {
		tsig_set_err(err,
			"tsig_server_table_apply_cfg: table not empty");
		return 0;
	}
	if(!load_keys(table, cfg, err))
		return 0;
	if(!load_bindings(table, cfg, err))
		return 0;
	return 1;
}

const struct tsig_key*
tsig_server_table_lookup(const struct tsig_server_table* table,
	const struct sockaddr_storage* addr, socklen_t addrlen)
{
	struct sockaddr_storage key;
	rbnode_type* n;
	(void)addrlen;
	if(!table || !addr) return NULL;
	if(addr->ss_family != AF_INET && addr->ss_family != AF_INET6)
		return NULL;
	memset(&key, 0, sizeof(key));
	if(addr->ss_family == AF_INET) {
		memcpy(&key, addr, sizeof(struct sockaddr_in));
	} else {
		memcpy(&key, addr, sizeof(struct sockaddr_in6));
	}
	tsig_normalize_addr(&key);
	n = rbtree_search((rbtree_type*)&table->map_by_addr, &key);
	if(!n) return NULL;
	return ((struct tsig_addr_node*)n)->key;
}

/** rbtree traversal callback: free tsig_key_node contents. */
static void
tsig_key_node_free(rbnode_type* n, void* ATTR_UNUSED(arg))
{
	struct tsig_key_node* kn = (struct tsig_key_node*)n;
	tsig_key_delete(kn->key);
	free(kn->name);
	free(kn);
}

/** rbtree traversal callback: free tsig_addr_node contents. */
static void
tsig_addr_node_free(rbnode_type* n, void* ATTR_UNUSED(arg))
{
	struct tsig_addr_node* an = (struct tsig_addr_node*)n;
	free(an);
}

void
tsig_server_table_delete(struct tsig_server_table* table)
{
	if(!table) return;
	/* free addr map first (borrows key ptrs from the name store) */
	traverse_postorder(&table->map_by_addr, &tsig_addr_node_free, NULL);
	traverse_postorder(&table->keys_by_name, &tsig_key_node_free, NULL);
	free(table);
}
