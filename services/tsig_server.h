/*
 * services/tsig_server.h - address->TSIG-key runtime lookup table.
 *
 * Copyright (c) 2026, SAP SE. All rights reserved.
 *
 * See LICENSE for the license.
 */

/**
 * \file
 *
 * Runtime resolution of the two-block TSIG config (util/config_file.h
 * `tsig_keys` and `server_tsigs`) into:
 *
 *   - A key store keyed by name (`struct tsig_key*` per entry, owned
 *     here; secrets loaded once from the BIND key files).
 *   - An address->key map for fast lookup by outgoing destination.
 *
 * The table is built at daemon-fork/apply time and torn down at
 * cleanup. It is read-only after build; workers hold a pointer to it
 * on their `struct outside_network`. Address match is IP-only, port
 * and IPv6 scope are normalized to zero at insert and lookup time.
 *
 * See doc/tsig.md for scope and rationale.
 */

#ifndef SERVICES_TSIG_SERVER_H
#define SERVICES_TSIG_SERVER_H

#include <sys/types.h>
#include <sys/socket.h>

struct config_file;
struct tsig_key;
struct tsig_server_table;

/**
 * Create an empty table. Returns NULL on allocation failure.
 */
struct tsig_server_table* tsig_server_table_create(void);

/**
 * Populate the table from a config. Loads every `tsig-key` file via
 * tsig_key_load_bind_file() and inserts every `server-tsig` binding
 * into the address->key map.
 *
 * On any error (missing file, wrong algorithm, malformed base64,
 * unparseable address, duplicate address, dangling key reference,
 * duplicate key name) the function frees any partial state and
 * returns 0. A caller-facing error string is written to *err
 * (malloc'd; caller frees). This mirrors the checkconf-time
 * validation in smallapp/unbound-checkconf.c so that a config that
 * passed `unbound-checkconf` is guaranteed to load here too.
 *
 * @param table: table to populate. Must be freshly created (empty).
 * @param cfg: config to read `tsig_keys` and `server_tsigs` from.
 * @param err: on failure, set to a malloc'd human-readable error
 *		string; NULL on success. Caller must free.
 * @return 1 on success, 0 on failure.
 */
int tsig_server_table_apply_cfg(struct tsig_server_table* table,
	struct config_file* cfg, char** err);

/**
 * Look up the key bound to a destination address. IP-only match:
 * port and IPv6 scope are ignored.
 *
 * @param table: table to search. NULL is allowed and always misses.
 * @param addr: destination address.
 * @param addrlen: length of addr.
 * @return the key to sign with, or NULL if the address is not bound.
 *		The returned pointer is owned by the table and remains
 *		valid for the table's lifetime.
 */
const struct tsig_key* tsig_server_table_lookup(
	const struct tsig_server_table* table,
	const struct sockaddr_storage* addr, socklen_t addrlen);

/**
 * Release the table and every key it owns. Safe on NULL.
 */
void tsig_server_table_delete(struct tsig_server_table* table);

/** Compare functions exposed for the fptr_wlist rbtree whitelist. */
int tsig_name_cmp(const void* a, const void* b);
int tsig_addr_cmp(const void* a, const void* b);

#endif /* SERVICES_TSIG_SERVER_H */
