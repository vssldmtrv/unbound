/*
 * util/tsig.c - TSIG (Transaction SIGnature) support for outgoing queries.
 *
 * Copyright (c) 2026, SAP SE. All rights reserved.
 *
 * See LICENSE for the license.
 */

/**
 * \file
 *
 * Implementation of client-side TSIG signing per RFC 8945.
 *
 * See util/tsig.h for the public API and doc/tsig.md for the overall design.
 */

#include "config.h"
#include "util/tsig.h"

#ifdef HAVE_SSL

#include "sldns/sbuffer.h"
#include "sldns/pkthdr.h"
#include "sldns/parseutil.h"
#include "sldns/str2wire.h"
#include "sldns/rrdef.h"
#include "util/log.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <openssl/evp.h>
#ifdef HAVE_HMAC_INIT_EX
#include <openssl/hmac.h>
#endif
#ifdef HAVE_EVP_MAC_CTX_SET_PARAMS
#include <openssl/params.h>
#include <openssl/core_names.h>
#endif

/* ------------------------------------------------------------------ */
/* Algorithm registry                                                 */
/* ------------------------------------------------------------------ */

/**
 * Canonical (lower-case, uncompressed, wire-format) name of the
 * hmac-sha256 algorithm. Per RFC 8945 §6, algorithm names are text
 * strings encoded using the syntax of a domain name.
 *
 * Wire encoding of "hmac-sha256.": label "hmac-sha256" (11 octets) then
 * root label (1 octet). Total 13 octets.
 */
static const uint8_t tsig_alg_wire_hmac_sha256[13] = {
	11, 'h','m','a','c','-','s','h','a','2','5','6', 0
};

const uint8_t*
tsig_alg_wire_name(enum tsig_algorithm alg, size_t* out_len)
{
	switch(alg) {
	case TSIG_ALG_HMAC_SHA256:
		if(out_len) *out_len = sizeof(tsig_alg_wire_hmac_sha256);
		return tsig_alg_wire_hmac_sha256;
	default:
		break;
	}
	if(out_len) *out_len = 0;
	return NULL;
}

enum tsig_algorithm
tsig_algorithm_parse(const char* str)
{
	size_t len;
	if(!str) return TSIG_ALG_UNKNOWN;
	len = strlen(str);
	/* accept a trailing dot */
	if(len > 0 && str[len-1] == '.')
		len--;
	if(len == 11 && strncasecmp(str, "hmac-sha256", 11) == 0)
		return TSIG_ALG_HMAC_SHA256;
	return TSIG_ALG_UNKNOWN;
}

/* ------------------------------------------------------------------ */
/* Small helpers                                                      */
/* ------------------------------------------------------------------ */

/**
 * Lower-case a wire-format DNS name in place. Only label bytes are
 * modified; length octets and pointers (there should be none here) are
 * left alone. name_len is the total length including the root label.
 */
static void
tsig_dname_tolower(uint8_t* name, size_t name_len)
{
	size_t i = 0;
	while(i < name_len) {
		uint8_t ll = name[i];
		if(ll == 0) {
			break;
		}
		if((ll & 0xC0) != 0) {
			/* compression pointers or reserved: refuse to mutate */
			return;
		}
		i++;
		if(i + ll > name_len)
			return;
		while(ll-- > 0) {
			uint8_t c = name[i];
			if(c >= 'A' && c <= 'Z')
				name[i] = (uint8_t)(c + ('a' - 'A'));
			i++;
		}
	}
}

/**
 * Convert a text domain name into malloc'd, lower-cased, wire format.
 * Trailing dot is optional. On success returns the buffer and stores
 * its length. On failure returns NULL.
 */
static uint8_t*
tsig_dname_from_text(const char* text, size_t* out_len)
{
	uint8_t buf[LDNS_MAX_DOMAINLEN+1];
	size_t len = sizeof(buf);
	uint8_t* out;
	int r = sldns_str2wire_dname_buf(text, buf, &len);
	if(r != 0)
		return NULL;
	out = (uint8_t*)malloc(len);
	if(!out) return NULL;
	memcpy(out, buf, len);
	tsig_dname_tolower(out, len);
	if(out_len) *out_len = len;
	return out;
}

/* ------------------------------------------------------------------ */
/* BIND key file parser                                               */
/* ------------------------------------------------------------------ */

/*
 * Grammar (loose, matches the practical BIND format):
 *
 *   file    := WS? 'key' WS QSTRING WS '{' body '};' WS?
 *   body    := (item ';')+
 *   item    := 'algorithm' WS name
 *           |  'secret' WS QSTRING
 *   QSTRING := '"' ... '"'
 *   name    := unquoted-atom or quoted string
 *   WS      := whitespace or C-style / shell / C++ comments
 *
 * Anything else in body is a hard error.
 */

/** Tokenizer state. */
struct tsig_parser {
	const char* p;   /* current position */
	const char* end; /* one past end of buffer */
	int line;        /* current line (1-based) */
};

static void
tsig_skip_ws(struct tsig_parser* ps)
{
	while(ps->p < ps->end) {
		char c = *ps->p;
		if(c == '\n') {
			ps->line++;
			ps->p++;
		} else if(c == ' ' || c == '\t' || c == '\r') {
			ps->p++;
		} else if(c == '#') {
			/* shell comment to EOL */
			while(ps->p < ps->end && *ps->p != '\n')
				ps->p++;
		} else if(c == '/' && ps->p+1 < ps->end && ps->p[1] == '/') {
			while(ps->p < ps->end && *ps->p != '\n')
				ps->p++;
		} else if(c == '/' && ps->p+1 < ps->end && ps->p[1] == '*') {
			ps->p += 2;
			while(ps->p+1 < ps->end &&
				!(ps->p[0] == '*' && ps->p[1] == '/')) {
				if(*ps->p == '\n') ps->line++;
				ps->p++;
			}
			if(ps->p+1 < ps->end) ps->p += 2;
		} else {
			return;
		}
	}
}

/** Match a keyword (case-insensitive) followed by non-ident. */
static int
tsig_match_kw(struct tsig_parser* ps, const char* kw)
{
	size_t klen = strlen(kw);
	if((size_t)(ps->end - ps->p) < klen) return 0;
	if(strncasecmp(ps->p, kw, klen) != 0) return 0;
	/* boundary: next char must not be an identifier char */
	if((size_t)(ps->end - ps->p) > klen) {
		char nc = ps->p[klen];
		if((nc >= 'a' && nc <= 'z') || (nc >= 'A' && nc <= 'Z') ||
			(nc >= '0' && nc <= '9') || nc == '-' || nc == '_')
			return 0;
	}
	ps->p += klen;
	return 1;
}

/**
 * Read a "double-quoted" string. Returns malloc'd NUL-terminated copy of
 * contents (excluding quotes), or NULL on failure. No escape processing.
 */
static char*
tsig_read_quoted(struct tsig_parser* ps)
{
	const char* start;
	size_t len;
	char* out;
	if(ps->p >= ps->end || *ps->p != '"')
		return NULL;
	ps->p++;
	start = ps->p;
	while(ps->p < ps->end && *ps->p != '"') {
		if(*ps->p == '\n') ps->line++;
		ps->p++;
	}
	if(ps->p >= ps->end)
		return NULL;
	len = (size_t)(ps->p - start);
	out = (char*)malloc(len+1);
	if(!out) return NULL;
	if(len > 0) memcpy(out, start, len);
	out[len] = '\0';
	ps->p++; /* consume closing quote */
	return out;
}

/**
 * Read an unquoted atom or a quoted string. Returns malloc'd NUL-terminated
 * copy or NULL. Unquoted atoms terminate on whitespace, semicolon, or brace.
 */
static char*
tsig_read_atom(struct tsig_parser* ps)
{
	const char* start;
	size_t len;
	char* out;
	if(ps->p >= ps->end) return NULL;
	if(*ps->p == '"')
		return tsig_read_quoted(ps);
	start = ps->p;
	while(ps->p < ps->end) {
		char c = *ps->p;
		if(c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
			c == ';' || c == '{' || c == '}' || c == '"')
			break;
		ps->p++;
	}
	len = (size_t)(ps->p - start);
	if(len == 0) return NULL;
	out = (char*)malloc(len+1);
	if(!out) return NULL;
	memcpy(out, start, len);
	out[len] = '\0';
	return out;
}

/** Format a parser error into *err (malloc'd). Consumes fmt like printf.
 * If err is NULL or already set, this is a no-op. */
static void
tsig_perror(char** err, const char* path, int line, const char* fmt, ...)
{
	char body[256];
	size_t plen;
	char* buf;
	va_list ap;
	if(!err || *err) return;
	va_start(ap, fmt);
	vsnprintf(body, sizeof(body), fmt, ap);
	va_end(ap);
	plen = strlen(path) + strlen(body) + 32;
	buf = (char*)malloc(plen);
	if(!buf) return;
	snprintf(buf, plen, "%s:%d: %s", path, line, body);
	*err = buf;
}

/** Compare two DNS names given as text, case-insensitively, trailing dot
 *  is optional on both sides.
 */
static int
tsig_dname_text_equal(const char* a, const char* b)
{
	size_t la, lb;
	if(!a || !b) return 0;
	la = strlen(a);
	lb = strlen(b);
	if(la > 0 && a[la-1] == '.') la--;
	if(lb > 0 && b[lb-1] == '.') lb--;
	if(la != lb) return 0;
	return strncasecmp(a, b, la) == 0;
}

struct tsig_key*
tsig_key_load_bind_file(const char* path, const char* expected_name,
	char** err)
{
	FILE* f = NULL;
	char* file_data = NULL;
	long fsz = 0;
	size_t nread;
	struct tsig_parser ps;
	char* key_name_text = NULL;
	char* alg_text = NULL;
	char* secret_b64 = NULL;
	enum tsig_algorithm alg = TSIG_ALG_UNKNOWN;
	struct tsig_key* key = NULL;
	uint8_t* name_wire = NULL;
	size_t name_len = 0;
	uint8_t* secret_bin = NULL;
	int secret_bin_len = 0;
	size_t secret_max = 0;

	if(err) *err = NULL;

	if(!path) {
		if(err) *err = strdup("null path");
		return NULL;
	}
	f = fopen(path, "rb");
	if(!f) {
		size_t l = strlen(path) + 64;
		char* buf = (char*)malloc(l);
		if(buf) {
			snprintf(buf, l, "%s: cannot open: %s",
				path, strerror(errno));
			if(err) *err = buf;
			else free(buf);
		}
		return NULL;
	}
	if(fseek(f, 0, SEEK_END) != 0 ||
		(fsz = ftell(f)) < 0 ||
		fseek(f, 0, SEEK_SET) != 0) {
		tsig_perror(err, path, 0, "seek failed: %s", strerror(errno));
		fclose(f);
		return NULL;
	}
	if(fsz > 1024*1024) {
		tsig_perror(err, path, 0, "file too large (%ld bytes)", fsz);
		fclose(f);
		return NULL;
	}
	file_data = (char*)malloc((size_t)fsz + 1);
	if(!file_data) {
		fclose(f);
		return NULL;
	}
	nread = fread(file_data, 1, (size_t)fsz, f);
	fclose(f);
	if(nread != (size_t)fsz) {
		tsig_perror(err, path, 0, "short read");
		free(file_data);
		return NULL;
	}
	file_data[fsz] = '\0';

	ps.p = file_data;
	ps.end = file_data + fsz;
	ps.line = 1;

	tsig_skip_ws(&ps);
	if(!tsig_match_kw(&ps, "key")) {
		tsig_perror(err, path, ps.line,
			"expected 'key' stanza");
		goto fail;
	}
	tsig_skip_ws(&ps);
	key_name_text = tsig_read_atom(&ps);
	if(!key_name_text) {
		tsig_perror(err, path, ps.line, "expected key name");
		goto fail;
	}
	tsig_skip_ws(&ps);
	if(ps.p >= ps.end || *ps.p != '{') {
		tsig_perror(err, path, ps.line, "expected '{'");
		goto fail;
	}
	ps.p++;

	for(;;) {
		tsig_skip_ws(&ps);
		if(ps.p >= ps.end) {
			tsig_perror(err, path, ps.line, "unexpected EOF in key body");
			goto fail;
		}
		if(*ps.p == '}') {
			ps.p++;
			break;
		}
		if(tsig_match_kw(&ps, "algorithm")) {
			tsig_skip_ws(&ps);
			if(alg_text) {
				tsig_perror(err, path, ps.line,
					"duplicate 'algorithm'");
				goto fail;
			}
			alg_text = tsig_read_atom(&ps);
			if(!alg_text) {
				tsig_perror(err, path, ps.line,
					"expected algorithm name");
				goto fail;
			}
			tsig_skip_ws(&ps);
			if(ps.p >= ps.end || *ps.p != ';') {
				tsig_perror(err, path, ps.line,
					"expected ';' after algorithm");
				goto fail;
			}
			ps.p++;
		} else if(tsig_match_kw(&ps, "secret")) {
			tsig_skip_ws(&ps);
			if(secret_b64) {
				tsig_perror(err, path, ps.line,
					"duplicate 'secret'");
				goto fail;
			}
			secret_b64 = tsig_read_quoted(&ps);
			if(!secret_b64) {
				tsig_perror(err, path, ps.line,
					"expected quoted base64 secret");
				goto fail;
			}
			tsig_skip_ws(&ps);
			if(ps.p >= ps.end || *ps.p != ';') {
				tsig_perror(err, path, ps.line,
					"expected ';' after secret");
				goto fail;
			}
			ps.p++;
		} else {
			tsig_perror(err, path, ps.line,
				"unrecognized directive in key body");
			goto fail;
		}
	}
	tsig_skip_ws(&ps);
	if(ps.p >= ps.end || *ps.p != ';') {
		tsig_perror(err, path, ps.line,
			"expected ';' after '}'");
		goto fail;
	}
	ps.p++;

	if(!alg_text) {
		tsig_perror(err, path, ps.line, "missing 'algorithm'");
		goto fail;
	}
	if(!secret_b64) {
		tsig_perror(err, path, ps.line, "missing 'secret'");
		goto fail;
	}

	alg = tsig_algorithm_parse(alg_text);
	if(alg != TSIG_ALG_HMAC_SHA256) {
		tsig_perror(err, path, ps.line,
			"unsupported algorithm '%s' (only hmac-sha256 is supported)",
			alg_text);
		goto fail;
	}

	if(expected_name && !tsig_dname_text_equal(key_name_text, expected_name)) {
		tsig_perror(err, path, ps.line,
			"key name in file is '%s', expected '%s'",
			key_name_text, expected_name);
		goto fail;
	}

	name_wire = tsig_dname_from_text(key_name_text, &name_len);
	if(!name_wire) {
		tsig_perror(err, path, ps.line,
			"invalid key name '%s'", key_name_text);
		goto fail;
	}

	/* Strictly validate the base64 alphabet before decoding.
	 * sldns_b64_pton silently skips characters outside [A-Za-z0-9+/=]
	 * for whitespace tolerance, but for a BIND key-file secret we
	 * want any stray character to be a hard error. */
	{
		const char* q = secret_b64;
		if(*q == '\0') {
			tsig_perror(err, path, ps.line, "empty secret");
			goto fail;
		}
		while(*q) {
			unsigned char c = (unsigned char)*q++;
			if(!((c >= 'A' && c <= 'Z') ||
				(c >= 'a' && c <= 'z') ||
				(c >= '0' && c <= '9') ||
				c == '+' || c == '/' || c == '=')) {
				tsig_perror(err, path, ps.line,
					"invalid character in base64 secret");
				goto fail;
			}
		}
	}

	secret_max = sldns_b64_pton_calculate_size(strlen(secret_b64));
	if(secret_max > 0) {
		secret_bin = (uint8_t*)malloc(secret_max);
		if(!secret_bin) goto fail;
		secret_bin_len = sldns_b64_pton(secret_b64, secret_bin,
			secret_max);
	}
	if(secret_bin_len <= 0) {
		tsig_perror(err, path, ps.line, "malformed base64 secret");
		goto fail;
	}

	key = (struct tsig_key*)calloc(1, sizeof(*key));
	if(!key) goto fail;
	key->name_wire = name_wire;
	key->name_len = name_len;
	key->algorithm = alg;
	key->secret = secret_bin;
	key->secret_len = (size_t)secret_bin_len;
	name_wire = NULL;
	secret_bin = NULL;

	free(file_data);
	free(key_name_text);
	free(alg_text);
	free(secret_b64);
	return key;

fail:
	free(file_data);
	free(key_name_text);
	free(alg_text);
	if(secret_b64) {
		/* wipe secret text from memory */
		memset(secret_b64, 0, strlen(secret_b64));
		free(secret_b64);
	}
	free(name_wire);
	if(secret_bin) {
		memset(secret_bin, 0, secret_max);
		free(secret_bin);
	}
	if(err && !*err) {
		*err = strdup("TSIG key load failed");
	}
	return NULL;
}

void
tsig_key_delete(struct tsig_key* key)
{
	if(!key) return;
	if(key->secret) {
		memset(key->secret, 0, key->secret_len);
		free(key->secret);
	}
	free(key->name_wire);
	memset(key, 0, sizeof(*key));
	free(key);
}

/* ------------------------------------------------------------------ */
/* HMAC-SHA256                                                        */
/* ------------------------------------------------------------------ */

/**
 * Compute HMAC-SHA256(key, data). Writes the 32-byte MAC to out.
 * Returns 1 on success, 0 on failure.
 *
 * Uses the OpenSSL 3.x EVP_MAC API where available, falling back to
 * HMAC_Init_ex() on OpenSSL 1.x. The autoconf machinery in configure.ac
 * probes for both variants and defines HAVE_EVP_MAC_CTX_SET_PARAMS or
 * HAVE_HMAC_INIT_EX accordingly.
 */
static int
tsig_hmac_sha256(const uint8_t* key, size_t key_len,
	const uint8_t* data, size_t data_len,
	uint8_t out[32])
{
#ifdef HAVE_EVP_MAC_CTX_SET_PARAMS
	EVP_MAC* mac = NULL;
	EVP_MAC_CTX* ctx = NULL;
	OSSL_PARAM params[2];
	size_t outlen = 0;
	int ok = 0;

	mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
	if(!mac) goto done;
	ctx = EVP_MAC_CTX_new(mac);
	if(!ctx) goto done;
	params[0] = OSSL_PARAM_construct_utf8_string(
		OSSL_MAC_PARAM_DIGEST, (char*)"SHA256", 0);
	params[1] = OSSL_PARAM_construct_end();
	if(EVP_MAC_init(ctx, key, key_len, params) != 1) goto done;
	if(EVP_MAC_update(ctx, data, data_len) != 1) goto done;
	if(EVP_MAC_final(ctx, out, &outlen, 32) != 1) goto done;
	if(outlen != 32) goto done;
	ok = 1;
done:
	if(ctx) EVP_MAC_CTX_free(ctx);
	if(mac) EVP_MAC_free(mac);
	return ok;
#elif defined(HAVE_HMAC_INIT_EX)
	HMAC_CTX* ctx = NULL;
	unsigned int outlen = 0;
	int ok = 0;
# if OPENSSL_VERSION_NUMBER < 0x10100000L
	HMAC_CTX legacy_ctx;
	HMAC_CTX_init(&legacy_ctx);
	ctx = &legacy_ctx;
# else
	ctx = HMAC_CTX_new();
	if(!ctx) goto done;
# endif
# ifdef HMAC_INIT_EX_RETURNS_VOID
	HMAC_Init_ex(ctx, key, (int)key_len, EVP_sha256(), NULL);
# else
	if(HMAC_Init_ex(ctx, key, (int)key_len, EVP_sha256(), NULL) != 1)
		goto done;
# endif
	if(HMAC_Update(ctx, data, data_len) != 1) goto done;
	if(HMAC_Final(ctx, out, &outlen) != 1) goto done;
	if(outlen != 32) goto done;
	ok = 1;
done:
# if OPENSSL_VERSION_NUMBER < 0x10100000L
	HMAC_CTX_cleanup(&legacy_ctx);
# else
	if(ctx) HMAC_CTX_free(ctx);
# endif
	return ok;
#else
	(void)key; (void)key_len; (void)data; (void)data_len; (void)out;
	return 0;
#endif
}

/* ------------------------------------------------------------------ */
/* Signing                                                            */
/* ------------------------------------------------------------------ */

/*
 * TSIG RR wire layout, for reference (RFC 8945 §4.2):
 *
 *   NAME     (variable, key name, canonical, uncompressed)
 *   TYPE     (2, = 250, LDNS_RR_TYPE_TSIG)
 *   CLASS    (2, = 255, LDNS_RR_CLASS_ANY)
 *   TTL      (4, = 0)
 *   RDLENGTH (2)
 *   -- RDATA follows --
 *   Algorithm Name (variable, canonical, uncompressed)
 *   Time Signed    (6, 48-bit BE)
 *   Fudge          (2)
 *   MAC Size       (2, = 32 for hmac-sha256, full length)
 *   MAC            (32)
 *   Original ID    (2)
 *   Error          (2, = 0 for request)
 *   Other Len      (2, = 0 for request)
 *   Other Data     (empty)
 *
 * The digest input (§4.3) is:
 *   1. DNS Message (whole current message, without any TSIG RR).
 *   2. TSIG Variables:
 *        NAME (canonical wire)
 *        CLASS (2, network order)
 *        TTL   (4, network order)
 *        Algorithm Name (canonical wire)
 *        Time Signed    (6, network order)
 *        Fudge          (2, network order)
 *        Error          (2, network order)
 *        Other Len      (2, network order)
 *        Other Data     (variable; empty here)
 *
 * RDLENGTH and MAC Size are NOT in the digest.
 */

/** Serialize the TSIG "variables" portion into the given buffer. Returns
 * bytes written (or 0 on capacity failure). */
static size_t
tsig_write_variables(uint8_t* out, size_t out_cap,
	const struct tsig_key* key, uint64_t now, uint16_t fudge)
{
	size_t p = 0;
	const uint8_t* alg_wire;
	size_t alg_len;

	alg_wire = tsig_alg_wire_name(key->algorithm, &alg_len);
	if(!alg_wire) return 0;

	if(out_cap < key->name_len + 6 + alg_len + 10)
		return 0;

	/* NAME */
	memcpy(out+p, key->name_wire, key->name_len);
	p += key->name_len;
	/* CLASS (ANY) */
	out[p++] = 0;
	out[p++] = (uint8_t)LDNS_RR_CLASS_ANY;
	/* TTL = 0 */
	out[p++] = 0; out[p++] = 0; out[p++] = 0; out[p++] = 0;
	/* Algorithm Name */
	memcpy(out+p, alg_wire, alg_len);
	p += alg_len;
	/* Time Signed (48-bit BE) */
	out[p++] = (uint8_t)((now >> 40) & 0xFF);
	out[p++] = (uint8_t)((now >> 32) & 0xFF);
	out[p++] = (uint8_t)((now >> 24) & 0xFF);
	out[p++] = (uint8_t)((now >> 16) & 0xFF);
	out[p++] = (uint8_t)((now >> 8) & 0xFF);
	out[p++] = (uint8_t)((now) & 0xFF);
	/* Fudge */
	out[p++] = (uint8_t)((fudge >> 8) & 0xFF);
	out[p++] = (uint8_t)((fudge) & 0xFF);
	/* Error = 0 */
	out[p++] = 0; out[p++] = 0;
	/* Other Len = 0 */
	out[p++] = 0; out[p++] = 0;
	/* Other Data = empty */
	return p;
}

int
tsig_sign_query(struct sldns_buffer* pkt, const struct tsig_key* key,
	time_t now)
{
	uint16_t fudge = TSIG_FUDGE_SECONDS;
	uint16_t orig_id;
	uint16_t arcount;
	uint64_t timeval;
	uint8_t mac[32];
	uint8_t vars_buf[LDNS_MAX_DOMAINLEN + 6 + 13 + 10 + 32];
	size_t vars_len;
	uint8_t* digest_buf = NULL;
	size_t msg_len;
	const uint8_t* alg_wire;
	size_t alg_len;
	size_t tsig_rr_len;
	size_t rdlen;
	uint16_t rdlen_u16;
	size_t rr_pos;

	if(!pkt || !key) return 0;
	if(key->algorithm != TSIG_ALG_HMAC_SHA256) return 0;
	alg_wire = tsig_alg_wire_name(key->algorithm, &alg_len);
	if(!alg_wire) return 0;

	msg_len = sldns_buffer_limit(pkt);
	if(msg_len < LDNS_HEADER_SIZE) return 0;

	orig_id = LDNS_ID_WIRE(sldns_buffer_begin(pkt));
	arcount = LDNS_ARCOUNT(sldns_buffer_begin(pkt));

	timeval = (uint64_t)now;
	if(now < 0) timeval = 0;

	/* Build TSIG variables (for digest input, and later reused fields). */
	vars_len = tsig_write_variables(vars_buf, sizeof(vars_buf),
		key, timeval, fudge);
	if(vars_len == 0) return 0;

	/* Digest input = message || variables. */
	digest_buf = (uint8_t*)malloc(msg_len + vars_len);
	if(!digest_buf) return 0;
	memcpy(digest_buf, sldns_buffer_begin(pkt), msg_len);
	memcpy(digest_buf + msg_len, vars_buf, vars_len);

	if(!tsig_hmac_sha256(key->secret, key->secret_len,
		digest_buf, msg_len + vars_len, mac)) {
		free(digest_buf);
		return 0;
	}
	free(digest_buf);

	/* Compute RDATA length:
	 *   Algorithm Name + Time Signed(6) + Fudge(2) + MAC Size(2) +
	 *   MAC(32) + Original ID(2) + Error(2) + Other Len(2)
	 */
	rdlen = alg_len + 6 + 2 + 2 + 32 + 2 + 2 + 2;
	if(rdlen > 0xFFFF) return 0;
	rdlen_u16 = (uint16_t)rdlen;

	/* Full RR length = NAME + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) + RDATA */
	tsig_rr_len = key->name_len + 2 + 2 + 4 + 2 + rdlen;

	/* Grow buffer if needed: current in "read" state, limit == msg_len,
	 * capacity may be larger. Switch to write mode at end of message,
	 * reserve tsig_rr_len, write, then set the new limit. */
	sldns_buffer_set_position(pkt, msg_len);
	if(!sldns_buffer_reserve(pkt, tsig_rr_len)) {
		/* leave buffer as we found it, on the read side */
		sldns_buffer_set_position(pkt, 0);
		return 0;
	}
	rr_pos = msg_len;

	/* NAME */
	sldns_buffer_write(pkt, key->name_wire, key->name_len);
	/* TYPE = TSIG (250) */
	sldns_buffer_write_u16(pkt, LDNS_RR_TYPE_TSIG);
	/* CLASS = ANY (255) */
	sldns_buffer_write_u16(pkt, LDNS_RR_CLASS_ANY);
	/* TTL = 0 */
	sldns_buffer_write_u32(pkt, 0);
	/* RDLENGTH */
	sldns_buffer_write_u16(pkt, rdlen_u16);
	/* Algorithm Name */
	sldns_buffer_write(pkt, alg_wire, alg_len);
	/* Time Signed (48-bit BE) */
	sldns_buffer_write_u48(pkt, timeval);
	/* Fudge */
	sldns_buffer_write_u16(pkt, fudge);
	/* MAC Size */
	sldns_buffer_write_u16(pkt, 32);
	/* MAC */
	sldns_buffer_write(pkt, mac, 32);
	/* Original ID */
	sldns_buffer_write_u16(pkt, orig_id);
	/* Error */
	sldns_buffer_write_u16(pkt, 0);
	/* Other Len */
	sldns_buffer_write_u16(pkt, 0);
	/* (no Other Data) */

	log_assert(sldns_buffer_position(pkt) == rr_pos + tsig_rr_len);

	/* Set new limit to end-of-message; reset read position. */
	sldns_buffer_set_limit(pkt, rr_pos + tsig_rr_len);
	sldns_buffer_set_position(pkt, 0);

	/* Increment ARCOUNT to reflect the added TSIG RR. */
	LDNS_ARCOUNT_SET(sldns_buffer_begin(pkt), (uint16_t)(arcount + 1));

	return 1;
}

#else /* !HAVE_SSL */

#include <stddef.h>

const uint8_t*
tsig_alg_wire_name(enum tsig_algorithm alg, size_t* out_len)
{
	(void)alg;
	if(out_len) *out_len = 0;
	return NULL;
}

enum tsig_algorithm
tsig_algorithm_parse(const char* str)
{
	(void)str;
	return TSIG_ALG_UNKNOWN;
}

struct tsig_key*
tsig_key_load_bind_file(const char* path, const char* expected_name,
	char** err)
{
	(void)path; (void)expected_name;
	if(err) {
		*err = strdup("TSIG requires unbound to be built with OpenSSL");
	}
	return NULL;
}

void
tsig_key_delete(struct tsig_key* key)
{
	(void)key;
}

int
tsig_sign_query(struct sldns_buffer* pkt, const struct tsig_key* key,
	time_t now)
{
	(void)pkt; (void)key; (void)now;
	return 0;
}

#endif /* HAVE_SSL */
