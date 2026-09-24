/*
 * util/tsig.h - TSIG (Transaction SIGnature) support for outgoing queries.
 *
 * Copyright (c) 2026, SAP SE. All rights reserved.
 *
 * See LICENSE for the license.
 */

/**
 * \file
 *
 * This file provides TSIG (RFC 8945) support for signing outgoing DNS
 * queries. Only the client-side signing path is implemented here; no
 * response verification, no server-side handling.
 *
 * Currently supports HMAC-SHA256 only. The struct carries an algorithm
 * enum so adding others later is mechanical.
 *
 * The BIND key file format is supported for loading keys, e.g.:
 *
 *     key "auth-cluster.corp." {
 *             algorithm hmac-sha256;
 *             secret "aW5zZXJ0LWtleS1kYXRh...";
 *     };
 *
 * The fudge value is fixed at 300 seconds; there is no configuration knob.
 *
 * See doc/tsig.md for the full design and scope.
 */

#ifndef UTIL_TSIG_H
#define UTIL_TSIG_H

#include <sys/types.h>
#include <stdint.h>
#include <time.h>

struct sldns_buffer;

/** Fudge value used in every signed request, in seconds (RFC 8945 §10). */
#define TSIG_FUDGE_SECONDS 300

/**
 * Worst-case wire size of a TSIG RR (RFC 8945 §4.2):
 *   owner NAME (up to 255) + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
 *   + RDATA:
 *       Algorithm Name ("hmac-sha256." = 13)
 *     + Time Signed (6) + Fudge (2)
 *     + MAC Size (2) + MAC (32 for hmac-sha256)
 *     + Original ID (2) + Error (2) + Other Len (2) + Other Data (0)
 *   = 255 + 10 + 61 = 326 bytes.
 *
 * Used to reserve response headroom against the advertised EDNS UDP
 * buffer size so a compliant server's TSIG-signed response fits
 * without triggering TC->TCP fallback.
 */
#define TSIG_RR_MAX_WIRE_SIZE 326

/**
 * TSIG algorithms supported by this implementation.
 * Wire-format algorithm names (canonical, lower-case, uncompressed)
 * are looked up from this enum via tsig_alg_name().
 */
enum tsig_algorithm {
	TSIG_ALG_UNKNOWN = 0,
	TSIG_ALG_HMAC_SHA256 = 1
};

/**
 * A TSIG key. Owns its name and secret allocations.
 *
 * name_wire is the DNS-wire-format encoding of the key's owner name,
 * lower-cased for canonical comparison and signing. It includes the
 * final root label (a trailing zero byte).
 */
struct tsig_key {
	/** owner name in wire format, lower-cased */
	uint8_t* name_wire;
	/** length of name_wire in bytes, including the root label */
	size_t name_len;
	/** algorithm identifier */
	enum tsig_algorithm algorithm;
	/** raw secret key bytes (as returned by base64 decode) */
	uint8_t* secret;
	/** length of secret in bytes */
	size_t secret_len;
};

/**
 * Look up the canonical wire-format algorithm name for a TSIG algorithm.
 * @param alg: algorithm identifier.
 * @param out_len: on success, filled with the length of the returned buffer
 *		in bytes (including the root label).
 * @return pointer to a static, lower-cased, wire-format name (uncompressed,
 *		with the final root label). NULL if alg is unknown.
 */
const uint8_t* tsig_alg_wire_name(enum tsig_algorithm alg, size_t* out_len);

/**
 * Parse a TSIG algorithm mnemonic (case-insensitive).
 * Accepts BIND-style names such as "hmac-sha256" or "hmac-sha256.".
 * @param str: NUL-terminated mnemonic.
 * @return the parsed algorithm, or TSIG_ALG_UNKNOWN.
 */
enum tsig_algorithm tsig_algorithm_parse(const char* str);

/**
 * Load a TSIG key from a BIND-format key file.
 *
 * The file must contain a single `key "NAME" { ... };` stanza with an
 * `algorithm` clause and a `secret "..."` (base64) clause. Whitespace
 * and C-style / shell-style comments are tolerated.
 *
 * All errors are hard failures. Callers own the returned pointer and
 * must release it with tsig_key_delete().
 *
 * @param path: filesystem path to the key file.
 * @param expected_name: if non-NULL, the owner name in the file is compared
 *		against this text (case-insensitive, trailing dot optional).
 *		A mismatch is a hard error.
 * @param err: on failure, set to a malloc'd, human-readable error string
 *		which the caller must free(). On success, set to NULL.
 * @return the loaded key on success, or NULL on failure with *err populated.
 */
struct tsig_key* tsig_key_load_bind_file(const char* path,
	const char* expected_name, char** err);

/**
 * Release a tsig_key returned by tsig_key_load_bind_file() and zero the
 * secret memory before freeing.
 * @param key: key to release. NULL is a no-op.
 */
void tsig_key_delete(struct tsig_key* key);

/**
 * Sign an outgoing DNS query buffer with TSIG.
 *
 * The buffer is expected to be in "read" state, i.e. produced by
 * sldns_buffer_flip() with _position == 0 and _limit == message_length.
 * On success the buffer is left in read state with _limit updated to
 * reflect the appended TSIG RR, and the ARCOUNT in the DNS header
 * has been incremented by one.
 *
 * The buffer will be grown via sldns_buffer_reserve() if necessary.
 *
 * The digested data are, in order per RFC 8945 §4.3 / §5.1:
 *   1. The DNS message as it currently is (without any TSIG RR).
 *   2. The TSIG variables: key name (canonical wire), class ANY, TTL 0,
 *      algorithm name (canonical wire), time signed (48-bit BE),
 *      fudge (16-bit BE), error 0 (16-bit BE), other-len 0 (16-bit BE),
 *      no other-data.
 *
 * The RDLENGTH and MAC-Size fields of the TSIG RR itself are NOT part
 * of the digest, per RFC 8945 §4.3.3.
 *
 * @param pkt: the DNS message buffer, in read state.
 * @param key: the TSIG key to sign with. Must be non-NULL.
 * @param now: current time in seconds since UNIX epoch (Time Signed).
 * @return 1 on success, 0 on failure (buffer growth failed, HMAC failed,
 *		or unsupported algorithm).
 */
int tsig_sign_query(struct sldns_buffer* pkt, const struct tsig_key* key,
	time_t now);

#endif /* UTIL_TSIG_H */
