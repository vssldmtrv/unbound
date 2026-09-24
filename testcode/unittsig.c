/*
 * testcode/unittsig.c - unit test for util/tsig.c
 *
 * Copyright (c) 2026, SAP SE. All rights reserved.
 *
 * See LICENSE for the license.
 */

/**
 * \file
 *
 * Unit tests for the TSIG signer and BIND-key-file loader.
 *
 * Coverage:
 *  - HMAC-SHA-256 primitive against RFC 4231 test cases 1, 2, 3.
 *  - Algorithm mnemonic parser.
 *  - BIND key file loader positive path.
 *  - BIND key file loader negative matrix (missing file, wrong algorithm,
 *    malformed base64, missing directives, name mismatch).
 *  - tsig_sign_query() structural checks: ARCOUNT increments,
 *    TSIG RR is appended last, RDLENGTH is correct, MAC-Size is 32,
 *    Original ID mirrors header ID, Error and Other Len are 0,
 *    Time Signed matches the value passed in, algorithm name is
 *    the canonical lower-case "hmac-sha256." wire form.
 *  - Determinism: signing the same message with the same key at the
 *    same time twice yields byte-identical MACs.
 */

#include "config.h"
#include "testcode/unitmain.h"
#include "util/log.h"
#include "util/tsig.h"

#ifdef HAVE_SSL

#include "sldns/sbuffer.h"
#include "sldns/pkthdr.h"
#include "sldns/rrdef.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* We rely on tsig_hmac_sha256 being a file-static helper. Rather than
 * exposing it in the header, the primitive is exercised transparently
 * through tsig_sign_query() plus a direct KAT check via a locally
 * duplicated HMAC that shares the same OpenSSL machinery. To keep the
 * unit test self-contained without leaking internal API, we implement
 * the KAT check by signing a controlled buffer and verifying the
 * appended MAC bytes against a value that we cross-check with an
 * externally computed reference. However, HMAC-SHA-256 KATs are the
 * most direct proof. To that end we include a minimal duplicate of
 * the HMAC primitive here, using the same OpenSSL calls the production
 * code uses. If both agree with the RFC 4231 vectors, we know the
 * OpenSSL wiring is correct on this build. */

#include <openssl/evp.h>
#ifdef HAVE_HMAC_INIT_EX
#include <openssl/hmac.h>
#endif
#ifdef HAVE_EVP_MAC_CTX_SET_PARAMS
#include <openssl/params.h>
#include <openssl/core_names.h>
#endif

/* ------------------------------------------------------------------ */
/* Local HMAC-SHA-256 helper mirroring util/tsig.c                    */
/* ------------------------------------------------------------------ */

static int
ut_hmac_sha256(const uint8_t* key, size_t klen,
	const uint8_t* data, size_t dlen, uint8_t out[32])
{
#ifdef HAVE_EVP_MAC_CTX_SET_PARAMS
	EVP_MAC* mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
	EVP_MAC_CTX* ctx = NULL;
	OSSL_PARAM params[2];
	size_t outlen = 0;
	int ok = 0;
	if(!mac) return 0;
	ctx = EVP_MAC_CTX_new(mac);
	if(!ctx) { EVP_MAC_free(mac); return 0; }
	params[0] = OSSL_PARAM_construct_utf8_string(
		OSSL_MAC_PARAM_DIGEST, (char*)"SHA256", 0);
	params[1] = OSSL_PARAM_construct_end();
	if(EVP_MAC_init(ctx, key, klen, params) != 1) goto done;
	if(EVP_MAC_update(ctx, data, dlen) != 1) goto done;
	if(EVP_MAC_final(ctx, out, &outlen, 32) != 1) goto done;
	ok = (outlen == 32);
done:
	EVP_MAC_CTX_free(ctx);
	EVP_MAC_free(mac);
	return ok;
#elif defined(HAVE_HMAC_INIT_EX)
	HMAC_CTX* ctx = HMAC_CTX_new();
	unsigned int outlen = 0;
	int ok = 0;
	if(!ctx) return 0;
	if(HMAC_Init_ex(ctx, key, (int)klen, EVP_sha256(), NULL) != 1) goto done;
	if(HMAC_Update(ctx, data, dlen) != 1) goto done;
	if(HMAC_Final(ctx, out, &outlen) != 1) goto done;
	ok = (outlen == 32);
done:
	HMAC_CTX_free(ctx);
	return ok;
#else
	(void)key; (void)klen; (void)data; (void)dlen; (void)out;
	return 0;
#endif
}

static int
ut_hex_eq(const uint8_t* mac, const char* hex, size_t maclen)
{
	size_t i;
	for(i = 0; i < maclen; i++) {
		unsigned int b;
		if(sscanf(hex + 2*i, "%2x", &b) != 1) return 0;
		if((uint8_t)b != mac[i]) return 0;
	}
	return 1;
}

/* ------------------------------------------------------------------ */
/* HMAC-SHA-256 KATs from RFC 4231 §4.2, §4.3, §4.4                   */
/* ------------------------------------------------------------------ */

static void
test_hmac_sha256_rfc4231(void)
{
	uint8_t mac[32];

	unit_show_feature("HMAC-SHA-256 KATs (RFC 4231)");

	/* Case 1: key = 0x0b*20, data = "Hi There" */
	{
		const uint8_t key[20] = {
			0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
			0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b
		};
		const uint8_t data[] = { 'H','i',' ','T','h','e','r','e' };
		const char* expect =
			"b0344c61d8db38535ca8afceaf0bf12b"
			"881dc200c9833da726e9376c2e32cff7";
		unit_assert(ut_hmac_sha256(key, sizeof(key),
			data, sizeof(data), mac));
		unit_assert(ut_hex_eq(mac, expect, 32));
	}

	/* Case 2: key = "Jefe", data = "what do ya want for nothing?" */
	{
		const uint8_t key[] = { 'J','e','f','e' };
		const uint8_t data[] = {
			'w','h','a','t',' ','d','o',' ','y','a',' ',
			'w','a','n','t',' ','f','o','r',' ',
			'n','o','t','h','i','n','g','?'
		};
		const char* expect =
			"5bdcc146bf60754e6a042426089575c7"
			"5a003f089d2739839dec58b964ec3843";
		unit_assert(ut_hmac_sha256(key, sizeof(key),
			data, sizeof(data), mac));
		unit_assert(ut_hex_eq(mac, expect, 32));
	}

	/* Case 3: key = 0xaa*20, data = 0xdd*50 */
	{
		uint8_t key[20];
		uint8_t data[50];
		const char* expect =
			"773ea91e36800e46854db8ebd09181a7"
			"2959098b3ef8c122d9635514ced565fe";
		memset(key, 0xaa, sizeof(key));
		memset(data, 0xdd, sizeof(data));
		unit_assert(ut_hmac_sha256(key, sizeof(key),
			data, sizeof(data), mac));
		unit_assert(ut_hex_eq(mac, expect, 32));
	}
}

/* ------------------------------------------------------------------ */
/* Algorithm mnemonic parser                                          */
/* ------------------------------------------------------------------ */

static void
test_algorithm_parse(void)
{
	unit_show_feature("TSIG algorithm mnemonic parser");
	unit_assert(tsig_algorithm_parse("hmac-sha256") == TSIG_ALG_HMAC_SHA256);
	unit_assert(tsig_algorithm_parse("HMAC-SHA256") == TSIG_ALG_HMAC_SHA256);
	unit_assert(tsig_algorithm_parse("hmac-sha256.") == TSIG_ALG_HMAC_SHA256);
	unit_assert(tsig_algorithm_parse("Hmac-Sha256.") == TSIG_ALG_HMAC_SHA256);
	unit_assert(tsig_algorithm_parse("hmac-sha1") == TSIG_ALG_UNKNOWN);
	unit_assert(tsig_algorithm_parse("hmac-md5.sig-alg.reg.int")
		== TSIG_ALG_UNKNOWN);
	unit_assert(tsig_algorithm_parse("") == TSIG_ALG_UNKNOWN);
	unit_assert(tsig_algorithm_parse(NULL) == TSIG_ALG_UNKNOWN);
}

/* ------------------------------------------------------------------ */
/* BIND key file loader                                               */
/* ------------------------------------------------------------------ */

/** Write s to a scratch file; returns malloc'd path. Caller unlink+free. */
static char*
write_tempfile(const char* s)
{
	char* path;
	FILE* f;
	const char* tmp = getenv("TMPDIR");
	if(!tmp) tmp = "/tmp";
	path = (char*)malloc(strlen(tmp) + 32);
	unit_assert(path != NULL);
	snprintf(path, strlen(tmp) + 32, "%s/ubtsig.XXXXXX", tmp);
	{
		int fd = mkstemp(path);
		unit_assert(fd >= 0);
		close(fd);
	}
	f = fopen(path, "wb");
	unit_assert(f != NULL);
	unit_assert(fwrite(s, 1, strlen(s), f) == strlen(s));
	fclose(f);
	return path;
}

static void
test_bind_key_load_ok(void)
{
	/* base64("hello") = "aGVsbG8="; secret raw 5 bytes: 68 65 6c 6c 6f */
	const char* body =
		"key \"test.example.\" {\n"
		"\talgorithm hmac-sha256;\n"
		"\tsecret \"aGVsbG8=\";\n"
		"};\n";
	char* path;
	char* err = NULL;
	struct tsig_key* key;

	unit_show_feature("BIND key file: positive path");
	path = write_tempfile(body);
	key = tsig_key_load_bind_file(path, NULL, &err);
	unit_assert(key != NULL);
	unit_assert(err == NULL);
	unit_assert(key->algorithm == TSIG_ALG_HMAC_SHA256);
	unit_assert(key->secret_len == 5);
	unit_assert(key->secret[0] == 'h' && key->secret[4] == 'o');
	/* wire form of "test.example.": 04 't' 'e' 's' 't' 07 'e' 'x' 'a' 'm' 'p' 'l' 'e' 00 = 14 bytes */
	unit_assert(key->name_len == 14);
	unit_assert(key->name_wire[0] == 4);
	unit_assert(key->name_wire[13] == 0);
	tsig_key_delete(key);
	unlink(path);
	free(path);
}

static void
test_bind_key_load_case_and_expected_name(void)
{
	const char* body =
		"key \"Test.Example.\" {\n"
		"\talgorithm HMAC-SHA256;\n"
		"\tsecret \"aGVsbG8=\";\n"
		"};\n";
	char* path;
	char* err = NULL;
	struct tsig_key* key;

	unit_show_feature("BIND key file: case-insensitivity + expected name");
	path = write_tempfile(body);

	/* name matches (case-insensitive, dot optional) */
	key = tsig_key_load_bind_file(path, "test.example", &err);
	unit_assert(key != NULL);
	unit_assert(err == NULL);
	/* name in the wire buffer must be lower-cased.
	 * Wire form of "test.example.": 04 t e s t 07 e x a m p l e 00 */
	unit_assert(key->name_wire[0] == 4);
	unit_assert(key->name_wire[1] == 't' && key->name_wire[2] == 'e');
	unit_assert(key->name_wire[3] == 's' && key->name_wire[4] == 't');
	unit_assert(key->name_wire[5] == 7);
	unit_assert(key->name_wire[6] == 'e' && key->name_wire[7] == 'x');
	unit_assert(key->name_wire[13] == 0);
	tsig_key_delete(key);

	/* name mismatch is a hard error */
	err = NULL;
	key = tsig_key_load_bind_file(path, "other.example", &err);
	unit_assert(key == NULL);
	unit_assert(err != NULL);
	free(err);

	unlink(path);
	free(path);
}

static void
test_bind_key_load_wrong_algorithm(void)
{
	const char* body =
		"key \"foo.\" {\n"
		"\talgorithm hmac-sha1;\n"
		"\tsecret \"aGVsbG8=\";\n"
		"};\n";
	char* path;
	char* err = NULL;
	struct tsig_key* key;
	unit_show_feature("BIND key file: wrong algorithm -> hard fail");
	path = write_tempfile(body);
	key = tsig_key_load_bind_file(path, NULL, &err);
	unit_assert(key == NULL);
	unit_assert(err != NULL);
	free(err);
	unlink(path);
	free(path);
}

static void
test_bind_key_load_malformed_base64(void)
{
	char* path;
	char* err = NULL;
	struct tsig_key* key;

	unit_show_feature("BIND key file: malformed base64 -> hard fail");

	/* Non-base64 characters in the secret must be rejected. */
	{
		const char* body =
			"key \"foo.\" {\n"
			"\talgorithm hmac-sha256;\n"
			"\tsecret \"@@not-base64@@\";\n"
			"};\n";
		path = write_tempfile(body);
		key = tsig_key_load_bind_file(path, NULL, &err);
		unit_assert(key == NULL);
		unit_assert(err != NULL);
		free(err); err = NULL;
		unlink(path); free(path);
	}
	/* Empty secret must be rejected. */
	{
		const char* body =
			"key \"foo.\" {\n"
			"\talgorithm hmac-sha256;\n"
			"\tsecret \"\";\n"
			"};\n";
		path = write_tempfile(body);
		key = tsig_key_load_bind_file(path, NULL, &err);
		unit_assert(key == NULL);
		unit_assert(err != NULL);
		free(err); err = NULL;
		unlink(path); free(path);
	}
}

static void
test_bind_key_load_missing_directives(void)
{
	char* path;
	char* err = NULL;
	struct tsig_key* key;

	unit_show_feature("BIND key file: missing algorithm/secret -> hard fail");

	/* Missing secret */
	{
		const char* body =
			"key \"foo.\" {\n"
			"\talgorithm hmac-sha256;\n"
			"};\n";
		path = write_tempfile(body);
		key = tsig_key_load_bind_file(path, NULL, &err);
		unit_assert(key == NULL);
		unit_assert(err != NULL);
		free(err); err = NULL;
		unlink(path); free(path);
	}
	/* Missing algorithm */
	{
		const char* body =
			"key \"foo.\" {\n"
			"\tsecret \"aGVsbG8=\";\n"
			"};\n";
		path = write_tempfile(body);
		key = tsig_key_load_bind_file(path, NULL, &err);
		unit_assert(key == NULL);
		unit_assert(err != NULL);
		free(err); err = NULL;
		unlink(path); free(path);
	}
	/* Not a key stanza */
	{
		const char* body = "options { directory \"/\"; };\n";
		path = write_tempfile(body);
		key = tsig_key_load_bind_file(path, NULL, &err);
		unit_assert(key == NULL);
		unit_assert(err != NULL);
		free(err); err = NULL;
		unlink(path); free(path);
	}
}

static void
test_bind_key_load_missing_file(void)
{
	char* err = NULL;
	struct tsig_key* key;
	unit_show_feature("BIND key file: missing file -> hard fail");
	key = tsig_key_load_bind_file(
		"/nonexistent/dir/no-such.key", NULL, &err);
	unit_assert(key == NULL);
	unit_assert(err != NULL);
	free(err);
}

/* ------------------------------------------------------------------ */
/* tsig_sign_query() structural checks                                */
/* ------------------------------------------------------------------ */

/** Build a tiny question-only DNS message in wire format into the buffer,
 * flip it, return the message length. Query "example.com. IN A". */
static size_t
build_query_example_com(struct sldns_buffer* buf, uint16_t id)
{
	sldns_buffer_clear(buf);
	sldns_buffer_write_u16(buf, id);   /* ID */
	sldns_buffer_write_u16(buf, 0x0100); /* flags: RD */
	sldns_buffer_write_u16(buf, 1);    /* QDCOUNT */
	sldns_buffer_write_u16(buf, 0);
	sldns_buffer_write_u16(buf, 0);
	sldns_buffer_write_u16(buf, 0);
	/* QNAME: example.com. */
	sldns_buffer_write_u8(buf, 7);
	sldns_buffer_write(buf, "example", 7);
	sldns_buffer_write_u8(buf, 3);
	sldns_buffer_write(buf, "com", 3);
	sldns_buffer_write_u8(buf, 0);
	/* QTYPE = A, QCLASS = IN */
	sldns_buffer_write_u16(buf, LDNS_RR_TYPE_A);
	sldns_buffer_write_u16(buf, LDNS_RR_CLASS_IN);
	sldns_buffer_flip(buf);
	return sldns_buffer_limit(buf);
}

/** Load a minimal in-memory key without touching the filesystem. */
static struct tsig_key*
make_test_key(void)
{
	const char* body =
		"key \"key.example.\" {\n"
		"\talgorithm hmac-sha256;\n"
		"\tsecret \"aGVsbG8=\";\n"
		"};\n";
	char* path = write_tempfile(body);
	char* err = NULL;
	struct tsig_key* k = tsig_key_load_bind_file(path, NULL, &err);
	unit_assert(k != NULL);
	unit_assert(err == NULL);
	unlink(path);
	free(path);
	return k;
}

static void
test_sign_structural(void)
{
	struct sldns_buffer* buf = sldns_buffer_new(1024);
	struct tsig_key* key = make_test_key();
	size_t base_len, new_len;
	uint16_t arcount_before, arcount_after;
	uint8_t* rr;
	size_t rr_len;
	size_t name_end;
	uint16_t rr_type, rr_class, rdlen, mac_size, orig_id_field,
		error_field, other_len_field;
	uint32_t ttl;
	size_t rd_off;
	uint16_t alg_owner_start;
	time_t signing_time = 1234567890;

	unit_show_feature("tsig_sign_query: appends valid TSIG RR");

	base_len = build_query_example_com(buf, 0xbeef);
	arcount_before = LDNS_ARCOUNT(sldns_buffer_begin(buf));
	unit_assert(arcount_before == 0);

	unit_assert(tsig_sign_query(buf, key, signing_time));

	new_len = sldns_buffer_limit(buf);
	unit_assert(new_len > base_len);
	rr = sldns_buffer_begin(buf) + base_len;
	rr_len = new_len - base_len;

	arcount_after = LDNS_ARCOUNT(sldns_buffer_begin(buf));
	unit_assert(arcount_after == 1);

	/* Owner name: "key.example." wire is
	 *   03 k e y 07 e x a m p l e 00
	 * = 13 bytes total (indices 0..12). */
	unit_assert(rr_len > 13);
	unit_assert(rr[0] == 3);
	unit_assert(rr[1] == 'k' && rr[2] == 'e' && rr[3] == 'y');
	unit_assert(rr[4] == 7);
	unit_assert(rr[5] == 'e' && rr[6] == 'x' && rr[7] == 'a' &&
		rr[8] == 'm' && rr[9] == 'p' && rr[10] == 'l' && rr[11] == 'e');
	unit_assert(rr[12] == 0);
	name_end = 13;

	rr_type = (uint16_t)((rr[name_end] << 8) | rr[name_end+1]);
	rr_class = (uint16_t)((rr[name_end+2] << 8) | rr[name_end+3]);
	ttl = ((uint32_t)rr[name_end+4] << 24) |
		((uint32_t)rr[name_end+5] << 16) |
		((uint32_t)rr[name_end+6] << 8) |
		((uint32_t)rr[name_end+7]);
	rdlen = (uint16_t)((rr[name_end+8] << 8) | rr[name_end+9]);
	rd_off = name_end + 10;

	unit_assert(rr_type == LDNS_RR_TYPE_TSIG);
	unit_assert(rr_class == LDNS_RR_CLASS_ANY);
	unit_assert(ttl == 0);
	unit_assert(rd_off + rdlen == rr_len);

	/* RDATA layout: alg-name (13 for hmac-sha256.), time(6), fudge(2),
	 *   mac-size(2), mac(32), orig-id(2), error(2), other-len(2)
	 */
	alg_owner_start = (uint16_t)rr[rd_off];
	unit_assert(alg_owner_start == 11); /* "hmac-sha256" label length */
	unit_assert(rr[rd_off + 12] == 0);  /* root label */
	/* case: canonical wire form is lower-case */
	unit_assert(rr[rd_off+1] == 'h' && rr[rd_off+2] == 'm' &&
		rr[rd_off+3] == 'a' && rr[rd_off+4] == 'c' &&
		rr[rd_off+5] == '-' && rr[rd_off+6] == 's' &&
		rr[rd_off+7] == 'h' && rr[rd_off+8] == 'a' &&
		rr[rd_off+9] == '2' && rr[rd_off+10] == '5' &&
		rr[rd_off+11] == '6');

	/* Time signed (48-bit BE) */
	{
		uint64_t t = 0;
		size_t p = rd_off + 13;
		t = ((uint64_t)rr[p] << 40) |
			((uint64_t)rr[p+1] << 32) |
			((uint64_t)rr[p+2] << 24) |
			((uint64_t)rr[p+3] << 16) |
			((uint64_t)rr[p+4] << 8) |
			((uint64_t)rr[p+5]);
		unit_assert(t == (uint64_t)signing_time);
	}

	/* Fudge */
	{
		size_t p = rd_off + 13 + 6;
		uint16_t fudge = (uint16_t)((rr[p] << 8) | rr[p+1]);
		unit_assert(fudge == TSIG_FUDGE_SECONDS);
	}

	/* MAC Size = 32 */
	{
		size_t p = rd_off + 13 + 6 + 2;
		mac_size = (uint16_t)((rr[p] << 8) | rr[p+1]);
		unit_assert(mac_size == 32);
	}

	/* Original ID mirrors the header ID */
	{
		size_t p = rd_off + 13 + 6 + 2 + 2 + 32;
		orig_id_field = (uint16_t)((rr[p] << 8) | rr[p+1]);
		unit_assert(orig_id_field == 0xbeef);
	}

	/* Error = 0, Other Len = 0 */
	{
		size_t p = rd_off + 13 + 6 + 2 + 2 + 32 + 2;
		error_field = (uint16_t)((rr[p] << 8) | rr[p+1]);
		other_len_field = (uint16_t)((rr[p+2] << 8) | rr[p+3]);
		unit_assert(error_field == 0);
		unit_assert(other_len_field == 0);
	}

	tsig_key_delete(key);
	sldns_buffer_free(buf);
}

static void
test_sign_determinism_and_kat(void)
{
	/*
	 * Determinism: signing the same message with the same key and
	 * same timestamp must produce byte-identical MACs.
	 *
	 * Cross-check: also recompute the digest independently using
	 * the local ut_hmac_sha256() helper over (message || TSIG variables)
	 * and confirm it matches the MAC bytes embedded in the appended
	 * TSIG RR. This is the tightest end-to-end proof that our signer
	 * follows RFC 8945 §4.3.
	 */
	struct sldns_buffer* buf = sldns_buffer_new(1024);
	struct sldns_buffer* buf2 = sldns_buffer_new(1024);
	struct tsig_key* key = make_test_key();
	size_t base_len;
	uint8_t* mac_a;
	uint8_t* mac_b;
	uint8_t expected[32];
	time_t signing_time = 1700000000;
	uint16_t query_id = 0x1234;

	unit_show_feature("tsig_sign_query: deterministic + cross-check MAC");

	base_len = build_query_example_com(buf, query_id);
	unit_assert(tsig_sign_query(buf, key, signing_time));
	(void)build_query_example_com(buf2, query_id);
	unit_assert(tsig_sign_query(buf2, key, signing_time));

	/* Locate MAC bytes: name(13) + type(2)+class(2)+ttl(4)+rdlen(2) +
	 *   alg_name(13) + time(6) + fudge(2) + mac_size(2) = 46 into RR */
	{
		size_t mac_off_in_rr = 13 + 10 + 13 + 6 + 2 + 2;
		mac_a = sldns_buffer_begin(buf) + base_len + mac_off_in_rr;
		mac_b = sldns_buffer_begin(buf2) + base_len + mac_off_in_rr;
	}
	unit_assert(memcmp(mac_a, mac_b, 32) == 0);

	/* Reconstruct the digest input and cross-check the MAC. */
	{
		/* Message = the first base_len bytes of buf (which are still
		 * the original message, since tsig_sign_query only appended). */
		uint8_t* msg = sldns_buffer_begin(buf);
		/* Variables:
		 *   name(13) + class(2) + ttl(4) + alg-name(13) +
		 *   time(6) + fudge(2) + error(2) + other-len(2) = 44
		 */
		uint8_t vars[44];
		size_t p = 0;
		/* NAME "key.example." wire lower-cased */
		vars[p++] = 3; vars[p++]='k'; vars[p++]='e'; vars[p++]='y';
		vars[p++] = 7; vars[p++]='e'; vars[p++]='x'; vars[p++]='a';
		vars[p++]='m'; vars[p++]='p'; vars[p++]='l'; vars[p++]='e';
		vars[p++] = 0;
		/* CLASS ANY */
		vars[p++] = 0; vars[p++] = 255;
		/* TTL 0 */
		vars[p++] = 0; vars[p++] = 0; vars[p++] = 0; vars[p++] = 0;
		/* Algorithm name */
		vars[p++] = 11;
		memcpy(vars+p, "hmac-sha256", 11); p += 11;
		vars[p++] = 0;
		/* Time signed 48-bit BE */
		{
			uint64_t t = (uint64_t)signing_time;
			vars[p++] = (uint8_t)((t>>40)&0xFF);
			vars[p++] = (uint8_t)((t>>32)&0xFF);
			vars[p++] = (uint8_t)((t>>24)&0xFF);
			vars[p++] = (uint8_t)((t>>16)&0xFF);
			vars[p++] = (uint8_t)((t>>8)&0xFF);
			vars[p++] = (uint8_t)(t&0xFF);
		}
		/* Fudge */
		vars[p++] = (uint8_t)((TSIG_FUDGE_SECONDS>>8)&0xFF);
		vars[p++] = (uint8_t)(TSIG_FUDGE_SECONDS&0xFF);
		/* Error 0 */
		vars[p++] = 0; vars[p++] = 0;
		/* Other Len 0 */
		vars[p++] = 0; vars[p++] = 0;
		unit_assert(p == sizeof(vars));

		/* Digest input = original message || variables. Note that
		 * ARCOUNT in the message at this point IS 1 (already
		 * incremented by tsig_sign_query()), but the digest input
		 * per RFC 8945 §4.3.2 uses ARCOUNT reflecting the message
		 * *without* the TSIG RR. Temporarily undo the increment for
		 * the cross-check. */
		{
			uint16_t saved = LDNS_ARCOUNT(msg);
			uint8_t* concat;
			unit_assert(saved == 1);
			LDNS_ARCOUNT_SET(msg, 0);
			concat = (uint8_t*)malloc(base_len + sizeof(vars));
			unit_assert(concat != NULL);
			memcpy(concat, msg, base_len);
			memcpy(concat + base_len, vars, sizeof(vars));
			unit_assert(ut_hmac_sha256(key->secret, key->secret_len,
				concat, base_len + sizeof(vars), expected));
			LDNS_ARCOUNT_SET(msg, saved);
			free(concat);
		}
		unit_assert(memcmp(mac_a, expected, 32) == 0);
	}

	tsig_key_delete(key);
	sldns_buffer_free(buf);
	sldns_buffer_free(buf2);
}

/* ------------------------------------------------------------------ */
/* Entry point                                                        */
/* ------------------------------------------------------------------ */

void
tsig_test(void)
{
	unit_show_func("util/tsig.c", "tsig");
	test_hmac_sha256_rfc4231();
	test_algorithm_parse();
	test_bind_key_load_ok();
	test_bind_key_load_case_and_expected_name();
	test_bind_key_load_wrong_algorithm();
	test_bind_key_load_malformed_base64();
	test_bind_key_load_missing_directives();
	test_bind_key_load_missing_file();
	test_sign_structural();
	test_sign_determinism_and_kat();
}

#else /* !HAVE_SSL */

void
tsig_test(void)
{
	unit_show_func("util/tsig.c", "tsig");
	unit_show_feature("TSIG unit tests skipped: built without OpenSSL");
}

#endif /* HAVE_SSL */
