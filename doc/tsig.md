# Outgoing TSIG signing (per-nameserver)

## Status

- Branch: `d073579/per-server-tsig` (off `release-1.26.1`)
- Current phase: **Phases 1–2 complete; Phase 3 next**
- Last updated: 2026-09-24

## Purpose

Let Unbound present a TSIG-signed query to configured upstream nameservers,
so that authoritative servers configured to require TSIG (e.g. BIND with
`allow-query { key "..."; };`) will accept the query. TSIG here is used as
a server-side authentication mechanism, not as a channel-security feature.

## Scope

- Sign every outbound query whose destination IP appears in the
  `server-tsig` table with HMAC-SHA256 TSIG.
- IP-only exact match, ignoring port. IPv4 and IPv6 addresses of the same
  logical server are separate entries.
- Applies uniformly to any outgoing traffic: forward-zone, stub-zone,
  normal recursion, priming, and target-fetch queries.
- Hard-fail on any TSIG config/key error at startup and on `unbound-control
  reload`. `unbound-checkconf` validates every referenced key file.

## Non-goals

- No response TSIG verification. The auth server signs its reply, but
  Unbound does not verify it. Rationale: goal is to satisfy the server's
  ACL, not to secure the transport.
- No algorithms other than HMAC-SHA256 in v1.
- No fudge/lifetime knobs. Fudge is fixed at 300 seconds.
- No CIDR ranges in v1 — exact IPs only.
- No per-zone TSIG configuration. The per-zone alternative was considered
  and rejected (see "Alternatives considered" below).

## Design decisions (locked)

1. **Per-nameserver, not per-zone.** TSIG is naturally a transaction-level
   authenticator between two endpoints (RFC 8945 §1). Per-nameserver
   matches how BIND's `server { keys { ... }; };` models it, covers
   forward/stub/recursion uniformly, and requires no changes to the
   `send_query` callback signature.
2. **IP-only exact match, ignoring port.** Same as BIND's server match.
3. **Top-level `tsig-key` block.** Reusable key definitions, referenced by
   name from `server-tsig` entries.
4. **BIND key file format** for the secret file. Owner name, algorithm and
   base64 secret are all read from the file.
5. **Hard-fail at startup / reload / checkconf** on missing file, wrong
   algorithm, malformed base64, or dangling key reference.
6. **`unbound-checkconf` validates key files** the same way the daemon
   does.
7. **Reload re-reads key files** and atomically swaps the tables.
8. **Fudge fixed at 300 seconds.** No knob.
9. **HMAC-SHA256 only** in v1. The `struct tsig_key` carries an algorithm
   enum so adding others later is mechanical.
10. **No per-IP verbose signing log.** Signing is silent on the hot path.

## Config surface

```
tsig-key:
    name: "auth-cluster.corp."
    key-file: "/etc/unbound/auth-cluster.key"

server-tsig:
    address: 10.1.1.1
    key: "auth-cluster.corp."

server-tsig:
    address: 2001:db8::1
    key: "auth-cluster.corp."
```

Both blocks are top-level. The key file is BIND format, e.g.:

```
key "auth-cluster.corp." {
    algorithm hmac-sha256;
    secret "aW5zZXJ0LWtleS1kYXRh...";
};
```

### Validation rules (hard-fail)

- `tsig-key.name` is a legal DNS name and matches the owner name in the
  BIND key file.
- `tsig-key.key-file` exists, is readable, parses as BIND format, declares
  `algorithm hmac-sha256`, and its secret base64-decodes.
- Every `server-tsig.key` references a defined `tsig-key.name`.
- Every `server-tsig.address` parses as an IPv4 or IPv6 literal.
- No duplicate `server-tsig.address` entries.

## Runtime data

- Shared, read-only key store keyed by name (`struct tsig_key*` per entry).
- Shared, read-only address→key table: rbtree keyed on normalized
  `sockaddr_storage` (port and IPv6 scope zeroed; address family is the
  discriminator).
- Both built off-lock at config apply and reload, then swapped atomically.
  Mirrors the `forwards_swap_tree` pattern in `iterator/iter_fwd.c`.
- In-flight signed queries keep their captured `sq->tsig_key` pointer
  valid until they complete; keys held via the swap machinery until safe
  to free.

## Architecture

### New files

- `util/tsig.h`, `util/tsig.c` — TSIG core (BIND key file loader, HMAC-SHA256 signer).
- `services/tsig_server.h`, `services/tsig_server.c` — address→key lookup table.

### Modified files

- `util/config_file.h`, `util/config_file.c` — new config structs and cleanup.
- `util/configparser.y`, `util/configlexer.lex` — new tokens, keywords, yacc rules.
- `services/outside_network.h`, `services/outside_network.c` — pointer to the
  address→key table on `outside_network`; `tsig_key` field on `serviced_query`;
  lookup at `serviced_create` (line 2702); sign hooks at
  `randomize_and_send_udp` (2281), `serviced_tcp_initiate` (3262),
  `serviced_tcp_send` (3283); size budgeting at `serviced_query_udp_size` (2925).
- `daemon/daemon.h`, `daemon/daemon.c` — build the key store and address table
  during config apply; free at shutdown.
- `daemon/remote.c` — reload rebuilds and atomically swaps.
- `smallapp/unbound-checkconf.c` — validate all `tsig-key` files and
  `server-tsig` references.
- `doc/unbound.conf.rst`, `doc/unbound.conf.5.in` — document new directives.
- `doc/FEATURES` — revise the "No TSIG support" line.
- `doc/Changelog` — entry.
- `doc/TODO` — mark line 51 as partial.

### `util/tsig.{h,c}` API

```c
struct tsig_key {
    uint8_t* name_wire;
    size_t   name_len;
    uint8_t* secret;
    size_t   secret_len;
    /* algorithm enum, currently only TSIG_ALG_HMAC_SHA256 */
};

struct tsig_key* tsig_key_load_bind_file(const char* path,
    const char* expected_name, char** err);
void tsig_key_delete(struct tsig_key* key);

/* Append TSIG RR (per RFC 8945 §5.3/§4.3), bump ARCOUNT,
 * compute HMAC-SHA256, write MAC. Fudge = 300s. */
int tsig_sign_query(struct sldns_buffer* pkt,
    const struct tsig_key* key, time_t now);
```

Uses OpenSSL `EVP_MAC` with the fallback pattern from `util/net_help.c`
(handles both `EVP_MAC_CTX_set_params` and legacy `HMAC_Init_ex`), so no
new autoconf work.

### Send-time chokepoints

TSIG covers the final packet including the real transaction ID. The ID is
placeholder `0` in `serviced_encode` and set by `select_id` afterwards, so
signing runs *after* the ID is fixed:

1. **UDP**: `services/outside_network.c:2281` `randomize_and_send_udp`,
   immediately after `select_id(...)` succeeds and before
   `comm_point_send_udp_msg(...)`. Covers immediate send and the fd
   wait-list path (both re-enter here).
2. **TCP initiate**: `services/outside_network.c:3262`
   `serviced_tcp_initiate`, after `serviced_encode` and before
   `pending_tcp_query`. The 2-byte length prefix reflects post-TSIG size.
3. **TCP send / reuse**: `services/outside_network.c:3283`
   `serviced_tcp_send`, same treatment.
4. **EDNS-fallback re-encode** paths re-enter one of the above; no
   separate hook needed.

Retransmits regenerate the timestamp automatically because signing runs on
every send attempt.

### Packet size

`serviced_query_udp_size` (`services/outside_network.c:2925`) reserves ~90
bytes of TSIG headroom against the advertised EDNS buffer when
`sq->tsig_key` is set. Existing TC → TCP fallback handles overflow with no
new code.

## Interactions confirmed neutral

- **EDNS**: OPT is placed by `serviced_encode`, TSIG appended after. ARCOUNT
  bumped in the signer.
- **`use_caps_for_id` (0x20)**: qname perturbation happens before signing;
  signature covers the perturbed qname.
- **DNS Cookies**: coexist; TSIG appended last per RFC 8945 §5.1.
- **DoT / DoQ**: TSIG lives inside the DNS message; transport transparent.
- **DNSSEC validation**: unaffected; validator ignores TSIG RRs.
- **dnstap**: captures the signed packet automatically.
- **`donotquery`, `access-control`, ratelimit, infra cache, RTT tracking**:
  unaffected.
- **`outgoing-interface`**: orthogonal to signing.

## Testing plan

- **Unit** (`testcode/unittsig.c`):
  - HMAC-SHA256 known-answer vectors from RFC 8945.
  - BIND key file parser matrix: good, wrong algorithm, malformed base64,
    missing name, missing file.
  - Address-table lookup: v4 hit, v6 hit, wrong-address miss, port
    variants all match the same entry.
- **`unbound-checkconf`**: matrix of missing-file, wrong-algorithm,
  malformed-base64, undefined-key-reference, duplicate-address configs.
  Each yields a distinct error message and non-zero exit.
- **Integration**: `testdata/` scenario running Unbound against a BIND
  instance configured with `allow-query { key "..."; };`. Signed queries
  succeed; removing the `server-tsig` entry yields REFUSED. Two
  forward-zones pointing at the same auth server need only one
  `server-tsig` entry.
- **Regression**: an existing forward-zone / recursion test with no
  `tsig-key`/`server-tsig` produces byte-identical wire traffic.

## Progress

Six phases, ticked as each lands. Order chosen so the crypto is proven
against RFC vectors before any daemon plumbing is touched.

- [x] **Phase 1** — `util/tsig.{c,h}`: HMAC-SHA256 + BIND key loader + unit vectors.
      Delivered:
      - `util/tsig.h`, `util/tsig.c`, `testcode/unittsig.c`.
      - `tsig_key_load_bind_file()` parses BIND key stanzas, tolerates
        C/C++/shell comments, enforces `hmac-sha256`, strict base64
        alphabet, non-empty secret, and optional owner-name match.
      - `tsig_sign_query()` appends a canonical TSIG RR (type 250,
        class ANY, TTL 0, algorithm `hmac-sha256.`, 48-bit time signed,
        fudge 300, full 32-byte MAC, Original ID mirroring the header,
        Error 0, Other Len 0), grows the buffer, and increments ARCOUNT.
      - Digest input follows RFC 8945 §4.3 exactly:
        (message-without-TSIG) || (name, class, TTL, algorithm-name,
         time-signed, fudge, error, other-len, other-data).
      - HMAC-SHA-256 via `EVP_MAC` on OpenSSL 3.x, `HMAC_Init_ex` on
        OpenSSL 1.x — mirrors the fallback pattern in
        `util/net_help.c:1934`.
      - Unit tests: RFC 4231 KATs 1/2/3, algorithm-mnemonic parser,
        BIND-loader positive path + case-insensitivity + wrong-algorithm
        + malformed-base64 + missing-directive + missing-file matrix,
        structural checks on the appended TSIG RR, and a determinism +
        independent-HMAC cross-check that recomputes the digest from
        scratch and compares byte-for-byte against the embedded MAC.
      - Registered in `Makefile.in` (COMMON_SRC/OBJ, UNITTEST_SRC/OBJ,
        dependency rules); `tsig_test()` called from
        `testcode/unitmain.c`.
      - `make unittest` passes; the full `unbound`, `unbound-checkconf`,
        `unbound-control`, `unbound-host` and `libunbound` link cleanly.
- [x] **Phase 2** — Config surface: `tsig-key` and `server-tsig` grammar +
      parser + `struct config_file` fields + free helpers +
      `unbound-checkconf` validation + docs.
      Delivered:
      - `struct config_tsig_key`, `struct config_server_tsig`, and the
        `tsig_keys` / `server_tsigs` list fields on `struct config_file`
        (util/config_file.h, util/config_file.c).
      - `config_deltsigkeys()` / `config_delservertsigs()` free helpers,
        called from `config_delete()`.
      - Lexer keywords `tsig-key:`, `server-tsig:`, `key-file:`,
        `address:`, `key:` (util/configlexer.lex); `name:` is reused
        from the existing keyword pool. New tokens `VAR_TSIG_KEY`,
        `VAR_KEY_FILE`, `VAR_SERVER_TSIG`, `VAR_ADDRESS`, `VAR_KEY`.
      - Grammar rules `tsigkey_clause` and `servertsig_clause` added
        to `toplevelvar` (util/configparser.y). Each rejects missing
        required subdirectives and duplicate assignments with a
        specific parse-time error.
      - `unbound-checkconf` gains `check_tsig()`: loads every
        `tsig-key` file (via `tsig_key_load_bind_file` with owner-name
        cross-check), enforces hmac-sha256, rejects duplicate
        `tsig-key` names, rejects unparseable `server-tsig` addresses,
        rejects duplicate `server-tsig` addresses, and rejects
        `server-tsig` entries pointing at undefined `tsig-key` names.
        All errors are hard fails via `fatal_exit`.
      - Unit tests: two new feature groups in `testcode/unittsig.c`
        cover positive parse (multiple keys + multiple v4/v6 servers,
        list traversal, name/address integrity) and the empty-config
        case (`cfg->tsig_keys` and `cfg->server_tsigs` are NULL when
        no blocks are declared). All 12 TSIG feature groups pass.
      - Docs: `doc/unbound.conf.rst` gains a "TSIG (Outgoing Signing)
        Options" section documenting the two blocks and every locked
        constraint. `doc/example.conf.in` gains a commented-out
        template. `doc/FEATURES` no longer says "No TSIG support".
      - `Makefile.in` gains `util/tsig.h` in the checkconf and
        unittsig dependency rules.
      - Manual `unbound-checkconf` matrix verified: valid config
        passes; duplicate address, dangling key reference, unparseable
        address, wrong algorithm in key file, and owner-name mismatch
        each yield a distinct fatal error with the correct exit code.
- [ ] **Phase 3** — `services/tsig_server.{c,h}`: build the resolved
      key store and address→key table at daemon apply time; atomic
      swap on reload; hang the table off `struct outside_network`.
      This is the runtime companion to Phase 2's static config.
- [ ] **Phase 4** — Outnet integration: `sq->tsig_key`, lookup at
      `serviced_create`, sign at UDP/TCP chokepoints, EDNS size
      budgeting.
- [ ] **Phase 5** — Integration test against BIND, Changelog, TODO.

Estimated total effort: ~9.5–13 engineer-days.

## Alternatives considered

### Per-forward-zone TSIG (rejected)

Attach a `forward-tsig-key` directive to individual `forward-zone` blocks
and sign only queries matching `iq->dp->name`. Rejected because:

- Only covers forward-zone traffic; misses target-fetch and any
  incidental recursion to the same auth server.
- Requires a new parameter on the `send_query` callback (touches 5
  implementations).
- Doesn't match how DNS-native tools model TSIG.
- Silently misbehaves when the same auth serves multiple private zones.

Per-nameserver was chosen instead. See the conversation history for the
full comparison table.

### Named key store vs inline path (per-zone plan)

The per-zone plan considered a single `forward-tsig-key: <path>` per
forward-zone. In the per-nameserver plan the top-level `tsig-key` block
gives us the same simplicity plus reusability across multiple servers.

## Open questions / deferred

- **CIDR ranges** for `server-tsig.address`: convenient for prefix
  deployments, but adds a prefix-tree or linear-prefix-scan. Deferred.
  Revisit if operational demand appears.
- **Response TSIG verification**: adds ~2–3 d and defense-in-depth against
  on-path UDP response forgery. Explicitly out of scope in v1 per the
  locked plan. Revisit if the threat model changes.
- **Other HMAC algorithms** (sha1, sha512): trivial to add given the
  `algorithm` enum. Deferred until asked.
- **Per-forward-zone TSIG**: kept on the shelf. If operationally justified
  later, layer it on top of the per-server model (`server-tsig` remains
  authoritative; per-zone becomes syntactic sugar that expands into
  per-server entries at config load).

## References

- RFC 8945 — Secret Key Transaction Authentication for DNS (TSIG),
  obsoletes RFC 2845 + RFC 4635.
- RFC 3597 — Handling of Unknown DNS Resource Record Types (canonical
  form used in TSIG signing).
- `util/net_help.c` — existing OpenSSL `EVP_MAC` / `HMAC_CTX` fallback
  pattern to mirror.
- `iterator/iter_fwd.c` `forwards_swap_tree` — pattern for atomic table
  swap on reload.
