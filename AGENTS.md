# Notes for AI-assisted development

This repository has an active feature branch adding outgoing TSIG signing
to Unbound (branch `d073579/per-server-tsig`, off `release-1.26.1`).
Before proposing changes in that area, read `doc/tsig.md` — it contains
the locked design, scope boundaries, and current progress.

## General guidance for this codebase

- **Build system**: autotools (`configure.ac`, `Makefile.in`). This
  checkout does not carry `Makefile.am` files; new source files must be
  registered in the effective build spec (`Makefile.in` and any relevant
  per-tool source lists).
- **Crypto**: OpenSSL via the `EVP_*` interface. Follow the fallback
  pattern already used in `util/net_help.c` — the code must handle both
  `EVP_MAC_CTX_set_params` (OpenSSL 3.x) and legacy `HMAC_Init_ex`
  (OpenSSL 1.x).
- **`send_query` callback has five implementations**:
  `daemon/worker.c`, `libunbound/libworker.c`, `smallapp/worker_cb.c`,
  `testcode/doqclient.c`, `dnstap/unbound-dnstap-socket.c`. Keep them in
  sync when touching the signature. Also update
  `util/fptr_wlist.{h,c}` and the typedef in `util/module.h`.
- **Style**: tabs for indentation, K&R braces, `verbose(VERB_*, ...)` for
  logging. Match the surrounding code where in doubt.
- **Locking discipline**: read-lock/write-lock via the `lock_rw_*` and
  `lock_basic_*` macros; use the `lock_protect` machinery when adding
  new shared state. See `iterator/iter_fwd.c` for a clean example of a
  read-mostly structure with an atomic swap on reload.

## Working with the TSIG feature branch

- Every commit that closes bullets under a phase updates the Progress
  section of `doc/tsig.md` in the same commit.
- `doc/tsig.md` is the source of truth for scope, design decisions, and
  progress. If a decision changes, update the doc first.
- The plan is deliberately staged so the crypto (Phase 1) is proven
  against RFC 8945 known-answer vectors before any daemon plumbing is
  touched.
