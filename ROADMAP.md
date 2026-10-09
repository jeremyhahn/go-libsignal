# go-libsignal roadmap

> **Status: REFERENCE** · Owner: Software Department · Last verified: 2026-10-08
> Changes are proposed by docs-only PR.

## Mission

Own the Signal Protocol for the portfolio: X3DH, Double Ratchet, PQXDH and Sealed Sender.
A pure-Go, byte-wire-compatible port of Rust libsignal at the commit pinned in `RUST_REV`.
A Layer 0 module whose only in-house dependency is go-enclave.

## Current milestone

[Release candidate (M9)](../../milestone/9), target kind RC.
Projected 2026-10-15.

## Now

- readiness: green main — blocked: main is red
- [#50](../../issues/50) release readiness for the public release — open
- [#38](../../issues/38) ratchet Decrypt verifies the MAC before allocating protected memory — open
- [#41](../../issues/41) package-level admission Allocator bounds pre-auth locked memory — open
- [#55](../../issues/55) release artifacts are signed — open
- [#39](../../issues/39) release-alpha recipe tags correctly — open
- [#48](../../issues/48) `make trivy` fails when trivy is missing — open

## Next

- [#24](../../issues/24) SPQR and ML-KEM key material held in protected memory — open
- [#42](../../issues/42) CI uses the runner image's pinned analysis tools — open
- [#56](../../issues/56) docs carry banners, stamps and an index — open
- [#14](../../issues/14) Go 1.27 toolchain wave adopted — open
- [#31](../../issues/31) guarded teardown cost measured and bounded — blocked: needs measurement

## Later

Nothing accepted. New work arrives as issues.

## Dependencies

- Up: go-enclave v0.3.0-alpha
- Down: go-quicbaas, go-signal

## Non-goals

- Anything outside the Signal Protocol domain; see [docs/00 §R](../handbook/software/docs/00-ownership-and-sdk-boundary.md).
- Server-side Signal concerns; go-libsignal never depends on go-signal.
