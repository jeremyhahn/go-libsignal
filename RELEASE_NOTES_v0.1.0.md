# go-libsignal v0.1.0

Initial release of **go-libsignal** — a complete, pure-Go implementation of the Signal Protocol that is byte-wire-compatible with the official Rust libsignal library.

**Upstream pin:** `98915c442d814cd420f4e1a15630ade0d48e66ae` (Rust libsignal v0.92.2)

## Headline features

- **Full Signal Protocol stack** — X3DH / PQXDH session establishment, Double Ratchet, SenderKey group messaging, Sealed Sender v1 and v2 with multi-recipient and multi-root validation.
- **Post-quantum cryptography** — ML-KEM-768 / ML-KEM-1024 via the standard library `crypto/mlkem` (no cgo), Kyber-1024 via `cloudflare/circl`, SPQR (Sparse Post-Quantum Ratchet) epoch-based key exchange, and ML-KEM Braid SCKA 13-state machine.
- **Zero-knowledge credentials** — POKSHO Stateful Hash Object, anonymous credentials (Chase-Perrin-Zaverucha), and the full ZkGroup suite: Auth, ProfileKey, Receipt, BackupAuth, CallLink, and GroupSendEndorsement credentials with V1/V3/V4 presentation back-compatibility.
- **Application layer** — Argon2id PIN hashing, legacy and modern message backup frame encryption, SVR4 Secure Value Recovery, Key Transparency (VRF + Merkle proofs), SGX/DCAP attestation, and media sanitisation (JPEG, PNG, WebP, MP4).
- **No cgo, ever** — pure Go throughout; runs on any GOOS/GOARCH target that Go 1.26.2 supports.

## Cross-implementation interop

10/10 live Rust↔Go round-trip tests pass via `make interop-live`:
session round-trip, SealedSenderV1, SealedSenderV2, SenderKey (both directions), and backup frame (both directions).
52 Rust-emitted wire fixtures are verified byte-for-byte at every CI run.

## Coverage and audit

- Total unit-test coverage: **92.1%**; every package meets a declared per-package minimum (90% default; 87–88% for packages whose only uncovered paths are OS-level OOM panic guards).
- Static analysis: **0** gosec findings, **0** govulncheck vulnerabilities, **0** staticcheck issues, forensic audit clean across 10 security categories.

## Compatibility note

This is a **pre-1.0** release. Breaking API changes may land in any 0.x minor version. The back-compat wrappers on `session.NewCipher`, `svr.MasterKey`, and `pkg/tripleratchet` are intended to remain stable across the 0.x series.

## Install

```bash
go get github.com/jeremyhahn/go-libsignal@v0.1.0
```

Verify the module checksum:

```bash
GOWORK=off go mod verify
```

## Full changelog

See [CHANGELOG.md](CHANGELOG.md) for the complete list of added packages, security notes, and upstream-compatibility details.
