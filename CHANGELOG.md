# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-05-24

Initial release — complete pure-Go port of the Signal Protocol, byte-wire-compatible
with Rust libsignal pinned at `RUST_REV = 98915c442d814cd420f4e1a15630ade0d48e66ae` (v0.92.2).

### Added

#### Cryptographic primitives

- AES-256-CTR / AES-256-CBC / AES-256-GCM / AES-256-GCM-SIV (RFC 8452) (`pkg/cipher`)
- HKDF-SHA256 / HKDF-SHA512 with separate Extract/Expand API (`pkg/kdf`)
- Incremental HMAC-SHA256 / HMAC-SHA512 with chunked validation (`pkg/incrementalmac`)
- Curve25519 + XEdDSA + VXEdDSA signing (`pkg/ecc`)
- Elligator-2 + Ristretto255 helpers (`pkg/crypto/elligator`, `pkg/crypto/keyops`)
- ML-KEM-768 / ML-KEM-1024 (stdlib `crypto/mlkem`), Kyber-1024 (`cloudflare/circl`) (`pkg/kem`)
- Pure-Go libcrux incremental ML-KEM-768 (`pkg/mlkembraid/internal/incremental_mlkem768`)

#### Protocol layers

- ServiceId / ProtocolAddress / message types (SignalMessage, PreKeySignalMessage,
  SenderKeyMessage, SenderKeyDistributionMessage, DecryptionErrorMessage, PlaintextContent)
  (`pkg/protocol`)
- X3DH / PQXDH session establishment, Double Ratchet (`pkg/session`, `pkg/ratchet`)
- Sealed Sender v1 and v2 with multi-recipient + multi-root validation (`pkg/sealed`)
- SenderKey group messaging (`pkg/groups`)
- SPQR (Sparse Post-Quantum Ratchet) v1 default with FIFO eviction matching Rust upstream
  (`pkg/spqr`)
- ML-KEM Braid SCKA state machine (`pkg/mlkembraid`)
- Triple Ratchet (EC + PQ hybrid) (`pkg/tripleratchet`)
- Sesame multi-device session management (`pkg/sesame`)
- High-level facade with automatic address-binding for canonical ServiceId pairs
  (`pkg/sessionmanagement`)

#### Application layer

- Argon2id PIN hashing, account-entropy validation (`pkg/accountkeys`)
- Message backup: legacy + modern (`SBACKUP\x01`) frame formats; HMAC streaming
  validation; scramble walker (`pkg/backup`)
- SVR4 protocol incl. rotation arms + MasterKey/DeriveStorageKey helpers (`pkg/svr`)
- Key Transparency: VRF + Merkle proofs (`pkg/keytrans`)
- Media validation/sanitization: MP4/WebP via `pkg/media`; JPEG/PNG/GIF via
  `pkg/media/goextensions`
- Username generation, hashing, ZK proofs (`pkg/usernames`)

#### Attestation and networking

- SGX/DCAP attestation, Noise NK handshake, HSM enclave transport (`pkg/attest`)
- RSA key generation + X.509 self-signed certs with Rust-compatible RDN ordering
  (`pkg/devicetransfer`)
- Network DTOs (CDSI fixed-length serializers, ConnectionConfig, KeyTrans constants
  prod/staging), embedded Signal + Google trust roots (`pkg/net`, `pkg/net/embeddedcerts`)

#### Zero-knowledge

- POKSHO Stateful Hash Object (SHA-256 + HMAC-SHA-256 variants) (`pkg/poksho`)
- Generic anonymous credentials (Chase-Perrin-Zaverucha) with `RoomCredential` example
  (`pkg/zkcredential`)
- ZK groups: Auth / Profile-key / Receipt / Backup-auth / CallLink /
  GroupSendEndorsement credentials, presentation V1↔V3↔V4 back-compat, 25 exported
  wire-format constants matching Rust (`pkg/zkgroup`)

#### Testing and interop

- 52 Rust-emitted wire fixtures verified byte-for-byte against upstream commit `98915c44`
- Live cross-implementation runner: Rust↔Go round-trip tests for Session,
  SealedSenderV1, SealedSenderV2, SenderKey, Backup (both directions) via
  `make interop-live`
- Rust-test ports in `pkg/incrementalmac/rust_vectors_test.go`, sender-key state
  machine, `tests/interop/rust_integration_test.go`, full backup-frame unit suite,
  Rust XEdDSA KAT, RFC 7748/8032/4231/5869/8452 vectors
- Property-based session tests (rapid framework)
- Forensic audit clean (0 HIGH findings across 10 categories)

### Security

- Address-binding (proto field 6) enforced on decrypt for canonical ServiceId session
  pairs
- Constant-time MAC / signature / address-blob comparisons throughout
- All sensitive material wiped via `clear` + `secret.Secret.Destroy` on `defer`
- 0 gosec issues; 0 govulncheck vulnerabilities affecting our code; 0 staticcheck
  issues

### Notes

- `RUST_REV` pinned at `98915c442d814cd420f4e1a15630ade0d48e66ae` (v0.92.2)
- `pkg/mlkembraid` mirrors standalone `sparsepostquantumratchet` crate v1.5.1 (used
  as external dep by Rust libsignal)
- `pkg/spqr` mirrors the same SPQR upstream
- pre-1.0: breaking changes may land in any 0.x version; the recently-restored
  back-compat wrappers on `session.NewCipher`, `svr.MasterKey`, `pkg/tripleratchet`
  are intended to remain stable through 0.x
- Coverage: 90.7% total; per-package minimums declared for `pkg/groups/ratchet`,
  `pkg/mlkembraid`, `pkg/util/crypto/secret`, `pkg/tripleratchet` (defensive OOM
  panic blocks)
- SPQR `MinVersion` defaults to `V1` per Rust upstream policy
  (`rust/protocol/src/ratchet.rs:88,152` hard-codes `spqr::Version::V1`). Peers
  still running V0 must upgrade before initiating a session — this is intentional
  Rust-conformance, not a backwards-compat option.
- v0.1.0 is the initial tagged release. The SPQR receive path uses the SCKA
  encoding exclusively; any pre-tag experimental 12-byte `epoch||counter` payload
  is not accepted. There is no installed-base predating v0.1.0 to be
  backwards-compatible with.
- `staticcheck` checks `ST1003` (Go initialism — `ServiceId` → `ServiceID`) and
  `ST1016` (consistent receiver names) are deferred to v1.0 prep. They are
  documented exclusions in `staticcheck.conf` with an explanatory rationale and
  will be addressed alongside the v1.0 API freeze.

[Unreleased]: https://github.com/jeremyhahn/go-libsignal/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jeremyhahn/go-libsignal/releases/tag/v0.1.0
