# Interop Test Vectors

This directory holds cross-implementation test vectors drawn from the Rust
libsignal reference implementation. The tests verify that the Go port
accepts the exact byte sequences produced by Rust and that round-trip
operations preserve byte identity on Rust-sourced inputs.

## Layout

```
tests/interop/
├── fixtures/
│   ├── MANIFEST.toml         # the source-of-truth fixture index
│   ├── crypto/               # rust/crypto/tests/data/
│   ├── attest/               # rust/attest/tests/data/
│   ├── messagebackup/        # rust/message-backup/tests/res/
│   ├── net/                  # rust/net/tests/data/
│   ├── protocol/kem/         # rust/protocol/src/kem/test-data/
│   ├── kem/                  # legacy duplicate (predates MANIFEST.toml,
│   │                         #  consumed by kem_interop_test.go; will be
│   │                         #  unified with protocol/kem/ in a follow-up)
│   └── zkgroup/              # see fixtures/zkgroup/presentations.go
├── loader/                   # canonical Go fixture-access package
├── rust/                     # SPQR live-interop CLI (Cargo project)
└── scripts/
    ├── check_fixtures.sh     # manifest + upstream-bytes drift detector
    └── refresh_fixtures.sh   # re-copy from local libsignal checkout
```

## Conformance harness pattern

1. **Fixture provenance** — every static fixture under `fixtures/` is a
   verbatim copy of an upstream Rust libsignal file. The upstream commit is
   recorded in `/RUST_REV` at the repo root. Do not edit fixture bytes by
   hand. To refresh, run `make interop-fixtures-refresh
   LIBSIGNAL_UPSTREAM=/path/to/libsignal-checkout`, update the affected
   sha256/size in `MANIFEST.toml`, and bump `/RUST_REV`.
2. **Drift detection** — `make interop-fixtures-check` runs the local
   manifest hash check on every push (CI). The dedicated
   `conformance-fixtures` CI job clones the upstream repo at the pinned
   commit and runs the same script with `LIBSIGNAL_UPSTREAM` set,
   guaranteeing every committed fixture byte is still byte-identical to
   the upstream source.
3. **Go consumers** — conformance tests import
   `github.com/jeremyhahn/go-libsignal/tests/interop/loader` and call
   `loader.Read("subsystem/file.ext")`. Do not duplicate path resolution.
4. **Adding a fixture** — copy the upstream file into the right
   subdirectory, add a `[[fixture]]` block to `MANIFEST.toml` with `path`,
   `upstream`, `sha256`, `size`, and `purpose`, then write a Go test
   under `tests/interop/<your_test>.go` that calls `loader.Read(...)`.
5. **Dynamic fixtures** (e.g. SPQR ratchet traces) — extend
   `tests/interop/rust/src/main.rs` with a new clap subcommand, build the
   binary via `make interop-live-build`, and run live tests behind the
   `interop_live` build tag (see `make interop-live`).

## fixtures/

The `fixtures/` subtree is copied verbatim from:

    /rust/protocol/src/kem/test-data/
    /rust/crypto/tests/data/
    /rust/attest/tests/data/
    /rust/message-backup/tests/res/
    /rust/net/tests/data/

in the Signal Rust libsignal repository at the commit pinned in
`/RUST_REV`. No transformation is applied; the files are binary-identical
to the Rust originals.

| File              | Size (bytes) | Content                                                   |
|-------------------|-------------|-----------------------------------------------------------|
| `kem/pk.dat`      | 1568        | Kyber-1024 raw public key, no type prefix                 |
| `kem/sk.dat`      | 3168        | Kyber-1024 raw secret key, no type prefix                 |
| `kem/mlkem-pk.dat`| 1569        | ML-KEM-1024 encapsulation key, includes 0x0A type prefix  |
| `kem/mlkem-sk.dat`| 3169        | ML-KEM-1024 secret key (libcrux expanded form), 0x0A prefix |

Rust source paths for the canonical test logic:

- `rust/protocol/src/kem.rs` — functions `test_serialize`, `test_kyber1024_kem`,
  `test_mlkem1024_kem` (lines 521–596)
- `rust/protocol/src/kem/test-data/` — the four fixture files above

## Phases

**Phase 3a (this directory):** Static fixture tests. Go loads the Rust-generated
byte sequences and verifies that its own KEM implementation accepts and
round-trips them correctly.

**Phase 3b (this directory, `live_spqr_test.go`):** Live harness. A Rust CLI
subprocess exercises the SPQR wire protocol at test time; Go verifies
structural and cryptographic parity. See the section below for details.

## Notes on ML-KEM-1024 Secret Key Compatibility

The Rust libsignal stores ML-KEM-1024 secret keys in the 3168-byte libcrux
expanded format (`MlKem1024PrivateKey`). Go's standard library `crypto/mlkem`
only accepts the 64-byte FIPS 203 seed form (`d || z`). As a result,
`mlkem-sk.dat` cannot be imported into Go's `MLKEM1024KEM` implementation.
The ML-KEM interop test therefore verifies public-key fixture deserialization
and encapsulate/decapsulate correctness using a freshly-generated Go key pair.

## fixtures/zkgroup/

`presentations.go` holds six hex-encoded byte-slice constants harvested verbatim
from the `hex!` macro calls in:

    /rust/zkgroup/tests/integration_tests.rs

| Go constant | Rust source line | Status |
|---|---|---|
| `AuthCredentialPresentationV1Bytes` | line 34 | known-bad: version 0x00 is rejected |
| `AuthCredentialPresentationV4ResultBytes` | line 38 | valid V4 auth presentation |
| `ProfileKeyCredentialPresentationV1Bytes` | line 42 | valid V1 profile key presentation |
| `ProfileKeyCredentialPresentationV2ResultBytes` | line 46 | valid V2 profile key presentation |
| `ProfileKeyCredentialPresentationV3ResultBytes` | line 51 | valid V3 expiring presentation |
| `ProfileKeyCredentialPresentationV4ResultBytes` | line 55 | valid V4 expiring presentation |

The four supplemental Rust test files (`backup_auth_flow.rs`, `call_link_flow.rs`,
`group_send_endorsements.rs`, `receipt_flow.rs`) generate key material dynamically
and contain no static `hex!` presentation constants. The gap is documented in
`TestInteropAdditionalKATsNotAvailable` inside `zkgroup_presentations_test.go`.

## Running interop tests

### Phase 3a (static fixtures)

```
make test-interop
```

Or directly:

```
GOWORK=off go test -race -v ./tests/interop/...
```

---

## Phase 3b — Live harness

The live harness tests SPQR wire-format parity between Go (`pkg/spqr`) and
the Rust `spqr` crate (v1.5.1) using a vendored Rust CLI binary.

### How to build

```
make interop-live-build
```

This runs `cargo build --release` for `tests/interop/rust/`.

### How to run

```
make interop-live
```

Equivalent to:

```
LIBSIGNAL_INTEROP_BIN=tests/interop/rust/target/release/libsignal-interop \
GOWORK=off go test -tags=interop_live -race -v ./tests/interop/...
```

### Docker path (no local Rust toolchain required)

```
make interop-docker
```

This builds a two-stage Docker image (Rust builder + Go runner) and executes
the live tests inside the container. No host-level Rust installation is needed.

### What is tested

| Test | Description |
|------|-------------|
| `TestInteropSPQRRustSelfTest` | Rust CLI: multi-step A↔B send/recv with key agreement |
| `TestInteropSPQRRustMultiRound` | Rust CLI: 8 alternating rounds, all keys unique |
| `TestInteropSPQRRustToGoWireFormat` | Go parses a Rust-generated varint wire message |
| `TestInteropSPQRWireFormatGapDocumented` | Go non-braid Recv correctly rejects Rust messages (gap documented) |
| `TestInteropSPQRGoChainKDFSelfConsistency` | Go send/recv round trip with KDF info string logging |
| `TestInteropSPQRRustToGoKeyParity` | Rust sends → Go receives → keys match (with epoch translation) |
| `TestInteropSPQRGoToRustKeyParity` | Go sends → Rust receives → keys match (bidirectional) |

### Wire-format parity findings

**KEY PARITY CONFIRMED**: Go and Rust derive identical message keys from the
same `auth_key`, `direction`, and chain position. The first-epoch message key
`3e04aa6332ce29c72b84d599663d65f8a556d4dc86e5e2499dc12b03d21b813a` matches
across both implementations.

**Wire-format gap (non-blocking)**: Go's non-braid `Send`/`Recv` uses a
legacy 12-byte wire format (`epoch(8 BE) + counter(4 BE)`), while Rust's
`spqr::send` always emits a variable-length SCKA format (`version(0x01) +
varint(epoch) + varint(counter) + msgType + chunk`). This means Go's
non-braid path cannot directly exchange messages with Rust without an
epoch-translation bridge (implemented in the key-parity tests above).

**Epoch mapping**: Rust uses 1-indexed SCKA epochs; Go's chain uses
0-indexed epochs. Mapping: `chain_epoch = scka_epoch - 1`.

**SCKA transcript incompatibility**: After the first epoch, keys diverge
because the SCKA state machines (Rust's v1 chunked vs Go's `mlkembraid`)
produce different ML-KEM outputs from different RNG streams. Key parity is
confirmed for epoch 0 chain keys; epoch-advanced keys require a shared SCKA
transcript to verify parity.

### Known limitations

- RNG divergence between Rust (`ChaCha20Rng`) and Go (`crypto/rand`-backed)
  precludes byte-identical `send` output from the same seed. Parity is
  verified via the receiver accepting the bytes and deriving the same key.
- Full multi-epoch cross-impl key parity requires a shared SCKA transcript
  (same ML-KEM random inputs), which is out of scope for this harness.

---

## Wire-format fixtures

Static wire-format fixtures for sealed sender, SenderKey messaging, and
fingerprints live under `tests/interop/fixtures/wire/`. They are produced by
a dedicated Rust emitter binary (`wire_emitter`) that uses the upstream
`libsignal-protocol` crate at the commit pinned in `/RUST_REV`.

### Files

| File | Purpose |
|------|---------|
| `sealed_sender_v1.json` | Sealed Sender v1 encrypt: fixed (sender_cert, recipient_identity, plaintext) → ciphertext bytes |
| `sealed_sender_v2_received.json` | Sealed Sender v2 received-format bytes for a single recipient |
| `sealed_sender_v2_multi.json` | Sealed Sender v2 multi-recipient: full sent-message bytes + per-recipient received bytes for 3 recipients |
| `senderkey_distribution.json` | SenderKeyDistributionMessage serialized bytes for a fixed sender + chain |
| `senderkey_message.json` | SenderKeyMessage ciphertext bytes for a fixed sender + plaintext |
| `fingerprint.json` | DisplayableFingerprint + ScannableFingerprint for pinned alice/bob keys, versions 1 and 2 |

### How to regenerate

```
make interop-wire-emit
```

This builds `wire_emitter` from `tests/interop/rust/src/bin/wire_emitter.rs` and
writes all six JSON files into `tests/interop/fixtures/wire/`. Run it manually
after bumping `/RUST_REV`. The output is deterministic: re-running with the same
`RUST_REV` produces byte-identical JSON.

### CI contract

CI does **not** depend on the Rust toolchain. The wire fixtures are checked-in
JSON files. Go tests consume them via `loader.MustRead("wire/...")`. The Rust
emitter is only needed when regenerating fixtures after a `RUST_REV` bump.

### Emitter source

`tests/interop/rust/src/bin/wire_emitter.rs` — all randomness is seeded with
`ChaCha20Rng::seed_from_u64(0xC0DECAFE)` so every run produces identical bytes.
