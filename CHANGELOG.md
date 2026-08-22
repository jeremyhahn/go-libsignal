# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- The group-messaging (sender key) persisted structures now cross the storage
  boundary in memguard-protected memory: the signing private key
  (`SenderKeyStateStructure.SigningKeyPrivate`), the sender chain key
  (`SenderChainKeyStructure.ChainKey`), and each sender message key's IV,
  cipher key and seed. These were the same exposure as the 1:1 structures
  below, on the group side. The signing key is the notable one: unlike a chain
  or message key it is long-lived, authenticating every `SenderKeyMessage` in
  the group. Decoding a sender key state now also releases everything it has
  already guarded when a later step fails, so malformed state cannot strand
  mlock'd pages.
- Persisted chain keys and message keys now cross the storage boundary in
  memguard-protected memory. `chain.KeyStructure.Key` and the four secret
  fields of `message.KeysStructure` (`CipherKey`, `MacKey`, `IV`,
  `SeedMaterial`) were the last families on the persisted-state path still
  held as plain `[]byte`; the 0.2.0-alpha conversion covered the fields the
  protected-memory audit enumerated and these were not in that list. The live
  objects behind them were already guarded and the structures were zeroized
  after serialization, so the exposure was the serialization window rather
  than a key resident for a session's lifetime — but a plain heap page can be
  swapped out or captured in a core dump, which zeroizing it afterwards does
  not undo. Material now moves guarded-to-guarded in both directions and never
  touches the Go heap.
- `secret.Secret.Clone` copies guarded buffer to guarded buffer. It used to
  allocate an ordinary `[]byte`, copy the plaintext into it and hand that to
  `secret.New`, so **every** cloned secret — not only the ones added here —
  spent the length of the call on a swappable, core-dumpable page. Zeroizing
  such a slice afterwards undoes neither exposure. `Secret32.Clone` inherits
  the fix. Guarded by a test that measures heap growth while cloning a 1 MiB
  secret, since independence and equality assertions cannot see the difference.
- Deserializing a chain releases everything it has already guarded when a
  later step fails, so malformed persisted or wire-supplied state cannot
  strand mlock'd pages. Covered by a locked-memory regression test.

### Changed

- **Breaking:** `ratchet.NewSenderChainKeyFromStruct`,
  `ratchet.NewStructFromSenderChainKey`, `ratchet.NewSenderMessageKeyFromStruct`
  and `ratchet.NewStructFromSenderMessageKey` return `(T, error)` instead of
  `T`, and reject an absent sender chain key with the typed
  `*ratchet.MissingKeyError` rather than panicking out of a `memguard`
  allocation on input an attacker can supply.
- `ecc.GuardPrivateKey` replaces the unexported helper that was duplicated
  between the 1:1 and group record layers. It lives in `pkg/ecc` because both
  need exactly this conversion and neither package can import the other.
- **Breaking:** `chain.NewKeyFromStruct`, `chain.NewStructFromKey`,
  `message.NewKeysFromStruct` and `message.NewStructFromKeys` return
  `(T, error)` instead of `T`. Moving guarded material can fail, and these
  constructors previously had nowhere to say so — a structure carrying no
  chain key panicked out of a `memguard` allocation on input an attacker
  could supply. They now return the typed `*chain.MissingKeyError` /
  `*message.MissingKeyError` and fail closed.
- `parseIntelRootKey` and `parseAttestKey` build the DCAP public key with
  `ecdsa.ParseUncompressedPublicKey` instead of validating the point through
  `crypto/ecdh` and then reassembling it from `big.Int` coordinates. Go 1.26
  deprecated `ecdsa.PublicKey.X`/`.Y` because reassembling a key that way can
  produce an invalid key and because `big.Int` methods are not suitable for
  operating on cryptographic values. The parser accepts the same encoding and
  performs the same on-curve and point-at-infinity checks, so accepted and
  rejected inputs are unchanged (`pkg/attest`).
- `checkMP4BoxDepth` looks the box type up directly in `containerBoxTypes`
  rather than materialising a string first, which the compiler lowers to an
  allocation-free map lookup (`pkg/media`).
- The declared Go toolchain is 1.26.7, the latest 1.26.x, in `go.mod`, every CI
  workflow and the interop test image. Routine currency rather than a fix:
  `govulncheck` is clean against the go1.26.6 standard library, so unlike the
  go1.26.5 bump on 2026-08-14 nothing was failing. Unrelated to the Go 1.27
  wave, which is blocked on `cockroachdb/swiss`.

### Security

- `secret.Secret.Seal` encrypts the secret straight out of guarded memory. It
  used to copy the plaintext into an ordinary `[]byte` and hand that to
  `memguard.NewEnclave`, so the key sat on a swappable, core-dumpable heap page
  until `NewEnclave` wiped it — the same defect fixed in `Secret.Clone`, on the
  sibling method. Latent rather than live: `Seal` and `OpenEnclave` have no
  production callers, so nothing was exposed; the point is that the next caller
  would have inherited it silently. The FIPS exemption register drops from 7
  memguard-enclave uses in that file to 6.

### Fixed

- `pkg/session`'s four `TestProptest_*` cases move behind a `proptest` build
  tag with their own `make test-proptest` target and their own CI job. They
  were 167s of that package's 213s — 79% of it — which left the 900s
  per-binary cap only 4.4x above a host measured varying 2.9x–8.7x between
  runs. On 2026-08-21 the margin ran out and the timeout took the whole `Test`
  job down, on a failure none of the other 225 tests in the package caused.
  `make test` drops to 46s for that package, taking the margin to roughly 19x.
  The target carries its own `PROPTEST_TIMEOUT` (2400s) rather than inheriting
  the shared 900s — a separate job that still times out would only be a
  smaller blast radius for the same failure — and sits below the job's
  45-minute cap so Go's timeout fires first and names the package.
  `GOTEST_TIMEOUT` is deliberately unchanged: it governs every suite including
  the FIPS gate, and a Go timeout names the package and dumps goroutines where
  a job timeout reports nothing. The property tests still run on every PR, and
  `make test-proptest` fails if fewer of them run than the source declares, so
  the job cannot pass by testing nothing. Coverage is unaffected (90.4% before
  and after): these are differential tests over paths the unit tests already
  cover.
- `make staticcheck` compares the installed analyser's **version** instead of
  testing that some staticcheck exists, pinned via `STATICCHECK_VERSION`
  (v0.8.1). It is the same defect fixed for golangci-lint, on the tool that
  actually reports the SA findings — `SA1019` and `SA6001` are what took `main`
  red on 2026-08-20, and `$(GOBIN)` is shared across agent lanes, so a presence
  test ran whatever a neighbour last installed. Pinned for reproducibility
  rather than to dodge a bad release: CI's Security Scan job deliberately keeps
  `@latest` on a clean runner, because discovering new SA findings is its job.
  When CI reports one a local run missed, bump the pin. The pinned analyser is
  installed to a repo-local `.tools/bin` rather than the shared `$(GOBIN)`, and
  verified and executed in one shell against that path — a check in one recipe
  line and a bare `staticcheck` in the next is a time-of-check/time-of-use race
  on a directory other lanes write to. CI's Security Scan calls a separate
  `make staticcheck-latest`, because a workflow that installs `@latest` and then
  calls the *pinned* target silently gets the pin, reporting success on the very
  version the discovery gate exists to improve on.
- `make lint` retries the `parallel golangci-lint is running` lock error rather
  than reporting it as a finding. golangci-lint takes a global lock and the host
  is shared, so a concurrent run exits 3 with a message that reads exactly like
  a lint failure — observed three times consecutively on 2026-08-21, and
  `make ci` includes the target. Only that signature is retried; a real finding
  still fails on the first attempt. The loop lives in its own `_lint-retry`
  target invoking `$(LINT_CMD)`, so `make lint-retry-selftest` can drive it with
  a stub linter and assert the whole contract: a lock error is retried and
  recovers, a genuine finding runs exactly once and keeps its status and output,
  and a persistent lock stops after `LINT_RETRY_MAX` attempts with a nonzero
  status — including when the linter itself exited 0, which the loop previously
  would have passed through as success. The stub is named through `$(LINT_CMD)`
  rather than planted on `PATH`, because the Makefile prepends `$(GOBIN)` to
  `PATH` for every recipe and a PATH-planted stub is unreachable — the trap that
  made an earlier `staticcheck` self-test pass against a deliberately broken
  recipe. `staticcheck-selftest` and `lint-retry-selftest` both now run in CI's
  Lint job; neither was gated anywhere before, and an ungated self-test only
  protects the developer who remembers to run it.

- `make coverage` fails when a package does not run to completion. The
  per-package loop discarded `go test`'s stderr and ignored its exit status, so
  a package that failed, panicked or timed out contributed nothing and the run
  moved on in silence. Because a failing test still writes its coverage
  profile, the aggregate stayed well-formed and the threshold gate added in
  #13 passed it honestly — a different hole from the one #13 closed, and both
  were real. Measured on this tree before the fix: with one package
  deliberately failing, `make coverage` exited 0 and reported the same 90.4% as
  a clean run. `go list ./...` failing is now fatal for the same reason. The
  loop moved into `_coverage-collect`, parameterised the way `_coverage-gate`
  already was, so `coverage-loop-selftest` exercises the real recipe rather
  than a copy of it; CI runs it next to the existing gate self-test.
- The same loop now checks that each package's profile was actually appended to
  the aggregate, and that the temporary is removed afterwards. An unchecked
  append could drop a package while leaving the aggregate syntactically valid —
  the identical silent contribution loss, arrived at from the write side rather
  than the test side — and a temporary that outlived its package would be
  counted again by the next package whose tests write no profile.
- The 138 generated `test-*`, `coverage-*` and `bench-*` targets are `.PHONY`,
  as is `bench`. `bench` was not, and a `bench/` directory exists, so
  `make bench` matched the directory and reported `'bench' is up to date`
  while running no benchmarks at all.
- `make help` advertises the real generated target names. It listed
  `make test-PACKAGE`, which reads as `make test-cipher`; the targets are named
  for the package path, so the real name is `make test-pkg/cipher`. Same for
  the `coverage-` and `bench-` families and the comments above each.
- `sortedEpochs`'s insertion sort is measured deterministically. Its shift loop
  runs only when Go's randomised map iteration order happens to hand it
  unsorted keys, so the function's coverage varied between runs on identical
  source — measured at 81.8% in 1 run of 12 on go1.26.6, 100% otherwise — and
  moved the repository total between 90.4% and 90.5% at random. The sort moved
  into `insertionSortEpochs`, which takes a slice and can therefore be tested
  on input the test chooses; the existing map-level tests keep covering the
  collection contract (`pkg/spqr`).
- The Lint job pins golangci-lint at v2.12.2. It previously took `latest`,
  which moved to v2.13.0 — that release ships a staticcheck whose nilness pass
  panics. `make lint` takes the pin from the same `GOLANGCI_LINT_VERSION`
  variable, and now compares the installed linter's **version** rather than
  testing that some golangci-lint exists: a binary of the wrong version answers
  a presence test perfectly well, which is how a local run could disagree with
  CI. It installs the pin on mismatch and fails rather than linting with a
  version CI does not run. The Security Scan job still installs staticcheck at
  `@latest`, so new SA findings remain visible while the pin holds.

## [0.2.0-alpha] - 2026-08-19

MINOR rather than PATCH: this release changes five exported signatures. Pre-1.0,
breakage lives in MINOR (`conventions/release-versioning.md` §1). See
**Changed** for the `Breaking` entries before upgrading.

### Security

- Persisted key material now crosses the storage boundary in memguard-protected
  memory instead of on the Go heap: session state (root key, chain and ratchet
  private keys, pending key exchange — including the long-term identity private
  key — and serialized SPQR state), pre-key, signed pre-key and Kyber pre-key
  records, the SVR v4 backup/restore entropy and backup secret, and the media
  root backup key (`pkg/state/record`, `pkg/svr`, `pkg/backup`).
- The live representations that outlive the storage boundary are guarded too:
  `record.KyberPreKey` holds a `kem.GuardedKeyPair` and `record.State` holds its
  SPQR ratchet state in a `secret.Secret`, so deserialization no longer moves
  either back onto the heap.
- A deserialization that fails part-way through now releases the guarded
  buffers it had already allocated. `NewChainFromStructure`,
  `NewPendingKeyExchangeFromStruct`, `NewStateFromStructure` and
  `NewSessionFromStructure` previously abandoned the well formed components of
  a malformed persisted record; because memguard registers no finalizer, those
  buffers stayed mlock'd for the life of the process, so a peer able to supply
  malformed records could drain the process's `RLIMIT_MEMLOCK` allowance
  (`pkg/state/record`).
- A decrypt that fails now releases the working clone it rolls back to, and
  the message keys it had taken out of that clone. Every failed decryption —
  a replay, a corrupted ciphertext — previously stranded a whole session
  state's worth of locked buffers, so any peer could drain the process's
  `RLIMIT_MEMLOCK` allowance one message at a time (`pkg/session`,
  `record.State.DiscardClone`). `record.Session.Copy` likewise releases the
  clones it made when a later one fails.
- A decrypt that succeeds now releases the material the commit supersedes, via
  the new `record.State.CommitClone`. Sending and receiving a message no longer
  accumulate locked memory at all: the session state destroys the chain key,
  sender chain, root key and evicted receiver chain each ratchet step replaces;
  `RemoveMessageKeys` destroys the entry it takes out of the chain rather than
  returning a copy and dropping the original; and the chain-key copies handed
  out by `SenderChainKey`/`ReceiverChainKey`, together with message keys derived
  before authentication, are released on the paths that do not consume them
  (`pkg/session`, `pkg/state/record`).
- Archiving a session releases the state it evicts. `record.Session.PromoteState`
  drops the oldest archived state once the archive is full, and that state owns
  a root key, PQ ratchet state, chain keys, ratchet private keys and message
  keys — a peer that establishes sessions could strand all of it, one archive
  eviction per session (`pkg/state/record`).
- A successful backup read hands the media root backup key to the caller in
  guarded memory, so `backup.ValidatedReadResult` now owns it and has a
  `Destroy`. Without one, every validated remote backup left its key locked for
  the life of the process (`pkg/backup`).

### Changed

- **Breaking** — `backup.ValidatedReadResult.Info` is a `*BackupInfoRaw`, so
  copying a result cannot produce two apparent owners of the same guarded
  buffer, and the result must be `Destroy`ed once the caller is done with it.
- `record.State.SetSenderChain` now documents that the state takes ownership of
  the ratchet key pair and chain key it is given and destroys the chain they
  supersede. Session establishment hands the state its own copy of the signed
  pre-key pair, which belongs to the pre-key store.
- **Breaking** — `record.NewKyberPreKey` takes a `*kem.GuardedKeyPair`, and
  `record.KyberPreKey.KeyPair()` is replaced by `PublicKey()` (public half),
  `GuardedKeyPair()` (an independent guarded copy) and `Destroy()`.
- **Breaking** — `record.State.SetPqRatchetState` returns an error, moves the
  caller's slice into guarded memory and destroys the state it replaces;
  `PqRatchetState()` returns a view into guarded memory that must not be
  retained.
- **Breaking** — `kem.NewGuardedSecretKeyFromSecret` returns an error and
  validates key type and length as `kem.NewSecretKey` does.
- **Breaking** — `svr.Backup4.Secret` is a `*secret.Secret32`; `NewBackup4`
  moves the caller's secret into guarded memory and `Destroy` releases it.
- CI's FIPS job runs `GODEBUG=fips140=only` instead of `fips140=on`, so a
  non-approved cryptographic operation now fails the gate instead of quietly
  succeeding (`automatethethings` `software/conventions/configuration.md` §5).
  The new `make fips` target reproduces the job locally.
- Test fixtures in `pkg/svr`, `pkg/net`, `pkg/kdf` and `pkg/keys/chain` now use
  key material of the length production actually passes (32-byte SVR passwords,
  master secrets, IKMs and chain keys) rather than short strings.

### Added

- `record.State.DiscardClone`, which releases the guarded material of a working
  clone that is thrown away instead of committed. It is valid only on a state
  from `Clone` that was not passed to `CopyFrom`; live session states share
  their guarded objects and are not destroyable this way.
- `record.State.CommitClone`, which commits a working clone and releases what
  the commit superseded. `CopyFrom` keeps its existing pointer-copy semantics
  for callers that rely on them.
- `kem.GuardedFromPublicAndPrivate`, `kem.GuardedSecretKey.CloneSecret` and
  `secret.FromSecret`, for moving key material between the guarded key types
  and the persisted-state structures without transiting the Go heap.
- `docs/FIPS.md` — the repository's FIPS 140-3 posture and the exemption
  register for the tests that exercise primitives the Signal Protocol or an
  external conformance vector mandates and FIPS 140-3 does not approve. Those
  tests carry a `//go:build !fips140only` tag and run in every other job.
- `tests/fipsaudit` — a static audit of every non-test `.go` file in the module
  for non-approved primitives, against a file-and-symbol-scoped register. It
  catches a non-approved call in production code whether or not a gated test
  reaches it, and fails on stale register entries too. It is allowlist-based:
  inside the policed namespaces every package must be classified as approved or
  registered, so an unenumerated primitive fails closed. It covers the pure-Go
  primitives `GODEBUG=fips140=only` can never reject — Ristretto255,
  edwards25519, Argon2id, Round-3 Kyber — which do their own field arithmetic
  and never enter the Go Cryptographic Module, and it classifies every `go.mod`
  dependency so a new cryptographic one cannot arrive unpoliced.

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

[Unreleased]: https://github.com/jeremyhahn/go-libsignal/compare/v0.2.0-alpha...HEAD
[0.2.0-alpha]: https://github.com/jeremyhahn/go-libsignal/compare/v0.1.2-alpha...v0.2.0-alpha
[0.1.0]: https://github.com/jeremyhahn/go-libsignal/releases/tag/v0.1.0
