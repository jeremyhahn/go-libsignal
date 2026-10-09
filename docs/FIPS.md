# FIPS 140-3 posture

> **Status: REFERENCE** · Last verified: 2026-10-09
> As-built description of go-libsignal code owned by this repository.

This document records what the repository's FIPS gate checks, what it cannot
check, and every exemption it carries. It is the register that the CI job
(`.github/workflows/ci.yml`, job `fips`) and `make fips` point at.

## The gate

```
GOFIPS140=latest GODEBUG=fips140=only go build ./...
GOFIPS140=latest GODEBUG=fips140=only go test -count=1 -tags fips140only ./...
```

`GOFIPS140=latest` selects the Go Cryptographic Module. `GODEBUG=fips140=only`
puts it in the mode where a non-approved operation **fails** — `crypto/hmac`
and `crypto/hkdf` panic, `crypto/ecdh` and `crypto/cipher` return an error.
The weaker `fips140=on` merely loads the module and still permits MD5, SHA-1
and the rest, so a gate built on it cannot fail on the thing it exists to
catch. `only` is mandatory portfolio-wide
(`automatethethings` `software/conventions/configuration.md` §5).

`make fips` runs both steps with the same environment, so a local run
reproduces CI exactly.

The build step is deliberately **untagged**: the library must compile exactly
as it ships. Only the test step carries `-tags fips140only`, and that tag only
ever appears in `_test.go` files. No production file in this repository is
compiled differently for the FIPS gate.

## go-libsignal is not FIPS 140-3 validated, and cannot be

Read this before enabling `GODEBUG=fips140=only` in a process that links this
library.

The Signal Protocol is built on primitives FIPS 140-3 does not approve, and
they are not implementation choices this repository is free to change:

- **X25519** is the DH function of X3DH (§2.1) and of the Double Ratchet's DH
  ratchet (§5.2). FIPS 140-3 approves no drop-in substitute; replacing it with
  a NIST curve would produce a different protocol that cannot talk to Signal.
- **AES-256-GCM under a protocol-derived nonce.** SP 800-38D §8.2.1 does allow
  a deterministic IV construction, but the Go module only exposes the §8.2.2
  RBG-based one (`NewGCMWithRandomNonce`), which prepends a nonce it generates
  itself. Signal's nonce is derived from ratchet state and is part of the wire
  format, so the module rejects the call regardless of the standard's view.
- **HKDF and HMAC under keys shorter than 112 bits**, where the short input is
  fixed by a protocol or a conformance vector — a username, a password, an
  RFC's own test key, Noise's empty-IKM `Split()`.
- **ChaCha20-Poly1305**, named by the Noise patterns Signal uses to reach its
  enclaves.

`CLAUDE.md` defines this repository as a "pure-Go, byte-wire-compatible port of
the Rust libsignal crates," with conformance vectors under `tests/interop/` and
CI that fails on byte-level divergence. Substituting approved primitives for
the above would end that property.

So: **do not run a Signal Protocol path under `GODEBUG=fips140=only`.** It will
error or panic. The gate below proves something narrower and still useful — see
the next section.

## What the gate actually proves

With 95 test files exempted (below), 4,610 of the repository's 5,787 tests
still run under `fips140=only` — 80%. Both counts come from `go test -list`,
so they count the tests the toolchain actually registers in each build:

```
set -o pipefail   # without this the grep's exit status hides a failing go test

go test -list '.*' ./... | grep -cE '^(Test|Fuzz)'        # 5,787
GOFIPS140=latest GODEBUG=fips140=only \
  go test -list '.*' -tags fips140only ./... \
  | grep -cE '^(Test|Fuzz)'                               # 4,610
```

The `grep` matters: `-list` also emits the 17 benchmarks, which are not tests
and are not what these numbers count.

Check the exit status when you re-derive these. `go test -list` reports a
package that fails to build as a `FAIL` line and simply omits its tests, so a
broken build silently *understates* both numbers rather than erroring out —
the count comes back plausible, stable, and short, with nothing to mark it
wrong.

Those cover every package that does not
implement Signal Protocol cryptography, plus the FIPS-relevant parts of the
ones that do: AES-CBC, AES-CTR, AES-256-GCM-SIV, SHA-2, P-256 and the DCAP
X.509 path, ML-KEM, and the HKDF/HMAC call sites that are not pinned by a
vector.

A new call to a non-approved stdlib primitive anywhere outside the register
fails this job — and for production code the static audit in the next section
makes that true regardless of which tests reach it. That is the regression the
gate exists to catch, and it is a real one: three classes of finding from the first `fips140=only` run turned out
to be ordinary defects rather than protocol constraints, and were fixed rather
than exempted (see "Fixed, not exempted").

## The static audit — closing the build-tag hole

The runtime gate can only observe code a *gated test* executes. Because a file
is tagged whole (a panic aborts the whole test binary), production code reached
only by an exempted test is outside its reach: a non-approved call added there
later would compile and never run under `fips140=only`.

`tests/fipsaudit` closes that from the other side. It parses **every non-test
`.go` file in the module** and fails on any non-approved primitive *imported or
called through a package qualifier* that is not in its register — independent of
which tests, if any, reach it. What it does not read is arithmetic: a primitive
implemented here by hand is outside its reach, and outside the runtime gate's
too ("What the runtime gate cannot see").

It keeps **two registers**, which fail for different reasons: `register`, which
pins direct uses file by file with an occurrence count, and `reachRegister`,
which pins which *packages* can reach a non-approved primitive at all. The
second exists because the first is blind to indirection — see "Indirection: the
reachability register" below.

It is **allowlist-based**. Inside the policed namespaces — stdlib `crypto/...`,
`golang.org/x/crypto/...`, and the module's cryptographic dependencies
(`filippo.io/edwards25519`, `github.com/gtank/ristretto255`,
`github.com/cloudflare/circl`, `github.com/flynn/noise`) — every package must
be classified as approved or as a registered exemption. A package classified
nowhere is a finding **for being unclassified**, so a primitive no one thought
to enumerate fails closed rather than passing silently. `crypto/dsa` and
`x/crypto/blake2b` both fail today without any rule naming them.

On top of that baseline the audit recognises:

- **Denied imports** — `crypto/md5`, `crypto/sha1`, `crypto/des`, `crypto/rc4`,
  `crypto/hpke`, `x/crypto/curve25519`, `x/crypto/chacha20poly1305`, and the
  other legacy `x/crypto` ciphers and hashes; plus the pure-Go dependencies
  `github.com/gtank/ristretto255`, `filippo.io/edwards25519` and its `/field`,
  `github.com/cloudflare/circl/kem/kyber/kyber1024`, `github.com/flynn/noise`,
  `x/crypto/argon2`, `bcrypt`, and `scrypt`.

  Each is named by **exact package, never by module tree**. CIRCL ships dozens
  of algorithms, so a `github.com/cloudflare/circl` prefix would let `pkg/kem` —
  already registered for Kyber — import an unrelated signature or cipher scheme
  and produce the same already-allowed finding, with no register or docs change
  required. `filippo.io/edwards25519` is smaller but the same shape. Because
  every one of these modules is inside a policed namespace, an unlisted package
  of them is not thereby permitted: it fails closed as **unclassified**, which
  is the stricter outcome, not the weaker one.
- **Denied selectors**, for packages that serve both approved and non-approved
  primitives — `ecdh.X25519` (but not `ecdh.P256`), and `cipher.NewGCM` /
  `NewGCMWithNonceSize` / `NewGCMWithTagSize` (but not
  `NewGCMWithRandomNonce`).
- **Dot imports of any package it reads by qualifier** — the selector-analysed
  ones and the denied ones alike. `import . "crypto/ecdh"` turns `ecdh.X25519()`
  into a bare `X25519()` with no qualifier to match, and the same erasure would
  hide every use of a denied package behind its single import line. The audit
  refuses the import rather than analysing past it and reporting nothing, or
  counting one use where there are ten. It fails closed on a shape it cannot
  read. The denied *import itself* is still matched by path, however it is
  bound.

`approvedCrypto` records the standard behind each approval, so a reader can
check the classification rather than trust it — AES (FIPS 197), SHA-2
(FIPS 180-4), SHA-3 (FIPS 202), HMAC (FIPS 198-1), HKDF (SP 800-56C Rev. 2),
ECDSA and Ed25519 (FIPS 186-5), ML-KEM (FIPS 203), ECDH over the NIST curves
(SP 800-56A Rev. 3). Denied beats approved, so a path in both tables fails
closed rather than being silently permitted.

`TestModuleDependenciesAreClassified` extends the same rule to `go.mod`: every
required module must be either inside a policed namespace or classified with
what it does instead. A new cryptographic dependency cannot arrive under a
module path the per-import rules do not police.

The pure-Go dependency rules matter most. Those are the **implementations the
Go Cryptographic Module never sees** — they do their own field arithmetic, so
`GODEBUG=fips140=only` cannot reject them however the tests are tagged.
Ristretto255, edwards25519, Argon2id and Round-3 Kyber are every bit as
non-approved as X25519; before this audit they were simply invisible. Each of
their production call sites is now registered with the protocol that
mandates it:

| Primitive | Where | Mandated by |
|---|---|---|
| Ristretto255 | `pkg/zkgroup`, `pkg/zkcredential`, `pkg/poksho`, `pkg/usernames`, `pkg/svr` | the prime-order group of the Chase–Perrin–Zaverucha credential system and the SVR OPRF; every group element is on the wire (`draft-irtf-cfrg-ristretto255-decaf448`) |
| edwards25519 (+ `/field`) | `pkg/ecc`, `pkg/crypto/elligator`, `pkg/keytrans` | XEdDSA/VXEdDSA sign with a Curve25519 identity key in Edwards form (XEdDSA §2, §4); Elligator-2 is defined over Curve25519; key transparency uses ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381 §5.5) |
| Round-3 Kyber-1024 (CIRCL) | `pkg/kem` | back-compat with peers that have not migrated. The FIPS 203 algorithms this repository also ships use stdlib `crypto/mlkem` and are approved, so they are not denied |
| Noise Protocol Framework | `pkg/attest` | `Noise_NK_25519_ChaChaPoly_SHA256` and `Noise_NKhfs_25519+Kyber1024_ChaChaPoly_SHA256` |
| Argon2id | `pkg/accountkeys` | Signal's PIN hash (Rust `PinHash`, `rust/account-keys/src/hash.rs`); FIPS 140-3 approves no memory-hard password hash, and PBKDF2 would change the stored value |

The register is file-and-symbol scoped and mirrors the tables here, so widening
it is a visible diff a reviewer sees, not a silent consequence of a build tag.
A register entry whose file is gone, or whose primitive is no longer used,
fails the audit too, so the list cannot rot into a blanket permission.

**Each entry pins a count, not just a permission.** `pkg/ecc/Curve.go` is
registered for *two* uses of X25519, not for X25519 in general. Every import of
a denied package and every qualified call into one is its own occurrence, so a
third X25519 operation added anywhere in that file fails the audit until the
count is raised deliberately — the same justification a new entry needs, in a
diff a reviewer can see. The count is pinned in both directions: leaving it
above the file's actual uses fails too, so an exemption cannot outlive the code
that earned it. This is also why a dot import of a denied package is refused
outright — it erases the qualifier the occurrences are counted through, and one
import would then stand in for any number of uses.

### Indirection: the reachability register

Counting qualified references is exact for a direct call and blind to everything
else. Once `pkg/kdf/HKDF.go` holds a `curve25519.X25519` call, a package that
calls `kdf.DeriveSecrets` performs an X25519 operation while adding no selector
anywhere — so no count rises, and nothing appears in a diff. A function-valued
alias behaves the same way: `agree := curve25519.X25519` counts once, and every
later invocation of `agree` counts not at all. Both shapes can also escape the
runtime gate, if the only tests that reach them are `!fips140only` — precisely
the hole this audit exists to cover.

`reachRegister` holds that boundary, and holds it **by import closure rather
than by call graph**. To name anything in a package — a function, a method, a
variable holding a function — you must import that package. So a package that
gains the ability to perform a non-approved operation gains an import edge to
the package that holds it, through however many wrappers. That edge cannot be
hidden. A call graph built from syntax, by contrast, has to guess at methods,
interface dispatch, function values and reflection, and every guess is a way to
miss a call; `golang.org/x/tools`-grade SSA would narrow the guessing without
ending it, at the cost of a new dependency for a weaker guarantee than an import
edge already gives.

The register is a table of module-relative package directories and the
primitives reachable from each. **46 of the module's 70 packages** are listed;
the other 24 are absent, and their absence asserts something stronger than an
exemption — that no non-approved primitive is reachable from them at all. A new
import edge into a registered package fails
`TestFIPSAudit_PackageReachMatchesRegister` until the register says the package
may have one, and a primitive a package can no longer reach fails
`TestFIPSAudit_ReachRegisterHasNoStaleEntries`, so it shrinks with the code the
same way the per-file counts do.

Two things it deliberately does not claim:

- **A value handed across an interface.** A package that receives an
  already-constructed object can drive it without importing its package. The
  package that *constructed* it did import, and is registered, so the closure
  bounds where a non-approved operation can be **introduced by static
  reference** — it does not claim to name every frame on the stack when one runs.
- **A local wrapper call inside an already-registered package.** No new
  qualified reference and no new import edge, so neither register counts it.
  What that leaves unflagged is one more use of a primitive the package is
  already exempt for, on a path already cited in the table below — and every
  exemption here is protocol-wide, never per-call-site, so an additional call is
  not a new compliance decision.
  `TestRegisterViolations_DoNotCountLocalWrapperCalls` pins that boundary so it
  stays reviewed rather than becoming a surprise.

The audit executes no cryptography, carries no build tag, and runs in
`make test`, `make integration-test` **and** `make fips-test`.

Two limits are worth naming. It reasons about imports and selectors, not
values, so it cannot see an HKDF or HMAC key that is too short; the runtime gate
covers those wherever a gated test reaches them. And it recognises a primitive
by the package it is imported from, so a primitive written out in this
repository's own source — field arithmetic and bit operations under a `pkg/...`
path, importing nothing denied — matches no rule and reports clean. Neither gate
sees that shape; see "What the runtime gate cannot see" below.

### The protected-memory layer — resolved

The protected-memory layer used to carry a non-approved primitive of its own.
`github.com/awnumar/memguard` held this library's key material in locked memory,
and it was not primitive-free: it encrypted every `Enclave` at rest with NaCl
secretbox (XSalsa20-Poly1305) and derived its rolling enclave key with BLAKE2b,
neither approved and neither visible to the Go Cryptographic Module. It reached
a public path — `secret.Secret.Seal()` returned a `memguard.Enclave` — so a
consumer could cause a non-approved operation on a secret-handling path. This
document once recorded that as an open owner-level question.

**It is resolved.** The layer now uses `github.com/jeremyhahn/go-enclave`, the
portfolio locked-memory primitive, in place of memguard. go-enclave holds
material in plaintext locked memory guarded by guard pages and a canary — it
has no at-rest cipher, so there is no secretbox and no BLAKE2b. Its only
cryptography is the FIPS-approved `crypto/rand` (SP 800-90A) for the canary and
`crypto/subtle` for constant-time comparisons. The non-approved primitive is
gone from the dependency graph, and with it the `Seal()` / `OpenEnclave()`
at-rest-encryption surface that exposed it (dropped: no production caller
depended on it, and the stack's at-rest sealing is being redesigned separately).

The audit reflects this directly: memguard is no longer a denied import, no
longer classified, and no longer named in any package's reachability set.
go-enclave is recorded in `dependencyClassification` as carrying only the two
approved stdlib primitives above — a reviewed, module-level classification on
the same footing as `memcall`'s, not a policed namespace. `go-enclave` is not
in `policedNamespaces`, so `classify` does not police its subpackages; what the
audit does enforce is `TestModuleDependenciesAreClassified`, under which a new
cryptographic dependency added to `go.mod` fails closed until it too is
classified or policed. What was option 1 of the former
open question — replace the layer with one whose operations are approved — is
what happened, and better than that framing anticipated: the replacement needs
no cipher at all.

## What the runtime gate cannot see

The Go Cryptographic Module only polices the standard library's `crypto/*`
packages, plus `golang.org/x/crypto/chacha20poly1305`, which carries its own
`fips140only` check. Pure-Go implementations that do their own arithmetic —
Ristretto255, edwards25519, Argon2id, and Round-3 Kyber — are invisible to it,
and none of them is FIPS-approved.

**In production code the static audit covers exactly that gap** wherever the
primitive arrives through a package, which is why its register lists all four.
Three blind spots remain, and none should be read as absence:

- **Test code using a pure-Go non-approved primitive.** The audit scans
  production source only; the runtime gate cannot see these primitives at all.
  A test that reaches for one is caught by neither.
- **Key material judged by value rather than by symbol** — an HKDF or HMAC key
  below 112 bits in a path no gated test exercises.
- **A primitive implemented in this repository's own source.** The audit
  classifies imports and qualified calls, not arithmetic: SHA-1 or ChaCha20
  written out by hand in a `pkg/...` file, importing nothing denied, produces no
  finding. The runtime gate is equally blind to it, because such code never
  enters the Go Cryptographic Module. **Nothing in this repository enforces this
  one.** It is held by code review, and by the rule that reimplementing a
  primitive is never a legitimate way to resolve a FIPS finding — a rule, not a
  control.

So a green run means "no non-approved primitive **reached through a package** in
production source outside the register, no package outside the reachability
register from which one is reachable, and none executed by a gated test". It
does not mean "no non-approved cryptography in this repository", and it does not
mean "FIPS 140-3 compliant". This library is not, and cannot be, FIPS 140-3
validated; see the section above.

## Fixed, not exempted

Three classes of finding from the first `fips140=only` run were ordinary
defects — test fixtures using key material far shorter than anything production
passes — and were corrected rather than exempted. `pkg/svr` and `pkg/net` are
fully inside the gate as a result, and `pkg/keys/chain` needs no exemption at
all.

| Where | Was | Now |
|---|---|---|
| `pkg/svr`, `pkg/net` SVR fixtures | 4-to-13-byte passwords | 32 bytes, via `testPassword` / `svrTestPassword` helpers — the length `BackupKey.DeriveForwardSecrecyPassword` always produces (`docs/backup/account-keys.md`) |
| `pkg/svr` `kdf`/`DeriveStorageKey` fixtures | 6-to-12-byte key material | 32 bytes, the length production passes |
| `pkg/kdf`, `pkg/keys/chain` IKM, salt and chain-key fixtures | 3-to-12-byte strings | 32 bytes for IKM and chain keys (a real DH shared secret and a real chain key), 17 bytes for the `Extract` salt HKDF uses as an HMAC key |

## The exemption register

Each file below carries `//go:build !fips140only` and a header comment naming
the primitive and the citation. `make test`, `make coverage` and the
`integration-test` job all still run every one of them — the tag only removes
them from the FIPS job.

"Tests" counts the tests in the file that actually trip the module. A file is
tagged whole because a panic aborts the whole test binary; where a file was
overwhelmingly clean, the offending tests were moved into a dedicated
`*_fips_exempt_test.go` instead, so the rest of the file stays gated
(`pkg/accountkeys`, `pkg/attest/dcap_coverage`, `pkg/kdf`,
`pkg/state/record/guarded_persistence`).

#### `pkg/accountkeys` — 1 exempt test

| File | Tests | Primitive FIPS 140-3 rejects | What mandates it |
|---|---:|---|---|
| `accountkeys_fips_exempt_test.go` | 1 | HKDF-SHA256 under an eight-byte key | MakeSalt feeds the username to HKDF as input key material (Rust PinHash::make_salt, rust/account-keys/src/hash.rs) and the vector pins it to "username" |

#### `pkg/attest` — 49 exempt tests

| File | Tests | Primitive FIPS 140-3 rejects | What mandates it |
|---|---:|---|---|
| `client_connection_test.go` | 7 | X25519 | the Noise_NK_25519_ChaChaPoly_SHA256 pattern Signal uses to reach its SGX and HSM enclaves requires it |
| `dcap_coverage_fips_exempt_test.go` | 10 | X25519 | the Noise_NK_25519_ChaChaPoly_SHA256 and Noise_NKhfs_25519+Kyber1024_ChaChaPoly_SHA256 patterns require it (Noise Protocol Framework rev 34) |
| `enclave_test.go` | 10 | X25519 | the Noise_NK_25519_ChaChaPoly_SHA256 pattern Signal uses to reach its SGX and HSM enclaves requires it |
| `hsm_enclave_test.go` | 6 | X25519 | the Noise_NK_25519_ChaChaPoly_SHA256 pattern Signal uses to reach its SGX and HSM enclaves requires it |
| `hsm_enclave_transport_test.go` | 3 | X25519 | the Noise_NK_25519_ChaChaPoly_SHA256 pattern Signal uses to reach its SGX and HSM enclaves requires it |
| `nkhfs_public_api_test.go` | 4 | X25519 | the Noise_NKhfs_25519+Kyber1024_ChaChaPoly_SHA256 pattern requires it (Noise Protocol Framework rev 34) |
| `noise_nkhfs_server_test.go` | 5 | X25519 | the Noise_NKhfs_25519+Kyber1024_ChaChaPoly_SHA256 pattern requires it (Noise Protocol Framework rev 34) |
| `noise_nkhfs_test.go` | 4 | X25519 and ChaCha20-Poly1305 | the Noise_NKhfs_25519+Kyber1024_ChaChaPoly_SHA256 pattern names both (Noise Protocol Framework rev 34) |

#### `pkg/cipher` — 26 exempt tests

| File | Tests | Primitive FIPS 140-3 rejects | What mandates it |
|---|---:|---|---|
| `aesgcm_test.go` | 5 | AES-256-GCM under a caller-supplied nonce | the nonce is derived by the protocol and carried on the wire, so it cannot be replaced by the module-generated nonce of NewGCMWithRandomNonce (rust/crypto/src/aes_gcm.rs) |
| `hpke_test.go` | 21 | X25519 | RFC 9180 fixes DHKEM(X25519, HKDF-SHA256) for the Base_X25519_HkdfSha256_Aes256Gcm suite this package implements (rust/crypto/src/hpke.rs) |

#### `pkg/ecc` — 82 exempt tests

| File | Tests | Primitive FIPS 140-3 rejects | What mandates it |
|---|---:|---|---|
| `Curve_test.go` | 32 | X25519 | the X3DH key agreement specification (section 2.1) requires it |
| `coverage_boost_test.go` | 9 | X25519 | the X3DH key agreement specification (section 2.1) requires it |
| `guarded_key_test.go` | 21 | X25519 | the X3DH key agreement specification (section 2.1) requires it |
| `vxeddsa_consistency_test.go` | 2 | X25519 | the X3DH key agreement specification (section 2.1) requires it |
| `vxeddsa_test.go` | 14 | X25519 | the X3DH key agreement specification (section 2.1) requires it |
| `vxeddsa_vectors_test.go` | 4 | X25519 | the X3DH key agreement specification (section 2.1) requires it |

#### `pkg/groups` — 36 exempt tests

| File | Tests | Primitive FIPS 140-3 rejects | What mandates it |
|---|---:|---|---|
| `GroupCipher_test.go` | 17 | X25519 | the X3DH key agreement specification (section 2.1) requires it |
| `GroupSessionBuilder_test.go` | 4 | X25519 | the X3DH key agreement specification (section 2.1) requires it |
| `cipher_edge_cases_test.go` | 5 | X25519 | the X3DH key agreement specification (section 2.1) requires it |
| `coverage_gaps_test.go` | 10 | X25519 | the X3DH key agreement specification (section 2.1) requires it |

#### `pkg/groups/state/record` — 33 exempt tests

| File | Tests | Primitive FIPS 140-3 rejects | What mandates it |
|---|---:|---|---|
| `SenderKeyRecord_test.go` | 10 | X25519 | the X3DH key agreement specification (section 2.1) requires it |
| `SenderKeyState_test.go` | 12 | X25519 | the X3DH key agreement specification (section 2.1) requires it |
| `coverage_boost_test.go` | 10 | X25519 | the X3DH key agreement specification (section 2.1) requires it |
| `sender_key_state_machine_test.go` | 1 | HMAC-SHA256 under a four-byte key | the key is INITIAL_SEED_KEY = [1, 2, 3, 4], the constant rust/protocol/src/sender_keys.rs fixes for the test this one ports |

#### `pkg/kdf` — 3 exempt tests

| File | Tests | Primitive FIPS 140-3 rejects | What mandates it |
|---|---:|---|---|
| `HKDF_fips_exempt_test.go` | 3 | X25519 and HMAC-SHA256 under a 13-byte key | CalculateSharedSecret is the X3DH DH function (X3DH section 2.1), and RFC 5869 Test Case 1 fixes the 13-byte salt that HKDF-Extract uses as the HMAC key |

#### `pkg/keys/identity` — 14 exempt tests

| File | Tests | Primitive FIPS 140-3 rejects | What mandates it |
|---|---:|---|---|
| `IdentityKeyPair_test.go` | 1 | X25519 | the X3DH key agreement specification (section 2.1) requires it |
| `alt_identity_test.go` | 10 | X25519 | the X3DH key agreement specification (section 2.1) requires it |
| `decode_generate_test.go` | 3 | X25519 | the X3DH key agreement specification (section 2.1) requires it |

#### `pkg/keys/prekey` — 5 exempt tests

| File | Tests | Primitive FIPS 140-3 rejects | What mandates it |
|---|---:|---|---|
| `PreKeyBundle_test.go` | 5 | X25519 | the X3DH key agreement specification (section 2.1) requires it |

#### `pkg/keys/root` — 4 exempt tests

| File | Tests | Primitive FIPS 140-3 rejects | What mandates it |
|---|---:|---|---|
| `RootKey_test.go` | 4 | X25519 | the X3DH key agreement specification (section 2.1) requires it |

#### `pkg/protocol` — 54 exempt tests

| File | Tests | Primitive FIPS 140-3 rejects | What mandates it |
|---|---:|---|---|
| `DecryptionErrorMessage_test.go` | 6 | X25519 | the X3DH key agreement specification (section 2.1) requires it |
| `PlaintextContent_test.go` | 1 | X25519 | the X3DH key agreement specification (section 2.1) requires it |
| `PreKeySignalMessage_test.go` | 11 | X25519 | the X3DH key agreement specification (section 2.1) requires it |
| `SenderKeyDistributionMessage_test.go` | 4 | X25519 | the X3DH key agreement specification (section 2.1) requires it |
| `SenderKeyMessage_test.go` | 4 | X25519 | the X3DH key agreement specification (section 2.1) requires it |
| `SignalMessage_test.go` | 17 | X25519 | the X3DH key agreement specification (section 2.1) requires it |
| `addresses_test.go` | 6 | X25519 | the X3DH key agreement specification (section 2.1) requires it |
| `protocol_coverage_test.go` | 5 | X25519 | the X3DH key agreement specification (section 2.1) requires it |

#### `pkg/ratchet` — 22 exempt tests

| File | Tests | Primitive FIPS 140-3 rejects | What mandates it |
|---|---:|---|---|
| `Ratchet_test.go` | 14 | X25519 | the Double Ratchet specification (section 5.2, DH ratchet) requires it |
| `ReceiverParameters_test.go` | 3 | X25519 | the Double Ratchet specification (section 5.2, DH ratchet) requires it |
| `SenderParameters_test.go` | 3 | X25519 | the Double Ratchet specification (section 5.2, DH ratchet) requires it |
| `errors_test.go` | 2 | X25519 | the Double Ratchet specification (section 5.2, DH ratchet) requires it |

#### `pkg/sealed` — 128 exempt tests

| File | Tests | Primitive FIPS 140-3 rejects | What mandates it |
|---|---:|---|---|
| `certificate_test.go` | 33 | X25519 | the X3DH specification (section 2.1) requires it for the Sealed Sender ephemeral keys |
| `known_server_certificates_test.go` | 4 | X25519 | the X3DH specification (section 2.1) requires it for the Sealed Sender ephemeral keys |
| `message_test.go` | 5 | X25519 | the X3DH specification (section 2.1) requires it for the Sealed Sender ephemeral keys |
| `sealed_coverage_test.go` | 24 | X25519 | the X3DH specification (section 2.1) requires it for the Sealed Sender ephemeral keys |
| `sealed_sender_test.go` | 24 | X25519 | the X3DH specification (section 2.1) requires it for the Sealed Sender ephemeral keys |
| `sealed_sender_v2_mrm_test.go` | 11 | X25519 | the X3DH specification (section 2.1) requires it for the Sealed Sender ephemeral keys |
| `sealed_sender_v2_received_test.go` | 8 | X25519 | the X3DH specification (section 2.1) requires it for the Sealed Sender ephemeral keys |
| `sealed_sender_v2_test.go` | 19 | X25519 | the X3DH specification (section 2.1) requires it for the Sealed Sender ephemeral keys |

#### `pkg/session` — 159 exempt tests

| File | Tests | Primitive FIPS 140-3 rejects | What mandates it |
|---|---:|---|---|
| `SessionCipher_compat_test.go` | 3 | X25519 | the X3DH specification (section 2.1) and the Double Ratchet specification (section 5.2) require it |
| `SessionCipher_fuzz_test.go` | 2 | X25519 | the X3DH specification (section 2.1) and the Double Ratchet specification (section 5.2) require it |
| `Session_test.go` | 72 | X25519 | the X3DH specification (section 2.1) and the Double Ratchet specification (section 5.2) require it |
| `clone_keypair_test.go` | 3 | X25519 | the Double Ratchet specification (section 5.2) requires the ratchet key pair these tests clone |
| `coverage_audit_test.go` | 9 | X25519 | the X3DH specification (section 2.1) and the Double Ratchet specification (section 5.2) require it |
| `decrypt_locked_memory_linux_test.go` | 5 | X25519 | the X3DH specification (section 2.1) and the Double Ratchet specification (section 5.2) require the session pair these tests establish before measuring locked memory |
| `coverage_test.go` | 35 | X25519 | the X3DH specification (section 2.1) and the Double Ratchet specification (section 5.2) require it |
| `encrypt_decrypt_errors_test.go` | 8 | X25519 | the X3DH specification (section 2.1) and the Double Ratchet specification (section 5.2) require it |
| `nil_prekey_test.go` | 1 | X25519 | the X3DH specification (section 2.1) and the Double Ratchet specification (section 5.2) require it |
| `proptest_session_test.go` | 4 | X25519 | the X3DH specification (section 2.1) and the Double Ratchet specification (section 5.2) require it. Also carries `//go:build proptest` for an unrelated reason — runtime, not FIPS (#30) — so it is excluded from `make test` as well as from the FIPS gate, and runs in its own CI job |
| `rust_integration_test.go` | 5 | X25519 | the X3DH specification (section 2.1) and the Double Ratchet specification (section 5.2) require it |
| `setidentitystore_test.go` | 1 | X25519 | the X3DH specification (section 2.1) and the Double Ratchet specification (section 5.2) require it |
| `store_errors_test.go` | 11 | X25519 | the X3DH specification (section 2.1) and the Double Ratchet specification (section 5.2) require it |

#### `pkg/sessionmanagement` — 16 exempt tests

| File | Tests | Primitive FIPS 140-3 rejects | What mandates it |
|---|---:|---|---|
| `sessionmanagement_coverage_test.go` | 16 | X25519 | the X3DH key agreement specification (section 2.1) requires it |

#### `pkg/state/record` — 112 exempt tests

| File | Tests | Primitive FIPS 140-3 rejects | What mandates it |
|---|---:|---|---|
| `SessionRecord_test.go` | 45 | X25519 | the X3DH key agreement specification (section 2.1) requires it |
| `SessionUsability_test.go` | 17 | X25519 | the X3DH key agreement specification (section 2.1) requires it |
| `additional_coverage_test.go` | 11 | X25519 | the X3DH key agreement specification (section 2.1) requires it |
| `coverage_test.go` | 22 | X25519 | the X3DH key agreement specification (section 2.1) requires it |
| `findings_regression_test.go` | 7 | X25519 | the X3DH key agreement specification (section 2.1) requires it |
| `generic_signed_prekey_test.go` | 3 | X25519 | the X3DH key agreement specification (section 2.1) requires it |
| `guarded_persistence_fips_exempt_test.go` | 7 | X25519 | the X3DH key agreement specification (section 2.1) requires the Curve25519 key pairs carried by the records these tests persist and reload |

#### `pkg/util/keyhelper` — 17 exempt tests

| File | Tests | Primitive FIPS 140-3 rejects | What mandates it |
|---|---:|---|---|
| `KeyHelper_test.go` | 17 | X25519 | the X3DH key agreement specification (section 2.1) requires it |

#### `tests` — 17 exempt tests

| File | Tests | Primitive FIPS 140-3 rejects | What mandates it |
|---|---:|---|---|
| `fingerprint_test.go` | 1 | X25519 | the X3DH specification (section 2.1) and the Double Ratchet specification (section 5.2) require it |
| `group_test.go` | 1 | X25519 | the X3DH specification (section 2.1) and the Double Ratchet specification (section 5.2) require it |
| `identity_test.go` | 1 | X25519 | the X3DH specification (section 2.1) and the Double Ratchet specification (section 5.2) require it |
| `prekey_test.go` | 1 | X25519 | the X3DH specification (section 2.1) and the Double Ratchet specification (section 5.2) require it |
| `saved_message_keys_test.go` | 1 | X25519 | the X3DH specification (section 2.1) and the Double Ratchet specification (section 5.2) require it |
| `serializer_test.go` | 1 | X25519 | the X3DH specification (section 2.1) and the Double Ratchet specification (section 5.2) require it |
| `session_extras_test.go` | 5 | X25519 | the X3DH specification (section 2.1) and the Double Ratchet specification (section 5.2) require it |
| `session_test.go` | 3 | X25519 | the X3DH specification (section 2.1) and the Double Ratchet specification (section 5.2) require it |
| `sessionmanagement_facade_test.go` | 1 | X25519 | the X3DH specification (section 2.1) and the Double Ratchet specification (section 5.2) require it |
| `sessionmanagement_stress_test.go` | 1 | X25519 | the X3DH specification (section 2.1) and the Double Ratchet specification (section 5.2) require it |
| `sharedsecret_test.go` | 1 | X25519 | the X3DH specification (section 2.1) and the Double Ratchet specification (section 5.2) require it |

#### `tests/interop` — 15 exempt tests

| File | Tests | Primitive FIPS 140-3 rejects | What mandates it |
|---|---:|---|---|
| `accountkeys_pin_hash_test.go` | 1 | HKDF-SHA256 under an eight-byte key | the key is the username, which Rust PinHash::make_salt (rust/account-keys/src/hash.rs) feeds to HKDF as input key material, and the vector pins it to "username" |
| `aes_gcm_conformance_test.go` | 1 | AES-256-GCM under a vector-supplied nonce | the Wycheproof vectors fix the nonce |
| `aes_gcm_smoke_test.go` | 1 | AES-256-GCM under a vector-supplied nonce | the Rust-emitted fixture pinned by /RUST_REV fixes the nonce |
| `chacha20poly1305_rfc7539_test.go` | 1 | ChaCha20-Poly1305 | the vectors are RFC 7539 section 2.8.2 and appendix A.5, which exist to pin that algorithm |
| `hmac_sha256_rfc4231_test.go` | 1 | HMAC-SHA256 under keys below 112 bits | RFC 4231 fixes the key of every test case, and several are shorter than 14 bytes |
| `noise_nkhfs_handshake_wire_test.go` | 1 | HKDF-SHA256 under an empty key | the Noise Protocol Framework rev 34 section 5.2 defines Split() as HKDF(ck, zerolen, 2) |
| `sealed_sender_v1_wire_test.go` | 1 | X25519 | the X3DH key agreement specification (section 2.1) requires it |
| `sealed_sender_v2_received_wire_test.go` | 1 | X25519 | the X3DH key agreement specification (section 2.1) requires it |
| `sesame_wire_test.go` | 3 | X25519 | the X3DH key agreement specification (section 2.1) requires it |
| `svr_svr4_protocol_test.go` | 1 | HKDF-SHA256 under a key below 112 bits | the Rust-emitted SVR4 fixture pinned by /RUST_REV replays a 13-byte and an empty password as HKDF input key material |
| `x25519_rfc7748_test.go` | 3 | X25519 | the vectors are RFC 7748 sections 5.2 and 6.1, which exist to pin that algorithm |

## Changing the register

Adding an entry is a last resort, in this order:

1. **Product code on a security path uses a non-approved primitive** — fix the
   code. This is the common case elsewhere in the portfolio and is not an
   exemption.
2. **A test fixture uses weak key material for convenience** — fix the fixture,
   as in "Fixed, not exempted" above. If production passes 32 bytes, so should
   the test.
3. **An external protocol, standard or conformance vector fixes the primitive**
   — only then add a file to this register, with the citation. Isolate the
   offending tests into a `*_fips_exempt_test.go` rather than tagging a whole
   file whenever the file is mostly clean.

If the primitive appears in *production* code, the entry belongs in the
`register` map in `tests/fipsaudit/fipsaudit_test.go` as well as in the table
above; the audit fails until both agree.

If the change gives a package that had none a path to non-approved cryptography
— even indirectly, through a wrapper in another package — it also needs an entry
in `reachRegister`, and a reason. That is the register to think hardest about:
`register` records that a primitive is used somewhere it must be, while
`reachRegister` records how far through the codebase that reach extends. Growing
it is how a protocol-mandated exemption quietly turns into a general licence, so
prefer confining the call behind the package that already holds it to giving a
new package the edge.

If the audit reports a package as **unclassified**, that is not a licence to
add it to `approvedCrypto` to make the message go away. `approvedCrypto` is for
primitives a FIPS standard approves, and its value must name that standard.
Anything else goes through the three steps above.

Reverting the job to `fips140=on`, adding a tag that skips the job, or
narrowing the package list so a failing package is not covered are **not**
exemptions and are not acceptable resolutions.

Removing an entry is always welcome: drop the build tag, run `make fips`, and
if it passes the exemption was stale.

## References

- Go FIPS 140-3 mode — <https://go.dev/doc/security/fips140>
- X3DH — <https://signal.org/docs/specifications/x3dh/> (`docs/references/x3dh.pdf`)
- Double Ratchet — <https://signal.org/docs/specifications/doubleratchet/> (`docs/references/doubleratchet.pdf`)
- Noise Protocol Framework rev 34 — <https://noiseprotocol.org/noise.html>
- RFC 9180 (HPKE), RFC 7748 (X25519), RFC 5869 (HKDF), RFC 4231 (HMAC-SHA-256 vectors), RFC 7539 (ChaCha20-Poly1305)
- NIST SP 800-38D §8.2 (GCM IV construction), SP 800-131A Rev. 2 (112-bit minimum key strength)
- Upstream Rust libsignal at the commit pinned in `/RUST_REV`
