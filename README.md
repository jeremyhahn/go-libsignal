# go-libsignal

[![Go Reference](https://pkg.go.dev/badge/github.com/jeremyhahn/go-libsignal.svg)](https://pkg.go.dev/github.com/jeremyhahn/go-libsignal)
[![Go Version](https://img.shields.io/badge/go-1.27.1-blue.svg)](https://go.dev/dl/)
[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](https://www.gnu.org/licenses/gpl-3.0.html)
[![CI](https://github.com/jeremyhahn/go-libsignal/actions/workflows/ci.yml/badge.svg)](https://github.com/jeremyhahn/go-libsignal/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-92.1%25-brightgreen.svg)](https://github.com/jeremyhahn/go-libsignal)
[![Rust Rev](https://img.shields.io/badge/rust--libsignal-v0.92.2%4098915c44-orange.svg)](https://github.com/signalapp/libsignal/commit/98915c44)

A pure-Go implementation of the Signal Protocol, byte-for-byte compatible with Rust libsignal v0.92.2 at commit `98915c44`. Supports X3DH/PQXDH session establishment, Double Ratchet, SenderKey groups, Sealed Sender v1/v2, post-quantum SPQR + ML-KEM Braid + Triple Ratchet, message backups, secure value recovery, zero-knowledge credentials, and key transparency.

## Status

| Dimension | Detail |
|---|---|
| Test status | 51 packages pass with `-race` |
| Coverage | 92.1% total; every package meets per-package minimum |
| Static analysis | gosec / govulncheck / staticcheck all clean |
| Cross-impl interop | 10/10 live Rust↔Go round-trip tests passing |
| Pinned upstream | Rust libsignal v0.92.2 (commit `98915c44`) |
| API stability | 0.x — breaking changes possible; see CHANGELOG |

## Installation

```bash
go get github.com/jeremyhahn/go-libsignal@v0.1.0
```

**Go 1.27.1 is required.** The module pins `go 1.27.1` in `go.mod`; the standard-library `crypto/mlkem` package used for ML-KEM-1024 first appeared in that toolchain.

> **In-tree development only:** If your workspace has a parent `go.work`, set `GOWORK=off` before running `go` commands — the parent workspace requires Go 1.26.3 and will conflict with this module's pin. Downstream consumers importing `go-libsignal` as a dependency do not need `GOWORK=off`.

## Quickstart

The following example establishes a PQXDH session between Alice and Bob and
exchanges a single encrypted message. It mirrors the pattern used in
`pkg/session/Session_test.go`.

```go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/prekey"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/session"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/state/store"
	"github.com/jeremyhahn/go-libsignal/pkg/util/keyhelper"
	"github.com/jeremyhahn/go-libsignal/pkg/util/optional"
)

// jsonKyberSerializer is a minimal JSON serializer for KyberPreKey records.
// The serialize.Serializer struct does not include a KyberPreKey field, so
// callers provide their own implementation of record.KyberPreKeySerializer.
type jsonKyberSerializer struct{}

func (j *jsonKyberSerializer) Serialize(s *record.KyberPreKeyStructure) ([]byte, error) {
	return json.Marshal(s)
}

func (j *jsonKyberSerializer) Deserialize(b []byte) (*record.KyberPreKeyStructure, error) {
	var s record.KyberPreKeyStructure
	return &s, json.Unmarshal(b, &s)
}

func main() {
	sr := serialize.NewJSONSerializer()

	// --- Bob publishes a prekey bundle (normally fetched from a key server) ---

	bobIdentity, err := keyhelper.GenerateIdentityKeyPair()
	must(err)
	bobRegID := keyhelper.GenerateRegistrationID()
	bobPreKeys, err := keyhelper.GeneratePreKeys(0, 1, sr.PreKeyRecord)
	must(err)
	bobSignedPreKey, err := keyhelper.GenerateSignedPreKey(bobIdentity, 0, sr.SignedPreKeyRecord)
	must(err)
	bobKyberPreKey, err := keyhelper.GenerateKyberPreKey(bobIdentity.PrivateKey(), 42, &jsonKyberSerializer{})
	must(err)

	bobAddress := protocol.NewSignalAddress("bob", 1)
	bobBundle := prekey.NewBundleWithKyber(
		bobRegID,
		bobAddress.DeviceID(),
		bobPreKeys[0].ID(),
		bobSignedPreKey.ID(),
		bobPreKeys[0].KeyPair().PublicKey(),
		bobSignedPreKey.KeyPair().PublicKey(),
		bobSignedPreKey.Signature(),
		bobIdentity.PublicKey(),
		&optional.Uint32{Value: 42},
		bobKyberPreKey.KeyPair().Public,
		bobKyberPreKey.Signature(),
	)

	// --- Alice builds a session from Bob's bundle ---

	aliceIdentity, err := keyhelper.GenerateIdentityKeyPair()
	must(err)
	aliceAddress := protocol.NewSignalAddress("alice", 1)

	aliceSessionStore := newInMemSessionStore(sr)
	alicePreKeyStore := newInMemPreKeyStore()
	aliceSignedPreKeyStore := newInMemSignedPreKeyStore()
	aliceIdentityStore := newInMemIdentityKeyStore(aliceIdentity, keyhelper.GenerateRegistrationID())

	aliceBuilder := session.NewBuilderWithKyber(
		aliceSessionStore,
		alicePreKeyStore,
		aliceSignedPreKeyStore,
		aliceIdentityStore,
		newInMemKyberPreKeyStore(),
		bobAddress,
		sr,
	)
	must(aliceBuilder.ProcessBundle(bobBundle))

	// --- Alice encrypts ---

	aliceCipher := session.NewCipher(aliceBuilder, bobAddress)
	ciphertext, err := aliceCipher.Encrypt([]byte("Hello, Bob!"))
	must(err)

	wire, err := ciphertext.Serialize()
	must(err)

	// --- Bob decrypts ---

	bobSessionStore := newInMemSessionStore(sr)
	bobPreKeyStoreFull := newInMemPreKeyStore()
	for _, pk := range bobPreKeys {
		must(bobPreKeyStoreFull.StorePreKey(pk.ID().Value,
			record.NewPreKey(pk.ID().Value, pk.KeyPair(), sr.PreKeyRecord)))
	}
	bobSignedPreKeyStore := newInMemSignedPreKeyStore()
	must(bobSignedPreKeyStore.StoreSignedPreKey(bobSignedPreKey.ID(),
		record.NewSignedPreKey(bobSignedPreKey.ID(), bobSignedPreKey.Timestamp(),
			bobSignedPreKey.KeyPair(), bobSignedPreKey.Signature(), sr.SignedPreKeyRecord)))
	bobKyberStore := newInMemKyberPreKeyStore()
	must(bobKyberStore.StoreKyberPreKey(42, bobKyberPreKey))
	bobIdentityStore := newInMemIdentityKeyStore(bobIdentity, bobRegID)

	bobBuilder := session.NewBuilderWithKyber(
		bobSessionStore,
		bobPreKeyStoreFull,
		bobSignedPreKeyStore,
		bobIdentityStore,
		bobKyberStore,
		aliceAddress,
		sr,
	)

	received, err := protocol.NewPreKeySignalMessageFromBytes(wire, sr.PreKeySignalMessage, sr.SignalMessage)
	must(err)
	deferred, err := bobBuilder.Process(received)
	must(err)
	must(deferred.Complete())

	bobCipher := session.NewCipher(bobBuilder, aliceAddress)
	plaintext, err := bobCipher.Decrypt(received.WhisperMessage())
	must(err)

	if !bytes.Equal(plaintext, []byte("Hello, Bob!")) {
		log.Fatalf("unexpected plaintext: %q", plaintext)
	}
	fmt.Println("Decrypted:", string(plaintext))
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// ---------------------------------------------------------------------------
// Minimal in-memory store implementations (implement the store interfaces).
// In production, back these with a persistent database.
// ---------------------------------------------------------------------------

type inMemSessionStore struct {
	sessions   map[string]*record.Session
	serializer *serialize.Serializer
}

func newInMemSessionStore(sr *serialize.Serializer) *inMemSessionStore {
	return &inMemSessionStore{sessions: make(map[string]*record.Session), serializer: sr}
}

func (s *inMemSessionStore) LoadSession(addr *protocol.SignalAddress) (*record.Session, error) {
	if r, ok := s.sessions[addr.String()]; ok {
		return r, nil
	}
	r := record.NewSession(s.serializer.Session, s.serializer.State)
	s.sessions[addr.String()] = r
	return r, nil
}

func (s *inMemSessionStore) GetSubDeviceSessions(_ string) ([]uint32, error) { return nil, nil }

func (s *inMemSessionStore) StoreSession(addr *protocol.SignalAddress, r *record.Session) error {
	s.sessions[addr.String()] = r
	return nil
}

func (s *inMemSessionStore) ContainsSession(addr *protocol.SignalAddress) (bool, error) {
	_, ok := s.sessions[addr.String()]
	return ok, nil
}

func (s *inMemSessionStore) DeleteSession(addr *protocol.SignalAddress) error {
	delete(s.sessions, addr.String())
	return nil
}

func (s *inMemSessionStore) DeleteAllSessions() error {
	s.sessions = make(map[string]*record.Session)
	return nil
}

var _ store.Session = (*inMemSessionStore)(nil)

type inMemPreKeyStore struct{ m map[uint32]*record.PreKey }

func newInMemPreKeyStore() *inMemPreKeyStore {
	return &inMemPreKeyStore{m: make(map[uint32]*record.PreKey)}
}

func (p *inMemPreKeyStore) LoadPreKey(id uint32) (*record.PreKey, error) { return p.m[id], nil }
func (p *inMemPreKeyStore) StorePreKey(id uint32, r *record.PreKey) error {
	p.m[id] = r
	return nil
}
func (p *inMemPreKeyStore) ContainsPreKey(id uint32) (bool, error) { _, ok := p.m[id]; return ok, nil }
func (p *inMemPreKeyStore) RemovePreKey(id uint32) error           { delete(p.m, id); return nil }

var _ store.PreKey = (*inMemPreKeyStore)(nil)

type inMemSignedPreKeyStore struct{ m map[uint32]*record.SignedPreKey }

func newInMemSignedPreKeyStore() *inMemSignedPreKeyStore {
	return &inMemSignedPreKeyStore{m: make(map[uint32]*record.SignedPreKey)}
}

func (s *inMemSignedPreKeyStore) LoadSignedPreKey(id uint32) (*record.SignedPreKey, error) {
	return s.m[id], nil
}
func (s *inMemSignedPreKeyStore) LoadSignedPreKeys() ([]*record.SignedPreKey, error) {
	var out []*record.SignedPreKey
	for _, v := range s.m {
		out = append(out, v)
	}
	return out, nil
}
func (s *inMemSignedPreKeyStore) StoreSignedPreKey(id uint32, r *record.SignedPreKey) error {
	s.m[id] = r
	return nil
}
func (s *inMemSignedPreKeyStore) ContainsSignedPreKey(id uint32) (bool, error) {
	_, ok := s.m[id]
	return ok, nil
}
func (s *inMemSignedPreKeyStore) RemoveSignedPreKey(id uint32) error {
	delete(s.m, id)
	return nil
}

var _ store.SignedPreKey = (*inMemSignedPreKeyStore)(nil)

type inMemIdentityKeyStore struct {
	trusted    map[string]*identity.Key
	keypair    *identity.KeyPair
	localRegID uint32
}

func newInMemIdentityKeyStore(kp *identity.KeyPair, regID uint32) *inMemIdentityKeyStore {
	return &inMemIdentityKeyStore{trusted: make(map[string]*identity.Key), keypair: kp, localRegID: regID}
}

func (i *inMemIdentityKeyStore) GetIdentityKeyPair() *identity.KeyPair { return i.keypair }
func (i *inMemIdentityKeyStore) GetLocalRegistrationId() uint32         { return i.localRegID }
func (i *inMemIdentityKeyStore) SaveIdentity(addr *protocol.SignalAddress, key *identity.Key) (store.IdentityChange, error) {
	prev, had := i.trusted[addr.String()]
	i.trusted[addr.String()] = key
	if had && prev.Fingerprint() != key.Fingerprint() {
		return store.IdentityChangeReplacedExisting, nil
	}
	return store.IdentityChangeNewOrUnchanged, nil
}
func (i *inMemIdentityKeyStore) IsTrustedIdentity(addr *protocol.SignalAddress, key *identity.Key, _ store.Direction) (bool, error) {
	t := i.trusted[addr.String()]
	return t == nil || t.Fingerprint() == key.Fingerprint(), nil
}
func (i *inMemIdentityKeyStore) GetIdentity(addr *protocol.SignalAddress) (*identity.Key, error) {
	return i.trusted[addr.String()], nil
}

var _ store.IdentityKey = (*inMemIdentityKeyStore)(nil)

type inMemKyberPreKeyStore struct {
	m      map[uint32]*record.KyberPreKey
	marked map[uint32]bool
}

func newInMemKyberPreKeyStore() *inMemKyberPreKeyStore {
	return &inMemKyberPreKeyStore{m: make(map[uint32]*record.KyberPreKey), marked: make(map[uint32]bool)}
}

func (k *inMemKyberPreKeyStore) LoadKyberPreKey(id uint32) (*record.KyberPreKey, error) {
	return k.m[id], nil
}
func (k *inMemKyberPreKeyStore) StoreKyberPreKey(id uint32, r *record.KyberPreKey) error {
	k.m[id] = r
	return nil
}
func (k *inMemKyberPreKeyStore) MarkKyberPreKeyUsed(id uint32, _ uint32, _ ecc.ECPublicKeyable) error {
	k.marked[id] = true
	return nil
}
func (k *inMemKyberPreKeyStore) ContainsKyberPreKey(id uint32) (bool, error) {
	_, ok := k.m[id]
	return ok, nil
}
```

> **Note on the store interfaces.** The in-memory implementations above satisfy `store.Session`, `store.PreKey`, `store.SignedPreKey`, `store.IdentityKey`, and `store.KyberPreKey`. In production, replace them with implementations backed by SQLite, a key-value store, or any persistent layer your application uses. The `KyberPreKeyStore.MarkKyberPreKeyUsed` method should record one-time use to prevent key reuse.

## Feature Matrix

| Component | Package | Status |
|---|---|---|
| **Cryptographic primitives** | | |
| AES-256-GCM-SIV (RFC 8452) | `pkg/cipher` | Implemented |
| HPKE (hybrid public-key encryption) | `pkg/cipher` | Implemented |
| HKDF (RFC 5869) | `pkg/kdf` | Implemented |
| XEdDSA / VXEdDSA signatures | `pkg/ecc` | Implemented |
| Incremental HMAC-SHA256 | `pkg/incrementalmac` | Implemented |
| Kyber-1024 KEM | `pkg/kem` | Implemented |
| ML-KEM-1024 (NIST FIPS 203) | `pkg/kem` | Implemented |
| Argon2id PIN hashing | `pkg/accountkeys` | Implemented |
| **Protocol layers** | | |
| X3DH key agreement | `pkg/session` | Implemented |
| PQXDH (post-quantum X3DH) | `pkg/session` | Implemented |
| Double Ratchet | `pkg/ratchet` | Implemented |
| SPQR (Sparse Post-Quantum Ratchet) | `pkg/spqr` | Implemented |
| ML-KEM Braid SCKA (11-state machine) | `pkg/mlkembraid` | Implemented |
| Triple Ratchet (EC + PQ hybrid) | `pkg/tripleratchet` | Implemented |
| SenderKey group messaging | `pkg/groups` | Implemented |
| Sealed Sender v1 | `pkg/sealed` | Implemented |
| Sealed Sender v2 | `pkg/sealed` | Implemented |
| **Application layer** | | |
| Message backup encryption | `pkg/backup` | Implemented |
| Secure Value Recovery v4 | `pkg/svr` | Implemented |
| Sesame multi-device sessions | `pkg/sesame` | Implemented |
| Safety number fingerprints | `pkg/fingerprint` | Implemented |
| Device transfer (RSA + X.509) | `pkg/devicetransfer` | Implemented |
| Media sanitization (JPEG/PNG/WebP/MP4) | `pkg/media` | Implemented |
| Username generation + ZK proofs | `pkg/usernames` | Implemented |
| **Attestation and networking** | | |
| SGX/DCAP attestation | `pkg/attest` | Implemented |
| Noise NK / NKhfs handshake | `pkg/attest` | Implemented |
| Network layer interfaces | `pkg/net` | Implemented |
| **Zero-knowledge** | | |
| Chase-Perrin-Zaverucha credentials | `pkg/zkcredential` | Implemented |
| ZK groups (auth, profiles, receipts) | `pkg/zkgroup` | Implemented |
| Group send endorsements | `pkg/zkgroup` | Implemented |
| Poksho stateful hash object | `pkg/poksho` | Implemented |
| Key transparency (VRF + Merkle) | `pkg/keytrans` | Implemented |

## Examples

The `examples/` directory (populated after v0.1.0) will contain three
ready-to-run programs:

- **`examples/simple-session`** — minimal Alice↔Bob X3DH/PQXDH session with encrypt and decrypt
- **`examples/sealed-sender`** — anonymous message delivery with Sealed Sender v2
- **`examples/group-messaging`** — SenderKey group session with multiple participants

## Documentation

The `docs/` directory is organized by topic area:

| Directory | Contents |
|---|---|
| `docs/architecture` | Package layout, layering rules, upstream tracing |
| `docs/backup` | Message backup key derivation and frame encryption |
| `docs/credentials` | Zero-knowledge credential issuance and presentation |
| `docs/crypto` | Primitive implementations and wire-format notes |
| `docs/groups` | SenderKey protocol and group session management |
| `docs/identity` | Identity key lifecycle and account key derivation |
| `docs/network` | Attestation, Noise handshakes, and network interfaces |
| `docs/post-quantum` | SPQR, ML-KEM Braid, Triple Ratchet, PQXDH |
| `docs/protocol` | Core message types, ServiceId, and address encoding |
| `docs/sessions` | X3DH session establishment and Double Ratchet |

Single documents:

| File | Contents |
|---|---|
| `docs/FIPS.md` | FIPS 140-3 posture, the `make fips` gate, and its exemption register |

## Architecture

go-libsignal mirrors the package layout of Rust libsignal. Each Go package documents the Rust source it ports in its package-level doc comment. The pinned commit in `/RUST_REV` is the byte-format oracle for every wire-level test; `tests/interop/fixtures/wire/*.json` are Rust-emitted vectors that the Go test suite consumes verbatim. Rust libsignal's tests are the primary correctness oracle; Java libsignal-protocol-java is a secondary oracle for flows not covered by Rust vectors. The library has no CGo dependency — all cryptographic primitives are pure Go, using the standard library (`crypto/mlkem`, `crypto/ecdh`) and the audited third-party libraries listed in the Dependencies section below.

## Building and Testing

```bash
# Build
make build

# Unit tests (race detector on)
make test

# Integration tests
make integration-test

# Verify static interop fixtures against Rust-emitted vectors (no Rust toolchain required)
make interop-fixtures-check

# Live Rust↔Go round-trip tests (requires Rust toolchain or Docker)
make interop-live-build   # compile Rust CLI binary
make interop-live         # run live tests

# Code coverage report
make coverage

# Linting and static analysis
make lint
make security

# Full CI pipeline
make ci
```

> All Makefile targets set `GOWORK=off` automatically to guard against a misconfigured parent workspace.

## Performance

Benchmark baselines for crypto-heavy packages are captured in [bench/baseline.txt](bench/baseline.txt). Run `make bench` to compare against your machine.

Representative results on Intel Core Ultra 9 285K (Go 1.26.3, linux/amd64):

| Benchmark | ns/op | Notes |
|---|---|---|
| `BenchmarkAESGCMSIVEncrypt` | 22 330 ns/op (45.9 MB/s) | 1 KiB plaintext, RFC 8452 |
| `BenchmarkDeriveSecrets` | 961 ns/op | HKDF-SHA256 extract+expand, 64-byte output |
| `BenchmarkGenerateKeyPair` | 53 581 ns/op | X25519 key pair + XEdDSA setup |
| `BenchmarkMLKEM768KeyGen` | 42 890 ns/op | ML-KEM-768 key generation (stdlib crypto/mlkem) |
| `BenchmarkDeserializeAnyPresentationV1` | 48 348 ns/op | ZkGroup AuthCredential deserialization |

## Dependencies

- **filippo.io/edwards25519** — Edwards25519 elliptic curve operations
- **github.com/jeremyhahn/go-enclave** — Locked-memory key storage with mlock, guard pages, and a canary
- **github.com/cloudflare/circl** — Kyber-1024 KEM (post-quantum, pre-FIPS-203 wire format)
- **github.com/flynn/noise** — Noise protocol framework (NK / NKhfs attestation handshakes)
- **github.com/gtank/ristretto255** — Ristretto255 group operations for ZK credentials
- **golang.org/x/crypto** — Argon2id, HKDF, Curve25519, ChaCha20-Poly1305
- **google.golang.org/protobuf** — Protocol Buffers serialization

## Relation to Rust libsignal

This port targets wire-format compatibility with the Rust reference at [signalapp/libsignal](https://github.com/signalapp/libsignal). A few deliberate differences are worth calling out.

### Features present in Go, not in Rust

- **ML-KEM Braid SCKA state machine** (`pkg/mlkembraid`). The Rust protocol crate does not contain a braid implementation; Go ships a complete 11-state machine with streaming `IncrementalKEM` (split `Encaps1`/`Encaps2`).
- **Inline SPQR** (`pkg/spqr`). The Rust reference pulls SPQR from an external `spqr` crate; Go keeps the implementation in-tree and auditable.
- **`go-enclave`-protected secret keys** (`pkg/kem`). Rust relies on `Zeroize` on drop; Go additionally mlocks long-lived key material behind guard pages.
- **AES-GCM-SIV export** and streaming media validators (GIF in addition to Rust's MP4/WebP sanitizer).

### zkgroup credential version policy

| Presentation family | Issuance | Acceptance |
|---|---|---|
| V1 (`ProfileKeyCredentialPresentationV1`) | Not supported | Accepted (legacy interop) |
| V2 (`ProfileKeyCredentialPresentationV2`) | Not supported | Accepted (legacy interop) |
| V3 / V4 (`ExpiringProfileKeyCredentialPresentation`) | Supported | Accepted |

### Architectural differences

- **Synchronous store interfaces.** Rust's stores are `async_trait`s; the Go interfaces under `pkg/state/store` are synchronous. Applications that need concurrency should compose goroutines around store methods.
- **Fingerprint constructor shape.** Rust uses `Fingerprint::new(local, remote)`; Go uses `NewFingerprint`, `NewDisplay`, `DeserializeScannable`.

## Specifications

- [X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/)
- [Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
- [PQXDH Post-Quantum Key Agreement](https://signal.org/docs/specifications/pqxdh/)
- [XEdDSA and VXEdDSA Signatures](https://signal.org/docs/specifications/xeddsa/)
- [ML-KEM Braid Key Exchange](https://signal.org/docs/specifications/mlkem_braid/)
- [Sesame Multi-Device Sessions](https://signal.org/docs/specifications/sesame/)
- [RFC 8452: AES-GCM-SIV Authenticated Encryption](https://tools.ietf.org/html/rfc8452)
- [RFC 5869: HKDF Key Derivation](https://tools.ietf.org/html/rfc5869)

## Project Structure

```
github.com/jeremyhahn/go-libsignal/pkg/
├── accountkeys/           # PIN hashing and account key derivation
├── attest/                # SGX/DCAP attestation and Noise handshakes
├── backup/                # Message backup encryption and key derivation
├── cipher/                # AES-256-GCM-SIV, AES-CTR, HPKE
├── devicetransfer/        # Device-to-device transfer with X.509
├── ecc/                   # Elliptic curve operations (Curve25519, P256)
├── fingerprint/           # Safety number generation
├── groups/                # SenderKey group messaging
├── incrementalmac/        # Streaming HMAC-SHA256
├── kdf/                   # HKDF key derivation
├── kem/                   # Kyber-1024 and ML-KEM-1024 encapsulation
├── keys/                  # Key types (chain, identity, message, prekey, root, session)
├── keytrans/              # Key transparency (VRF, Merkle trees)
├── media/                 # Media sanitization
├── mlkembraid/            # ML-KEM Braid SCKA protocol (11-state machine)
├── net/                   # Network and attestation interfaces
├── poksho/                # Zero-knowledge proofs and SHO
├── protocol/              # Core protocol types and messages
├── ratchet/               # Double Ratchet implementation
├── sealed/                # Sealed Sender v1 and v2
├── serialize/             # Serialization interfaces (JSON, Protobuf)
├── sesame/                # Multi-device session management
├── session/               # Session cipher and builder
├── spqr/                  # Sparse Post-Quantum Ratchet
├── state/                 # Session state storage and records
├── svr/                   # Secure Value Recovery v4
├── tripleratchet/         # EC + PQ hybrid ratcheting
├── usernames/             # Username generation and linking
├── util/                  # Utilities (byte helper, error handling, key generation)
├── zkcredential/          # Anonymous credentials (CPZ)
└── zkgroup/               # Zero-knowledge groups
```

## Security

Vulnerability reports go to [SECURITY.md](SECURITY.md). go-libsignal is a security-critical cryptographic library; please disclose issues responsibly via GitHub Security Advisories rather than public issue trackers. The library enforces constant-time cryptographic operations throughout, mlocks long-lived key material behind go-enclave guard pages, zeroizes intermediate secrets on return, and uses typed errors to avoid leaking implementation details through error strings.

## License

GPL-3.0. See [LICENSE](LICENSE). Note: upstream Rust libsignal is AGPL-3.0; this Go port is GPL-3.0 by the maintainer's choice. Downstream users should review both licenses before adopting.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Credits

See [CREDITS.md](CREDITS.md). Adapted from libsignal-protocol-java (Open Whisper Systems / Signal Messenger, LLC) and Rust libsignal (Signal Messenger, LLC). Signal Protocol design by Moxie Marlinspike and Trevor Perrin.
