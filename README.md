# go-libsignal

[![Go Reference](https://pkg.go.dev/badge/github.com/jeremyhahn/go-libsignal)](https://pkg.go.dev/github.com/jeremyhahn/go-libsignal)
[![Go Report Card](https://goreportcard.com/badge/github.com/jeremyhahn/go-libsignal)](https://goreportcard.com/report/github.com/jeremyhahn/go-libsignal)
[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](https://www.gnu.org/licenses/gpl-3.0.html)

A pure Go implementation of the Signal Protocol, originally ported from the Java libsignal-protocol-java implementation and extended with post-quantum cryptography, zero-knowledge credentials, and modern security features using the Rust libsignal as a reference for correctness. Provides end-to-end encryption with X3DH, Double Ratchet, SenderKey groups, Sealed Sender, PQXDH (ML-KEM-1024), zero-knowledge credentials, and secure value recovery.

## Features

### Core Protocol
- X3DH (Extended Triple Diffie-Hellman) key agreement
- Double Ratchet symmetric-key ratcheting
- SenderKey group messaging protocol
- SignalMessage and PreKeySignalMessage serialization
- ServiceId and PNI (Phone Number Identity) support
- Sealed Sender v1 (anonymous delivery)
- Sealed Sender v2 (with support for explicit sender identities)

### Post-Quantum Cryptography
- PQXDH (Post-Quantum X3DH) key agreement
- Kyber-1024 KEM (Cloudflare circl implementation)
- ML-KEM-1024 (NIST FIPS 203) via Go stdlib
- Post-Quantum Noise NKhfs handshake
- SPQR (Sparse Post-Quantum Ratchet) with epoch-based key management
- ML-KEM Braid (13-state SCKA protocol for post-quantum session establishment)
- Triple Ratchet (hybrid EC + PQ state machine)

### Zero-Knowledge & Credentials
- Chase-Perrin-Zaverucha anonymous credentials
- ZK groups (authentication, profiles, receipts)
- Group send endorsements with privacy
- Poksho stateful hash-based zero-knowledge proofs
- Username hashing and ZK proofs
- Profile credential issuance and validation

### Security Infrastructure
- AES-256-GCM-SIV (RFC 8452) authenticated encryption
- memguard-protected key material
- Constant-time cryptographic operations
- XEdDSA and VXEdDSA signature schemes
- Key transparency with VRF and Merkle trees
- Secure Value Recovery v4 (encrypted key backup)
- Message backup encryption with forward secrecy
- Device transfer with RSA and X.509 certificates

### Additional Capabilities
- Fingerprint and safety number generation
- SGX/DCAP attestation with Noise NK/NKhfs
- Media sanitization (JPEG, PNG, WebP, MP4)
- Incremental MAC for streaming validation
- Username generation and linking
- Account key derivation and PIN management

## Installation

```bash
go get github.com/jeremyhahn/go-libsignal
```

## Quick Start

### Basic Session Setup

```go
package main

import (
    "log"

    "github.com/jeremyhahn/go-libsignal/pkg/protocol"
    "github.com/jeremyhahn/go-libsignal/pkg/session"
    "github.com/jeremyhahn/go-libsignal/pkg/util/keyhelper"
)

func main() {
    // Generate identity keypair
    identityKeyPair, err := keyhelper.GenerateIdentityKeyPair()
    if err != nil {
        log.Fatal(err)
    }

    // Generate registration ID
    registrationID := keyhelper.GenerateRegistrationID(false)

    // Create identity store (implement the store.IdentityKeyStore interface)
    identityStore := NewInMemoryIdentityKeyStore(identityKeyPair, registrationID)

    // Create session store (implement the store.SessionStore interface)
    sessionStore := NewInMemorySessionStore()

    // Build a session with a remote peer
    address := protocol.NewSignalAddress("alice", 1)
    builder := session.NewBuilder(
        sessionStore,
        nil, // preKeyStore
        nil, // signedPreKeyStore
        identityStore,
        address,
        nil, // serializer
    )

    // Process a pre-key bundle from the remote peer
    // (In production, retrieve this from your server)
    // err = builder.ProcessBundle(remotePreKeyBundle)

    // Encrypt a message
    cipher := session.NewCipher(builder, address)
    ciphertext, err := cipher.Encrypt([]byte("Hello, Signal!"))
    if err != nil {
        log.Fatal(err)
    }

    // Send ciphertext over the network
    _ = ciphertext
}
```

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
├── logger/                # Logging interface
├── media/                 # Media sanitization
├── mlkembraid/            # ML-KEM Braid SCKA protocol
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

## Development

### Build
```bash
make build
```

### Testing
```bash
# Run all tests
make test

# Run tests with verbose output
make test-verbose

# Run integration tests
make integration-test

# Test a specific package
make test-pkg/session
```

### Code Coverage
```bash
# Generate coverage report for all packages
make coverage

# Coverage for a specific package
make coverage-pkg/cipher
```

### Linting & Static Analysis
```bash
# Run go vet
make vet

# Run golangci-lint
make lint

# Run security scanners
make security
```

### Full CI Pipeline
```bash
make ci
```

### Cleanup
```bash
make clean
```

## Security

This library implements security-critical cryptography and provides multiple layers of protection:

- **Memguard Integration**: All long-lived key material is protected with memory guards via the memguard library, preventing accidental key exposure in memory dumps or swaps.

- **Constant-Time Operations**: Cryptographic operations use constant-time implementations to prevent timing side-channels. This includes elliptic curve operations, key agreement, and signature verification.

- **Key Zeroization**: Sensitive intermediate values are explicitly zeroized with `crypto.Zeroize()` and `defer` statements to prevent key recovery through memory inspection.

- **Typed Errors**: All errors are defined as typed structs rather than formatted strings, enabling robust error handling and avoiding information leakage through error messages.

- **Reference Implementation**: The core protocol was originally ported from Java libsignal-protocol-java. Post-quantum extensions, zero-knowledge credentials, and modern features were implemented using the Rust libsignal as a reference for correctness.

**Important**: While this library implements the Signal Protocol correctly, security of the overall system also depends on proper integration, key management, and network security. Always review the security implications of your use case and consider professional security review for production deployments.

## Specifications

The implementation is based on the following specifications and RFCs:

- [X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/)
- [Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
- [PQXDH Post-Quantum Key Agreement](https://signal.org/docs/specifications/pqxdh/)
- [XEdDSA and VXEdDSA Signatures](https://signal.org/docs/specifications/xeddsa/)
- [ML-KEM Braid Key Exchange](https://signal.org/docs/specifications/mlkem_braid/)
- [Sesame Multi-Device Sessions](https://signal.org/docs/specifications/sesame/)
- [RFC 8452: AES-GCM-SIV Authenticated Encryption](https://tools.ietf.org/html/rfc8452)
- [RFC 5869: HKDF Key Derivation](https://tools.ietf.org/html/rfc5869)

For additional reference materials, see the `docs/references/` directory.

## Dependencies

- **filippo.io/edwards25519** — Edwards25519 elliptic curve operations
- **github.com/awnumar/memguard** — Memory-guarded key storage
- **github.com/cloudflare/circl** — Kyber-1024 KEM (post-quantum)
- **github.com/flynn/noise** — Noise protocol framework
- **github.com/gtank/ristretto255** — Ristretto255 group operations
- **golang.org/x/crypto** — Argon2id, HKDF, curve25519, ChaCha20-Poly1305
- **google.golang.org/protobuf** — Protocol Buffers serialization

## License

Licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.

## Credits

**Signal Protocol Design**: Moxie Marlinspike and Trevor Perrin

**Original Java Implementation**: [libsignal-protocol-java](https://github.com/signalapp/libsignal-protocol-java) by Open Whisper Systems / Signal Messenger, LLC

**Original Go Port**: William Edwards and Eric Hernandez (libsignal-protocol-go)

**This Implementation**: Extended and hardened by Jeremy Hahn with post-quantum cryptography, zero-knowledge credentials, memguard key protection, and modern features using the [Rust libsignal](https://github.com/signalapp/libsignal) as a reference for correctness.
