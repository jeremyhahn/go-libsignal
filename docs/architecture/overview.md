# Architecture Overview

go-libsignal is a Go port of Signal's Rust `libsignal` reference implementation. It covers X3DH/PQXDH key exchange, Double Ratchet messaging, SenderKey group messaging, Sealed Sender anonymity, post-quantum ratcheting (SPQR/ML-KEM Braid), zero-knowledge credentials, and secure value recovery.

## Layered Architecture

The codebase is organized into five layers, where each layer depends only on layers below it.

### Layer 0: Cryptographic Primitives

Low-level cryptographic operations and memory protection.

| Package | Purpose |
|---------|---------|
| `util/crypto/secret` | locked-memory-backed secret storage (mlock, guard pages) |
| `util/crypto` | Zeroization with `runtime.KeepAlive` to prevent dead-store elimination |
| `cipher` | AES-256-GCM-SIV (RFC 8452), AES-CBC, AES-CTR, HPKE |
| `ecc` | Curve25519 key pairs, XEdDSA/VXEdDSA signing |
| `kem` | Kyber-768/1024 KEM via cloudflare/circl |
| `kdf` | HKDF (RFC 5869) key derivation |
| `crypto/keyops` | Abstract interfaces for signing, key agreement, KEM |
| `crypto/elligator` | Elligator inverse map (constant-time) |
| `poksho` | Zero-knowledge proofs, Stateful Hash Object |

### Layer 1: Protocol Types and Keys

Message formats, identity types, and key derivation structures.

| Package | Purpose |
|---------|---------|
| `protocol` | ServiceId (ACI/PNI), SignalMessage, PreKeySignalMessage, SenderKeyMessage |
| `keys/root` | Root key with ratchet step (HKDF derive) |
| `keys/chain` | Chain key with forward ratchet (HMAC chain) |
| `keys/message` | Per-message encryption keys |
| `keys/identity` | Identity key pairs |
| `keys/prekey` | PreKeyBundle aggregation |
| `keys/session` | Derived secrets from X3DH/PQXDH |
| `serialize` | JSON and Protobuf serialization |
| `proto` | Generated protobuf types |

### Layer 2: Ratcheting and Session Management

Session state machines, ratchet protocols, and persistent storage.

| Package | Purpose |
|---------|---------|
| `ratchet` | X3DH/PQXDH key agreement, Double Ratchet initialization |
| `session` | Session cipher (encrypt/decrypt), session builder |
| `state/record` | Session, PreKey, SignedPreKey, KyberPreKey records |
| `state/store` | Store interfaces (Session, PreKey, IdentityKey, etc.) |
| `groups` | SenderKey group cipher and session builder |
| `groups/ratchet` | SenderKey chain key / message key derivation |
| `groups/state` | SenderKeyRecord, SenderKeyState, SenderKeyStore |
| `spqr` | Sparse Post-Quantum Ratchet (epoch-based PQ forward secrecy) |
| `mlkembraid` | ML-KEM Braid SCKA (13-state machine for PQ key agreement) |
| `tripleratchet` | Triple Ratchet (EC + PQ hybrid, snapshot/restore rollback) |

### Layer 3: Application Protocols

Higher-level protocols built on the session layer.

| Package | Purpose |
|---------|---------|
| `sealed` | Sealed Sender v1 (ECDH + HKDF) and v2 (HPKE-based) |
| `fingerprint` | Safety number fingerprints for identity verification |
| `backup` | Message backup key derivation and frame encryption |
| `svr` | Secure Value Recovery v4 (threshold secret sharing) |
| `accountkeys` | Argon2id PIN hashing, registration lock |
| `devicetransfer` | RSA key generation, X.509 self-signed certificates |
| `incrementalmac` | Streaming chained HMAC-SHA256 for large payloads |
| `media` | Media sanitization (JPEG, PNG, WebP, MP4 structure validation) |
| `sesame` | Sesame multi-device session management |

### Layer 4: Identity and Credentials

Zero-knowledge credential systems and identity management.

| Package | Purpose |
|---------|---------|
| `zkcredential` | Anonymous credentials (Chase-Perrin-Zaverucha scheme) |
| `zkgroup` | ZK groups, auth credentials, profile credentials, receipts |
| `usernames` | Username generation, hashing, encrypted username links |
| `keytrans` | Key transparency: VRF proofs, Merkle tree verification |
| `attest` | SGX/DCAP remote attestation, Noise NK handshake |
| `net` | Network layer (CDSi, SVR, chat, WebSocket interfaces) |

## Package Dependency Graph

Dependencies flow bottom-up. Key dependency chains:

```
session.Cipher
  -> state/record.Session (session state)
  -> ratchet (X3DH/PQXDH + Double Ratchet init)
     -> keys/root, keys/chain, keys/message (key derivation)
        -> kdf (HKDF)
        -> ecc (Curve25519)
        -> kem (Kyber)
           -> util/crypto/secret (go-enclave)

sealed.SealedSenderEncrypt
  -> session.Cipher (inner encryption)
  -> ecc (ephemeral ECDH)
  -> kdf (HKDF key derivation)
  -> cipher (AES-CTR + HMAC)

spqr.SPQR
  -> mlkembraid.Braid (PQ key agreement)
  -> util/crypto/secret (epoch chain keys)
```

## Session Lifecycle

A typical 1:1 messaging session follows this flow:

1. **Key bundle fetch**: The sender fetches the recipient's PreKeyBundle (identity key, signed pre-key, one-time pre-key, Kyber pre-key).

2. **Session setup** (`session.Builder.Process`): Runs PQXDH key agreement via `ratchet.CalculateSenderSession`, derives root key + chain keys + initial PQ ratchet key, stores the new session in `state/store.Session`.

3. **First message** (`session.Cipher.Encrypt`): Produces a `PreKeySignalMessage` containing the sender's base key, identity key, and Kyber ciphertext. The recipient uses this to run `ratchet.CalculateReceiverSession` and establish their side.

4. **Subsequent messages** (`session.Cipher.Encrypt/Decrypt`): The Double Ratchet advances chain keys on each message. When the sender ratchets, a new EC key pair is generated and a DH ratchet step derives new root and chain keys.

5. **PQ ratcheting** (when SPQR is active): The SPQR piggybacks ML-KEM Braid chunks on each message. When a full Braid round completes, the SPQR advances to a new epoch, deriving fresh chain keys from the Braid output.

## Store Interface Pattern

The library defines storage as Go interfaces in `state/store/`. Callers provide their own implementations (SQLite, in-memory, etc.). The core store interfaces are:

- `store.Session` -- load, store, and query session records
- `store.PreKey` -- one-time pre-key storage
- `store.SignedPreKey` -- signed pre-key storage
- `store.KyberPreKey` -- Kyber pre-key storage (for PQXDH)
- `store.IdentityKey` -- identity key pair and trusted identity storage
- `store.SenderKey` -- SenderKey records for group messaging
- `store.SignalProtocol` -- composite interface combining all stores

Sessions are loaded, mutated in memory, then stored back. The library does not manage persistence or locking. The store implementation handles those.

## Serialization

Two serialization backends are provided:

- `serialize.JSONSerializer` -- human-readable, used primarily in tests
- `serialize.ProtobufSerializer` -- compact binary, used in production

Both implement the same set of serializer interfaces (`SessionSerializer`, `StateSerializer`, `SignalMessageSerializer`, etc.). The `serialize.Serializer` struct bundles all serializers together and is passed to session builders and ciphers.

## Constants

Key protocol constants (from the Rust reference):

| Constant | Value | Location |
|----------|-------|----------|
| `CurrentVersion` | 4 | `state/record` |
| `MAX_MESSAGE_KEYS` | 2000 | `state/record` |
| `MAX_RECEIVER_CHAINS` | 5 | `state/record` |
| `ARCHIVED_STATES_MAX` | 40 | `state/record` |
| `MAX_FORWARD_JUMPS` | 25000 | `session` |
| `MAX_SENDER_KEY_STATES` | 5 | `groups/state/record` |
| `MAC_LENGTH` | 8 | `protocol` |
| `DerivedSecretsSize` | 96 | `keys/session` (RootKey + ChainKey + InitialPQRKey) |

## External Dependencies

| Dependency | Used For |
|------------|----------|
| `filippo.io/edwards25519` | Edwards25519 point arithmetic |
| `github.com/jeremyhahn/go-enclave` | mlock'd memory, guard pages, canary; zeroizes on destruction |
| `github.com/cloudflare/circl` | Kyber-768/1024 KEM (round-3 kyber, not NIST ML-KEM) |
| `github.com/flynn/noise` | Noise NK handshake for attestation channels |
| `github.com/gtank/ristretto255` | Ristretto255 group for ZK credentials |
| `golang.org/x/crypto` | Argon2id, HKDF, curve25519, nacl |
| `google.golang.org/protobuf` | Protocol buffer serialization |
