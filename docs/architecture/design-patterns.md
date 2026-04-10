# Design Patterns

This document covers the major design patterns used throughout go-libsignal.

## Guarded Keys with memguard

Private key material is stored in mlock'd, guard-page-protected memory via the `github.com/awnumar/memguard` library. memguard prevents keys from being paged to swap, places guard pages around buffers to catch overflows, and zeroizes memory on destruction.

### The secret Package

`util/crypto/secret` wraps memguard's `LockedBuffer` in two types:

- `secret.Secret` -- variable-length guarded buffer for KEM secret keys and other non-32-byte secrets
- `secret.Secret32` -- fixed 32-byte specialization for EC private keys, chain keys, root keys, shared secrets, and HMAC keys

Both types provide:

- `Bytes()` -- returns a view into guarded memory (must not outlive the Secret)
- `Destroy()` -- zeroizes and frees the buffer (idempotent)
- `Clone()` -- deep copy into new guarded memory
- `EqualTo()` -- constant-time comparison
- `Freeze()` / `Melt()` -- toggle read-only protection (write attempts segfault)
- `Seal()` / `OpenEnclave()` -- encrypt at rest in a memguard Enclave

### Move Semantics

`secret.New(data)` zeroizes the source slice when moving data into guarded memory. After calling `New`, the caller's original slice contains zeros. If the caller needs to retain the data, they must copy it first.

```go
// source is zeroized after this call
s, err := secret.New(sourceSlice)

// If you need to keep sourceSlice:
tmp := make([]byte, len(sourceSlice))
copy(tmp, sourceSlice)
s, err := secret.New(tmp)
```

### Guarded Key Types

The `ecc` and `kem` packages build on `secret.Secret32` and `secret.Secret`:

**`ecc.GuardedECPrivateKey`** wraps a `secret.Secret32` and implements:
- `ECPrivateKeyable` -- backward compatibility with the original key interface
- `keyops.Signer` -- XEdDSA signing without exposing raw bytes
- `keyops.VRFSigner` -- VXEdDSA for key transparency
- `keyops.KeyAgreement` -- X25519 DH returning a guarded `Secret32`
- `keyops.PrivateKey` -- composite of Signer + KeyAgreement

**`kem.GuardedSecretKey`** wraps a `secret.Secret` and implements:
- `keyops.Decapsulator` -- Kyber decapsulation returning a guarded `Secret32`

**`kem.GuardedSharedSecret`** wraps a `secret.Secret32` for KEM shared secrets.

### Key Pair Generation

`ecc.GenerateGuardedKeyPair()` generates a Curve25519 key pair where the private key never exists outside guarded memory (except briefly during clamping, which is zeroized immediately):

1. Generate 32 random bytes
2. Apply Curve25519 clamping
3. Derive public key via `ScalarBaseMult`
4. Move private key into guarded memory (source array zeroized)
5. Return `GuardedECKeyPair{public, private}`

### Panic Recovery

All guarded key constructors use `defer/recover` to catch memguard panics (e.g., mlock failures on systems with low `RLIMIT_MEMLOCK`) and convert them to typed errors:

```go
func NewGuardedECPrivateKey(data [32]byte) (k *GuardedECPrivateKey, err error) {
    defer func() {
        if r := recover(); r != nil {
            k = nil
            err = &ErrGuardedKeyAllocation{...}
        }
    }()
    s, sErr := secret.NewSecret32(data)
    // ...
}
```

## keyops Interfaces

The `crypto/keyops` package defines interfaces for cryptographic operations, separating the operation (sign, agree, decapsulate) from the backing implementation (software memguard, HSM, secure enclave).

| Interface | Methods | Used By |
|-----------|---------|---------|
| `keyops.Signer` | `Sign`, `PublicKey`, `Destroy` | EC signing |
| `keyops.VRFSigner` | extends Signer with `VRFSign` | Key transparency |
| `keyops.KeyAgreement` | `Agreement`, `PublicKey`, `Destroy` | X25519 DH |
| `keyops.PrivateKey` | combines Signer + KeyAgreement | EC private keys |
| `keyops.Decapsulator` | `Decapsulate`, `Destroy` | KEM secret keys |
| `keyops.Encapsulator` | `Encapsulate` | KEM public keys |

Software implementations (`ecc.GuardedECPrivateKey`, `kem.GuardedSecretKey`) back these interfaces with memguard. Hardware implementations can implement the same interfaces, delegating to HSM or secure enclave APIs.

## Snapshot/Restore for Rollback

Decrypt operations are speculative: the ratchet state is advanced before the message is authenticated. If authentication fails, the state must be rolled back. Two patterns handle this.

### Clone-Based Rollback (Session State)

`state/record.State.Clone()` creates a deep copy by serializing and deserializing through the state's serializer. `CopyFrom()` commits a successfully-modified clone back to the original:

```go
// In session.Cipher.Decrypt:
clone, err := sessionState.Clone()
// ... advance ratchet on clone, decrypt, verify MAC ...
// On success:
sessionState.CopyFrom(clone)
// On failure:
// clone is discarded, original state unchanged
```

### Interface-Based Rollback (Triple Ratchet)

The `tripleratchet` package defines `ECCipherSnapshotable`:

```go
type ECCipherSnapshotable interface {
    TakeECSnapshot() ([]byte, error)
    RestoreECSnapshot(data []byte) error
}
```

Before decryption, the Triple Ratchet checks if its EC cipher implements this interface. If so, it takes a snapshot, attempts the decrypt, and restores on failure. This prevents a forged message from permanently advancing the receive chain.

### Session-Level Deep Copy

`state/record.Session.Copy()` creates a deep copy of the entire session record (current state plus all previous states) by cloning each state independently. This is used when the caller needs to speculatively modify a session without affecting the stored version.

## Typed Errors

All error types are declared as structs or sentinel `var` values. The codebase does not use `fmt.Errorf` or `errors.New` inline. Callers match errors with `errors.Is` (for sentinels) or `errors.As` (for typed structs).

### Sentinel Errors

For cases where no additional context is needed:

```go
var ErrGuardedKeyDestroyed = errors.New("ecc: guarded key has been destroyed")
var ErrSignFailed = errors.New("ecc: XEdDSA sign operation failed")
```

### Typed Error Structs

For errors that carry context (wrapped causes, operation names, key types):

```go
type ErrGuardedKeyAllocation struct {
    Operation string
    Err       error
}

func (e *ErrGuardedKeyAllocation) Error() string {
    return fmt.Sprintf("ecc: %s failed: %v", e.Operation, e.Err)
}

func (e *ErrGuardedKeyAllocation) Unwrap() error {
    return e.Err
}
```

Every typed error struct implements `Unwrap() error` for `errors.As`/`errors.Is` chain traversal. Error messages never leak sensitive data (key bytes, plaintext, shared secrets).

### Package-Level Error Files

Each package has an `errors.go` file that centralizes all error declarations for that package.

## Clone-on-Read Store Semantics

The store interfaces (`state/store`) return records by value or by deep copy. The session layer never holds references to store-owned memory:

1. **Load**: `store.Session.LoadSession(address)` returns a `*record.Session`
2. **Clone/Mutate**: The session cipher clones the state before speculative operations
3. **Store**: `store.Session.StoreSession(address, session)` persists the final state

The library does not manage locking or transactions. Store implementations handle concurrent access (e.g., database-level locking or per-address mutexes).

## Session State Archival

Sessions maintain a current state and up to 40 previous states (`archivedStatesMaxLength`). When a new session is established on an existing record:

1. The current state's pending pre-key is cleared
2. The current state is prepended to `previousStates`
3. The new state becomes current
4. If `previousStates` exceeds 40, the oldest is dropped

When a message arrives for a previous state, that state is promoted to current (`PromoteOldSession`). The previous entry is removed first to prevent duplicates, then the promotion follows the same archive flow.

## Constant-Time Base Key Comparison

`Session.HasSessionState()` uses `subtle.ConstantTimeCompare` when comparing sender base keys to prevent timing side channels that could leak session identity information.

## Protocol Versioning

Session states carry a version number (`CurrentVersion = 4`). Version 3 is `PreKyberVersion`, used for sessions that predate PQXDH. The derived secrets size is 96 bytes: 32 for root key + 32 for chain key + 32 for initial PQ ratchet key. Pre-Kyber sessions derive only 64 bytes (no PQR key).

## SPQR Version Negotiation

The Sparse Post-Quantum Ratchet uses a two-phase version negotiation:

1. **Pending**: New sessions start with `negotiationPending`. The SPQR sends empty PQR messages and holds the initial PQR key in `authKey`.
2. **Resolved**: On first received message, the negotiation resolves to V0 (PQR disabled, `authKey` discarded) or V1 (PQR enabled, `authKey` used to initialize the epoch chain).

This maintains backward compatibility with peers that do not support post-quantum ratcheting.

## Bounded Deserialization

SPQR enforces deserialization limits to prevent memory exhaustion from malformed state:
- Maximum 100 epoch chains
- Maximum 5000 skipped message keys
- Amortized garbage collection with `trimSize = 2201` (110% of max + 1)

A corrupted or adversarial serialized state cannot cause unbounded memory allocation.

## Zeroization Strategy

Stack-local copies of key material use `defer` for cleanup:

```go
var secret [32]byte
defer crypto.ZeroizeArray32(&secret)
```

`crypto.Zeroize` uses `runtime.KeepAlive` to prevent the Go compiler from optimizing away the zero-writes as dead stores. Variants: `Zeroize([]byte)`, `ZeroizeArray32(*[32]byte)`, `ZeroizeArray64(*[64]byte)`.

For heap-allocated secrets, `secret.Secret.Destroy()` delegates to memguard's `LockedBuffer.Destroy()`, which uses platform-specific secure zeroization (memset_s or explicit_bzero where available).
