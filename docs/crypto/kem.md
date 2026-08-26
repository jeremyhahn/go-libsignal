# Post-Quantum Key Encapsulation Mechanisms

Package `kem/` provides lattice-based Key Encapsulation Mechanisms (KEMs) for post-quantum key exchange in the Signal Protocol. The package supports Kyber-1024 and Kyber-768 (round-3), with both plain and locked-memory-protected variants. Source files are in `/kem/`.

## Algorithm Variants

### Kyber-1024

**File:** `kyber.go`

Used for PQXDH key exchange (the post-quantum extension of X3DH). Backed by `cloudflare/circl`'s `kem/kyber/kyber1024` package.

Type identifier: `KeyTypeKyber1024 = 0x08`

### Kyber-768 (labeled as ML-KEM-768)

**File:** `mlkem768.go`

Despite the type name `MLKEM768KEM`, this implementation uses round-3 Kyber-768 from `cloudflare/circl`'s `kem/kyber/kyber768`, NOT the NIST-final ML-KEM-768 standard. This matches the Rust reference implementation which uses `libcrux_ml_kem::kyber768`. The distinction matters because round-3 Kyber and final ML-KEM differ in hash function usage and are not interoperable.

Type identifier: `KeyTypeKyber768 = 0x07`

### ML-KEM-1024

Type identifier: `KeyTypeMLKEM1024 = 0x0A`

Shares key sizes with Kyber-1024 (public key: 1568 bytes, secret key: 3168 bytes, ciphertext: 1568 bytes).

## Key Sizes

| Algorithm | Public Key | Secret Key | Ciphertext | Shared Secret |
|-----------|-----------|------------|------------|---------------|
| Kyber-768 | 1184 bytes | 2400 bytes | 1088 bytes | 32 bytes |
| Kyber-1024 | 1568 bytes | 3168 bytes | 1568 bytes | 32 bytes |

All serialized forms include a 1-byte type prefix: `[type_byte] || raw_data`.

## Core Types

### KEM Interface

```go
type KEM interface {
    KeyType() KeyType
    Generate() (*KeyPair, error)
    Encapsulate(publicKey *PublicKey) (*SharedSecret, *Ciphertext, error)
    Decapsulate(secretKey *SecretKey, ciphertext *Ciphertext) (*SharedSecret, error)
}
```

Implementations: `Kyber1024KEM`, `MLKEM768KEM`.

### Data Types

**`PublicKey`** -- holds key type and raw key data. Created via `NewPublicKey(keyType, data)` or `DeserializePublicKey(serialized)`. `Data()` returns a defensive copy.

**`SecretKey`** -- holds key type and raw key data. Created via `NewSecretKey(keyType, data)` with length validation against `expectedSecretKeySize`. `Data()` returns a defensive copy.

**`Ciphertext`** -- holds key type and raw encapsulated data. Created via `NewCiphertext(keyType, data)` or `DeserializeCiphertext(serialized)`.

**`SharedSecret`** -- `[32]byte` typedef. The output of encapsulation and decapsulation.

**`KeyPair`** -- holds `Public *PublicKey` and `Secret *SecretKey`.

## Encapsulation Flow

```
Sender                              Recipient
------                              ---------
                                    kp, _ := kem.Generate()
                                    // send kp.Public to sender

ss, ct, _ := kem.Encapsulate(pk)
// send ct to recipient
                                    ss, _ := kem.Decapsulate(kp.Secret, ct)
// ss is now shared                 // ss is now shared
```

Both `Encapsulate` and `Decapsulate` validate that the key types match the expected algorithm (`KeyTypeMismatchError` on mismatch).

---

## Guarded KEM Types

**File:** `guarded_kem.go`, `guarded_secret.go`

For production use, secret keys and shared secrets should be stored in locked memory.

### GuardedSecretKey

Wraps a `secret.Secret` (variable-length mlock'd buffer). Created via:

- `NewGuardedSecretKey(keyType KeyType, data []byte)` -- moves data into guarded memory, source slice is zeroized
- `NewGuardedSecretKeyFromSecret(keyType KeyType, s *secret.Secret)` -- takes ownership of existing Secret

Methods:
- `Data() []byte` -- returns a view into guarded memory (must not be retained)
- `Destroy()` -- zeroizes and frees guarded memory (idempotent)
- `IsDestroyed() bool`
- `Clone() (*GuardedSecretKey, error)` -- deep copy into new guarded memory
- `Decapsulate(ciphertext []byte) (*secret.Secret32, error)` -- implements `keyops.Decapsulator`
- `DecapsulateGuarded(ciphertext []byte) (*GuardedSharedSecret, error)` -- returns richer type

The `Decapsulate` method on `GuardedSecretKey` deserializes the ciphertext (extracting the type byte), dispatches to the appropriate guarded KEM implementation, and returns the shared secret. It accepts raw serialized ciphertext bytes (with type prefix).

### GuardedSharedSecret

Wraps a `secret.Secret32` (32-byte mlock'd buffer). Created via:

- `NewGuardedSharedSecret(data [32]byte)` -- source array is zeroized
- `NewGuardedSharedSecretFromSlice(data []byte)` -- must be exactly 32 bytes, source is zeroized
- `NewGuardedSharedSecretFromSecret32(s *secret.Secret32)` -- takes ownership

Methods:
- `Bytes() []byte` -- view into guarded memory
- `Array() [32]byte` -- copy (caller must zeroize)
- `Destroy()` -- idempotent
- `Secret32() *secret.Secret32` -- access underlying Secret32

### Guarded KEM Operations

`GuardedKyber768` and `GuardedKyber1024` mirror the `KEM` interface but use guarded types:

```go
type GuardedKyber768 struct{}

func (g *GuardedKyber768) Generate() (*GuardedKeyPair, error)
func (g *GuardedKyber768) Encapsulate(publicKey *PublicKey) (*GuardedSharedSecret, *Ciphertext, error)
func (g *GuardedKyber768) Decapsulate(secretKey *GuardedSecretKey, ciphertext *Ciphertext) (*GuardedSharedSecret, error)
```

All guarded constructors return a `GuardedKeyAllocationError` on locked-memory allocation failure.

### GuardedKeyPair

Holds a `*PublicKey` and `*GuardedSecretKey`. The `Destroy()` method zeroizes only the secret key (public keys are not sensitive).

---

## Error Types

| Error | Condition |
|-------|-----------|
| `ErrInvalidKeyType` | Unrecognized key type byte |
| `ErrEmptyInput` | Input is empty or too short for deserialization |
| `ErrKeyTypeMismatch` | Key type does not match expected algorithm |
| `BadKeyLengthError` | Serialized key/ciphertext has wrong length |
| `UnsupportedKeyTypeError` | Operation not supported for key type |
| `KeyGenError` | Key generation failure |
| `MarshalError` | Key serialization failure |
| `UnmarshalError` | Key deserialization failure |
| `EncapsulationError` | Encapsulation failure |
| `DecapsulationError` | Decapsulation failure |
| `GuardedKeyAllocationError` | locked-memory allocation failure |
| `GuardedKeyDestroyedError` | Operation on destroyed guarded key |
| `DeserializeError` | Ciphertext deserialization failure |

All error types implement `error`. Wrapping errors (`KeyGenError`, `MarshalError`, etc.) implement `Unwrap() error` for `errors.Is`/`errors.As` chains.
