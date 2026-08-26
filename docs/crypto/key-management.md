# Key Derivation and Memory Protection

This document covers key derivation via HKDF, the zeroization strategy for sensitive material, locked-memory integration (go-enclave) through the `secret` package, and the incremental MAC scheme for streaming integrity verification.

## HKDF Key Derivation

**File:** `kdf/HKDF.go`

The `kdf` package provides HKDF (HMAC-based Key Derivation Function) using SHA-256, built on `golang.org/x/crypto/hkdf`.

### DeriveSecrets

```go
func DeriveSecrets(inputKeyMaterial, salt, info []byte, outputLength int) ([]byte, error)
```

Derives `outputLength` bytes from the given input key material, salt, and info string. Uses `io.ReadFull` to read exactly the requested number of bytes from the HKDF reader. Returns `ErrShortRead` if fewer bytes are produced than requested (should not happen in practice given HKDF's output capacity of `255 * HashLen`).

All key derivation in the protocol flows through this function: root keys, chain keys, message keys, sealed sender keys, and backup encryption keys.

### CalculateSharedSecret

```go
func CalculateSharedSecret(theirKey, ourKey [32]byte) ([32]byte, error)
```

Performs X25519 Diffie-Hellman key agreement. Both input key arrays are zeroized via `defer crypto.ZeroizeArray32()` after use. The result is validated:

1. `curve25519.X25519` rejects low-order points (returns error, wrapped as `ErrLowOrderPoint`)
2. All-zero shared secrets are rejected in constant time via `subtle.ConstantTimeCompare` (returns `ErrAllZeroSharedSecret`)
3. The intermediate `result` slice is zeroized after copying into the return array

### KeyMaterial

```go
type KeyMaterial struct {
    CipherKey []byte
    MacKey    []byte
    IV        []byte
}
```

Holds derived key material split into cipher key, MAC key, and IV. Populated by callers after `DeriveSecrets` returns the raw byte output.

---

## Zeroization Strategy

**File:** `util/crypto/zeroize.go`

### Functions

```go
func Zeroize(b []byte)
func ZeroizeArray32(b *[32]byte)
func ZeroizeArray64(b *[64]byte)
```

Each function overwrites the input with zeros and calls `runtime.KeepAlive` on the buffer to prevent the Go compiler from eliminating the stores as dead writes. Without `runtime.KeepAlive`, the compiler may observe that the zeroed buffer is never read again and optimize away the zeroization.

### Usage Pattern

Zeroization is applied through `defer` statements immediately after sensitive material is created:

```go
privateKey := key.Serialize()
defer crypto.Zeroize(privateKey[:])

var random [64]byte
defer crypto.Zeroize(random[:])
```

This pattern appears throughout the codebase for:
- Private key copies extracted from guarded storage for signing or key agreement
- Random nonces used in XEdDSA/VXEdDSA signing
- Intermediate derived keys (POLYVAL hash keys, AES encryption keys)
- DH shared secrets before they are moved into guarded memory
- Stack-local `[32]byte` copies of key material (using `ZeroizeArray32`)

### Limitations

`runtime.KeepAlive` prevents the compiler from removing the zero-write loop, but it does not prevent the operating system from copying the page to swap. For secrets that must also be protected from swap, use `secret.Secret` or `secret.Secret32` which rely on `mlock(2)`.

---

## Locked-Memory Integration (secret package)

**File:** `util/crypto/secret/secret.go`, `util/crypto/secret/secret32.go`

The `secret` package wraps `github.com/jeremyhahn/go-enclave`, the portfolio locked-memory primitive, to provide secure storage for cryptographic key material.

### Memory Protections

Secrets stored via this package receive:

- **mlock**: pages are locked in RAM, preventing swap to disk
- **Guard pages**: placed before and after the allocation to detect buffer overflows
- **Canary values**: detect corruption
- **Zeroization on destroy**: memory is overwritten with zeros when `Destroy()` is called

### Secret (variable-length)

```go
func New(data []byte) (*Secret, error)          // move into a frozen (read-only) enclave; source slice is zeroized
func NewRandom(size int) (*Secret, error)        // cryptographically random, returned frozen (read-only)
func NewEmpty(size int) (*Secret, error)          // writable zero-initialized buffer, filled in place
```

`New` is the primary constructor. It moves the input data into a frozen (read-only) locked enclave and zeroizes the source slice. After calling `New(data)`, the original `data` slice contains all zeros.

If the source must survive, copy it first:

```go
k := make([]byte, len(original))
copy(k, original)
s, err := secret.New(k)  // k is now zeroed; original is untouched
```

Methods:
- `Bytes() []byte` -- returns a view into guarded memory (panics if destroyed)
- `Size() int` -- returns 0 if destroyed
- `Destroy()` -- idempotent, zeroizes and frees
- `IsDestroyed() bool`
- `Clone() (*Secret, error)` -- independent deep copy in new guarded memory
- `EqualTo(other []byte) bool` -- constant-time comparison

### Secret32 (fixed 32 bytes)

Optimized for the most common key size in the Signal Protocol: EC private keys, chain keys, root keys, shared secrets, and HMAC keys.

```go
func NewSecret32(data [32]byte) (*Secret32, error)         // zeroizes source array
func NewSecret32FromSlice(data []byte) (*Secret32, error)   // validates len == 32
func NewSecret32Random() (*Secret32, error)                 // random
```

Methods beyond `Secret`:
- `Array() [32]byte` -- returns a copy (caller must zeroize)
- `Ptr() *[32]byte` -- returns a pointer aliasing the locked memory (panics if destroyed)

### At-Rest Encryption

This layer does not provide at-rest encryption. go-enclave holds key material as plaintext in locked memory; guard pages and a canary protect it, and the memory is zeroized on destruction.

### Allocation Failure

On allocation failure the constructors return a typed `secret.Error` (kind `ErrSecretAlloc`) rather than panicking or calling `os.Exit`. Callers handle it like any other error return.

### System Requirements

mlock has per-process limits. The default on Linux is often 64 KiB. Applications managing many concurrent secrets need to raise this:

```bash
ulimit -l unlimited
```

Or in `/etc/security/limits.conf`:

```
*  hard  memlock  unlimited
*  soft  memlock  unlimited
```

### Error Types

| Error Kind | Sentinel | Description |
|-----------|----------|-------------|
| `errSecretDestroyed` | `ErrSecretDestroyed` | Attempt to use a destroyed secret |
| `errNilInput` | `ErrNilInput` | nil data provided to constructor |
| `errSecretSizeMismatch` | (dynamic) | Length mismatch for Secret32 |
| `errSecretAlloc` | `ErrSecretAlloc` | locked-memory allocation failure |

Errors use a `kind`-based matching via `Is()` for `errors.Is` compatibility.

---

## Incremental MAC

**File:** `incrementalmac/incrementalmac.go`

The `incrementalmac` package provides streaming HMAC-SHA256 computation for large data such as message backups. Data is split into fixed-size chunks, and each chunk boundary produces an intermediate MAC that covers all data from the beginning up to that point.

### Chaining Semantics

```
MAC_0 = HMAC(key, chunk_0)
MAC_1 = HMAC(key, chunk_0 || chunk_1)
MAC_2 = HMAC(key, chunk_0 || chunk_1 || chunk_2)
...
MAC_final = HMAC(key, all_data)
```

A single HMAC state accumulates all input. At each chunk boundary, the inner SHA-256 hash state is cloned (via `encoding.BinaryMarshaler`) and finalized to produce an intermediate MAC without disrupting the running computation.

### Incremental (computation)

```go
func New(key []byte, chunkSize int) (*Incremental, error)
```

Creates an incremental MAC with the given HMAC key and chunk size. The chunk size must be in `[MinChunkSize, MaxChunkSize]` (64 KiB to 2 MiB).

- `Update(data []byte) (int, error)` -- feeds data, returns number of MACs produced at chunk boundaries
- `Finalize() ([][]byte, error)` -- completes with one final MAC covering all data
- `Bytes() []byte` -- all MACs concatenated

### Validating (verification)

```go
func NewValidating(key []byte, chunkSize int, macs [][]byte) (*Validating, error)
```

Mirrors the `Incremental` computation but compares each produced MAC against expected values in constant time (`subtle.ConstantTimeCompare`).

- `Update(data []byte) error` -- feeds data, validates MACs at chunk boundaries. Continues processing all chunks even after a mismatch to avoid timing leaks (mismatch is deferred and returned after all data in the call is consumed).
- `Finalize() error` -- validates the final MAC, checks that exactly one expected MAC remains unconsumed

### Chunk Size Calculation

```go
func CalculateChunkSize(dataLength int64) int
```

Chooses a chunk size targeting approximately 256 chunks (8 KiB total digest size / 32 bytes per SHA-256 digest). The algorithm matches the Rust reference:

- Data < 256 * 64 KiB: returns `MinChunkSize` (64 KiB)
- Data < 256 * 2 MiB: returns `ceil(dataLength / 256)`
- Otherwise: returns `MaxChunkSize` (2 MiB)

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `DigestLength` | 32 | SHA-256 output size |
| `MinChunkSize` | 65536 | 64 KiB minimum chunk |
| `MaxChunkSize` | 2097152 | 2 MiB maximum chunk |

### clonableHMAC Implementation

The `clonableHMAC` struct decomposes the HMAC into an inner hash (`H(ipad || data...)`) and a pre-computed outer key (`K XOR opad`). This decomposition is necessary because Go's `crypto/hmac` does not expose the inner hash state for cloning. By implementing the HMAC construction manually (RFC 2104) with `sha256.New()` directly, the inner hash can be cloned via `encoding.BinaryMarshaler`/`BinaryUnmarshaler` at chunk boundaries.

### Error Types

| Error | Condition |
|-------|-----------|
| `ErrChunkSizeTooSmall` | Chunk size < MinChunkSize |
| `ErrChunkSizeTooLarge` | Chunk size > MaxChunkSize |
| `ErrAlreadyFinalized` | Update or Finalize called after Finalize |
| `ErrMACMismatch` | MAC validation failed |
| `ErrTooFewMACs` | More chunks than expected MACs |
| `ErrUnconsumedMACs` | Expected MACs remain after Finalize |
