# Cipher Primitives

Package `cipher/` implements the symmetric encryption primitives used throughout the Signal Protocol. All implementations are pure Go. Source files are in `/cipher/`.

## AES-256-GCM-SIV (RFC 8452)

**Files:** `aesgcmsiv.go`, `polyval.go`

AES-GCM-SIV is a nonce-misuse-resistant AEAD cipher. If the same nonce is accidentally reused with the same key, the only information leaked is whether the same plaintext was encrypted twice. The plaintext itself stays confidential. Sealed Sender v2 and SVR use AES-GCM-SIV instead of standard AES-GCM for this reason.

### Construction

The implementation follows RFC 8452 Section 4 for AES-256:

1. **Per-message key derivation** (`derivePolyvalKey`): Six AES blocks are computed from `le32(counter) || nonce` using the master key. The first 8 bytes of each block are concatenated to form:
   - Blocks 0-1: 16-byte POLYVAL hash key
   - Blocks 2-5: 32-byte AES-256 encryption key

2. **Tag computation** (`computeTag`): POLYVAL is evaluated over `pad(AAD) || pad(plaintext) || le64(len(AAD)*8) || le64(len(plaintext)*8)`. The result is XORed with the nonce, bit 127 is cleared, and the result is encrypted with AES to produce the 16-byte tag (synthetic IV).

3. **Encryption** (`aesGCMSIVCTR`): AES-CTR with the tag as initial counter value, bit 127 set. Only the low 32 bits of the counter are incremented (little-endian). Plaintext is limited to `< 2^36` bytes to prevent counter wrap. The `>=` check in the length guard rejects inputs of exactly `maxPlaintextLen` because the counter would wrap back to its initial value on the last block.

4. **Decryption**: Decrypt first, then recompute the tag from the recovered plaintext and compare in constant time (`subtle.ConstantTimeCompare`). On authentication failure, the plaintext buffer is zeroed before returning `ErrAESGCMSIVAuthFailed`.

### AEAD Interface

`NewAESGCMSIV(key []byte)` returns a `crypto/cipher.AEAD` implementation. The key is stored in memguard-protected memory via `secret.New()`. Call the `Zeroize()` method on the returned value (type-assert to `*aesGCMSIV`) to destroy key material when the cipher is no longer needed.

```go
aead, err := cipher.NewAESGCMSIV(key)
// ... use aead.Seal() / aead.Open() ...
aead.(*cipher.aesGCMSIV).Zeroize()  // internal type; prefer defer
```

### Standalone Functions

For one-shot use without the AEAD interface:

- `AESGCMSIVEncrypt(key, nonce, plaintext, aad []byte) ([]byte, error)` -- returns ciphertext with 16-byte tag appended
- `AESGCMSIVDecrypt(key, nonce, ciphertext, aad []byte) ([]byte, error)` -- returns plaintext or `ErrAESGCMSIVAuthFailed`

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `aesGCMSIVKeySize` | 32 | AES-256 key size |
| `aesGCMSIVNonceSize` | 12 | 96-bit nonce |
| `aesGCMSIVTagSize` | 16 | 128-bit authentication tag |

---

## POLYVAL

**File:** `polyval.go`

POLYVAL is the universal hash function underlying AES-GCM-SIV, defined in RFC 8452 Section 3. It is equivalent to GHASH with byte-order conversions:

```
POLYVAL(H, X_1, ..., X_s) =
    ByteReverse(GHASH(mulX_GHASH(ByteReverse(H)), ByteReverse(X_1), ..., ByteReverse(X_s)))
```

### Constant-Time Multiplication

The `ghashMul` function performs GF(2^128) multiplication using a bit-by-bit approach where every operation is constant-time. No branches depend on secret data. The conditional XOR uses branchless masking:

```go
bit := (word >> uint(j)) & 1
mask := uint32(-int32(bit))  // 0xFFFFFFFF when bit=1, 0x00000000 when bit=0
z[0] ^= v[0] & mask
```

The polynomial reduction constant is `0xe1000000` (representing `x^7 + x^2 + x + 1` in big-endian uint32 form), applied via the same masking technique on the LSB carry.

### Key Conversion

`toGHASHKey` converts a POLYVAL key H to a GHASH key by computing `mulX_GHASH(ByteReverse(H))`. The multiplication by x is a right-shift by 1 bit with conditional XOR of `0xe1` at byte 0 when the LSB was set. The conditional XOR uses `mask := -hiBit` for constant-time operation.

### Performance Note

The pure Go carry-less multiplication is correct but not optimized for throughput. High-volume deployments should consider replacing `ghashMul` with architecture-specific assembly (PCLMULQDQ on x86-64, PMULL on ARM64).

---

## AES-CTR with 32-bit Big-Endian Counter

**File:** `aesctr.go`

This AES-CTR variant uses a 32-bit big-endian counter in the last 4 bytes of the 16-byte counter block. The first 12 bytes remain fixed (all zeros). This matches Rust's `ctr::Ctr32BE<Aes256>` used by the Sealed Sender v1 protocol.

Go's standard library `crypto/cipher.NewCTR` uses a full 128-bit counter, which is incompatible with the Rust implementation. This custom implementation exists solely for that reason.

### Counter Layout

```
Byte:  [ 0  1  2  3  4  5  6  7  8  9 10 11 | 12 13 14 15 ]
       [        fixed nonce (zeros)          | BE counter  ]
```

The counter starts at 0 and increments as a big-endian uint32 via `binary.BigEndian.Uint32/PutUint32` on bytes [12:16].

### Functions

- `AESCTREncrypt(key, plaintext []byte) ([]byte, error)` -- AES-256-CTR encryption (zero IV, 32-bit BE counter)
- `AESCTRDecrypt(key, ciphertext []byte) ([]byte, error)` -- same operation (CTR mode is symmetric)

Both reject keys that are not exactly 32 bytes (`ErrAESCTRKeySize`) and inputs exceeding `aesCTR32BEMaxLength` (approximately 64 GiB, computed as `math.MaxUint32 * aes.BlockSize`).

---

## AES-CBC with PKCS7 Padding

**Files:** `Cipher.go`, `aescbc.go`

Two AES-CBC implementations exist:

### Legacy Interface (`Cipher.go`)

Used by the Signal group cipher. Requires exactly 32-byte keys (AES-256 only).

- `Encrypt(iv, key, plaintext []byte) ([]byte, error)`
- `Decrypt(iv, key, ciphertext []byte) ([]byte, error)`

### General Interface (`aescbc.go`)

Supports AES-128, AES-192, and AES-256 (key sizes 16, 24, or 32 bytes). Used by message backup frame encryption.

- `AESCBCEncrypt(key, iv, plaintext []byte) ([]byte, error)`
- `AESCBCDecrypt(key, iv, ciphertext []byte) ([]byte, error)`

Note the parameter order difference: the legacy interface takes `(iv, key, ...)` while the general interface takes `(key, iv, ...)`.

### PKCS7 Padding

The `pkcs7Unpad` function validates padding in constant time. It iterates over the last `blocksize` bytes regardless of the actual padding length, using `subtle.ConstantTimeLessOrEq` and `subtle.ConstantTimeByteEq` to avoid leaking the padding length through timing:

```go
for i := 0; i < blocksize; i++ {
    isPad := subtle.ConstantTimeLessOrEq(i+1, padLen)
    match := subtle.ConstantTimeByteEq(b[len(b)-1-i], padByte)
    good &= (isPad & match) | (1 - isPad)
}
```

---

## HPKE (Hybrid Public Key Encryption)

**File:** `hpke.go`

RFC 9180 HPKE in Base mode using X25519 + HKDF-SHA256 + AES-256-GCM. The implementation wraps `cloudflare/circl`'s HPKE primitives.

### Wire Format

Signal's HPKE wire format prepends a type byte to the ciphertext:

```
[type_byte | enc (32 bytes) | AEAD_ciphertext]
```

Currently only one type is defined: `0x01 = Base_X25519_HkdfSha256_Aes256Gcm`.

### Interface Types

- `HPKESender` -- created via `NewHPKESender(recipientPub []byte)`, provides `Seal(info, aad, plaintext []byte) ([]byte, error)`
- `HPKEReceiver` -- created via `NewHPKEReceiver(recipientPriv []byte)`, provides `Open(info, aad, ciphertext []byte) ([]byte, error)` and `Zeroize()`

### Convenience Functions

For one-shot use without managing sender/receiver objects:

- `HPKESeal(recipientPub, info, aad, plaintext []byte) (enc, ciphertext []byte, err error)` -- returns enc and ciphertext separately (no type byte prefix)
- `HPKEOpen(recipientPriv, enc, info, aad, ciphertext []byte) ([]byte, error)` -- zeroizes internal copy of private key via defer
- `HPKEGenerateKeyPair() (privateKey, publicKey []byte, err error)` -- generates X25519 key pair for HPKE

### Zeroization Limitations

The `hpkeReceiver.Zeroize()` method clears the local copy of the private key bytes (`privKeyBytes`) and nils the `kem.PrivateKey` reference. The circl library's internal `kem.PrivateKey` may retain a copy that cannot be zeroized from outside the library. This is a documented limitation.

---

## Error Types

All errors in the cipher package are typed structs (per project convention). Key error types:

| Error | Condition |
|-------|-----------|
| `ErrAESGCMSIVKeySize` | Key is not 32 bytes |
| `ErrAESGCMSIVAuthFailed` | Authentication tag mismatch on decryption |
| `ErrAESCTRKeySize` | AES-CTR key is not 32 bytes |
| `ErrAESCTRInputTooLong` | Input exceeds 32-bit counter capacity |
| `ErrAESCBCInvalidKey` | Key is not 16, 24, or 32 bytes |
| `ErrAESCBCCiphertextNotAligned` | Ciphertext length not a multiple of 16 |
| `ErrHPKE` | HPKE operation errors (matched by `kind` field via `errors.Is`) |
