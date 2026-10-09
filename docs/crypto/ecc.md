# Elliptic Curve Cryptography

> **Status: REFERENCE** · Last verified: 2026-10-09
> As-built description of go-libsignal code owned by this repository.

Package `ecc/` implements Curve25519 key operations, XEdDSA/VXEdDSA signature schemes, and locked-memory key storage. Source files are in `/ecc/`.

## Key Types

### Public Keys

`ECPublicKeyable` is the interface for all EC public keys:

```go
type ECPublicKeyable interface {
    Serialize() []byte      // [0x05] || 32-byte key
    Type() int              // DjbType = 0x05
    PublicKey() [32]byte    // raw 32-byte Montgomery x-coordinate
    IsCanonical() bool      // torsion-free + in-range check
}
```

`DjbECPublicKey` is the concrete implementation. The `0x05` type byte prefix (`DjbType`) identifies Curve25519 keys in the serialized format. The `KeySize` constant is 33 (1 type byte + 32 key bytes).

`DecodePoint(bytes []byte, offset int)` parses a serialized public key starting at the given offset. It reads the type byte and the following 32 bytes. Returns `ErrBadKeyType` for unrecognized types and `ErrBadKeyLength` if the buffer is too short.

### Canonical Key Validation

`DjbECPublicKey.IsCanonical()` performs two checks matching the Rust `PublicKey::is_canonical()`:

1. **Torsion-free** (`isTorsionFree`): Converts the Montgomery x-coordinate to an Edwards y-coordinate via `y = (u-1)/(u+1)`, reconstructs the Edwards point with sign bit 0 (matching Rust's `to_edwards(0)`), rejects the identity point, then verifies the point has prime order using the cofactor inverse trick: `[8]([8^{-1} mod l] * P) == P`. The constant `cofactorInvBytes` holds `8^{-1} mod l` in little-endian.

2. **In-range** (`scalarIsInRange`): The 32-byte encoding must be in `[0, 2^255 - 19)`. Values with bit 255 set are rejected. Values in `[p, 2^255 - 1]` (where `p = 2^255 - 19`) are detected by checking `k[0] >= 237 && k[1..30] all 0xFF && k[31] == 0x7F`.

### Private Keys

Two private key implementations exist:

**`DjbECPrivateKey`** -- stores the 32-byte private key in a plain `[32]byte` field. Exists for test vector construction. Has a `Zeroize()` method that uses `runtime.KeepAlive` to prevent dead-store elimination.

**`GuardedECPrivateKey`** -- stores the private key in a `secret.Secret32` backed by mlock'd, guard-page protected memory. This is the production type used by `GenerateKeyPair()` and `GenerateGuardedKeyPair()`. Implements:

- `ECPrivateKeyable` -- backward compatibility (`Serialize()`, `Type()`)
- `keyops.Signer` -- `Sign(rand io.Reader, message []byte) ([64]byte, error)`
- `keyops.VRFSigner` -- `VRFSign(rand io.Reader, message []byte) ([]byte, []byte, error)`
- `keyops.KeyAgreement` -- `Agreement(peerPublic [32]byte) (*secret.Secret32, error)`
- `keyops.PrivateKey` -- combined interface

### Key Pairs

`ECKeyPair` holds an `ECPublicKeyable` and `ECPrivateKeyable`. The `ZeroizePrivateKey()` method dispatches to either `GuardedECPrivateKey.Zeroize()` or `DjbECPrivateKey.Zeroize()` via type switch.

`GuardedECKeyPair` is the recommended type. It exposes `KeyOps()` to access the `keyops.PrivateKey` interface without exposing raw key bytes.

### Key Generation

`GenerateKeyPair()` generates a random Curve25519 key pair. The private key undergoes standard clamping:

```go
private[0] &= 248    // clear low 3 bits
private[31] &= 127   // clear bit 255
private[31] |= 64    // set bit 254
```

The public key is derived via `curve25519.ScalarBaseMult`. The private key is moved into a `GuardedECPrivateKey` (source array is zeroized).

`GenerateGuardedKeyPair()` does the same but returns a `GuardedECKeyPair` and uses `secret.NewSecret32` directly.

---

## XEdDSA Signatures

**File:** `SignCurve25519.go`

XEdDSA allows signing with Curve25519 private keys using Ed25519 mathematics. The scheme converts between Montgomery (Curve25519) and Edwards (Ed25519) representations. See https://moderncrypto.org/mail-archive/curves/2014/000205.html.

### Signing (`sign`)

The algorithm follows the XEdDSA spec (Section 3):

1. Compute the Edwards key pair by calling `SetBytesWithClamping` on the private key and then `ScalarBaseMult`. The sign bit of the Edwards public key is captured.

2. Generate the nonce `r = hash_1(a || M || Z) mod q` where `hash_1` uses the diversifier prefix `0xFE` (32 bytes of `0xFE, 0xFF, ..., 0xFF`). The hash input uses the raw clamped private key bytes (not the reduced scalar), matching the Rust reference for test vector compatibility.

3. Compute `R = r * B` and `h = SHA-512(R || A || M) mod L`.

4. Compute `s = (r + h*a) mod L`.

5. Embed the sign bit of the Edwards public key into `signature[63]`'s MSB. This bit would otherwise always be 0 for a canonical scalar less than L. The verifier extracts it to reconstruct the correct Edwards point from the ambiguous Montgomery x-coordinate.

### Nonce Zeroization

The 64-byte random nonce and the `keyData` copy are zeroized via `defer crypto.Zeroize()`. A nonce leak in XEdDSA allows private key recovery (same as Ed25519).

### Verification (`verify`)

1. Clear the sign bit from the Montgomery public key, then reject non-canonical field elements via `isNonCanonicalFieldElement` (checks if the value is `>= p = 2^255 - 19`).

2. Extract the Edwards sign bit from `signature[63] >> 7`.

3. Convert Montgomery x to Edwards y via `(mont_x - 1) / (mont_x + 1)` using `field.Element` arithmetic. Set the sign bit extracted from the signature.

4. Parse R and check canonicity via `edwards25519.Point.SetBytes` (rejects non-canonical y and off-curve points).

5. Parse s with the sign bit cleared. Reject non-canonical scalars: after clearing bit 7, if `sPadded[31] & 0xE0 != 0`, the scalar exceeds the group order L.

6. Verify using non-cofactored check: `[S]B - [h]A == R` via `VarTimeDoubleScalarBaseMult`.

### Public API

- `CalculateSignature(signingKey ECPrivateKeyable, message []byte) ([64]byte, error)` -- XEdDSA sign
- `VerifySignature(signingKey ECPublicKeyable, message []byte, signature [64]byte) bool` -- XEdDSA verify

---

## VXEdDSA (Verifiable XEdDSA)

**File:** `vxeddsa.go`

VXEdDSA extends XEdDSA with a verifiable random function (VRF) output. For a given (key, message) pair, the VRF output is deterministic. See https://signal.org/docs/specifications/xeddsa/#vxeddsa.

### Hash Diversifiers

The spec defines diversified hash functions `hash_i(X) = SHA-512(prefix_i || X)` where each prefix is 32 bytes:

| Function | Prefix byte | Purpose |
|----------|------------|---------|
| `hash_1` | `0xFE` | XEdDSA nonce (in `SignCurve25519.go`) |
| `hash_2` | `0xFD` | hash-to-point via Elligator 2 |
| `hash_3` | `0xFC` | VXEdDSA nonce r |
| `hash_4` | `0xFB` | VXEdDSA challenge h |
| `hash_5` | `0xFA` | VRF output derivation |

### VXEdDSA Signing (`vxeddsaSign`)

1. Compute Edwards key pair with `calculateEdwardsKeyPair` (sign bit normalized to 0). The scalar negation uses `subtle.ConstantTimeCopy` for constant-time selection.

2. `B_v = hashToPoint(A || M)` -- hashes to a curve point via Elligator 2 then multiplies by cofactor 8.

3. `V = a * B_v` -- the VRF point.

4. `r = hash_3(a || V || Z) mod q` -- nonce generation.

5. `R = r * B`, `R_v = r * B_v`.

6. `h = hash_4(A || V || R || R_v || M) mod q` -- challenge.

7. `s = (r + h*a) mod q`.

8. VRF output = `hash_5(cV)` where `c = 8` (cofactor), truncated to 32 bytes per spec (`VRFOutputSize = 32`).

9. Signature = `V || h || s` (96 bytes, `VXEdDSASignatureSize = 96`).

### Elligator 2 (`elligator2`)

Maps a field element r to a Montgomery u-coordinate on Curve25519:

1. `d = 1 + 2*r^2` (with `d = 1` fallback when `d == 0`, selected via `field.Element.Select`)
2. `u1 = -A / d` where `A = 486662`
3. `w1 = u1*(u1^2 + A*u1 + 1)`
4. If `w1` is not a quadratic residue, use `u2 = -A - u1`

All operations use `field.Element.Select` for constant-time branching, with no data-dependent control flow.

### Hash-to-Point (`hashToPoint`)

1. Hash input with `hash_2` (SHA-512, `0xFD` prefix).
2. Extract sign bit from bit 255 of the digest.
3. Clear bit 255 to get `r mod 2^255`, interpret as a field element.
4. Apply `elligator2(r)` to get Montgomery u-coordinate.
5. Convert to Edwards y-coordinate via `(u-1)/(u+1)`.
6. Reconstruct Edwards point with the extracted sign bit.
7. Multiply by cofactor 8 to project into the prime-order subgroup.

### VXEdDSA Verification (`vxeddsaVerify`)

1. Convert Montgomery public key to Edwards form (sign bit always 0).
2. Parse signature as `V (32) || h (32) || s (32)`.
3. Compute `B_v = hashToPoint(A || M)`.
4. Reject small-order points: `cA == I`, `cV == I`, or `B_v == I`.
5. Compute `R = s*B - h*A` and `R_v = s*B_v - h*V`.
6. Recompute `h_check = hash_4(A || V || R || R_v || M) mod q`.
7. Compare `h == h_check` in constant time.
8. On success, return VRF output = `hash_5(cV)`.

### Public API

- `VXEdDSASign(key ECPrivateKeyable, message []byte) ([]byte, []byte, error)` -- returns (96-byte signature, 32-byte VRF output)
- `VXEdDSAVerify(key ECPublicKeyable, message, signature []byte) (bool, []byte, error)` -- returns (valid, VRF output)

---

## X25519 Key Agreement

`GuardedECPrivateKey.Agreement(peerPublic [32]byte)` performs X25519 Diffie-Hellman and returns the shared secret in a `secret.Secret32`. The result is checked in constant time against all-zeros (`subtle.ConstantTimeCompare`), rejecting low-order peer public keys that would produce a zero shared secret (`ErrInvalidKeyAgreement`).

The `kdf.CalculateSharedSecret` function in `kdf/HKDF.go` provides the same operation with `[32]byte` inputs/outputs and explicit zeroization of local key copies.

---

## Error Types

| Error | Condition |
|-------|-----------|
| `ErrBadKeyType` | Unrecognized key type byte during `DecodePoint` |
| `ErrBadKeyLength` | Buffer too short for key data after type byte |
| `ErrInputTooShort` | Buffer too short to read type byte at offset |
| `ErrSignFailed` | XEdDSA sign produced nil (invalid scalar) |
| `ErrGuardedKeyDestroyed` | Operation on a destroyed `GuardedECPrivateKey` |
| `ErrInvalidKeyAgreement` | DH produced all-zero shared secret |
| `ErrGuardedKeyAllocation` | locked-memory allocation failure |
| `ErrInvalidVXEdDSASignatureLength` | VXEdDSA signature is not 96 bytes |
| `ErrHashToPointFailed` | Elligator 2 hash-to-point failed |
