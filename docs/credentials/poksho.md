# Poksho: Proof of Knowledge using SHO

Package `poksho` implements Schnorr-style zero-knowledge proofs over Ristretto255 and the Stateful Hash Object (SHO) abstraction that underlies them. It is the cryptographic foundation for Signal's `zkcredential`, `zkgroup`, and `usernames` packages.

## Stateful Hash Object (SHO)

The SHO is a sponge-like construction that absorbs input data and squeezes deterministic output. It comes in two variants: HMAC-SHA-256 and SHA-256.

### Construction

```go
sho := poksho.NewShoHmacSha256("my_label")   // HMAC-SHA-256 variant
sho := poksho.NewShoSha256("my_label")       // SHA-256 variant
```

Both constructors absorb and ratchet the label string as the first operation, establishing domain separation.

### State Machine

The SHO alternates between two modes:

- **ABSORBING**: data is being written to an internal hasher
- **RATCHETED**: the chaining value has been finalized, ready for squeezing or new absorption

```
[RATCHETED] --Absorb--> [ABSORBING] --Ratchet--> [RATCHETED] --Squeeze--> [RATCHETED]
```

`Absorb` in RATCHETED mode initializes a new hasher from the current chaining value. Multiple `Absorb` calls accumulate data into the same hasher. `Ratchet` in RATCHETED mode is a no-op.

### Core Operations

| Method | Description |
|--------|-------------|
| `Absorb(data)` | Feed data into the SHO; initializes hasher if RATCHETED |
| `Ratchet()` | Finalize absorb phase, update chaining value |
| `AbsorbAndRatchet(data)` | Absorb then ratchet in one call |
| `SqueezeAndRatchet(length)` | Produce output bytes and update chaining value |
| `Squeeze(length)` | Ratchet if absorbing, then squeeze (backward-compat alias) |
| `Clone()` | Deep copy of the SHO state |

### HMAC-SHA-256 Variant

- `initHasher(cv)`: `HMAC-SHA-256` keyed by the chaining value
- `ratchetFinalize(h)`: appends `0x00`, then `cv = HMAC.finalize()`
- `squeezeBlock(cv, counter)`: `HMAC(cv, counter_be64 || 0x01)`
- `squeezeStateUpdate(cv, outLen)`: `HMAC(cv, outlen_be64 || 0x02)`

### SHA-256 Variant

- `initHasher(cv)`: `SHA-256` with 64 zero-byte prefix, then cv
- `ratchetFinalize(h)`: double hash, `cv = SHA-256(SHA-256(accumulated))`
- `squeezeBlock(cv, counter)`: `SHA-256(pad63 || 0x01 || cv || counter_be64)`
- `squeezeStateUpdate(cv, outLen)`: `SHA-256(pad63 || 0x02 || cv || outlen_be64)`

### Cloning

`Clone()` produces a deep copy. When the SHO is in ABSORBING mode, the clone replays the absorbed data into a fresh hasher (since Go's `crypto/hmac` does not support cloning). This replay produces an identical hasher state because the hash computation is deterministic.

### Convenience

```go
output := poksho.ShoHash(poksho.NewShoHmacSha256, "label", input, 32)
```

`ShoHash` creates a new SHO, absorbs input, and squeezes output in a single call.

## Proof Statement

`Statement` defines a system of linear equations over Ristretto255 points. Each equation asserts that a linear combination of generators weighted by secret scalars equals a target point.

```go
st := poksho.NewStatement()
st.Add("C_W", [][2]string{{"w", "G_w"}, {"wprime", "G_wprime"}})
```

This declares the equation `C_W = w * G_w + wprime * G_wprime`.

### Named References

Scalars and points are identified by string names. The Ristretto basepoint is pre-assigned as point index 0 with name `"G"`. Internally, names are mapped to uint8 indices (maximum 256 scalars and 256 points).

### Binary Encoding

The statement is serialized to bytes (`toBytes()`) and absorbed into the SHO transcript. Format:

```
[1 byte: num_equations]
  for each equation:
    [1 byte: LHS point index]
    [1 byte: num_terms]
      for each term:
        [1 byte: scalar index]
        [1 byte: point index]
```

Different statements produce different challenges even with identical inputs.

## Proof Generation

`Statement.Prove` creates a Schnorr-style proof:

```go
proof, err := st.Prove(scalarArgs, pointArgs, message, randomness)
```

Parameters:
- `scalarArgs`: `*ScalarArgs` with named `*ristretto255.Scalar` values (the witness)
- `pointArgs`: `*PointArgs` with named `*ristretto255.Element` values (public inputs, excluding "G")
- `message`: arbitrary bytes bound into the transcript
- `randomness`: exactly 32 bytes of randomness

### Protocol

1. Initialize SHO with label `"POKSHO_Ristretto_SHOHMACSHA256"`
2. Absorb statement description D and all point values A, then ratchet
3. Clone the SHO; the clone absorbs randomness Z and witness scalars a, then ratchets
4. The clone absorbs message M, ratchets, and squeezes `N * 64` bytes for nonce scalars (where N = number of scalars). Each 64-byte block is reduced to a scalar via `SetUniformBytes`
5. Compute commitment: `R_i = sum(nonce_j * point_j)` for each equation i (via `homomorphismWithSubtraction` with nil challenge)
6. The original SHO absorbs all R points and message M, ratchets, and squeezes 64 bytes for the challenge scalar
7. Compute responses: `response_i = nonce_i + witness_i * challenge`
8. The proof self-verifies before being returned

### Output Format

```
[32 bytes: challenge scalar] [32 bytes: response_0] [32 bytes: response_1] ...
```

Total size: `32 * (1 + num_scalars)` bytes.

## Proof Verification

`Statement.VerifyProof` checks a proof against public inputs:

```go
err := st.VerifyProof(proofBytes, pointArgs, message)
```

### Protocol

1. Parse the proof: extract challenge (first 32 bytes) and response scalars (subsequent 32-byte blocks)
2. Validate: proof length must be `32 * (1 + num_scalars)`, all scalars must be canonical
3. Reconstruct the SHO transcript with the same label, statement, and point values
4. Reconstruct commitments: `R_i = sum(response_j * point_j) - challenge * LHS_i` (via `homomorphismWithSubtraction` with the challenge scalar)
5. Absorb reconstructed R and message, squeeze 64 bytes for the recomputed challenge
6. Compare the recomputed challenge against the proof's challenge using `crypto/subtle.ConstantTimeCompare`

## Scalar Arithmetic

### ScalarFromSliceWide

```go
scalar, err := poksho.ScalarFromSliceWide(input) // input must be 64 bytes
```

Interprets a 64-byte value as a little-endian integer and reduces modulo the Ed25519 group order L = 2^252 + 27742317777372353535851937790883648493. Returns a 32-byte little-endian scalar.

### ScalarFromSliceCanonical

```go
scalar, err := poksho.ScalarFromSliceCanonical(input) // input must be 32 bytes
```

Verifies the 32-byte value is strictly less than L. Returns a `ScalarNotCanonicalError` if the value is >= L.

## Argument Types

### ScalarArgs

```go
args := poksho.NewScalarArgs()
args.Add("w", wScalar)
args.Add("x0", x0Scalar)
```

### PointArgs

```go
args := poksho.NewPointArgs()
args.Add("G_w", gwPoint)
args.Add("C_W", cwPoint)
```

The basepoint "G" should not be added to `PointArgs`; it is automatically included at index 0.

## Error Types

| Error | Description |
|-------|-------------|
| `ProofError` | Wraps a sentinel error with optional context |
| `ErrBadArgs` | General bad arguments |
| `ErrBadArgsWrongNumberOfScalarArgs` | Scalar count mismatch |
| `ErrBadArgsWrongNumberOfPointArgs` | Point count mismatch |
| `ErrBadArgsMissingScalarArg` | Named scalar not provided |
| `ErrBadArgsMissingPointArg` | Named point not provided |
| `ErrVerificationFailure` | Proof verification failed |
| `ErrProofCreationVerificationFailure` | Proof self-verification failed during creation |
| `ScalarSizeError` | Input byte length does not match expected (32 or 64) |
| `ScalarNotCanonicalError` | Scalar value >= group order L |
| `InvalidInputError` | General input validation failure |

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `hashLen` | 32 | SHA-256 output length |
| `blockLen` | 64 | SHA-256/HMAC block length |
| Ed25519 group order L | 2^252 + 27742317777372353535851937790883648493 | Scalar field modulus |
