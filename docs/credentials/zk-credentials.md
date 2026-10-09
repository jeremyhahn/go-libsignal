# ZK Credentials (Chase-Perrin-Zaverucha)

> **Status: REFERENCE** · Last verified: 2026-10-09
> As-built description of go-libsignal code owned by this repository.

Package `zkcredential` implements the anonymous credential scheme from "The Signal Private Group System and Anonymous Credentials Supporting Efficient Verifiable Encryption" by Chase, Perrin, and Zaverucha. All operations use the Ristretto255 group over Curve25519.

## Credential System

A credential is a MAC over a set of attribute points, issued by a server and presented by a client without revealing the attributes to the verifying server.

### System Parameters

`SystemParams` contains shared generator points (G_w, G_wprime, G_x0, G_x1, G_V, G_z, G_y[0..6]) derived deterministically from the label `"Signal_ZKCredential_ConstantSystemParams_generate_20230410"` using `ShoSha256Ext`. Call `GetSystemParams()` to access them (computed once via `sync.Once`).

**Legacy system parameters**: Credential types that predate the modern zkcredential system (auth, profile key, receipt, PNI, expiring profile key, auth-with-PNI) use hardcoded system parameters parsed from a 544-byte blob (`legacyCredentialSystemHardcoded`). These are 17 Ristretto255 points in bincode struct field order. Call `GetLegacySystemParams()` to access them.

The distinction matters: legacy credentials use `LegacyNumSupportedAttrs` = 6 attribute slots, while modern credentials use `NumSupportedAttrs` = 7.

## Attributes

Attributes come in several forms:

### Public Attributes

`PublicAttribute` values are hashed into the SHO state but not hidden from the server. Built-in implementations:

| Type | Description |
|------|-------------|
| `PublicAttributeBytes` | Raw byte slice |
| `PublicAttributeU32` | 4-byte big-endian uint32 |
| `PublicAttributeU64` | 8-byte big-endian uint64 |

### Hidden Attributes

`Attribute` values are represented as pairs of Ristretto255 points `(M1, M2)` and are hidden from the server via encryption. `PointPairAttribute` is the basic implementation.

### Revealed Attributes

`RevealedAttribute` values are hidden from the issuing server but revealed to the verifying server. They consist of a single Ristretto255 point. `PointAttribute` is the basic implementation.

## Encryption Domains

`Domain` separates encryption contexts. Each domain has an ID string and a pair of generator points `Ga = (G_a1, G_a2)`. Use `DeriveDefaultGeneratorPoints(domainID)` to generate points from a domain ID via SHO with label `"Signal_ZKCredential_Domain_20231011"`.

### Key Pairs

`KeyPair` encrypts attributes within a domain:

```
E_A1 = a1 * M1
E_A2 = a2 * E_A1 + M2
```

`InverseKeyPair(other, newDomain)` creates a key pair whose encryption undoes the other's, allowing re-encryption between domains.

`DecryptToSecondPoint(ct)` recovers M2: `M2 = E_A2 - a2 * E_A1`. Returns an error if E_A1 equals the generator point (indicating a1 is not encrypting).

## Credential Key Pair

`CredentialPrivateKey` (section 3.1) contains scalars `(W, Wprime, X0, X1, Y[0..6])` and the point `Wpoint = W * G_w`.

`CredentialPublicKey` contains `CW = Wpoint + Wprime * G_wprime` and an array of `I` values computed as progressive subtractions of `y_i * G_y_i` from `G_V - x0*G_x0 - x1*G_x1`.

### Key Generation

```go
kp := zkcredential.GenerateCredentialKeyPair(randomness)
```

For chained generation through a shared SHO (matching Rust's `ServerSecretParams::generate`):

```go
kp := zkcredential.GenerateCredentialKeyPairFromSHO(sho)
```

For legacy credential types with fewer attributes:

```go
kp := zkcredential.GenerateCredentialKeyPairFromSHOWithStorage(sho, storageLen, numAttrs)
```

`storageLen` controls how many y-scalars are drawn from the SHO (affects state advancement). `numAttrs` controls how many G_y points are used in the public key I computation. When `numAttrs <= LegacyNumSupportedAttrs` (6), the legacy hardcoded system parameters are used automatically.

### Credential Core

`CredentialPrivateKey.CredentialCore(M, sho)` computes the MAC:

```
V = W + (x0 + x1*t) * U + sum(y_i * M_i)
```

where `t` and `U` are derived from the SHO.

## Issuance

`IssuanceProofBuilder` constructs credentials with zero-knowledge proofs of correct issuance.

### Server Side (Issue)

```go
builder := zkcredential.NewIssuanceProofBuilder(label)
builder.AddPublicAttribute(somePublicAttr)
builder.AddAttribute(someHiddenAttr)
proof, err := builder.Issue(keyPair, randomness)
```

The proof statement (section 3.2) asserts three equations:

1. `C_W = w * G_w + wprime * G_wprime`
2. `G_V - I = x0 * G_x0 + x1 * G_x1 + sum(y_i * G_y_i)`
3. `V = w * G_w + x0 * U + x1 * tU + sum(y_i * M_i)`

Fresh randomness is critical for each issuance. Reusing randomness reveals the server's private key.

### Client Side (Verify)

```go
builder := zkcredential.NewIssuanceProofBuilder(label)
builder.AddPublicAttribute(somePublicAttr)
builder.AddAttribute(someHiddenAttr)
credential, err := builder.Verify(publicKey, proof)
```

## Blind Issuance

Blind issuance lets the client hide attributes from the server during issuance. The client blinds attributes with a `BlindingKeyPair`, and the server issues a `BlindedCredential` that the client unblinds.

### Client: Prepare Request

```go
sho := zkcredential.NewShoHmacSha256Ext("...")
sho.AbsorbAndRatchet(randomness[:])
bkp, err := zkcredential.GenerateBlindingKeyPair(sho)
blindedAttr, err := bkp.Encrypt(attr, sho)
```

`BlindedPoint` consists of `D1 = r * G` and `D2 = r * Y + M`, where `r` is a random nonce and `Y` is the blinding public key. The client sends `BlindedPointWithoutNonce` (stripping the nonce) to the server.

### Server: Issue Blinded Credential

```go
inner := zkcredential.NewIssuanceProofBuilder(label)
inner.AddPublicAttribute(publicAttr)
builder := zkcredential.NewBlindedIssuanceProofBuilder(inner)
builder.AddBlindedAttribute(blindedAttrWithoutNonce)
proof, err := builder.Issue(keyPair, blindingPubKey, randomness)
```

The blinded credential contains `(T, U, S1, S2)` where:
- `S1 = rprime * G + sum(y_i * D1_i)`
- `S2 = rprime * Y + V + sum(y_i * D2_i)`

### Client: Verify and Unblind

```go
credential, err := clientBuilder.Verify(publicKey, blindingKeyPair, proof)
```

Unblinding recovers `V = S2 - y * S1`, producing a standard `Credential`.

## Presentation

`PresentationProofBuilder` proves possession of a credential without revealing the attributes.

### Client: Present

```go
builder := zkcredential.NewPresentationProofBuilder(label)
builder.AddAttribute(encryptedAttr, keyPair)
proof, err := builder.Present(publicKey, credential, randomness)
```

The presentation commits to each attribute: `C_y_i = z * G_y_i + M_i`, where `z` is a random blinding scalar. The proof demonstrates knowledge of `z`, the credential's `t`, and the encryption key scalars.

Attributes can be added with verified keys (`AddAttribute`), without key verification (`AddAttributeWithoutVerifiedKey`), or as revealed values (`AddRevealedAttribute`).

### Server: Verify

```go
verifier := zkcredential.NewPresentationProofVerifier(label)
verifier.AddPublicAttribute(publicAttr)
verifier.AddAttribute(ciphertext, publicKey)
err := verifier.Verify(keyPair, proof)
```

The verifier reconstructs `Z = C_V - W - x0*C_x0 - x1*C_x1 - sum(y_i * C_y_i) - y0*M0` and verifies the poksho proof against the statement.

## Endorsements

Endorsements are lightweight token-based credentials used for group send authorization. Unlike full credentials, they produce fixed-size 16-byte tokens (`TokenLen`).

### Key Hierarchy

```go
rootKP, err := zkcredential.GenerateServerRootKeyPair(randomness)
derivedKP, err := rootKP.DeriveKey(tagInfo)  // tagInfo encodes expiration
```

`ServerRootKeyPair` holds a scalar `sk` and point `PK = sk * G`. `DeriveKey` computes `sk' = (sk + t)^{-1}` where `t` is derived from the tag info SHO.

### Issuing Endorsements

```go
response, err := zkcredential.IssueEndorsements(hiddenPoints, derivedKP, randomness)
```

For each hidden point `E_i`, the endorsement is `R_i = sk' * E_i`. A batch proof is generated using the poksho statement:

```
weighted_sum(R) = sk_prime * weighted_sum(E)
G = sk_prime * PK_prime
```

Weights are derived from a deterministic SHO to compress multiple equations into one.

### Receiving and Verifying

```go
received, err := response.Receive(hiddenPoints, derivedPublicKey)
```

`Receive` decompresses the endorsement points, recomputes the weights, and verifies the poksho proof.

### Combining and Converting to Tokens

```go
combined := zkcredential.CombineEndorsements(endorsements)
token := combined.ToToken(clientDecryptionKey)
```

`ToToken` unblinds the endorsement (`P = aInv * R`) and hashes: `SHA-256(P.Bytes())[:16]`.

### Server-Side Token Verification

```go
err := derivedKP.Verify(point, token)
```

Recomputes `P = sk' * point`, hashes it, and performs constant-time comparison with the token.

## Serialization

| Function | Format |
|----------|--------|
| `EncodeCredential` / `DecodeCredential` | 96 bytes: [32 scalar T][32 point U][32 point V] |
| `EncodeCiphertext` / `DecodeCiphertext` | 64 bytes: [32 point EA1][32 point EA2] |
| `EncodeIssuanceProof` | Credential bytes + poksho proof bytes |
| `EncodePresentationProof` | [32 Cx0][32 Cx1][32 CV][4 numCy][32*N Cy...][proof] |

## ShoExt

`ShoExt` wraps `poksho.SHO` with methods for deriving Ristretto255 group elements:

| Method | Output | Bytes Squeezed |
|--------|--------|---------------|
| `GetPoint()` | `*ristretto255.Element` | 64 (mapped via `SetUniformBytes`) |
| `GetScalar()` | `*ristretto255.Scalar` | 64 (reduced mod group order) |
| `GetPointSingleElligator()` | `*ristretto255.Element` | 32 (single Elligator map) |

`PointFromSingleElligator(input)` maps 32 bytes using `SetUniformBytes(input || zeros)`, which computes `MAP(input) + MAP(zeros) = MAP(input) + identity = MAP(input)`.

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `NumSupportedAttrs` | 7 | Maximum attribute points (modern) |
| `LegacyNumSupportedAttrs` | 6 | Maximum attribute points (legacy) |
| `RandomnessLen` | 32 | Required randomness length |
| `TokenLen` | 16 | Endorsement token length |
