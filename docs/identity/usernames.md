# Usernames

> **Status: REFERENCE** · Last verified: 2026-10-09
> As-built description of go-libsignal code owned by this repository.

Package `usernames` implements Signal's username system: nickname validation, discriminator generation, cryptographic hashing via Ristretto255, zero-knowledge proofs of username knowledge, and encrypted username links.

## Username Format

A Signal username consists of a nickname and a numeric discriminator separated by a dot: `alice.42`. The nickname is case-insensitive (lowercased before hashing) and the discriminator must be at least two digits, non-zero, and cannot have leading zeros (except for two-digit discriminators like `01` through `09`).

### Parsing

```go
u, err := usernames.New("alice.42")
```

`New` parses a username string, validates the nickname characters and discriminator format, and computes the internal scalar representation. It does not enforce nickname length limits.

### Construction with Limits

```go
limits := usernames.NewNicknameLimits(3, 32)
u, err := usernames.FromParts("alice", "42", limits)
```

`NicknameLimits` enforces minimum and maximum nickname lengths. `DefaultNicknameLimits()` returns bounds of 3..32. `MaxNicknameLength` is 48, the hard ceiling imposed by the base-37 scalar encoding.

## Candidate Generation

`CandidatesFrom` generates a list of username candidates for a given nickname by drawing random discriminators from predefined ranges:

```go
candidates, err := usernames.CandidatesFrom("alice", usernames.DefaultNicknameLimits())
// Returns ~20 candidates like ["alice.37", "alice.841", "alice.5902", ...]
```

The discriminator ranges are defined in `discriminatorRanges` as 8 half-open intervals: [1,100), [100,1000), [1000,10000), and so on up to [100000000,1000000000). The `candidatesPerRange` array specifies how many random discriminators to draw from each range: `{4, 3, 3, 2, 2, 2, 2, 2}`, yielding 20 candidates total.

## Username Hash

`Hash()` returns a 32-byte compressed Ristretto255 point computed as a multi-scalar multiplication over three base points:

```
username_hash = username_sha_scalar * G1 + nickname_scalar * G2 + discriminator_scalar * G3
```

The three scalars are:

1. `username_sha_scalar`, SHA-512 of `nickname || 0x00 || discriminator_be64`, reduced to a Ristretto scalar via `SetUniformBytes`
2. `nickname_scalar`, the nickname encoded in base-37, where `_` maps to 1, `a-z` maps to 2-27, and `0-9` maps to 28-37
3. `discriminator_scalar`, the discriminator as a little-endian Ristretto scalar

The three base points `G1`, `G2`, `G3` are hardcoded compressed Ristretto255 points defined in `compressedBasePointsRaw`, decompressed at package init time.

```go
hash := u.Hash() // [32]byte
```

## Zero-Knowledge Proofs

The proof system demonstrates knowledge of the three scalars that produce a given `username_hash` without revealing the scalars themselves. It uses the `poksho.Statement` system.

### Proof Statement

The proof statement is:

```
username_hash = username_sha_scalar * G1 + nickname_scalar * G2 + discriminator_scalar * G3
```

This is constructed via `usernameProofStatement()` using `poksho.NewStatement()` with named scalar arguments `"username_sha_scalar"`, `"nickname_scalar"`, `"discriminator_scalar"` and named point arguments `"G1"`, `"G2"`, `"G3"`, `"username_hash"`.

### Generating a Proof

```go
var randomness [32]byte
// fill randomness from crypto/rand
proof, err := u.Proof(randomness)
```

The proof is a byte slice produced by `poksho.Statement.Prove`. The message bound into the proof transcript is the 32-byte compressed `username_hash` point.

### Verifying a Proof

```go
err := usernames.VerifyProof(proof, hash)
```

`VerifyProof` decompresses the hash to a Ristretto point, then calls `poksho.Statement.VerifyProof`. Returns `ProofVerificationFailure{}` on any failure (invalid point, proof mismatch, etc.).

## Username Links

Username links allow sharing a username via an encrypted blob. The encryption scheme uses AES-256-CBC with HMAC-SHA-256 authentication.

### Creating a Link

```go
entropy, encrypted, err := usernames.CreateForUsername("alice.42", nil)
```

If `entropy` is nil, 32 random bytes are generated. The encrypted buffer layout is:

```
[16-byte IV] [AES-256-CBC ciphertext] [32-byte HMAC-SHA-256]
```

Two 32-byte keys are derived from the entropy via HKDF-SHA-256 with no salt:
- Encryption key: info = `"Signal Username Link Encryption Key"`
- Authentication key: info = `"Signal Username Link Authentication Key"`

The plaintext is a protobuf-like encoding of the username with zero-byte padding to fill 48 bytes (3 AES blocks). PKCS#7 padding is applied before CBC encryption. The HMAC covers the IV and ciphertext.

### Decrypting a Link

```go
username, err := usernames.DecryptUsername(entropy, encrypted)
```

HMAC verification uses `crypto/subtle.ConstantTimeCompare`. PKCS#7 unpadding is also constant-time to prevent timing side channels.

## Nickname Validation Rules

| Rule | Error |
|------|-------|
| Nickname cannot be empty | `ErrNicknameCannotBeEmpty` |
| Cannot start with a digit | `ErrNicknameCannotStartWithDigit` |
| Only `a-z`, `A-Z`, `0-9`, `_` allowed | `ErrBadNicknameCharacter` |
| Shorter than NicknameLimits.minLen | `ErrNicknameTooShort` |
| Longer than NicknameLimits.maxLen | `ErrNicknameTooLong` |

## Discriminator Validation Rules

| Rule | Error |
|------|-------|
| Cannot be empty | `ErrDiscriminatorCannotBeEmpty` |
| Cannot be zero | `ErrDiscriminatorCannotBeZero` |
| Cannot be a single digit | `ErrDiscriminatorCannotBeSingleDigit` |
| No leading zeros (except 2-digit) | `ErrDiscriminatorCannotHaveLeadingZeros` |
| Must be all digits | `ErrBadDiscriminatorCharacter` |
| Overflow on parse | `ErrDiscriminatorTooLarge` |

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MaxNicknameLength` | 48 | Hard ceiling from base-37 scalar overflow |
| `UsernameLinkEntropySize` | 32 | Entropy length for username links |
| `usernameLinkKeySize` | 32 | AES-256 key size |
| `usernameLinkIVSize` | 16 | AES-CBC IV size |
| `usernameLinkHMACLen` | 32 | HMAC-SHA-256 output length |

## Error Types

| Error | Description |
|-------|-------------|
| `UsernameError` | Enum-style errors for nickname/discriminator validation |
| `ProofVerificationFailure` | ZK proof failed verification |
| `UsernameLinkError` | Enum-style errors for link encryption/decryption |
| `CryptoError` | RNG or cryptographic operation failure |
| `CBCDecryptError` | AES-CBC decryption validation failure |
| `PKCS7Error` | PKCS#7 padding validation failure |
| `ProtobufError` | Username data protobuf encoding/decoding failure |
