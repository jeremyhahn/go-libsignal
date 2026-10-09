# ZK Groups

> **Status: REFERENCE** · Last verified: 2026-10-09
> As-built description of go-libsignal code owned by this repository.

Package `zkgroup` provides the higher-level API for Signal's Private Group System. It wraps the `zkcredential` package with application-specific credential types for authentication, profile keys, receipts, group send endorsements, backups, and call links.

All types in zkgroup are serialized with a leading reserved byte (0x00) via `Serialize`/`Deserialize`. Timestamps should be day-aligned (multiples of `SecondsPerDay` = 86400) to avoid fingerprinting.

## Server Parameters

### ServerSecretParams

`ServerSecretParams` holds all server-side key pairs for issuing credentials. Generated from 32 bytes of randomness:

```go
var randomness zkgroup.RandomnessBytes
// fill from crypto/rand
params, err := zkgroup.GenerateServerSecretParams(randomness)
```

Key generation follows the Rust reference implementation exactly. Legacy credential key pairs are drawn from a shared SHO (`"Signal_ZKGroup_20200424_Random_ServerSecretParams_Generate"`), consuming state in this order:

1. `AuthCredentialsKeyPair` (storageLen=4, numAttrs=3)
2. `ProfileKeyCredentialsKeyPair` (storageLen=4, numAttrs=5)
3. `SigKeyPair` (Ed25519 signature key, drawn from same SHO)
4. `ReceiptCredentialsKeyPair` (storageLen=4, numAttrs=4)
5. `PniCredentialsKeyPair` (storageLen=6, numAttrs=6)
6. `ExpiringProfileKeyCredentialsKeyPair` (storageLen=6, numAttrs=6)
7. `AuthCredentialsWithPniKeyPair` (storageLen=6, numAttrs=6)

`GenericCredentialKeyPair` and `EndorsementKeyPair` use the randomness bytes directly (independent SHO), not chained through the shared SHO.

All legacy credentials (those with `numAttrs <= 6`) automatically use the hardcoded `LegacySystemParams` from the Rust reference implementation, not SHO-derived parameters.

### ServerPublicParams

```go
publicParams := params.GetPublicParams()
```

Contains public keys for all credential types plus the `EndorsementPublicKey` (`*zkcredential.ServerRootPublicKey`).

## Auth Credentials

Auth credentials bind an ACI (Account Identity) and PNI (Phone Number Identity) together with a redemption time. The current version is `AuthCredentialWithPniVersionZkc` (version 3), using the zkcredential system with label `"20240222_Signal_AuthCredentialZkc"`.

### Types

| Type | Description |
|------|-------------|
| `AuthCredentialWithPniZkc` | Credential binding ACI + PNI + redemption time |
| `AuthCredentialWithPniZkcResponse` | Server's issuance response |
| `AuthCredentialWithPniZkcPresentation` | Client's presentation to server |
| `AuthCredentialWithPni` | Version-tagged wrapper |

### Presentation Versions

| Constant | Value |
|----------|-------|
| `PresentationVersion1` | 0 |
| `PresentationVersion2` | 1 |
| `PresentationVersion3` | 2 |
| `PresentationVersion4` | 3 |

## Profile Key Credentials

Profile key credentials prove that a user possesses a specific profile key without revealing it to the server during issuance. The issuance protocol uses blind issuance (section 5.9 of Chase-Perrin-Zaverucha) to hide the profile key from the issuing server.

### Request Flow

1. Client generates a `profileKeyCredentialRequestKeyPair` with secret scalar `y` and public point `Y = y * G`
2. Client blinds profile key struct points as `(D1 = r1 * G, D2 = r1 * Y + M3)` and `(E1 = r2 * G, E2 = r2 * Y + M4)`
3. Server issues a `blindedExpiringProfileKeyCredential` with blinded MAC values `(t, U, S1, S2)`
4. Client unblinds: `V = S2 - y * S1`

The credential type `ExpiringProfileKeyCredential` binds the profile key to an ACI and an expiration time.

## Receipt Credentials

Receipt credentials prove purchase of a subscription or donation. The receipt serial bytes are hidden from the server during issuance via blind issuance.

### Types

| Type | Description |
|------|-------------|
| `ReceiptCredential` | Credential with expiration time and receipt level |
| `ReceiptLevel` | `uint64` identifying what to redeem |

The request uses a `receiptCredentialRequestKeyPair` to blind the serial bytes. The server responds with a `blindedReceiptCredential` that the client unblinds.

## Group Send Endorsements

Group send endorsements authorize a user to send messages to specific group members. The server issues endorsements for all group members at once, and the client combines individual endorsements into tokens.

### Expiration

```go
expiration := zkgroup.DefaultExpiration(currentTime)
```

`DefaultExpiration` computes an expiration at the start of the day, 2 days ahead. If fewer than 25 hours remain until that boundary, it adds another day.

### Key Derivation

```go
derived, err := zkgroup.ForExpiration(expiration, rootKeyPair)
```

Derives a `GroupSendDerivedKeyPair` by hashing the expiration through `groupSendDerivedKeyPairTagInfo` with label `"20240215_Signal_GroupSendEndorsement"`.

### Types

| Type | Description |
|------|-------------|
| `GroupSendDerivedKeyPair` | Derived key + expiration |
| `GroupSendEndorsementsResponse` | Endorsements + expiration |

### Point Sorting

`sortPoints` establishes a deterministic ordering over Ristretto255 points by doubling each point and comparing the compressed 32-byte representations lexicographically. This matches Rust's `double_and_compress_batch` approach.

## Backup Credentials

Backup credentials authorize access to message and media backup services. The backup ID is a 16-byte identifier derived from the client's entropy pool.

### Types

| Type | Description |
|------|-------------|
| `BackupLevel` | `BackupLevelFree` (200) or `BackupLevelPaid` (201) |
| `BackupCredentialType` | `BackupCredentialTypeMessages` (1) or `BackupCredentialTypeMedia` (2) |
| `BackupID` | 16-byte backup identifier |
| `BackupAuthCredentialRequestContext` | Client-side request state |

The credential label is `"20231003_Signal_BackupAuthCredential"`. The backup ID is converted to a Ristretto255 point via SHO with label `"20231003_Signal_BackupId"` and used as a revealed attribute in the blind issuance protocol.

## Call Link Credentials

Call link credentials bind a user's ACI to a call link room. The call link has secret parameters derived from a root key.

### Secret Parameters

```go
params, err := zkgroup.DeriveCallLinkSecretParams(rootKey)
```

Derives a `CallLinkSecretParams` containing a `UIDEncKeyPair` from the root key (up to `CallLinkRootKeyMaxBytesForSHO` = 16 bytes) using the label `"Signal_ZKGroup_20230419_CallLinkSecretParams_DeriveFromRootKey"`.

### Types

| Type | Description |
|------|-------------|
| `CallLinkSecretParams` | UID encryption key pair |
| `CallLinkPublicParams` | UID encryption public key |

Credential labels:
- Auth: `"20230421_Signal_CallLinkAuthCredential"`
- Create: `"20230413_Signal_CreateCallLinkCredential"`

## Common Types

### ServiceID

`ServiceID` represents a Signal user identity (ACI or PNI) within zkgroup:

```go
aci := zkgroup.NewACI(uuid)
pni := zkgroup.NewPNI(uuid)
binary := aci.ServiceIdBinary() // 16 bytes for ACI, 17 bytes for PNI
```

`ServiceIdBinary()` returns the raw UUID for ACI, or `[0x01 || UUID]` for PNI.

### Timestamp

```go
ts := zkgroup.NewTimestamp(epochSeconds)
ts.IsDayAligned()                    // true if seconds % 86400 == 0
ts.SaturatingSecondsSince(earlier)   // 0 if earlier is after ts
```

`Timestamp` implements `zkcredential.PublicAttribute` via `HashInto`, absorbing its 8-byte big-endian representation.

### Scalar Encoding

- `scalarFromBytesModOrder(input)`: interprets a 32-byte little-endian value mod the Ed25519 group order L
- `encodeRedemptionTime(u32)`: big-endian u32 in first 4 bytes of a 32-byte array, then mod-L reduction
- `encodeReceiptSerialBytes(serial)`: first 16 bytes into a 32-byte array, then mod-L reduction

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `RandomnessLen` | 32 | Required randomness length |
| `UUIDLen` | 16 | UUID byte length |
| `ProfileKeyLen` | 32 | Profile key byte length |
| `GroupMasterKeyLen` | 32 | Group master key byte length |
| `GroupIdentifierLen` | 32 | Group identifier byte length |
| `SignatureLen` | 64 | Ed25519 signature byte length |
| `SecondsPerDay` | 86400 | Seconds in a UTC day |
| `AccessKeyLen` | 16 | Access key byte length |
| `ReceiptSerialLen` | 16 | Receipt serial byte length |

## Error Types

| Error | Description |
|-------|-------------|
| `ErrDataTooShort` | Serialized data shorter than minimum |
| `ErrUnexpectedReservedByte` | Leading byte is not 0x00 |
| `ZkGroupVerificationFailure` | Credential verification failed |
| `ErrGeneratingSignatureKeyPair` | Signature key pair generation failure |
| `ErrGeneratingEndorsementKeyPair` | Endorsement key pair generation failure |
