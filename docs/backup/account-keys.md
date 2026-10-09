# Account Keys

> **Status: REFERENCE** · Last verified: 2026-10-09
> As-built description of go-libsignal code owned by this repository.

Package: `accountkeys/`

Source files: `accountkeys.go`, `backup_forward_secrecy.go`, `errors.go`

## Account Entropy Pool

`AccountEntropyPool` is a 64-character lowercase alphanumeric string (`[0-9a-z]`) that serves as the root entropy for deriving backup and SVR keys.

### Generation

`GenerateAccountEntropyPool` uses cryptographically random bytes in locked memory with rejection sampling to avoid modulo bias. The alphabet has 36 characters; bytes < 252 (36 * 7) are accepted, others are rejected. The resulting pool string is copied out and the guarded buffer is destroyed.

### Validation

`AccountEntropyPool.Validate` checks that the pool is exactly 64 runes, each in the range `[0-9a-z]`.

## PIN Hashing

### Argon2id (Remote SVR Authentication)

`HashPin` derives an encryption key and an access key from a PIN and a 32-byte salt using Argon2id:

| Parameter | Value |
|-----------|-------|
| Time cost | 32 iterations |
| Memory | 16384 KiB (16 MiB) |
| Parallelism | 1 |
| Output length | 64 bytes |

The 64-byte Argon2id output is split:
- Bytes 0-31: `EncryptionKey` (for local encryption)
- Bytes 32-63: `AccessKey` (for SVR authentication)

Both halves are stored in `secret.Secret` (guarded memory). The full 64-byte Argon2id output is moved into guarded memory immediately and zeroized from the heap. Each half is copied out before creating individual secrets.

`VerifyPin` re-hashes the PIN with the same salt and performs a constant-time comparison against the expected access key.

### Argon2i (Local Screen Lock)

`LocalPinHash` creates a PHC-string encoded hash for local screen lock verification:

| Parameter | Value |
|-----------|-------|
| Algorithm | Argon2i |
| Time cost | 64 iterations |
| Memory | 512 KiB |
| Parallelism | 1 |
| Output length | 32 bytes |
| Salt length | 16 bytes (random) |

Output format: `$argon2i$v=19$m=512,t=64,p=1$<base64_salt>$<base64_hash>`

`VerifyLocalPinHash` parses the PHC string, re-derives the hash, and performs a constant-time comparison.

### PIN Normalization

`normalizePin` follows the Rust reference implementation:

1. Trim leading and trailing whitespace.
2. Transliterate non-ASCII Unicode decimal digits to ASCII equivalents. For example, Arabic-Indic digits (U+0660-U+0669) map to `0`-`9`. The function finds the zero digit of each Unicode block by walking back through contiguous digit ranges.
3. Apply NFKD normalization via `golang.org/x/text/unicode/norm`.

### Salt Generation

`MakeSalt` generates a 32-byte salt from a username and group ID using HKDF-SHA256 with the username as IKM and the group ID (big-endian 8 bytes) as salt, with empty info.

## HKDF Key Derivation

`AccountEntropyPool` derives two keys:

- `DeriveSVRKey()`: 32-byte SVR key. HKDF-SHA256 with info `"20240801_SIGNAL_SVR_MASTER_KEY"`, no salt.
- `DeriveBackupKey()`: 32-byte backup key. HKDF-SHA256 with info `"20240801_SIGNAL_BACKUP_KEY"`, no salt.

Both return `*secret.Secret` in guarded memory. Callers must destroy the returned secret when done.

The internal `hkdfExpandInto` function panics on failure, since HKDF-SHA256 supports up to 8160 bytes of output and all callers request 64 bytes or fewer.

## Backup Forward Secrecy

### BackupKey

`BackupKey` is the primary key for backup operations, derived from an `AccountEntropyPool`:

```go
type BackupKey struct {
    data *secret.Secret  // 32 bytes, guarded
}
```

`DeriveBackupKeyFromEntropyPool` derives it using HKDF-SHA256 with info `"20240801_SIGNAL_BACKUP_KEY"`.

### Derived Keys

From a `BackupKey`, the following can be derived:

| Method | Output Size | HKDF Info Label |
|--------|-------------|-----------------|
| `DeriveBackupId(aci)` | 16 bytes | `"20241024_SIGNAL_BACKUP_ID:" \|\| aci` |
| `DeriveECKey(aci)` | 32 bytes | `"20241024_SIGNAL_BACKUP_ID_KEYPAIR:" \|\| aci` |
| `DeriveLocalBackupMetadataKey()` | 32 bytes | `"20241011_SIGNAL_LOCAL_BACKUP_METADATA_KEY"` |
| `DeriveMediaId(mediaName)` | 15 bytes | `"20241007_SIGNAL_BACKUP_MEDIA_ID:" \|\| mediaName` |
| `DeriveMediaEncryptionKeyData(mediaId)` | 64 bytes | `"20241007_SIGNAL_BACKUP_ENCRYPT_MEDIA:" \|\| mediaId` |
| `DeriveThumbnailTransitEncryptionKeyData(mediaId)` | 64 bytes | `"20241030_SIGNAL_BACKUP_ENCRYPT_THUMBNAIL:" \|\| mediaId` |
| `DeriveForwardSecrecyPassword(salt)` | 32 bytes | `"Signal Message Backup 20250627:SVR PIN"` |
| `DeriveForwardSecrecyEncryptionKey(salt)` | 64 bytes (2x32) | `"Signal Message Backup 20250627:BackupForwardSecrecyToken Encryption Key"` |

All methods that return `*secret.Secret` require the caller to destroy the secret when done. `DeriveBackupId` requires the ACI to be exactly 16 raw UUID bytes.

### Forward Secrecy Key Derivation

`DeriveForwardSecrecyPassword` derives a 32-byte password used to protect forward secrecy tokens within secure storage. The salt is provided by the caller.

`DeriveForwardSecrecyEncryptionKey` produces a `BackupForwardSecrecyEncryptionKey` containing:
- `CipherKey`: 32-byte AES key (first half of 64-byte HKDF output)
- `HMACKey`: 32-byte HMAC key (second half)

Both are stored in guarded memory. The full 64-byte HKDF output is allocated in guarded memory, split, and then destroyed.

### Forward Secrecy Token

`BackupForwardSecrecyToken` is a 32-byte token stored in a secure enclave. It is used as HKDF salt when deriving `MessageBackupKey` in the modern backup format.

```go
const BackupForwardSecrecyTokenLength = 32

type BackupForwardSecrecyToken struct {
    data [32]byte
}
```

### Media Encryption Keys

The 64-byte media encryption key from `DeriveMediaEncryptionKeyData` is split into:
- First 32 bytes: HMAC key
- Last 32 bytes: AES-CBC key

The same layout applies to thumbnail transit encryption keys.

## PinHash Type

```go
type PinHash struct {
    EncryptionKey *secret.Secret  // bytes 0-31 of Argon2id output
    AccessKey     *secret.Secret  // bytes 32-63 of Argon2id output
}
```

Call `PinHash.Zeroize()` to destroy both keys when no longer needed.
