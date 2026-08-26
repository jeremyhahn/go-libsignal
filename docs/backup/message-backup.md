# Message Backup

Package: `backup/`

Source files: `backup.go`, `key.go`, `frame.go`, `parse.go`, `purpose.go`, `export.go`, `forward_secrecy.go`, `scramble.go`, `errors.go`

## Key Derivation

Backup encryption keys are derived from an `AccountEntropyPool` through a three-step HKDF-SHA256 chain:

1. **BackupKey** (32 bytes): derived from the entropy pool with info label `"20240801_SIGNAL_BACKUP_KEY"` and no salt.
2. **BackupID** (16 bytes): derived from the BackupKey with info label `"20241024_SIGNAL_BACKUP_ID:"` concatenated with the ACI's 16-byte UUID (no prefix byte). Only ACI-type ServiceIds are accepted.
3. **MessageBackupKey**: derived from the BackupKey with the BackupID appended to the info label. Contains two 32-byte keys (HMAC key in bytes 0-31, AES key in bytes 32-63).

```
AccountEntropyPool
    |
    v  HKDF-SHA256(ikm=pool, salt=nil, info="20240801_SIGNAL_BACKUP_KEY")
 BackupKey [32 bytes]
    |
    v  HKDF-SHA256(ikm=backupKey, salt=nil, info="20241024_SIGNAL_BACKUP_ID:" || aci_uuid)
 BackupID [16 bytes]
    |
    v  HKDF-SHA256(ikm=backupKey, salt=fwdSecrecyToken|nil, info=dst || backupID)
 MessageBackupKey { HMACKey [32], AESKey [32] }
```

### Forward Secrecy Token

`DeriveMessageBackupKey` supports two modes:

- **Legacy** (no forward secrecy token): uses DST `"20241007_SIGNAL_BACKUP_ENCRYPT_MESSAGE_BACKUP:"` with no salt.
- **Modern** (with forward secrecy token): uses DST `"20250708_SIGNAL_BACKUP_ENCRYPT_MESSAGE_BACKUP:"` with the token as HKDF salt.

All key material is stored in locked memory (`secret.Secret`). Callers must call `Zeroize()` on `BackupKey`, `BackupID`, and `MessageBackupKey` when finished.

### Key Types

| Type | Size | Purpose |
|------|------|---------|
| `BackupKey` | 32 bytes | Intermediate key for deriving IDs and message keys |
| `BackupID` | 16 bytes | Per-account identifier for backup storage |
| `MessageBackupKey` | 64 bytes (2x32) | HMAC and AES keys for frame encryption |

## Encrypted Backup Format

An encrypted backup file is structured as:

```
[ 16-byte IV ] [ AES-256-CBC ciphertext ] [ 32-byte HMAC-SHA256 ]
```

The ciphertext contains gzip-compressed, varint-delimited protobuf frames. PKCS#7 padding is applied before AES-CBC encryption.

### Encryption (FrameEncryptor)

`FrameEncryptor.EncryptFrames`:

1. Write each protobuf frame as varint-delimited data into a gzip stream.
2. Close the gzip writer to flush and finalize compression.
3. Generate a random 16-byte IV via `crypto/rand`.
4. Apply PKCS#7 padding to the compressed data.
5. Encrypt with AES-256-CBC using the `MessageBackupKey.AESKey`.
6. Compute HMAC-SHA256 over (IV || ciphertext) using `MessageBackupKey.HMACKey`.
7. Write IV, ciphertext, and HMAC to the output writer.

### Decryption (FrameDecryptor)

`FrameDecryptor.DecryptFrames`:

1. Read the entire input into memory.
2. Validate minimum size (16 + 32 = 48 bytes for IV + HMAC).
3. Split into content (IV + ciphertext) and the trailing 32-byte HMAC.
4. Verify the HMAC using `crypto/subtle.ConstantTimeCompare` (constant-time).
5. Decrypt with AES-256-CBC.
6. Remove PKCS#7 padding (constant-time validation to prevent timing side-channels).
7. Decompress with gzip.
8. Parse varint-delimited frames.

### HMAC Verification

`VerifyHMAC` checks the integrity of an encrypted backup without decrypting it. The `HMACMismatchError` type keeps the expected and computed HMAC values unexported to prevent accidental leakage through logging.

### PKCS#7 Padding Security

The `pkcs7Unpad` function validates padding in constant time using `crypto/subtle.ConstantTimeLessOrEq` and `ConstantTimeByteEq`. It iterates over exactly `blockSize` bytes (16 for AES) regardless of the actual padding length, preventing timing side-channels.

## Frame Size Cap

`VarintDelimitedReader` enforces a maximum frame size of 10 MiB (`maxFrameSize = 10 * 1024 * 1024`). Any varint-delimited frame exceeding this limit returns a `FrameTooLargeError`. This prevents a malicious varint from triggering multi-GiB allocations. Normal backup frames are well below this limit.

```go
const maxFrameSize = 10 * 1024 * 1024 // 10 MiB
```

The varint reader also caps varint values to `uint32` range (`maxVarintValue = 1<<32 - 1`).

## Varint-Delimited I/O

`VarintDelimitedReader` reads protobuf-style varint-length-prefixed messages from an `io.Reader`. It maintains an internal 10-byte buffer for varint parsing. `WriteVarintDelimited` performs the inverse operation for writing.

## Backup Purpose

The `Purpose` type distinguishes between two use cases:

- `PurposeDeviceTransfer` (0): backup for device-to-device transfer.
- `PurposeRemoteBackup` (1): backup stored on a remote server.

`ParsePurpose` accepts multiple string forms: `"backup"`, `"remote_backup"`, `"remote-backup"` for remote; `"transfer"`, `"device_transfer"`, `"device-transfer"` for device transfer.

## Padded Length

`PaddedLength` rounds a content length up using exponential bucketing to obscure the exact size of a backup. It computes `floor(1.05^ceil(log_1.05(contentLength)))` with a minimum output of 541. This matches the Rust reference implementation's `f64` arithmetic.

## Export Helpers

The `export.go` file provides standalone helpers for building backup exports:

- `GzipCompress`: gzip-compresses raw data.
- `PadGzippedBucketed`: pads gzipped data to the bucketed length from `PaddedLength`.
- `AESCBCEncryptExport`: delegates to `cipher.AESCBCEncrypt` with 32-byte key and 16-byte IV.
- `HMACChecksum`: computes HMAC-SHA256 over (IV || encryptedContents).

## Forward Secrecy Format

Backups using forward secrecy are identified by the magic number `"SBACKUP\x01"` (8 bytes). The `DetectFormat` function reads the first 8 bytes to determine whether a backup uses the modern forward secrecy format or the legacy ciphertext-only format.

### BackupMetadata

The metadata structure appears after the magic number and before the encrypted data:

```go
type BackupMetadata struct {
    IV    []byte              // 12 bytes (GCM nonce)
    Pairs []ForwardSecrecyPair // 1 or 2 pairs
}

type ForwardSecrecyPair struct {
    CT     []byte // 48 bytes (32-byte token + 16-byte MAC)
    PWSalt []byte // 32 bytes (SHA-256 output size)
}
```

`ValidateMetadata` enforces:
- At least 1 pair, at most 2 (`maxForwardSecrecyPairs = 2`).
- Each pair's CT must be exactly 48 bytes (`BackupForwardSecrecyTokenLen + ctMACLen`).
- Each pair's PWSalt must be exactly 32 bytes.
- IV must be exactly 12 bytes.

Two pairs is the common case (current key + replacement). One pair occurs when there is no key currently on the service.

`IsCloseToMagicNumber` detects files that start with `"SBACKUP"` but have a different version byte, useful for warning about potentially misidentified backup files.

## Scrambling

The `Scrambler` type replaces sensitive backup data with deterministic replacements for testing and anonymization. It uses a seeded PRNG (xoshiro256-style) for deterministic output.

Replacement strategies:
- **E164 phone numbers**: sequential replacement starting at `+15555550100`, consistent across the backup.
- **ServiceIds/UUIDs**: random v4 UUIDs, preserving the type prefix byte for non-ACI ServiceIds. Nil (all-zero) UUIDs are left unchanged.
- **Usernames**: sequential `"user.XX"` format.
- **Strings**: alphanumeric replacements of the same length.
- **Content types**: major type preserved, subtype replaced with `"unknown"` (e.g., `"image/jpeg"` becomes `"image/unknown"`).
- **Body text**: replaced with `"https://signal.org: Why use Signal?"`.
- **Emoji**: replaced with the red X emoji (`U+274C`).
- **URLs**: replaced with `"https://signal.org"`.

`CryptoRandomUUID` and `CryptoRandomizeBytes` use `crypto/rand` for cases requiring true randomness.

## BackupReader

`BackupReader` wraps a `VarintDelimitedReader` and tracks the backup's `Purpose`. Two constructors are available:

- `NewBackupReader(r, purpose)`: reads from a plaintext (unencrypted) stream.
- `NewEncryptedBackupReader(key, r, purpose)`: decrypts first, then yields frames.

`ReadResult` pairs the read outcome with any `FoundUnknownField` entries encountered during protobuf parsing, recording the frame index and the path within the protobuf message where the unknown field was found.

## Error Types

All errors use typed structs. Key error types:

| Error Type | Description |
|------------|-------------|
| `Error` | General backup error with `ErrorKind` (Validation, Parse, NoFrames, InvalidProtobuf, HMACMismatch) |
| `HMACMismatchError` | HMAC verification failed (values kept unexported) |
| `FrameTooLargeError` | Frame exceeds 10 MiB cap |
| `ForwardSecrecyError` | Forward secrecy metadata validation failure |
| `ExportError` | Export operation failure |
| `ScramblerError` | Scrambling operation failure |
