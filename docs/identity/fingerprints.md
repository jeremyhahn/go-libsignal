# Safety Number Fingerprints

Package `fingerprint` implements the Signal Protocol's safety number verification system. Safety numbers let two users verify that they are communicating directly, without a man-in-the-middle, by comparing a shared numeric code or scanning a QR code.

## Overview

A `Fingerprint` has two components:

- `Display`, a 60-digit numeric string for visual or voice comparison
- `Scannable`, a protobuf-encoded payload for QR code exchange

Both are derived from the same underlying SHA-512 hash of each party's identity key and stable identifier.

## Fingerprint Generation

`NumericFingerprintGenerator` performs the iterative SHA-512 computation defined by the Signal Protocol specification. Create one with `NewNumericFingerprintGenerator`:

```go
gen, err := fingerprint.NewNumericFingerprintGenerator(fingerprint.DefaultIterations)
```

`DefaultIterations` is 5200. The iteration count must be in the range (1, 1000000].

### Single Key

```go
fp, err := gen.CreateFor(
    2,                  // version (used in scannable fingerprint)
    localStableID,      // e.g., phone number bytes
    localIdentityKey,   // *identity.Key
    remoteStableID,
    remoteIdentityKey,
)
```

### Multiple Keys

When a party has multiple identity keys (e.g., across devices), use `CreateForMultiple`. Key bytes are concatenated in order before hashing.

```go
fp, err := gen.CreateForMultiple(
    2,
    localStableID,
    []*identity.Key{key1, key2},
    remoteStableID,
    []*identity.Key{key3},
)
```

## Hash Algorithm

The iterative SHA-512 computation works as follows:

```
iteration 0: SHA-512(version_bytes || key_bytes || stable_id || key_bytes)
iteration i: SHA-512(previous_hash || key_bytes)
```

`version_bytes` is the 2-byte big-endian encoding of 0 (`[0x00, 0x00]`), not the `version` parameter passed to `CreateFor`. The `version` parameter is only used in the scannable fingerprint.

The output is a 64-byte SHA-512 hash. The full 64 bytes feed the display fingerprint, while the first 32 bytes are used for the scannable fingerprint.

## Display Fingerprint

`Display` converts the 64-byte hash into a 30-digit numeric string per party (60 digits total). Each fingerprint byte slice must be at least 30 bytes (`minFingerprintLength`).

The encoding reads 6 chunks of 5 bytes at offsets 0, 5, 10, 15, 20, 25. Each chunk is converted to a `uint64` via `bytehelper.Bytes5ToInt64`, taken modulo 100000, and zero-padded to 5 digits.

`DisplayText()` returns the 60-digit string by concatenating both parties' 30-digit strings in lexicographic order. Both parties produce the same output regardless of which is "local" and which is "remote".

```go
display := fp.Display()
text := display.DisplayText() // e.g., "123450678901234506789012345067890..."
```

## Scannable Fingerprint

`Scannable` stores a version number and two 32-byte fingerprint hashes (the first 32 bytes of each party's SHA-512 output). It serializes to a protobuf `CombinedFingerprints` message containing:

- `version` (uint32)
- `local_fingerprint` (LogicalFingerprint with 32-byte content)
- `remote_fingerprint` (LogicalFingerprint with 32-byte content)

### Serialization

```go
data, err := fp.Scannable().Serialize()
```

### Deserialization

```go
scanned, err := fingerprint.DeserializeScannable(data)
```

### Comparison

`Compare` verifies a scanned fingerprint from the remote party. The remote party's "local" fingerprint should match our "remote" fingerprint and vice versa. Comparison uses `crypto/subtle.ConstantTimeCompare` to avoid timing side channels.

```go
match, err := myFingerprint.Scannable().Compare(scannedData)
```

Returns `false` without error if versions differ.

## Types

| Type | Description |
|------|-------------|
| `Fingerprint` | Container for `Display` and `Scannable` |
| `Display` | 60-digit numeric display fingerprint |
| `Scannable` | Protobuf-serializable QR code fingerprint |
| `NumericFingerprintGenerator` | Generator implementing `FingerprintGenerator` |
| `FingerprintGenerator` | Interface with `CreateFor` and `CreateForMultiple` |

## Error Types

| Error | Condition |
|-------|-----------|
| `FingerprintTooShortError` | Input byte slice < 30 bytes |
| `InvalidIterationCountError` | Iteration count <= 1 or > 1000000 |
| `ParsingError` | Protobuf decode failure or missing fields |
| `VersionMismatchError` | Scanned version does not match local |

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `DefaultIterations` | 5200 | Standard SHA-512 iteration count |
| `minFingerprintLength` | 30 | Minimum bytes for display encoding |
| `scannableFingerprintSize` | 32 | Bytes used from hash for scannable fingerprint |

## ServiceId

The `protocol` package defines `ServiceId`, which represents a Signal user's identity. These are the stable identifiers typically used as input to fingerprint generation.

A `ServiceId` has a `ServiceIdKind` (either `ServiceIdKindACI` = 0x00 for Account Identity, or `ServiceIdKindPNI` = 0x01 for Phone Number Identity) and a 16-byte UUID.

```go
id := protocol.NewACI(uuid)          // ACI ServiceId
id := protocol.NewPNI(uuid)          // PNI ServiceId
id, err := protocol.ServiceIdFromString(protocol.ServiceIdKindACI, "550e8400-e29b-41d4-a716-446655440000")
```

`FixedWidthBinary()` returns a 17-byte encoding (`[kind_byte][16_uuid_bytes]`) suitable for use as a stable identifier in fingerprint generation. `UUIDString()` returns the standard 8-4-4-4-12 dash format.
