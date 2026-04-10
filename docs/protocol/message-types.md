# Protocol Message Types

The `protocol/` package defines the message types used in the Signal Protocol wire format.

Source files: `protocol/CiphertextMessage.go`, `protocol/SignalMessage.go`, `protocol/PreKeySignalMessage.go`, `protocol/SenderKeyMessage.go`, `protocol/SenderKeyDistributionMessage.go`, `protocol/DecryptionErrorMessage.go`, `protocol/PlaintextContent.go`, `protocol/ServiceId.go`, `protocol/errors.go`

## Version Constants

Defined in `protocol/CiphertextMessage.go`:

| Constant | Value | Description |
|----------|-------|-------------|
| `UnsupportedVersion` | 1 | Rejected on all deserialization paths |
| `PreKyberVersion` | 3 | Minimum supported version (backward-compatible, no Kyber) |
| `CurrentVersion` | 4 | PQXDH-aware version with Kyber key exchange |
| `SenderKeyCurrentVersion` | 3 | Version used for SenderKey group messages |

Version validation applies only on the deserialization path (`NewXxxFromBytes`). Constructor paths (`NewXxx`) do not enforce version bounds, matching the Rust reference where `try_from` validates and `new` does not.

Accepted version range for `SignalMessage` and `PreKeySignalMessage`: `[PreKyberVersion, CurrentVersion]` (i.e., 3 and 4).

Accepted version range for `SenderKeyMessage` and `SenderKeyDistributionMessage`: exactly `SenderKeyCurrentVersion` (3).

## Message Type Constants

Defined in `protocol/CiphertextMessage.go`:

| Constant | Value | Type |
|----------|-------|------|
| `WHISPER_TYPE` | 2 | `SignalMessage` |
| `PREKEY_TYPE` | 3 | `PreKeySignalMessage` |
| `SENDERKEY_DISTRIBUTION_TYPE` | 5 | `SenderKeyDistributionMessage` |
| `SENDERKEY_TYPE` | 7 | `SenderKeyMessage` |
| `PLAINTEXT_TYPE` | 8 | `PlaintextContent` |

## CiphertextMessage Interface

All encrypted message types implement:

```go
type CiphertextMessage interface {
    Serialize() ([]byte, error)
    Type() uint32
}
```

`Type()` returns one of the message type constants above. `Serialize()` produces the wire-format bytes for transmission.

## Wire Format Version Encoding

The version byte is the first byte in the serialized form of `SignalMessage`, `PreKeySignalMessage`, `SenderKeyMessage`, and `SenderKeyDistributionMessage`. It encodes two version numbers:

```
version_byte = (message_version << 4) | current_version
```

The high nibble carries the message's own version. The low nibble carries the library's `CurrentVersion` (or `SenderKeyCurrentVersion` for SenderKey messages). On deserialization, the version is extracted as `serialized[0] >> 4`.

## SignalMessage

File: `protocol/SignalMessage.go`

The primary encrypted message type, used after a session is established. Wire format:

```
[version_byte] [protobuf_body] [mac]
```

The MAC is the last 8 bytes (`macLength = 8`). The protobuf body is defined in `proto/wire.proto` as:

```protobuf
message SignalMessage {
  optional bytes  ratchet_key      = 1;
  optional uint32 counter          = 2;
  optional uint32 previous_counter = 3;
  optional bytes  ciphertext       = 4;
  optional bytes  pq_ratchet       = 5;
}
```

Field `pq_ratchet` (field 5) carries the SPQR post-quantum ratchet key. It is omitted when SPQR is not active.

### MAC Calculation

`getMac()` computes HMAC-SHA256 over:
- For version >= 3: `sender_identity_public_key || receiver_identity_public_key || serialized_message`
- For version < 3: `serialized_message` only

The MAC key must be exactly 32 bytes. The output is truncated to 8 bytes. MAC verification uses `hmac.Equal` for constant-time comparison.

### Construction vs Deserialization

- `NewSignalMessage(...)`, the constructor path: builds the message, computes the MAC, does not validate version.
- `NewSignalMessageFromBytes(serialized, serializer)`, the deserialization path: validates version in `[PreKyberVersion, CurrentVersion]`, rejects with `ErrLegacyVersion` or `ErrUnrecognizedVersion`.

## PreKeySignalMessage

File: `protocol/PreKeySignalMessage.go`

Used for session establishment. Wraps a `SignalMessage` inside a pre-key envelope. Wire format:

```
[version_byte] [protobuf_body]
```

No trailing MAC (the inner `SignalMessage` carries its own MAC).

```protobuf
message PreKeySignalMessage {
  optional uint32 registration_id   = 5;
  optional uint32 pre_key_id        = 1;
  optional uint32 signed_pre_key_id = 6;
  optional uint32 kyber_pre_key_id  = 7;
  optional bytes  kyber_ciphertext  = 8;
  optional bytes  base_key          = 2;
  optional bytes  identity_key      = 3;
  optional bytes  message           = 4;
}
```

### PQXDH Enforcement

On deserialization (`NewPreKeySignalMessageFromBytes`), version 4+ messages must include both `kyber_pre_key_id` and `kyber_ciphertext`. Missing either produces `ErrMissingKyberPayload`.

On construction (`NewPreKeySignalMessageFromStruct`), the Kyber fields must be symmetrically present or absent (both set or both nil). Asymmetric presence produces `ErrIncompleteMessage`.

### Structure Fields

```go
type PreKeySignalMessageStructure struct {
    RegistrationID  uint32
    PreKeyID        *optional.Uint32   // One-time pre-key, may be nil/empty
    SignedPreKeyID  uint32
    BaseKey         []byte             // Sender's ephemeral base key
    IdentityKey     []byte             // Sender's identity public key
    Message         []byte             // Serialized inner SignalMessage
    Version         int
    KyberPreKeyID   *optional.Uint32   // PQXDH Kyber pre-key ID
    KyberCiphertext []byte             // PQXDH Kyber ciphertext
}
```

## SenderKeyMessage

File: `protocol/SenderKeyMessage.go`

Used for group messaging with SenderKey. Wire format:

```
[version_byte] [protobuf_body] [signature]
```

The signature is the last 64 bytes (`SenderKeySignatureLength = 64`), an Ed25519 signature over the serialized message (excluding the signature itself). On deserialization, the minimum message length is `1 + 64` bytes.

```protobuf
message SenderKeyMessage {
  optional bytes  distribution_uuid = 1;
  optional uint32 chain_id          = 2;
  optional uint32 iteration         = 3;
  optional bytes  ciphertext        = 4;
}
```

`Serialize()` returns the message without the signature (used for signing/verification). `SignedSerialize()` returns the message with the signature appended (used for transmission).

## SenderKeyDistributionMessage

File: `protocol/SenderKeyDistributionMessage.go`

Distributed to group members to establish the SenderKey session. Wire format:

```
[version_byte] [protobuf_body]
```

```protobuf
message SenderKeyDistributionMessage {
  optional bytes  distribution_uuid = 1;
  optional uint32 chain_id          = 2;
  optional uint32 iteration         = 3;
  optional bytes  chain_key         = 4;
  optional bytes  signing_key       = 5;
}
```

Field validation on deserialization:
- `chain_key` must be exactly 32 bytes
- `signing_key` must be exactly 33 bytes (0x05 type prefix + 32 key bytes)

## DecryptionErrorMessage

File: `protocol/DecryptionErrorMessage.go`

Sent when a message fails to decrypt, allowing the sender to potentially resend. Serialized directly via protobuf (defined in `proto/service.proto`), not using the version-byte wire format.

```go
type DecryptionErrorMessage struct {
    ratchetKey ecc.ECPublicKeyable  // optional, may be nil
    timestamp  uint64
    deviceID   uint32
}
```

`DeserializeDecryptionErrorMessage(data)` returns `EmptyMessageError` if data is empty. The ratchet key is optional and parsed from the protobuf field if present.

## PlaintextContent

File: `protocol/PlaintextContent.go`

Wraps unencrypted content (type 8). Used for protocol-level messages like `DecryptionErrorMessage` that do not need encryption. Wire format:

```
[version_byte] [body]
```

The version byte uses the same encoding as other messages: `(CurrentVersion << 4) | CurrentVersion`. The body is everything after the version byte.

`NewPlaintextContentFromBytes(serialized)` returns `ContentTooShortError` if the input is empty.

## ServiceId

File: `protocol/ServiceId.go`

Identifies Signal users. Two kinds:

| Kind | Byte Value | Description |
|------|------------|-------------|
| `ServiceIdKindACI` | `0x00` | Account Identity |
| `ServiceIdKindPNI` | `0x01` | Phone Number Identity |

### Representations

- **String format**: `"ACI:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"` or `"PNI:..."` (via `String()`)
- **UUID string**: `"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"` (via `UUIDString()`)
- **Fixed-width binary**: 17 bytes `[kind_byte][16_uuid_bytes]` (via `FixedWidthBinary()`)

`ServiceIdFromString(kind, uuidStr)` accepts both dashed (`8-4-4-4-12`) and plain 32-character hex UUID strings.

`ServiceIdFromFixedWidthBinary(data)` rejects unknown kind bytes with `ServiceIdParseError`.

## Error Types

All protocol errors use the typed `protocol.Error` struct with `errors.Is` support via kind matching:

| Sentinel | Condition |
|----------|-----------|
| `ErrLegacyVersion` | Version below `PreKyberVersion` |
| `ErrUnrecognizedVersion` | Version above `CurrentVersion` |
| `ErrIncompleteMessage` | Missing required fields |
| `ErrMissingKyberPayload` | Version 4+ PreKeySignalMessage missing Kyber fields |
| `ErrBadMac` | HMAC verification failed |
| `ErrInvalidMacKeyLength` | MAC key not 32 bytes |
| `ErrInvalidKeyLength` | Key field has wrong length |
| `ErrMessageTooShort` | Serialized message too short |

Other error types:
- `ServiceIdParseError`, failure parsing a ServiceId
- `EmptyMessageError`, empty data when content expected
- `ContentTooShortError`, content too short to parse
