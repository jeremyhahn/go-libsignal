# Serialization Framework

> **Status: REFERENCE** · Last verified: 2026-10-09
> As-built description of go-libsignal code owned by this repository.

The `serialize/` package provides serialization and deserialization for all Signal Protocol objects. The `proto/` package defines the protobuf schemas.

Source files: `serialize/Serializer.go`, `serialize/ProtobufSerializer.go`, `serialize/JSONSerializer.go`, `serialize/errors.go`

Proto definitions: `proto/wire.proto`, `proto/storage.proto`, `proto/sealed_sender.proto`, `proto/service.proto`, `proto/fingerprint.proto`

## Architecture

The serialization layer uses an interface-based design. Each message and record type defines its own serializer interface (e.g., `protocol.SignalMessageSerializer`, `record.SessionSerializer`). The `serialize.Serializer` struct aggregates all of these into a single container:

```go
type Serializer struct {
    SenderKeyRecord              groupRecord.SenderKeySerializer
    SenderKeyState               groupRecord.SenderKeyStateSerializer
    SignalMessage                protocol.SignalMessageSerializer
    PreKeySignalMessage          protocol.PreKeySignalMessageSerializer
    SenderKeyMessage             protocol.SenderKeyMessageSerializer
    SenderKeyDistributionMessage protocol.SenderKeyDistributionMessageSerializer
    SignedPreKeyRecord           record.SignedPreKeySerializer
    PreKeyRecord                 record.PreKeySerializer
    State                        record.StateSerializer
    Session                      record.SessionSerializer
}
```

Two implementations exist: `NewProtobufSerializer()` and `NewJSONSerializer()`. The protobuf serializer is used in production. The JSON serializer is available for debugging and testing.

## Protobuf Schemas

### Wire Messages (`proto/wire.proto`)

Uses `proto2` syntax (optional fields). These define the on-the-wire message format:

- `SignalMessage`: ratchet_key, counter, previous_counter, ciphertext, pq_ratchet
- `PreKeySignalMessage`: registration_id, pre_key_id, signed_pre_key_id, kyber_pre_key_id, kyber_ciphertext, base_key, identity_key, message
- `SenderKeyMessage`: distribution_uuid, chain_id, iteration, ciphertext
- `SenderKeyDistributionMessage`: distribution_uuid, chain_id, iteration, chain_key, signing_key

### Storage Records (`proto/storage.proto`)

Uses `proto3` syntax. These define the at-rest storage format:

- `SessionStructure`: full session state including chains, keys, pending pre-key state, PQ ratchet state
- `RecordStructure`: wraps a current `SessionStructure` and repeated opaque-bytes previous sessions
- `PreKeyRecordStructure`: id, public_key, private_key
- `SignedPreKeyRecordStructure`: id, public_key, private_key, signature, timestamp
- `SenderKeyStateStructure`: message_version, chain_id, sender_chain_key, sender_signing_key, sender_message_keys
- `SenderKeyRecordStructure`: repeated sender_key_states

`RecordStructure.previous_sessions` stores each previous session as opaque bytes (`repeated bytes`), not as inline `SessionStructure` messages. Each entry is independently serialized and deserialized as a `SessionStructure`.

## Protobuf Serializer Details

### SignalMessage

The `ProtobufSignalMessageSerializer` handles the Signal wire format, which is not raw protobuf:

**Serialize**: `version_byte || protobuf_body || mac`

- `version_byte` = `(message_version << 4) | CurrentVersion`
- `protobuf_body` = proto-marshaled `wirepb.SignalMessage`
- `mac` = the 8-byte MAC from the structure

**Deserialize**: Splits the input into version byte (first byte), MAC (last 8 bytes), and protobuf body (everything between). Extracts the version as `serialized[0] >> 4`.

### PreKeySignalMessage

**Serialize**: `version_byte || protobuf_body`

- Same version encoding as SignalMessage
- No trailing MAC (the inner SignalMessage carries its own)

**Deserialize**: Version extracted from the first byte. Kyber fields (`kyber_pre_key_id`, `kyber_ciphertext`) are deserialized if present in the protobuf.

### SenderKeyMessage

**Serialize**: `version_byte || protobuf_body || signature`

- Version byte uses `SenderKeyCurrentVersion` in the low nibble
- Signature (64 bytes) is appended after the protobuf body

**Deserialize**: Minimum length is `1 + 64` (version byte + signature). The signature is stripped from the end before protobuf unmarshaling. The `distribution_uuid` must be exactly 16 bytes.

### SenderKeyDistributionMessage

**Serialize**: `version_byte || protobuf_body`

**Deserialize**: After protobuf unmarshaling, field lengths are validated:
- `chain_key`: must be 32 bytes (returns `FieldLengthError` otherwise)
- `signing_key`: must be 33 bytes (returns `FieldLengthError` otherwise)

### Session (SessionRecord)

**Serialize**: The current session state is converted to `storagepb.SessionStructure`. Each previous state is independently marshaled to bytes. Both are packed into `storagepb.RecordStructure`.

**Deserialize**: After unmarshaling `RecordStructure`, the `previous_sessions` count is checked against `archivedStatesMaxLength` (40). Each opaque-bytes entry is individually unmarshaled as a `SessionStructure`. Within each session structure, chain message keys are checked against `maxMessageKeys` (2000).

### SenderKey Record

**Deserialize**: The `sender_key_states` count is checked against `maxSenderKeyStates` (5).

## Deserialization Bounds Enforcement

The protobuf deserializer enforces bounds on collections to prevent unbounded memory allocation from malformed or adversarial input. These checks produce `BoundsExceededError`:

| Collection | Max Count | Location |
|------------|-----------|----------|
| `previous_sessions` (archived session states) | 40 | `ProtobufSessionSerializer.Deserialize` |
| `message_keys` (per chain) | 2000 | `protoToChainStructure` |
| `sender_key_states` (per SenderKey record) | 5 | `ProtobufSenderKeyRecordSerializer.Deserialize` |

These constants match the runtime limits enforced elsewhere in the codebase:
- `archivedStatesMaxLength = 40` in `state/record/SessionRecord.go`
- `maxMessageKeys = 2000` in `state/record/SessionState.go`
- `MAX_SENDER_KEY_STATES = 5` in `groups/state/record/SenderKeyRecord.go`

## Error Types

### serialize.MessageDeserializeError

Returned when a message is too short or otherwise structurally invalid for deserialization. Contains `MessageType` (e.g., "signal message") and optional `Detail`.

### serialize.FieldLengthError

Returned when a deserialized field has an unexpected length. Contains `MessageType`, `Field`, `Expected`, and `Actual`.

### serialize.BoundsExceededError

Returned when a deserialized collection exceeds its maximum allowed size. Contains `MessageType`, `Field`, `Max`, and `Actual`.

```go
type BoundsExceededError struct {
    MessageType string
    Field       string
    Max         int
    Actual      int
}
```

Example error message: `serialize: session record: previous_sessions count 50 exceeds maximum 40`

## JSON Serializer

`NewJSONSerializer()` provides JSON-based serialization for all the same types. It uses standard `encoding/json` marshaling and does not apply the version-byte wire format. The JSON serializer does not enforce deserialization bounds (it relies on Go's `json.Unmarshal` behavior).

The JSON serializer is intended for testing and debugging. Production code should use `NewProtobufSerializer()`.

## State Conversion Helpers

The protobuf serializer contains internal conversion functions that map between Go domain structs and protobuf-generated types:

- `stateStructureToProto` / `protoToStateStructure`: converts `record.StateStructure` to/from `storagepb.SessionStructure`
- `chainStructureToProto` / `protoToChainStructure`: converts `record.ChainStructure` to/from `storagepb.SessionStructure_Chain`
- `senderKeyStateStructureToProto` / `protoToSenderKeyStateStructure`: converts SenderKey state structures

These handle conversion of nested types (chains, message keys, pending pre-keys, pending Kyber pre-keys, PQ ratchet state) and apply the deserialization bounds checks described above.

### Pending Pre-Key Mapping

The `PendingPreKey` protobuf field maps to `record.PendingPreKeyStructure`. The `PendingKyberPreKey` is stored as a separate protobuf field but merged into the same Go structure during deserialization.

### PQ Ratchet State

The `pq_ratchet_state` field (protobuf field 15 in `SessionStructure`) stores the serialized SPQR ratchet state as opaque bytes. The serializer passes it through without interpretation.

### Message Key Seed Material

The `SessionStructure.Chain.MessageKey` protobuf includes a `seed` field (field 5). When present, the `cipher_key`, `mac_key`, and `iv` fields are empty, and the actual message keys are derived from the seed at message decryption time (used for SPQR re-derivation of skipped message keys).
