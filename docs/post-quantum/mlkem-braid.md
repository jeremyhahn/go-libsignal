# ML-KEM Braid SCKA Protocol

The ML-KEM Braid is a Sparse Continuous Key Agreement (SCKA) protocol that provides post-quantum key agreement using ML-KEM-768. It exchanges KEM key material incrementally across multiple messages, producing shared output keys that SPQR uses to advance its epoch. The protocol targets bandwidth-constrained channels where a full KEM exchange cannot fit in a single message.

Source: `mlkembraid/` package.

## Protocol overview

The braid exchanges KEM material between Alice (initiator) and Bob (responder) in chunks of 32 bytes each. A complete key agreement round involves:

1. Alice generates a KEM key pair, sends the header (`ek_seed || hek`) and then the full encapsulation key (`ek_vector`) across multiple messages.
2. Bob receives the header (verified via MAC), collects the full `ek_vector`, performs encapsulation, and sends back `ct1` and `ct2` across multiple messages.
3. Alice receives `ct1` and `ct2`, performs decapsulation, and both parties derive a shared output key via `KDF_OK`.

Each party piggybacks one chunk per message. The number of messages required depends on the KEM key sizes.

## State machine

The protocol has 11 named states (defined in `mlkembraid/state.go`). Including the terminal re-entry point after a completed round, the state machine manages 13 effective transitions.

### Alice states

| State                    | Value | Description                                          |
|--------------------------|-------|------------------------------------------------------|
| `StateKeysUnsampled`     | 0     | Initial state. No keys generated yet.                |
| `StateKeysSampled`       | 1     | Keys generated, sending header chunks.               |
| `StateHeaderSent`        | 2     | All header chunks sent, sending Ek chunks.           |
| `StateCt1Received`       | 3     | ct1 fully received, sending remaining EkCt1Ack chunks. |
| `StateEkSentCt1Received` | 4     | All Ek sent and ct1 received, waiting for ct2.       |

### Bob states

| State                        | Value | Description                                          |
|------------------------------|-------|------------------------------------------------------|
| `StateNoHeaderReceived`      | 5     | Initial state. Waiting for header chunks.            |
| `StateHeaderReceived`        | 6     | Complete header received, collecting Ek chunks.      |
| `StateCt1Sampled`            | 7     | Encapsulation done, sending ct1 chunks.              |
| `StateEkReceivedCt1Sampled`  | 8     | Ek fully received, ct1 sampled, waiting for ct1 ack. |
| `StateCt1Acknowledged`       | 9     | ct1 was acknowledged, receiving remaining Ek.        |
| `StateCt2Sampled`            | 10    | ct2 computed, sending ct2 chunks.                    |

### State transitions

Alice's flow:

```
KeysUnsampled -> KeysSampled -> HeaderSent -> Ct1Received -> EkSentCt1Received
                                    |                              |
                                    +-----> (back to KeysUnsampled for next round)
```

Bob's flow:

```
NoHeaderReceived -> HeaderReceived -> Ct1Sampled -> EkReceivedCt1Sampled -> Ct1Acknowledged -> Ct2Sampled
                                                          |                                        |
                                                          +-----> (back to NoHeaderReceived for next round)
```

The terminal states (`EkSentCt1Received` for Alice, `Ct2Sampled` for Bob) produce an `OutputKey` and transition back to the initial state for the next epoch.

## Message types

Seven message types are defined in `mlkembraid/message.go`:

| Type              | Value | Carries chunk data | Description                                  |
|-------------------|-------|--------------------|----------------------------------------------|
| `MessageTypeNone` | 0     | No                 | Epoch tick only, no payload                  |
| `MessageTypeHdr`  | 1     | Yes                | Header chunks: `ek_seed(32) || hek(32)`      |
| `MessageTypeEk`   | 2     | Yes                | Encapsulation key vector chunks              |
| `MessageTypeEkCt1Ack` | 3 | Yes                | Ek chunks with ct1 acknowledgment            |
| `MessageTypeCt1Ack` | 4   | No                 | ct1 acknowledgment only                      |
| `MessageTypeCt1`  | 5     | Yes                | First ciphertext chunks                      |
| `MessageTypeCt2`  | 6     | Yes                | Second ciphertext (reconciliation) chunks    |

The function `messageTypeHasChunk(mt)` returns true for types 1, 2, 3, 5, and 6.

## Wire format

Each braid message is serialized on the SPQR wire using `Message.SerializeSCKA(chainIndex)`:

```
version(1) = 0x01 (SPQRVersion)
varint(epoch)
varint(chain_index)
message_type(1)
[varint(chunk_index) + chunk_data(32)]    -- only for types with chunks
```

`DeserializeSCKA(data)` parses this format and returns the `Message`, chain index, and any error. It validates that the epoch is non-zero and the message type does not exceed `MessageTypeCt2`.

## Chunked encoding

### Encoder

`Encoder` (in `mlkembraid/encoder.go`) splits data into fixed 32-byte chunks (`ChunkDataSize = 32`). Each chunk on the wire is:

```
varint(index) + data(32 bytes, zero-padded if last)
```

The encoder wraps around after all chunks are sent, allowing retransmission redundancy. `HasMore()` returns false after the first complete pass. The maximum chunk index is `MaxChunkIndex = 65535`.

The encoder offset is bounded to prevent unbounded growth during retransmission: when `offset >= 2 * total`, it resets to `total`.

### Decoder

`Decoder` (in `mlkembraid/decoder.go`) collects indexed chunks and reconstructs the original message once all chunks arrive. Chunks may arrive in any order; duplicates are silently ignored. The wire format per chunk matches the encoder output.

`HasMessage()` returns true when `len(chunks) == totalChunks`. `Message()` concatenates chunks in index order and truncates to `expectedSize` (since the last chunk may be zero-padded).

### Bounded deserialization

The `maxSecretLength` constant (4096 bytes) caps the byte length of any deserialized secret or encoder data, preventing unbounded allocation from malformed input.

## ML-KEM-768 parameters

Defined in `mlkembraid/params.go`:

| Constant              | Value | Description                          |
|-----------------------|-------|--------------------------------------|
| `HeaderSize`          | 64    | `ek_seed(32) + hek(32)`             |
| `MacSize`             | 32    | HMAC-SHA256 output                   |
| `DefaultChunkSize`    | 32    | Fixed chunk payload size             |
| `EKSeedSize`          | 32    | ek_seed portion                      |
| `MLKEM768EKSize`      | 1152  | ek_vector size (without ek_seed)     |
| `MLKEM768FullEKSize`  | 1184  | `EKSeedSize + MLKEM768EKSize`        |
| `MLKEM768CT1Size`     | 960   | First ciphertext size                |
| `MLKEM768CT2Size`     | 128   | Second ciphertext (reconciliation)   |
| `MLKEM768FullCTSize`  | 1088  | `CT1Size + CT2Size`                  |
| `ProtocolInfo`        | `"Signal_PQCKA_V1_MLKEM768"` | KDF and MAC label      |

The header is `ek_seed(32) || SHA3-256(ek_seed || ek_vector)(32)`, computed by the `Header()` function using `computeHEK()`.

## IncrementalKEM interface

`IncrementalKEM` (in `mlkembraid/kem_interface.go`) abstracts the KEM operations for the split encapsulation flow:

```go
type IncrementalKEM interface {
    KeyGen() (dk, ekSeed, ekVector []byte, err error)
    Encaps1(ekSeed, hek []byte) (encapsSecret, ct1, sharedSecret []byte, err error)
    Encaps2(encapsSecret, ekSeed, ekVector []byte) (ct2 []byte, err error)
    Decaps(dk, ct1, ct2 []byte) (sharedSecret []byte, err error)
    EKSize() int
    CT1Size() int
    CT2Size() int
    HeaderSize() int
}
```

### Deferred Encaps1

The `MLKEM768IncrementalKEM` implementation defers the actual cryptographic encapsulation to `Encaps2` (or `CompleteEncaps2`). The standard ML-KEM-768 API (circl) does not expose split encapsulation internals, so `Encaps1` captures `ek_seed || hek` into an opaque `encapsSecret` token and returns nil for `ct1` and `sharedSecret`. The state machine calls `CompleteEncaps2` (via `bobCompleteEncapsulation`) when the full `ek_vector` arrives to perform the actual KEM operation.

### hek verification

`Encaps2` and `CompleteEncaps2` both verify `hek` consistency using `subtle.ConstantTimeCompare` between the stored `hek` (from `Encaps1`) and the freshly computed `SHA3-256(ek_seed || ek_vector)`. A mismatch returns `ErrHeaderFormat`.

## Authenticator

`Authenticator` (in `mlkembraid/authenticator.go`) provides a ratcheted HMAC-based authenticator for the SCKA protocol. Per spec Section 2.4, it maintains a `root_key` and derives `mac_key` values via `KDF_AUTH`.

### KDF_AUTH divergence from spec

The spec defines:

```
HKDF(salt=root_key, ikm=update_key, info=..., length=64)
```

The Rust reference implementation uses different parameters:

```
HKDF(salt=zeros(32), ikm=root_key||update_key, info=ProtocolInfo+":Authenticator Update"+ToBytes(epoch), length=64)
```

This implementation follows the Rust reference for wire compatibility. The divergence is documented in `kdfAuth()`.

### MAC operations

- `MacHdr(epoch, header)`: `HMAC-SHA256(mac_key, ProtocolInfo+":ekheader" || ToBytes(epoch) || header)`
- `MacCt(epoch, ct)`: `HMAC-SHA256(mac_key, ProtocolInfo+":ciphertext" || ToBytes(epoch) || ct)`
- `VfyHdr` and `VfyCt` use `hmac.Equal` for constant-time comparison.

### KDF_OK

Output key derivation:

```
HKDF(salt=zeros(32), ikm=shared_secret, info=ProtocolInfo+":SCKA Key"+ToBytes(epoch), length=32)
```

## Braid API

### Initialization

```go
braid, err := mlkembraid.InitAlice(sharedSecret, kemImpl, chunkSize)
braid, err := mlkembraid.InitBob(sharedSecret, kemImpl, chunkSize)
```

Alice starts at `StateKeysUnsampled`, epoch 1. Bob starts at `StateNoHeaderReceived`, epoch 1, with a header decoder initialized for 96 bytes (`HeaderSize + MacSize`).

### Send and Receive

```go
msg, sendingEpoch, outputKey, err := braid.Send()
receivingEpoch, outputKey, err := braid.Receive(msg)
```

`Send()` returns the next outbound `Message`, the `sending_epoch` (the latest epoch known to be received by the other party), and an optional `OutputKey`. `Receive()` processes an inbound `Message` and returns the `receiving_epoch` and optional `OutputKey`.

When `OutputKey` is non-nil, the SPQR should advance its epoch using `OutputKey.Key` as the SCKA output.

## Serialization

`Braid.Serialize()` produces a versioned binary format:

```
version(1) = 0x01
kemType(1) = 0x00 (MLKEM768)
chunkSize(4 BE)
stateLen(4 BE)
stateBytes(N)
```

State serialization includes the fixed header (state kind, epoch, chunk size, ct1Ack flag, headerMACEpoch, lastReceivedEpoch), the authenticator, 11 optional secrets (dk, ekSeed, ekVector, bobEkSeed, bobHek, bobEncapSecret, bobEkVector, bobCt1, bobCt2, bobSS, receivedCt1), 4 optional encoders, and 4 optional decoders.

Optional fields use a `hasField(1)` flag followed by `dataLen(4 BE) + data(N)` when present.

`DeserializeBraid(data)` reconstructs the `Braid` with a fresh `MLKEM768IncrementalKEM` based on the `kemType` field.

## Error types

| Error                  | Condition                                           |
|------------------------|-----------------------------------------------------|
| `ErrInvalidState`      | State transition invalid for current state          |
| `ErrInvalidEpoch`      | Received message has unexpected epoch               |
| `ErrInvalidMessageType`| Received message has wrong type for current state   |
| `ErrMACVerification`   | MAC check failed on header or ciphertext            |
| `ErrDecoderIncomplete` | Not all chunks received yet                         |
| `ErrKEMOperation`      | KEM operation (KeyGen, Encaps, Decaps) failed       |
| `ErrInvalidInput`      | Input validation failure                            |
| `ErrChunkSize`         | Invalid chunk size parameter                        |
| `ErrHeaderFormat`      | Invalid header format or hek mismatch               |
| `ErrChunkFormat`       | Invalid chunk wire format                           |
| `ErrChunkIndex`        | Chunk index out of range                            |
| `ErrChunkCount`        | Too many chunks for the data size                   |
| `ErrEpochOutOfRange`   | Received epoch too far ahead                        |
| `ErrSCKADecode`        | SCKA wire message decode failure                    |
| `ErrSerialize`         | Braid/State serialization failure                   |
| `ErrDeserialize`       | Braid/State deserialization failure                  |

## Concurrency

Braid is NOT safe for concurrent use by multiple goroutines. The session-level serialization (load, mutate, store) provides implicit synchronization when used through the session cipher.
