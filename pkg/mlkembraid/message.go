package mlkembraid

import (
	"encoding/binary"
	"fmt"
)

// MessageType identifies the kind of data carried in a protocol message.
// Per spec Section 2.3, there are 7 message types.
// Values match the Rust reference: serialize.rs MessageType enum.
type MessageType uint8

const (
	// MessageTypeNone indicates no payload (epoch tick only).
	MessageTypeNone MessageType = iota
	// MessageTypeHdr carries header chunks containing ek_seed || hek.
	MessageTypeHdr
	// MessageTypeEk carries encapsulation key (ek_vector) chunks.
	MessageTypeEk
	// MessageTypeEkCt1Ack carries ek_vector chunks AND acknowledges ct1 receipt.
	MessageTypeEkCt1Ack
	// MessageTypeCt1Ack carries no payload but acknowledges ct1 receipt.
	MessageTypeCt1Ack
	// MessageTypeCt1 carries first ciphertext chunks.
	MessageTypeCt1
	// MessageTypeCt2 carries second ciphertext (reconciliation) chunks.
	MessageTypeCt2
)

// messageTypeNames maps message types to human-readable names.
var messageTypeNames = map[MessageType]string{
	MessageTypeNone:     "None",
	MessageTypeHdr:      "Hdr",
	MessageTypeEk:       "Ek",
	MessageTypeEkCt1Ack: "EkCt1Ack",
	MessageTypeCt1Ack:   "Ct1Ack",
	MessageTypeCt1:      "Ct1",
	MessageTypeCt2:      "Ct2",
}

// String returns the human-readable name of the message type.
func (mt MessageType) String() string {
	if name, ok := messageTypeNames[mt]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(%d)", mt)
}

// SPQRVersion is the SPQR protocol version byte prepended to wire messages.
// Matches Rust: Version::V1 = 1.
const SPQRVersion uint8 = 1

// maxVarintLen is the maximum encoded varint length for u64 values.
const maxVarintLen = binary.MaxVarintLen64

// messageTypeHasChunk returns true if the message type carries chunk data.
func messageTypeHasChunk(mt MessageType) bool {
	return mt == MessageTypeHdr ||
		mt == MessageTypeEk ||
		mt == MessageTypeEkCt1Ack ||
		mt == MessageTypeCt1 ||
		mt == MessageTypeCt2
}

// Message is a protocol message exchanged between Alice and Bob.
type Message struct {
	// Epoch is the protocol epoch counter for this message.
	Epoch uint64
	// Type identifies what kind of data this message carries.
	Type MessageType
	// Data is the chunk payload in Rust-compatible wire format:
	// [varint(chunk_index)] [chunk_data(32 bytes)]
	// May be nil for MessageTypeNone and MessageTypeCt1Ack.
	Data []byte
}

// SerializeSCKA serializes the message into the Rust SPQR wire format:
//
//	[version(1 byte)]
//	[varint(epoch)]
//	[varint(chain_index)]
//	[message_type(1 byte)]
//	[varint(chunk_index) + chunk_data(32 bytes)]  -- only for types with chunks
//
// The chain_index parameter is the SPQR chain counter for this message.
// This matches Rust's v1::chunked::states::serialize::Message::serialize().
func (m *Message) SerializeSCKA(chainIndex uint32) []byte {
	// Pre-allocate: 1 + 10 + 5 + 1 + 3 + 32 = ~52 bytes max
	buf := make([]byte, 0, 52)

	// Version byte.
	buf = append(buf, SPQRVersion)

	// Varint-encoded epoch.
	var tmp [maxVarintLen]byte
	n := binary.PutUvarint(tmp[:], m.Epoch)
	buf = append(buf, tmp[:n]...)

	// Varint-encoded chain index.
	n = binary.PutUvarint(tmp[:], uint64(chainIndex))
	buf = append(buf, tmp[:n]...)

	// Message type byte.
	buf = append(buf, byte(m.Type))

	// For types that carry chunk data, append the raw chunk bytes directly.
	// The chunk data is already in Rust wire format: [varint(index)] [data(32)].
	if messageTypeHasChunk(m.Type) && len(m.Data) > 0 {
		buf = append(buf, m.Data...)
	}

	return buf
}

// ErrSCKADecode is returned when an SCKA wire message cannot be decoded.
type ErrSCKADecode struct {
	Reason string
}

func (e *ErrSCKADecode) Error() string {
	return fmt.Sprintf("mlkembraid: SCKA decode failed: %s", e.Reason)
}

// DeserializeSCKA parses a Rust SPQR wire format message:
//
//	[version(1 byte)]
//	[varint(epoch)]
//	[varint(chain_index)]
//	[message_type(1 byte)]
//	[varint(chunk_index) + chunk_data(32 bytes)]  -- only for types with chunks
//
// Returns the deserialized Message, the chain_index, and any error.
func DeserializeSCKA(data []byte) (*Message, uint32, error) {
	if len(data) == 0 {
		return nil, 0, &ErrSCKADecode{Reason: "empty input"}
	}

	// Version check.
	if data[0] != SPQRVersion {
		return nil, 0, &ErrSCKADecode{
			Reason: "unsupported version: " + uitoa(int(data[0])),
		}
	}

	at := 1

	// Decode epoch.
	epoch, n := binary.Uvarint(data[at:])
	if n <= 0 {
		return nil, 0, &ErrSCKADecode{Reason: "invalid epoch varint"}
	}
	at += n
	if epoch == 0 {
		return nil, 0, &ErrSCKADecode{Reason: "epoch must be non-zero"}
	}

	// Decode chain index.
	chainIndex64, n := binary.Uvarint(data[at:])
	if n <= 0 {
		return nil, 0, &ErrSCKADecode{Reason: "invalid chain_index varint"}
	}
	at += n

	if chainIndex64 > uint64(^uint32(0)) {
		return nil, 0, &ErrSCKADecode{Reason: "chain_index exceeds u32 range"}
	}
	chainIndex := uint32(chainIndex64)

	// Message type byte.
	if at >= len(data) {
		return nil, 0, &ErrSCKADecode{Reason: "missing message type byte"}
	}
	msgType := MessageType(data[at])
	if msgType > MessageTypeCt2 {
		return nil, 0, &ErrSCKADecode{
			Reason: "unknown message type: " + uitoa(int(msgType)),
		}
	}
	at++

	// For types that carry chunk data, the rest is the chunk wire bytes.
	// Validate the inner chunk index against the Rust bound of 65535
	// (chunked/states/serialize.rs:196: index > 65535 → MsgDecode).
	var chunkData []byte
	if messageTypeHasChunk(msgType) && at < len(data) {
		// Peek at the chunk index varint to enforce the 65535 upper bound.
		chunkIdx, n2 := binary.Uvarint(data[at:])
		if n2 <= 0 {
			return nil, 0, &ErrSCKADecode{Reason: "invalid chunk index varint"}
		}
		if chunkIdx > 65535 {
			return nil, 0, &ErrSCKADecode{Reason: "chunk index exceeds 65535"}
		}
		chunkData = make([]byte, len(data)-at)
		copy(chunkData, data[at:])
	}

	return &Message{
		Epoch: epoch,
		Type:  msgType,
		Data:  chunkData,
	}, chainIndex, nil
}
