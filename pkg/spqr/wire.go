package spqr

import (
	"encoding/binary"
	"fmt"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
)

const (
	// wireVersion is the version byte prepended to variable-length wire messages.
	wireVersion uint8 = 0x01

	// legacyPQRMsgSize is the fixed 12-byte wire format used by legacy (non-braid)
	// SPQR messages: epoch(8 BE) + counter(4 BE).
	legacyPQRMsgSize = 12

	// maxWireMessageSize is the maximum expected size of a wire message,
	// used for pre-allocation: version(1) + epoch(10) + counter(5) + msgType(1) +
	// chunkIndex(3) + chunkData(32) = ~52 bytes.
	maxWireMessageSize = 52
)

// ErrWireDecode is returned when a wire message cannot be decoded.
type ErrWireDecode struct {
	Reason string
}

func (e *ErrWireDecode) Error() string {
	return fmt.Sprintf("spqr: wire decode failed: %s", e.Reason)
}

// ErrWireEncode is returned when a wire message cannot be encoded.
type ErrWireEncode struct {
	Reason string
}

func (e *ErrWireEncode) Error() string {
	return fmt.Sprintf("spqr: wire encode failed: %s", e.Reason)
}

// messageTypeHasChunk returns true if the given message type carries chunk data.
func messageTypeHasChunk(mt mlkembraid.MessageType) bool {
	return mt == mlkembraid.MessageTypeHdr ||
		mt == mlkembraid.MessageTypeEk ||
		mt == mlkembraid.MessageTypeEkCt1Ack ||
		mt == mlkembraid.MessageTypeCt1 ||
		mt == mlkembraid.MessageTypeCt2
}

// WireMessage holds the decoded components of a variable-length SPQR wire message.
type WireMessage struct {
	Epoch   uint64
	Counter uint32
	MsgType mlkembraid.MessageType
	Chunk   []byte // nil for MessageTypeNone and MessageTypeCt1Ack
}

// encodeWireMessage serializes a variable-length SPQR wire message:
//
//	version(1) + varint(epoch) + varint(counter) + msg_type(1) + [chunk_data]
//
// The chunk data is already in Rust-compatible wire format (varint(index) + data(32))
// and is appended raw when present.
func encodeWireMessage(epoch uint64, counter uint32, msgType mlkembraid.MessageType, chunk []byte) []byte {
	buf := make([]byte, 0, maxWireMessageSize)

	// Version byte.
	buf = append(buf, wireVersion)

	// Varint-encoded epoch.
	var tmp [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(tmp[:], epoch)
	buf = append(buf, tmp[:n]...)

	// Varint-encoded counter.
	n = binary.PutUvarint(tmp[:], uint64(counter))
	buf = append(buf, tmp[:n]...)

	// Message type byte.
	buf = append(buf, byte(msgType))

	// Chunk data (already in wire format) for types that carry data.
	if messageTypeHasChunk(msgType) && len(chunk) > 0 {
		buf = append(buf, chunk...)
	}

	return buf
}

// decodeWireMessage parses a variable-length SPQR wire message.
// Returns the decoded WireMessage or an error.
//
// For backward compatibility, if the data is exactly 12 bytes it is parsed as
// a legacy fixed-format message (epoch(8 BE) + counter(4 BE)) with
// MessageTypeNone and nil chunk.
func decodeWireMessage(data []byte) (*WireMessage, error) {
	if len(data) == 0 {
		return nil, &ErrWireDecode{Reason: "empty input"}
	}

	// Legacy format detection: exactly 12 bytes = epoch(8 BE) + counter(4 BE).
	if len(data) == legacyPQRMsgSize {
		epoch := binary.BigEndian.Uint64(data[0:8])
		counter := binary.BigEndian.Uint32(data[8:12])
		return &WireMessage{
			Epoch:   epoch,
			Counter: counter,
			MsgType: mlkembraid.MessageTypeNone,
		}, nil
	}

	// Variable-length format.
	if data[0] != wireVersion {
		return nil, &ErrWireDecode{
			Reason: fmt.Sprintf("unsupported version: %d", data[0]),
		}
	}

	at := 1

	// Decode epoch.
	epoch, n := binary.Uvarint(data[at:])
	if n <= 0 {
		return nil, &ErrWireDecode{Reason: "invalid epoch varint"}
	}
	at += n

	// Decode counter.
	counter64, n := binary.Uvarint(data[at:])
	if n <= 0 {
		return nil, &ErrWireDecode{Reason: "invalid counter varint"}
	}
	at += n
	if counter64 > uint64(^uint32(0)) {
		return nil, &ErrWireDecode{Reason: "counter exceeds u32 range"}
	}
	counter := uint32(counter64)

	// Message type byte.
	if at >= len(data) {
		return nil, &ErrWireDecode{Reason: "missing message type byte"}
	}
	msgType := mlkembraid.MessageType(data[at])
	if msgType > mlkembraid.MessageTypeCt2 {
		return nil, &ErrWireDecode{
			Reason: fmt.Sprintf("unknown message type: %d", msgType),
		}
	}
	at++

	// Chunk data for types that carry it.
	var chunk []byte
	if messageTypeHasChunk(msgType) && at < len(data) {
		chunk = make([]byte, len(data)-at)
		copy(chunk, data[at:])
	}

	return &WireMessage{
		Epoch:   epoch,
		Counter: counter,
		MsgType: msgType,
		Chunk:   chunk,
	}, nil
}

// encodeLegacyMessage builds the legacy 12-byte fixed wire format:
// epoch(8 BE) + counter(4 BE).
func encodeLegacyMessage(epoch uint64, counter uint32) []byte {
	msg := make([]byte, legacyPQRMsgSize)
	binary.BigEndian.PutUint64(msg[0:8], epoch)
	binary.BigEndian.PutUint32(msg[8:12], counter)
	return msg
}
