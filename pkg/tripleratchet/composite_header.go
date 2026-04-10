package tripleratchet

import (
	"encoding/binary"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
)

const (
	// ecHeaderLenSize is the byte size of the EC header length prefix.
	ecHeaderLenSize = 4

	// compositeHeaderMinSize is the minimum serialized size of a composite header:
	// 4 bytes EC header length + 1 byte version (min SCKA message).
	compositeHeaderMinSize = ecHeaderLenSize + 1
)

// CompositeHeader combines an EC Signal message header with an SCKA
// (Sparse Continuous Key Agreement) message from the ML-KEM Braid.
// Together they carry both EC and PQ ratchet advancement data.
type CompositeHeader struct {
	// ECHeader is the serialized EC Signal message header containing
	// ratchet_key, counter, and previous_counter.
	ECHeader []byte

	// PQCounter is the SPQR chain counter for this message, enabling
	// out-of-order message key derivation on the receive side.
	PQCounter uint32

	// SCKAMsg is the SCKA message carrying epoch, type, and chunk data
	// from the ML-KEM Braid protocol.
	SCKAMsg *mlkembraid.Message
}

// Serialize encodes the composite header into a binary format:
//
//	[4 bytes: EC header length]
//	[N bytes: EC header data]
//	[M bytes: SCKA wire message (Rust SPQR format)]
//
// The SCKA message is serialized using the Rust-compatible wire format:
//
//	[version(1)] [varint(epoch)] [varint(chain_index)] [msg_type(1)] [chunk...]
//
// This ensures wire compatibility with the Rust SPQR reference implementation.
func (h *CompositeHeader) Serialize() ([]byte, error) {
	if h.ECHeader == nil {
		return nil, &ErrInvalidInput{Field: "ECHeader", Reason: "must not be nil"}
	}
	if h.SCKAMsg == nil {
		return nil, &ErrInvalidInput{Field: "SCKAMsg", Reason: "must not be nil"}
	}

	ecLen := len(h.ECHeader)

	// Serialize the SCKA message in Rust-compatible wire format.
	sckaBytes := h.SCKAMsg.SerializeSCKA(h.PQCounter)

	totalSize := ecHeaderLenSize + ecLen + len(sckaBytes)
	buf := make([]byte, totalSize)

	offset := 0

	// EC header length (4 bytes, big-endian).
	binary.BigEndian.PutUint32(buf[offset:], uint32(ecLen))
	offset += ecHeaderLenSize

	// EC header data.
	copy(buf[offset:], h.ECHeader)
	offset += ecLen

	// SCKA wire message (Rust SPQR format).
	copy(buf[offset:], sckaBytes)

	return buf, nil
}

// DeserializeCompositeHeader decodes a binary composite header back into
// its EC header and SCKA message components.
func DeserializeCompositeHeader(data []byte) (*CompositeHeader, error) {
	if len(data) < compositeHeaderMinSize {
		return nil, &ErrInvalidCompositeMessage{
			Reason: "data too short for composite header",
		}
	}

	offset := 0

	// EC header length.
	ecLen := int(binary.BigEndian.Uint32(data[offset:]))
	offset += ecHeaderLenSize

	if ecLen > maxCompositeComponentLen {
		return nil, &ErrMessageTooLarge{
			Component: "EC header",
			Size:      ecLen,
			Max:       maxCompositeComponentLen,
		}
	}

	if ecLen < 0 || offset+ecLen > len(data) {
		return nil, &ErrInvalidCompositeMessage{
			Reason: "EC header length exceeds available data",
		}
	}

	// EC header data.
	ecHeader := make([]byte, ecLen)
	copy(ecHeader, data[offset:offset+ecLen])
	offset += ecLen

	// Remaining bytes are the SCKA wire message in Rust SPQR format.
	if offset >= len(data) {
		return nil, &ErrInvalidCompositeMessage{
			Reason: "no SCKA message data after EC header",
		}
	}

	sckaMsg, pqCounter, err := mlkembraid.DeserializeSCKA(data[offset:])
	if err != nil {
		return nil, &ErrInvalidCompositeMessage{
			Reason: "failed to decode SCKA message: " + err.Error(),
		}
	}

	return &CompositeHeader{
		ECHeader:  ecHeader,
		PQCounter: pqCounter,
		SCKAMsg:   sckaMsg,
	}, nil
}
