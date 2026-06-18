package tripleratchet

import (
	"encoding/binary"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
)

// CompositeHeader carries the EC header, PQ counter, and SCKA message for
// each Triple Ratchet message.
//
// Serialized format:
//
//	ecHeaderLen(4 BE) + ecHeader(N) + sckaWireMessage(M)
//
// The SCKA wire message uses the Rust-compatible format:
//
//	version(1) + varint(epoch) + varint(chain_index) + msg_type(1) + [chunk_data]
//
// where chain_index is encoded as PQCounter to support out-of-order delivery.
type CompositeHeader struct {
	// ECHeader is the serialized EC Signal message header.
	ECHeader []byte

	// PQCounter is the SPQR chain counter for out-of-order support.
	// This is the chain_index embedded in the SCKA wire message.
	PQCounter uint32

	// SCKAMsg is the SCKA chunk from the Braid.
	SCKAMsg *mlkembraid.Message
}

// marshalCompositeHeader serializes a CompositeHeader into:
//
//	ecHeaderLen(4 BE) + ecHeader(N) + sckaWireMsg(M)
//
// where the sckaWireMsg includes the PQCounter as the chain_index.
func marshalCompositeHeader(h *CompositeHeader) ([]byte, error) {
	if h == nil {
		return nil, &ErrInvalidInput{Field: "header", Reason: "must not be nil"}
	}

	var sckaBytes []byte
	if h.SCKAMsg != nil {
		sckaBytes = h.SCKAMsg.SerializeSCKA(h.PQCounter)
	}

	// ecHeaderLen(4) + ecHeader(N) + sckaBytes(M)
	buf := make([]byte, 0, 4+len(h.ECHeader)+len(sckaBytes))
	buf = appendU32BE(buf, uint32(len(h.ECHeader)))
	buf = append(buf, h.ECHeader...)
	buf = append(buf, sckaBytes...)

	return buf, nil
}

// unmarshalCompositeHeader deserializes a CompositeHeader from wire bytes.
func unmarshalCompositeHeader(data []byte) (*CompositeHeader, error) {
	if len(data) < 4 {
		return nil, &ErrInvalidCompositeMessage{Reason: "too short for composite header"}
	}

	ecHeaderLen := int(binary.BigEndian.Uint32(data[0:4]))
	offset := 4

	if len(data) < offset+ecHeaderLen {
		return nil, &ErrInvalidCompositeMessage{Reason: "EC header length exceeds data"}
	}

	ecHeader := make([]byte, ecHeaderLen)
	copy(ecHeader, data[offset:offset+ecHeaderLen])
	offset += ecHeaderLen

	var (
		sckaMsg   *mlkembraid.Message
		pqCounter uint32
	)
	if offset < len(data) {
		var err error
		var chainIndex uint32
		sckaMsg, chainIndex, err = mlkembraid.DeserializeSCKA(data[offset:])
		if err != nil {
			return nil, &ErrInvalidCompositeMessage{Reason: "failed to unmarshal SCKA message: " + err.Error()}
		}
		pqCounter = chainIndex
	}

	return &CompositeHeader{
		ECHeader:  ecHeader,
		PQCounter: pqCounter,
		SCKAMsg:   sckaMsg,
	}, nil
}

// marshalCompositeMessage serializes a full Triple Ratchet message:
//
//	headerLen(4 BE) + header(N) + ciphertextLen(4 BE) + ciphertext(M)
func marshalCompositeMessage(headerBytes, ciphertext []byte) []byte {
	buf := make([]byte, 0, 8+len(headerBytes)+len(ciphertext))
	buf = appendU32BE(buf, uint32(len(headerBytes)))
	buf = append(buf, headerBytes...)
	buf = appendU32BE(buf, uint32(len(ciphertext)))
	buf = append(buf, ciphertext...)
	return buf
}

// unmarshalCompositeMessage parses a full Triple Ratchet message into
// its header bytes and ciphertext bytes.
func unmarshalCompositeMessage(data []byte) (headerBytes, ciphertext []byte, err error) {
	if len(data) < 8 {
		return nil, nil, &ErrInvalidCompositeMessage{Reason: "too short for composite message"}
	}

	headerLen := int(binary.BigEndian.Uint32(data[0:4]))
	offset := 4

	if len(data) < offset+headerLen {
		return nil, nil, &ErrInvalidCompositeMessage{Reason: "header length exceeds data"}
	}

	headerBytes = data[offset : offset+headerLen]
	offset += headerLen

	if len(data) < offset+4 {
		return nil, nil, &ErrInvalidCompositeMessage{Reason: "too short for ciphertext length"}
	}

	ciphertextLen := int(binary.BigEndian.Uint32(data[offset : offset+4]))
	offset += 4

	if len(data) < offset+ciphertextLen {
		return nil, nil, &ErrInvalidCompositeMessage{Reason: "ciphertext length exceeds data"}
	}

	ciphertext = data[offset : offset+ciphertextLen]
	return headerBytes, ciphertext, nil
}

// appendU32BE appends a big-endian uint32 to buf.
func appendU32BE(buf []byte, v uint32) []byte {
	return append(buf, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
