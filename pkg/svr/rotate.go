package svr

// Package svr implements Signal Secure Value Recovery; rotation requests use a hand-written encoder identical to proto.Marshal (Rust svrb.proto Request4/Response4).

import (
	"encoding/binary"

	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-libsignal/pkg/svr/svrpb"
)

// protoFieldFixed32 encodes a protobuf fixed32 field (wire type 5).
func protoFieldFixed32(fieldNum uint32, val uint32) []byte {
	var buf [9]byte
	// tag = (fieldNum << 3) | 5
	n := binary.PutUvarint(buf[:], uint64(fieldNum)<<3|5)
	binary.LittleEndian.PutUint32(buf[n:], val)
	return buf[:n+4]
}

// protoFieldBytes encodes a protobuf bytes field (wire type 2).
func protoFieldBytes(fieldNum uint32, val []byte) []byte {
	// tag
	var tagBuf [binary.MaxVarintLen64]byte
	tn := binary.PutUvarint(tagBuf[:], uint64(fieldNum)<<3|2)
	// length
	var lenBuf [binary.MaxVarintLen64]byte
	ln := binary.PutUvarint(lenBuf[:], uint64(len(val)))
	out := make([]byte, tn+ln+len(val))
	copy(out, tagBuf[:tn])
	copy(out[tn:], lenBuf[:ln])
	copy(out[tn+ln:], val)
	return out
}

// protoFieldMessage encodes a protobuf embedded message field (wire type 2).
func protoFieldMessage(fieldNum uint32, msg []byte) []byte {
	return protoFieldBytes(fieldNum, msg)
}

// encodeRotateStart encodes Request4.RotateStart (oneof 6: version, oprf and encryption share deltas).
func encodeRotateStart(version uint32, oprfDelta, encDelta []byte) []byte {
	// Encode the RotateStart submessage.
	var sub []byte
	sub = append(sub, protoFieldFixed32(1, version)...)
	sub = append(sub, protoFieldBytes(2, oprfDelta)...)
	sub = append(sub, protoFieldBytes(3, encDelta)...)
	// Wrap in Request4.inner (field 6).
	return protoFieldMessage(6, sub)
}

// encodeRotateCommit encodes Request4.RotateCommit (oneof 7: version).
func encodeRotateCommit(version uint32) []byte {
	sub := protoFieldFixed32(1, version)
	return protoFieldMessage(7, sub)
}

// encodeRotateRollback encodes Request4.RotateRollback (oneof 8: version).
func encodeRotateRollback(version uint32) []byte {
	sub := protoFieldFixed32(1, version)
	return protoFieldMessage(8, sub)
}

// RotateStart4 is an SVR4 rotation-start request set carrying deltas to each server.
type RotateStart4 struct {
	// Requests contains one serialized Request4 per server.
	Requests [][]byte
}

// NewRotateStart4 returns n rotation-start requests with the given version and precomputed deltas.
func NewRotateStart4(n int, version uint32, oprfDelta, encDelta []byte) (*RotateStart4, error) {
	if n <= 0 {
		return nil, ErrBadData
	}
	requests := make([][]byte, n)
	for i := range requests {
		requests[i] = encodeRotateStart(version, oprfDelta, encDelta)
	}
	return &RotateStart4{Requests: requests}, nil
}

// FinalizeRotateStart4 checks every RotateStart response is OK.
func FinalizeRotateStart4(responses [][]byte) error {
	return finalizeRotation(responses, decodeRotateStartStatus)
}

// RotateCommit4 is an SVR4 request set that makes the new OPRF key permanent.
type RotateCommit4 struct {
	// Requests contains one serialized Request4 per server.
	Requests [][]byte
}

// NewRotateCommit4 creates rotation-commit requests for n servers.
//
// Rust libsignal ref: rust/svrb/src/svrb.proto Request4.RotateCommit
func NewRotateCommit4(n int, version uint32) (*RotateCommit4, error) {
	if n <= 0 {
		return nil, ErrBadData
	}
	requests := make([][]byte, n)
	for i := range requests {
		requests[i] = encodeRotateCommit(version)
	}
	return &RotateCommit4{Requests: requests}, nil
}

// FinalizeRotateCommit4 checks every RotateCommit response is OK.
func FinalizeRotateCommit4(responses [][]byte) error {
	return finalizeRotation(responses, decodeRotateCommitStatus)
}

// RotateRollback4 is an SVR4 request set that aborts a rotation.
type RotateRollback4 struct {
	// Requests contains one serialized Request4 per server.
	Requests [][]byte
}

// NewRotateRollback4 creates rotation-rollback requests for n servers.
//
// Rust libsignal ref: rust/svrb/src/svrb.proto Request4.RotateRollback
func NewRotateRollback4(n int, version uint32) (*RotateRollback4, error) {
	if n <= 0 {
		return nil, ErrBadData
	}
	requests := make([][]byte, n)
	for i := range requests {
		requests[i] = encodeRotateRollback(version)
	}
	return &RotateRollback4{Requests: requests}, nil
}

// FinalizeRotateRollback4 checks every RotateRollback response is OK.
func FinalizeRotateRollback4(responses [][]byte) error {
	return finalizeRotation(responses, decodeRotateRollbackStatus)
}

// finalizeRotation is the shared finalization logic for all rotation arms.
// It parses each response with the given status extractor and checks for OK.
func finalizeRotation(responses [][]byte, statusOf func([]byte) (svrpb.Response4_Status, error)) error {
	if len(responses) == 0 {
		return ErrBadData
	}
	for _, b := range responses {
		status, err := statusOf(b)
		if err != nil {
			return err
		}
		if err := checkStatus(status); err != nil {
			return err
		}
	}
	return nil
}

// decodeRotateStartStatus returns the RotateStart status from a Response4, read from unknown fields.
func decodeRotateStartStatus(b []byte) (svrpb.Response4_Status, error) {
	return decodeRotationResponseStatus(b, 6)
}

// decodeRotateCommitStatus parses the RotateCommit status from a Response4.
//
// Rust libsignal ref: rust/svrb/src/svrb.proto Response4.RotateCommit
func decodeRotateCommitStatus(b []byte) (svrpb.Response4_Status, error) {
	return decodeRotationResponseStatus(b, 7)
}

// decodeRotateRollbackStatus parses the RotateRollback status from a Response4.
//
// Rust libsignal ref: rust/svrb/src/svrb.proto Response4.RotateRollback
func decodeRotateRollbackStatus(b []byte) (svrpb.Response4_Status, error) {
	return decodeRotationResponseStatus(b, 8)
}

// decodeRotationResponseStatus returns field 1 of the rotation submessage at oneof field (6, 7 or 8) of a Response4.
func decodeRotationResponseStatus(b []byte, oneofFieldNum int) (svrpb.Response4_Status, error) {
	// First pass: use proto.Unmarshal to validate the outer message structure.
	resp := &svrpb.Response4{}
	if err := proto.Unmarshal(b, resp); err != nil {
		return 0, ErrBadData
	}

	// Locate the rotation oneof submessage directly from raw bytes to read
	// the status varint without allocating additional generated types.
	submsg, err := extractProtoLenField(b, uint64(oneofFieldNum))
	if err != nil || submsg == nil {
		return 0, ErrBadResponse
	}

	// The rotation response submessage has status at field 1 (varint).
	status, err := extractProtoVarintField(submsg, 1)
	if err != nil {
		return 0, ErrBadResponse
	}
	return svrpb.Response4_Status(status), nil
}

// extractProtoLenField scans raw protobuf bytes for the first occurrence of
// a length-delimited field with the given field number and returns its value.
// Returns nil, nil if the field is not present.
func extractProtoLenField(b []byte, fieldNum uint64) ([]byte, error) {
	for len(b) > 0 {
		tag, n := binary.Uvarint(b)
		if n <= 0 {
			return nil, ErrBadData
		}
		b = b[n:]
		fn := tag >> 3
		wt := tag & 7
		switch wt {
		case 0: // varint
			_, n := binary.Uvarint(b)
			if n <= 0 {
				return nil, ErrBadData
			}
			b = b[n:]
		case 1: // 64-bit
			if len(b) < 8 {
				return nil, ErrBadData
			}
			b = b[8:]
		case 2: // length-delimited
			length, n := binary.Uvarint(b)
			if n <= 0 {
				return nil, ErrBadData
			}
			b = b[n:]
			if uint64(len(b)) < length {
				return nil, ErrBadData
			}
			val := b[:length]
			b = b[length:]
			if fn == fieldNum {
				return val, nil
			}
		case 5: // 32-bit
			if len(b) < 4 {
				return nil, ErrBadData
			}
			b = b[4:]
		default:
			return nil, ErrBadData
		}
	}
	return nil, nil
}

// extractProtoVarintField scans raw protobuf bytes for the first occurrence
// of a varint field with the given field number and returns its value.
func extractProtoVarintField(b []byte, fieldNum uint64) (uint64, error) {
	for len(b) > 0 {
		tag, n := binary.Uvarint(b)
		if n <= 0 {
			return 0, ErrBadData
		}
		b = b[n:]
		fn := tag >> 3
		wt := tag & 7
		switch wt {
		case 0: // varint
			val, n := binary.Uvarint(b)
			if n <= 0 {
				return 0, ErrBadData
			}
			b = b[n:]
			if fn == fieldNum {
				return val, nil
			}
		case 1: // 64-bit
			if len(b) < 8 {
				return 0, ErrBadData
			}
			b = b[8:]
		case 2: // length-delimited
			length, n := binary.Uvarint(b)
			if n <= 0 {
				return 0, ErrBadData
			}
			b = b[n:]
			if uint64(len(b)) < length {
				return 0, ErrBadData
			}
			b = b[length:]
		case 5: // 32-bit
			if len(b) < 4 {
				return 0, ErrBadData
			}
			b = b[4:]
		default:
			return 0, ErrBadData
		}
	}
	return 0, ErrBadResponse
}
