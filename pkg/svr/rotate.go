package svr

// Package svr implements Secure Value Recovery (SVR) for the Signal protocol.
//
// This file provides constructors for SVR4 rotation request messages and
// response decoders for the rotation arms of the Request4/Response4 protocol.
//
// Rotation requests use a hand-rolled protobuf wire encoder (encodeRotateStart,
// encodeRotateCommit, encodeRotateRollback) that is byte-for-bit identical to
// the generated proto.Marshal path; see TestRotateStartWireByteEquality.
//
// Rust libsignal ref: rust/svrb/src/proto/svrb.proto Request4/Response4

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

// encodeRotateStart encodes a Request4 with a RotateStart inner message.
// Wire encoding: oneof field 6, submessage with fixed32 version=1,
// bytes oprf_secretshare_delta=2, bytes encryption_secretshare_delta=3.
//
// Rust libsignal ref: rust/svrb/src/svrb.proto Request4.RotateStart
func encodeRotateStart(version uint32, oprfDelta, encDelta []byte) []byte {
	// Encode the RotateStart submessage.
	var sub []byte
	sub = append(sub, protoFieldFixed32(1, version)...)
	sub = append(sub, protoFieldBytes(2, oprfDelta)...)
	sub = append(sub, protoFieldBytes(3, encDelta)...)
	// Wrap in Request4.inner (field 6).
	return protoFieldMessage(6, sub)
}

// encodeRotateCommit encodes a Request4 with a RotateCommit inner message.
// Wire encoding: oneof field 7, submessage with fixed32 version=1.
//
// Rust libsignal ref: rust/svrb/src/svrb.proto Request4.RotateCommit
func encodeRotateCommit(version uint32) []byte {
	sub := protoFieldFixed32(1, version)
	return protoFieldMessage(7, sub)
}

// encodeRotateRollback encodes a Request4 with a RotateRollback inner message.
// Wire encoding: oneof field 8, submessage with fixed32 version=1.
//
// Rust libsignal ref: rust/svrb/src/svrb.proto Request4.RotateRollback
func encodeRotateRollback(version uint32) []byte {
	sub := protoFieldFixed32(1, version)
	return protoFieldMessage(8, sub)
}

// RotateStart4 represents a v4 SVR rotation-start request set. It sends a
// delta to each server to begin rotating the OPRF key and encryption shares.
//
// Rust libsignal ref: rust/svrb/src/svrb.proto Request4.RotateStart
type RotateStart4 struct {
	// Requests contains one serialized Request4 per server.
	Requests [][]byte
}

// NewRotateStart4 creates rotation-start requests for n servers. Each request
// carries the same version, oprfDelta, and encDelta values. In a real
// protocol flow the deltas would be computed per-server; this constructor
// accepts pre-computed values for symmetry with NewOPRFBackup4.
//
// Rust libsignal ref: rust/svrb/src/svrb.proto Request4.RotateStart
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

// FinalizeRotateStart4 processes server responses to RotateStart requests.
// It verifies that all servers returned OK status.
//
// Rust libsignal ref: rust/svrb/src/svrb.proto Response4.RotateStart
func FinalizeRotateStart4(responses [][]byte) error {
	return finalizeRotation(responses, decodeRotateStartStatus)
}

// RotateCommit4 represents a v4 SVR rotation-commit request set. Sending it
// makes the new OPRF key permanent on all servers.
//
// Rust libsignal ref: rust/svrb/src/svrb.proto Request4.RotateCommit
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

// FinalizeRotateCommit4 processes server responses to RotateCommit requests.
// It verifies that all servers returned OK status.
//
// Rust libsignal ref: rust/svrb/src/svrb.proto Response4.RotateCommit
func FinalizeRotateCommit4(responses [][]byte) error {
	return finalizeRotation(responses, decodeRotateCommitStatus)
}

// RotateRollback4 represents a v4 SVR rotation-rollback request set. Sending
// it aborts a previously started rotation and reverts to the prior OPRF key.
//
// Rust libsignal ref: rust/svrb/src/svrb.proto Request4.RotateRollback
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

// FinalizeRotateRollback4 processes server responses to RotateRollback
// requests. It verifies that all servers returned OK status.
//
// Rust libsignal ref: rust/svrb/src/svrb.proto Response4.RotateRollback
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

// decodeRotateStartStatus parses a Response4 and extracts the RotateStart
// status field. It uses the generated proto decoder for the Response4 outer
// message; because the generated types do not include the rotation oneof
// wrappers, the oneof inner bytes are read from the unknown fields and decoded
// manually.
//
// Rust libsignal ref: rust/svrb/src/svrb.proto Response4.RotateStart
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

// decodeRotationResponseStatus decodes a Response4 protobuf and extracts the
// status field from the rotation submessage at the given oneof field number
// (6=RotateStart, 7=RotateCommit, 8=RotateRollback). Each rotation response
// submessage has a single status field at field number 1.
//
// proto.Unmarshal validates the outer message structure; the raw submessage
// bytes are then located directly via extractProtoLenField to read the status
// varint without allocating additional generated types.
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
