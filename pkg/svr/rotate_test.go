package svr

import (
	"bytes"
	"encoding/binary"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-libsignal/pkg/svr/svrpb"
)

// TestResponseStatusRotationStrings verifies the new rotation status constants
// have the correct string representations, matching
// rust/svrb/src/svrb.proto Response4.Status.
func TestResponseStatusRotationStrings(t *testing.T) {
	tests := []struct {
		status ResponseStatus
		want   string
	}{
		{StatusNotRotating, "NOT_ROTATING"},
		{StatusAlreadyRotating, "ALREADY_ROTATING"},
		{StatusMerkleFailure, "MERKLE_FAILURE"},
		{StatusDuplicateVersion, "DUPLICATE_VERSION"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.status.String()
			if got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestRotationStatusValues verifies the numeric values of the new status
// constants match the Rust svrb.proto definition.
func TestRotationStatusValues(t *testing.T) {
	if StatusNotRotating != 7 {
		t.Errorf("StatusNotRotating = %d, want 7", StatusNotRotating)
	}
	if StatusAlreadyRotating != 8 {
		t.Errorf("StatusAlreadyRotating = %d, want 8", StatusAlreadyRotating)
	}
	if StatusMerkleFailure != 9 {
		t.Errorf("StatusMerkleFailure = %d, want 9", StatusMerkleFailure)
	}
	if StatusDuplicateVersion != 10 {
		t.Errorf("StatusDuplicateVersion = %d, want 10", StatusDuplicateVersion)
	}
}

// TestNewRotateStart4Valid verifies RotateStart4 request construction.
func TestNewRotateStart4Valid(t *testing.T) {
	const version = uint32(42)
	oprfDelta := []byte{0x01, 0x02, 0x03}
	encDelta := []byte{0xAA, 0xBB, 0xCC}

	rs, err := NewRotateStart4(3, version, oprfDelta, encDelta)
	if err != nil {
		t.Fatalf("NewRotateStart4: %v", err)
	}
	if len(rs.Requests) != 3 {
		t.Fatalf("Requests count = %d, want 3", len(rs.Requests))
	}

	// Each request must be non-empty.
	for i, req := range rs.Requests {
		if len(req) == 0 {
			t.Errorf("Requests[%d] is empty", i)
		}
	}

	// Verify the wire bytes contain the version (fixed32 = little-endian 4 bytes).
	// The encoded message has field 6 (rotate_start) with field 1 (version) inside.
	req := rs.Requests[0]
	// Outer field tag for rotate_start (field 6, wire type 2) = 0x32
	if req[0] != byte((6<<3)|2) {
		t.Errorf("outer tag = 0x%02x, want 0x%02x (field 6 LEN)", req[0], byte((6<<3)|2))
	}
}

// TestNewRotateStart4InvalidN verifies that zero servers is rejected.
func TestNewRotateStart4InvalidN(t *testing.T) {
	_, err := NewRotateStart4(0, 1, nil, nil)
	if err == nil {
		t.Fatal("expected error for n=0")
	}
}

// TestNewRotateCommit4Valid verifies RotateCommit4 request construction.
func TestNewRotateCommit4Valid(t *testing.T) {
	rc, err := NewRotateCommit4(2, 99)
	if err != nil {
		t.Fatalf("NewRotateCommit4: %v", err)
	}
	if len(rc.Requests) != 2 {
		t.Fatalf("Requests count = %d, want 2", len(rc.Requests))
	}

	req := rc.Requests[0]
	// Outer field tag for rotate_commit (field 7, wire type 2) = 0x3a
	if req[0] != byte((7<<3)|2) {
		t.Errorf("outer tag = 0x%02x, want 0x%02x (field 7 LEN)", req[0], byte((7<<3)|2))
	}
}

// TestNewRotateCommit4InvalidN verifies that zero servers is rejected.
func TestNewRotateCommit4InvalidN(t *testing.T) {
	_, err := NewRotateCommit4(0, 1)
	if err == nil {
		t.Fatal("expected error for n=0")
	}
}

// TestNewRotateRollback4Valid verifies RotateRollback4 request construction.
func TestNewRotateRollback4Valid(t *testing.T) {
	rr, err := NewRotateRollback4(1, 7)
	if err != nil {
		t.Fatalf("NewRotateRollback4: %v", err)
	}
	if len(rr.Requests) != 1 {
		t.Fatalf("Requests count = %d, want 1", len(rr.Requests))
	}

	req := rr.Requests[0]
	// Outer field tag for rotate_rollback (field 8, wire type 2) = 0x42
	if req[0] != byte((8<<3)|2) {
		t.Errorf("outer tag = 0x%02x, want 0x%02x (field 8 LEN)", req[0], byte((8<<3)|2))
	}
}

// TestNewRotateRollback4InvalidN verifies that zero servers is rejected.
func TestNewRotateRollback4InvalidN(t *testing.T) {
	_, err := NewRotateRollback4(0, 1)
	if err == nil {
		t.Fatal("expected error for n=0")
	}
}

// buildRotationResponse encodes a Response4 protobuf with a rotation oneof arm
// (field number oneofFieldNum) containing status at field 1.
// Used to build synthetic server responses for testing FinalizeRotate* functions.
func buildRotationResponse(oneofFieldNum uint32, status svrpb.Response4_Status) []byte {
	// Encode inner submessage: field 1 (status), varint.
	var tagBuf [binary.MaxVarintLen64]byte
	tn := binary.PutUvarint(tagBuf[:], uint64(1)<<3) // field 1, wire type 0 (varint)
	var valBuf [binary.MaxVarintLen64]byte
	vn := binary.PutUvarint(valBuf[:], uint64(status))
	sub := append(tagBuf[:tn], valBuf[:vn]...)

	// Encode outer message: field oneofFieldNum, wire type 2.
	var outerTagBuf [binary.MaxVarintLen64]byte
	otn := binary.PutUvarint(outerTagBuf[:], uint64(oneofFieldNum)<<3|2)
	var outerLenBuf [binary.MaxVarintLen64]byte
	oln := binary.PutUvarint(outerLenBuf[:], uint64(len(sub)))
	msg := append(outerTagBuf[:otn], outerLenBuf[:oln]...)
	msg = append(msg, sub...)
	return msg
}

// TestFinalizeRotateStart4OK verifies FinalizeRotateStart4 accepts OK
// responses from all servers.
func TestFinalizeRotateStart4OK(t *testing.T) {
	resp := buildRotationResponse(6, svrpb.Response4_OK)
	err := FinalizeRotateStart4([][]byte{resp, resp})
	if err != nil {
		t.Fatalf("FinalizeRotateStart4: %v", err)
	}
}

// TestFinalizeRotateStart4NonOK verifies FinalizeRotateStart4 rejects a
// non-OK status.
func TestFinalizeRotateStart4NonOK(t *testing.T) {
	resp := buildRotationResponse(6, svrpb.Response4_ALREADY_ROTATING)
	err := FinalizeRotateStart4([][]byte{resp})
	if err == nil {
		t.Fatal("expected error for ALREADY_ROTATING status")
	}
}

// TestFinalizeRotateStart4WrongArm verifies that a response with the wrong
// oneof arm (e.g. rotate_commit instead of rotate_start) is rejected.
func TestFinalizeRotateStart4WrongArm(t *testing.T) {
	resp := buildRotationResponse(7, svrpb.Response4_OK) // commit arm, not start
	err := FinalizeRotateStart4([][]byte{resp})
	if err == nil {
		t.Fatal("expected error for wrong oneof arm")
	}
}

// TestFinalizeRotateCommit4OK verifies FinalizeRotateCommit4 accepts OK.
func TestFinalizeRotateCommit4OK(t *testing.T) {
	resp := buildRotationResponse(7, svrpb.Response4_OK)
	err := FinalizeRotateCommit4([][]byte{resp})
	if err != nil {
		t.Fatalf("FinalizeRotateCommit4: %v", err)
	}
}

// TestFinalizeRotateCommit4NonOK verifies non-OK status is rejected.
func TestFinalizeRotateCommit4NonOK(t *testing.T) {
	resp := buildRotationResponse(7, svrpb.Response4_NOT_ROTATING)
	err := FinalizeRotateCommit4([][]byte{resp})
	if err == nil {
		t.Fatal("expected error for NOT_ROTATING status")
	}
}

// TestFinalizeRotateRollback4OK verifies FinalizeRotateRollback4 accepts OK.
func TestFinalizeRotateRollback4OK(t *testing.T) {
	resp := buildRotationResponse(8, svrpb.Response4_OK)
	err := FinalizeRotateRollback4([][]byte{resp})
	if err != nil {
		t.Fatalf("FinalizeRotateRollback4: %v", err)
	}
}

// TestFinalizeRotateRollback4NonOK verifies non-OK status is rejected.
func TestFinalizeRotateRollback4NonOK(t *testing.T) {
	resp := buildRotationResponse(8, svrpb.Response4_MERKLE_FAILURE)
	err := FinalizeRotateRollback4([][]byte{resp})
	if err == nil {
		t.Fatal("expected error for MERKLE_FAILURE status")
	}
}

// TestFinalizeRotationEmptyResponses verifies empty response slices are rejected.
func TestFinalizeRotationEmptyResponses(t *testing.T) {
	if err := FinalizeRotateStart4(nil); err == nil {
		t.Error("FinalizeRotateStart4: expected error for nil responses")
	}
	if err := FinalizeRotateCommit4(nil); err == nil {
		t.Error("FinalizeRotateCommit4: expected error for nil responses")
	}
	if err := FinalizeRotateRollback4(nil); err == nil {
		t.Error("FinalizeRotateRollback4: expected error for nil responses")
	}
}

// TestProtoFieldFixed32 verifies the raw fixed32 encoding helper produces
// the correct wire bytes.
func TestProtoFieldFixed32(t *testing.T) {
	// field 1 (version), value = 42 (0x2a000000 little-endian)
	got := protoFieldFixed32(1, 42)
	// tag = (1 << 3) | 5 = 0x0d; value = 0x2a 0x00 0x00 0x00
	want := []byte{0x0d, 0x2a, 0x00, 0x00, 0x00}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i, b := range want {
		if got[i] != b {
			t.Errorf("byte[%d] = 0x%02x, want 0x%02x", i, got[i], b)
		}
	}
}

// TestProtoFieldBytes verifies the raw bytes field encoding helper.
func TestProtoFieldBytes(t *testing.T) {
	val := []byte{0xAA, 0xBB}
	got := protoFieldBytes(2, val)
	// tag = (2 << 3) | 2 = 0x12; len varint = 0x02; bytes
	want := []byte{0x12, 0x02, 0xAA, 0xBB}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d: %x vs %x", len(got), len(want), got, want)
	}
	for i, b := range want {
		if got[i] != b {
			t.Errorf("byte[%d] = 0x%02x, want 0x%02x", i, got[i], b)
		}
	}
}

// TestEncodeRotateStartVersionRoundTrip verifies that the version embedded
// in a RotateStart request can be extracted by extractProtoLenField and
// extractProtoVarintField.
func TestEncodeRotateStartVersionRoundTrip(t *testing.T) {
	const want = uint32(0xDEAD_BEEF)
	encoded := encodeRotateStart(want, []byte{1}, []byte{2})

	// The outer message has a single length-delimited field (field 6).
	sub, err := extractProtoLenField(encoded, 6)
	if err != nil || sub == nil {
		t.Fatalf("extractProtoLenField: err=%v sub=%v", err, sub)
	}

	// Inside the sub-message, field 1 is a fixed32 (wire type 5).
	// extractProtoVarintField won't work for fixed32; decode manually.
	// fixed32 tag = (1 << 3) | 5 = 0x0d
	if len(sub) < 5 || sub[0] != 0x0d {
		t.Fatalf("unexpected sub-message encoding: %x", sub)
	}
	got := binary.LittleEndian.Uint32(sub[1:5])
	if got != want {
		t.Errorf("version = 0x%08x, want 0x%08x", got, want)
	}
}

// TestRotateStartWireByteEquality verifies that the hand-rolled wire encoder in
// rotate.go produces bit-for-bit identical bytes to proto.Marshal using the
// generated Request4 / Request4_RotateStart_ types.
//
// This guards against any divergence between the two encoding paths and
// confirms that the regenerated pb.go is wire-compatible with the hand-rolled
// encoder used before the proto regen was available.
func TestRotateStartWireByteEquality(t *testing.T) {
	const version = uint32(0x0000_0042)
	oprfDelta := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	encDelta := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	// Hand-rolled encoding (the path used before proto regen).
	handRolled := encodeRotateStart(version, oprfDelta, encDelta)

	// Generated proto encoding via the new pb.go types.
	msg := &svrpb.Request4{
		Inner: &svrpb.Request4_RotateStart_{
			RotateStart: &svrpb.Request4_RotateStart{
				Version:                    version,
				OprfSecretshareDelta:       oprfDelta,
				EncryptionSecretshareDelta: encDelta,
			},
		},
	}
	generated, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}

	if !bytes.Equal(handRolled, generated) {
		t.Errorf("wire bytes differ:\n  hand-rolled: %x\n  generated:   %x", handRolled, generated)
	}
}
