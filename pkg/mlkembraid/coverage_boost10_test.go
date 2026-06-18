package mlkembraid

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid/internal/polynomial"
)

// ================== ProtoUnmarshalEncoder: Polys-state empty message ==================

// TestProtoUnmarshalEncoder_PolysStateEmptyMessage verifies that
// ProtoUnmarshalEncoder returns an error when the PolyEncoder is in Polys state
// and encoderMessage returns an empty byte slice (no stored Points).
// This exercises proto_accessors.go:494-496, the "encoder produced empty message"
// branch triggered when ProtoEncoderMessageLen returns 0.
//
// When polys are provided (not pts), protoPolyEncoderFromFields calls
// NewPolyEncoderFromPolys which creates an encoder in EncoderStatePolys.
// In Polys state, e.Points() returns an array of empty Points (Value==nil),
// so encoderMessage computes totalElems=0, msgLen=0, and returns []byte{}.
// ProtoEncoderMessageLen then returns 0, triggering the error path.
func TestProtoUnmarshalEncoder_PolysStateEmptyMessage(t *testing.T) {
	// Build 16 minimal valid serialized polynomials (2 bytes each = 1 coefficient).
	// DeserializePoly requires len > 0 and len%2 == 0.
	polys := make([][]byte, polynomial.NumPolys)
	for i := range polys {
		// Serialize a single GF(2^16) coefficient as 2 bytes.
		// Any non-zero even-length byte slice is accepted.
		polys[i] = []byte{byte(i + 1), byte(i + 2)}
	}

	// With pts==nil and len(polys)==NumPolys, protoPolyEncoderFromFields enters
	// the Polys-state branch and creates an encoder with empty points arrays.
	// ProtoEncoderMessageLen(inner) then returns 0, triggering the error.
	_, err := ProtoUnmarshalEncoder(0, nil, polys)
	if err == nil {
		t.Fatal("expected error when Polys-state encoder produces empty message")
	}
}

// ================== ProtoUnmarshalEncoder: pts with wrong channel count ==================

// TestProtoUnmarshalEncoder_PtsWrongChannelCount verifies that
// ProtoUnmarshalEncoder returns an error when pts has the wrong number of
// channels (not NumPolys). This exercises proto_accessors.go:504-506.
func TestProtoUnmarshalEncoder_PtsWrongChannelCount(t *testing.T) {
	// Provide 3 channels instead of NumPolys (16).
	pts := make([][]byte, 3)
	for i := range pts {
		pts[i] = []byte{0x00, 0x01}
	}

	_, err := ProtoUnmarshalEncoder(0, pts, nil)
	if err == nil {
		t.Fatal("expected error for wrong pts channel count")
	}
}

// ================== ProtoUnmarshalEncoder: pts with odd-length channel ==================

// TestProtoUnmarshalEncoder_PtsOddLength verifies that ProtoUnmarshalEncoder
// returns an error when a pts channel has an odd byte length.
// This exercises proto_accessors.go:508-510.
func TestProtoUnmarshalEncoder_PtsOddLength(t *testing.T) {
	pts := make([][]byte, polynomial.NumPolys)
	for i := range pts {
		pts[i] = []byte{0x00, 0x01} // 2 bytes = valid
	}
	// Make channel 0 odd-length.
	pts[0] = []byte{0x00}

	_, err := ProtoUnmarshalEncoder(0, pts, nil)
	if err == nil {
		t.Fatal("expected error for odd-length pts channel")
	}
}

// ================== ProtoUnmarshalEncoder: polys with wrong count ==================

// TestProtoUnmarshalEncoder_PolysWrongCount verifies that ProtoUnmarshalEncoder
// returns an error when neither pts nor polys has the right length.
// This exercises proto_accessors.go:575, the "neither pts nor polys" error.
func TestProtoUnmarshalEncoder_PolysWrongCount(t *testing.T) {
	// pts is empty, polys has wrong count (not NumPolys).
	polys := make([][]byte, 3)
	for i := range polys {
		polys[i] = []byte{0x01, 0x02}
	}

	_, err := ProtoUnmarshalEncoder(0, nil, polys)
	if err == nil {
		t.Fatal("expected error for wrong polys count")
	}
}

// ================== ProtoUnmarshalEncoder: invalid poly bytes ==================

// TestProtoUnmarshalEncoder_InvalidPolyBytes verifies that ProtoUnmarshalEncoder
// returns an error when a poly entry has invalid bytes (odd length).
// This exercises proto_accessors.go:562-564.
func TestProtoUnmarshalEncoder_InvalidPolyBytes(t *testing.T) {
	polys := make([][]byte, polynomial.NumPolys)
	for i := range polys {
		polys[i] = []byte{byte(i + 1), byte(i + 2)} // valid 2-byte poly
	}
	// Make poly[5] invalid: odd length fails DeserializePoly.
	polys[5] = []byte{0x01}

	_, err := ProtoUnmarshalEncoder(0, nil, polys)
	if err == nil {
		t.Fatal("expected error for invalid poly bytes (odd length)")
	}
}
