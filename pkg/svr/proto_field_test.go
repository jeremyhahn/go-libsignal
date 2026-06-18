package svr

import (
	"encoding/binary"
	"testing"
)

// protoVarintField encodes a varint field for test inputs.
// wire type 0 = varint. tag = (fieldNum << 3) | 0
func protoVarintFieldBytes(fieldNum uint64, val uint64) []byte {
	tag := fieldNum << 3
	buf := make([]byte, 20)
	n := binary.PutUvarint(buf, tag)
	n += binary.PutUvarint(buf[n:], val)
	return buf[:n]
}

// proto64BitField encodes a 64-bit fixed field for test inputs.
// wire type 1. tag = (fieldNum << 3) | 1
func proto64BitField(fieldNum uint64, val uint64) []byte {
	tag := fieldNum<<3 | 1
	buf := make([]byte, 20)
	n := binary.PutUvarint(buf, tag)
	binary.LittleEndian.PutUint64(buf[n:], val)
	return buf[:n+8]
}

// proto32BitField encodes a 32-bit fixed field for test inputs.
// wire type 5. tag = (fieldNum << 3) | 5
func proto32BitFieldBytes(fieldNum uint64, val uint32) []byte {
	tag := fieldNum<<3 | 5
	buf := make([]byte, 20)
	n := binary.PutUvarint(buf, tag)
	binary.LittleEndian.PutUint32(buf[n:], val)
	return buf[:n+4]
}

// protoLenField encodes a length-delimited field for test inputs.
// wire type 2. tag = (fieldNum << 3) | 2
func protoLenFieldBytes(fieldNum uint64, data []byte) []byte {
	tag := fieldNum<<3 | 2
	buf := make([]byte, 30+len(data))
	n := binary.PutUvarint(buf, tag)
	n += binary.PutUvarint(buf[n:], uint64(len(data)))
	copy(buf[n:], data)
	return buf[:n+len(data)]
}

// ================== extractProtoLenField ==================

// TestExtractProtoLenField_VarintFieldSkip verifies that a varint (wire type 0)
// field before the target length-delimited field is skipped correctly.
func TestExtractProtoLenField_VarintFieldSkip(t *testing.T) {
	// Encode: field 1 (varint=99), field 2 (bytes=[0xAB])
	msg := append(protoVarintFieldBytes(1, 99), protoLenFieldBytes(2, []byte{0xAB})...)
	got, err := extractProtoLenField(msg, 2)
	if err != nil {
		t.Fatalf("extractProtoLenField: unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != 0xAB {
		t.Errorf("got %x, want [0xAB]", got)
	}
}

// TestExtractProtoLenField_64BitFieldSkip verifies that a 64-bit (wire type 1)
// field before the target is skipped correctly.
func TestExtractProtoLenField_64BitFieldSkip(t *testing.T) {
	// Encode: field 3 (64-bit=0xDEADBEEF), field 4 (bytes=[0x01,0x02])
	msg := append(proto64BitField(3, 0xDEADBEEF), protoLenFieldBytes(4, []byte{0x01, 0x02})...)
	got, err := extractProtoLenField(msg, 4)
	if err != nil {
		t.Fatalf("extractProtoLenField: unexpected error: %v", err)
	}
	if len(got) != 2 || got[0] != 0x01 || got[1] != 0x02 {
		t.Errorf("got %x, want [0x01 0x02]", got)
	}
}

// TestExtractProtoLenField_32BitFieldSkip verifies that a 32-bit (wire type 5)
// field before the target is skipped correctly.
func TestExtractProtoLenField_32BitFieldSkip(t *testing.T) {
	// Encode: field 5 (32-bit=0xCAFE), field 6 (bytes=[0x07])
	msg := append(proto32BitFieldBytes(5, 0xCAFE), protoLenFieldBytes(6, []byte{0x07})...)
	got, err := extractProtoLenField(msg, 6)
	if err != nil {
		t.Fatalf("extractProtoLenField: unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != 0x07 {
		t.Errorf("got %x, want [0x07]", got)
	}
}

// TestExtractProtoLenField_DefaultWireType verifies that an unknown wire type
// returns ErrBadData.
func TestExtractProtoLenField_DefaultWireType(t *testing.T) {
	// Construct a tag with wire type 3 (unused, causes default branch).
	tag := uint64(1)<<3 | 3
	buf := make([]byte, 8)
	n := binary.PutUvarint(buf, tag)
	_, err := extractProtoLenField(buf[:n], 1)
	if err == nil {
		t.Fatal("expected ErrBadData for unknown wire type")
	}
}

// TestExtractProtoLenField_64BitTruncated verifies ErrBadData when the 64-bit
// value is truncated (fewer than 8 remaining bytes).
func TestExtractProtoLenField_64BitTruncated(t *testing.T) {
	// Tag for field 1, wire type 1, followed by only 4 bytes (not 8).
	tag := uint64(1)<<3 | 1
	buf := make([]byte, 16)
	n := binary.PutUvarint(buf, tag)
	n += 4 // only 4 bytes instead of 8
	_, err := extractProtoLenField(buf[:n], 2)
	if err == nil {
		t.Fatal("expected ErrBadData for truncated 64-bit field")
	}
}

// TestExtractProtoLenField_32BitTruncated verifies ErrBadData when the 32-bit
// value is truncated (fewer than 4 remaining bytes).
func TestExtractProtoLenField_32BitTruncated(t *testing.T) {
	// Tag for field 1, wire type 5, followed by only 2 bytes (not 4).
	tag := uint64(1)<<3 | 5
	buf := make([]byte, 16)
	n := binary.PutUvarint(buf, tag)
	n += 2 // only 2 bytes instead of 4
	_, err := extractProtoLenField(buf[:n], 2)
	if err == nil {
		t.Fatal("expected ErrBadData for truncated 32-bit field")
	}
}

// TestExtractProtoLenField_LenDataTruncated verifies ErrBadData when the
// length-delimited field claims a length longer than remaining bytes.
func TestExtractProtoLenField_LenDataTruncated(t *testing.T) {
	// field 1 (bytes), but the claimed length (10) exceeds remaining data (2).
	tag := uint64(1)<<3 | 2
	buf := make([]byte, 20)
	n := binary.PutUvarint(buf, tag)
	n += binary.PutUvarint(buf[n:], 10) // claim 10 bytes
	n += 2                              // but only provide 2
	_, err := extractProtoLenField(buf[:n], 1)
	if err == nil {
		t.Fatal("expected ErrBadData for truncated length-delimited data")
	}
}

// ================== extractProtoVarintField ==================

// TestExtractProtoVarintField_LenDelimitedSkip verifies that a length-delimited
// (wire type 2) field before the target varint field is skipped correctly.
func TestExtractProtoVarintField_LenDelimitedSkip(t *testing.T) {
	// Encode: field 2 (bytes=[0xAA, 0xBB]), field 3 (varint=42)
	msg := append(protoLenFieldBytes(2, []byte{0xAA, 0xBB}), protoVarintFieldBytes(3, 42)...)
	got, err := extractProtoVarintField(msg, 3)
	if err != nil {
		t.Fatalf("extractProtoVarintField: unexpected error: %v", err)
	}
	if got != 42 {
		t.Errorf("got %d, want 42", got)
	}
}

// TestExtractProtoVarintField_64BitFieldSkip verifies that a 64-bit (wire type 1)
// field before the target varint is skipped correctly.
func TestExtractProtoVarintField_64BitFieldSkip(t *testing.T) {
	// Encode: field 1 (64-bit=0xF00F), field 2 (varint=99)
	msg := append(proto64BitField(1, 0xF00F), protoVarintFieldBytes(2, 99)...)
	got, err := extractProtoVarintField(msg, 2)
	if err != nil {
		t.Fatalf("extractProtoVarintField: unexpected error: %v", err)
	}
	if got != 99 {
		t.Errorf("got %d, want 99", got)
	}
}

// TestExtractProtoVarintField_32BitFieldSkip verifies that a 32-bit (wire type 5)
// field before the target varint is skipped correctly.
func TestExtractProtoVarintField_32BitFieldSkip(t *testing.T) {
	// Encode: field 4 (32-bit=0xABCD), field 5 (varint=77)
	msg := append(proto32BitFieldBytes(4, 0xABCD), protoVarintFieldBytes(5, 77)...)
	got, err := extractProtoVarintField(msg, 5)
	if err != nil {
		t.Fatalf("extractProtoVarintField: unexpected error: %v", err)
	}
	if got != 77 {
		t.Errorf("got %d, want 77", got)
	}
}

// TestExtractProtoVarintField_DefaultWireType verifies ErrBadData for unknown
// wire type.
func TestExtractProtoVarintField_DefaultWireType(t *testing.T) {
	// Wire type 3 is unused in protobuf.
	tag := uint64(1)<<3 | 3
	buf := make([]byte, 8)
	n := binary.PutUvarint(buf, tag)
	_, err := extractProtoVarintField(buf[:n], 1)
	if err == nil {
		t.Fatal("expected ErrBadData for unknown wire type")
	}
}

// TestExtractProtoVarintField_64BitTruncated verifies ErrBadData when the
// 64-bit field is truncated.
func TestExtractProtoVarintField_64BitTruncated(t *testing.T) {
	tag := uint64(1)<<3 | 1
	buf := make([]byte, 16)
	n := binary.PutUvarint(buf, tag)
	n += 3 // only 3 bytes instead of 8
	_, err := extractProtoVarintField(buf[:n], 2)
	if err == nil {
		t.Fatal("expected ErrBadData for truncated 64-bit field")
	}
}

// TestExtractProtoVarintField_32BitTruncated verifies ErrBadData when the
// 32-bit field is truncated.
func TestExtractProtoVarintField_32BitTruncated(t *testing.T) {
	tag := uint64(1)<<3 | 5
	buf := make([]byte, 16)
	n := binary.PutUvarint(buf, tag)
	n += 2 // only 2 bytes instead of 4
	_, err := extractProtoVarintField(buf[:n], 2)
	if err == nil {
		t.Fatal("expected ErrBadData for truncated 32-bit field")
	}
}

// TestExtractProtoVarintField_LenDataTruncated verifies ErrBadData when the
// length-delimited data is shorter than the claimed length.
func TestExtractProtoVarintField_LenDataTruncated(t *testing.T) {
	tag := uint64(1)<<3 | 2
	buf := make([]byte, 20)
	n := binary.PutUvarint(buf, tag)
	n += binary.PutUvarint(buf[n:], 10) // claim 10 bytes
	n += 2                              // but only provide 2
	_, err := extractProtoVarintField(buf[:n], 2)
	if err == nil {
		t.Fatal("expected ErrBadData for truncated length-delimited data")
	}
}

// TestExtractProtoVarintField_FieldNotFound verifies ErrBadResponse when the
// field is not found in the message.
func TestExtractProtoVarintField_FieldNotFound(t *testing.T) {
	// Only field 1 exists, asking for field 99.
	msg := protoVarintFieldBytes(1, 5)
	_, err := extractProtoVarintField(msg, 99)
	if err == nil {
		t.Fatal("expected error when field not found")
	}
}
