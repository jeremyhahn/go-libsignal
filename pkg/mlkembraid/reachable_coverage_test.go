package mlkembraid

import (
	"errors"
	"testing"
)

// overflowVarint returns 10 bytes that each have the continuation bit set,
// which makes encoding/binary.Uvarint report an overflow (n < 0).
func overflowVarint() []byte {
	b := make([]byte, 10)
	for i := range b {
		b[i] = 0x80
	}
	return b
}

// TestDeserializeSCKA_EpochVarintOverflow exercises the n<=0 branch on the
// epoch varint decode in DeserializeSCKA (message.go:149).
func TestDeserializeSCKA_EpochVarintOverflow(t *testing.T) {
	data := append([]byte{SPQRVersion}, overflowVarint()...)
	_, _, err := DeserializeSCKA(data)
	if err == nil {
		t.Fatal("expected error for overflowing epoch varint")
	}
	var de *ErrSCKADecode
	if !errors.As(err, &de) {
		t.Fatalf("expected *ErrSCKADecode, got %T: %v", err, err)
	}
}

// TestDeserializeSCKA_ChainIndexVarintOverflow exercises the n<=0 branch on the
// chain_index varint decode (message.go:159). The epoch varint is valid (=1),
// then the chain_index varint overflows.
func TestDeserializeSCKA_ChainIndexVarintOverflow(t *testing.T) {
	data := []byte{SPQRVersion, 0x01} // version + epoch=1
	data = append(data, overflowVarint()...)
	_, _, err := DeserializeSCKA(data)
	if err == nil {
		t.Fatal("expected error for overflowing chain_index varint")
	}
	var de *ErrSCKADecode
	if !errors.As(err, &de) {
		t.Fatalf("expected *ErrSCKADecode, got %T: %v", err, err)
	}
}

// TestDeserializeSCKA_ChainIndexExceedsU32 exercises the chain_index > u32 range
// check (message.go:164). chain_index is a valid varint but larger than 2^32-1.
func TestDeserializeSCKA_ChainIndexExceedsU32(t *testing.T) {
	// version + epoch=1 + chain_index = 2^32 (encoded as varint) + type
	data := []byte{SPQRVersion, 0x01}
	// 2^32 = 4294967296; varint encoding:
	var ci uint64 = 1 << 32
	for ci >= 0x80 {
		data = append(data, byte(ci)|0x80)
		ci >>= 7
	}
	data = append(data, byte(ci))
	data = append(data, byte(MessageTypeNone))
	_, _, err := DeserializeSCKA(data)
	if err == nil {
		t.Fatal("expected error for chain_index exceeding u32 range")
	}
	var de *ErrSCKADecode
	if !errors.As(err, &de) {
		t.Fatalf("expected *ErrSCKADecode, got %T: %v", err, err)
	}
}

// TestDeserializeSCKA_ChunkIndexVarintOverflow exercises the n2<=0 branch on the
// chunk index varint for a chunk-bearing message type (message.go:188).
func TestDeserializeSCKA_ChunkIndexVarintOverflow(t *testing.T) {
	// version + epoch=1 + chain_index=0 + type=Hdr(chunk-bearing) + overflow varint
	data := []byte{SPQRVersion, 0x01, 0x00, byte(MessageTypeHdr)}
	data = append(data, overflowVarint()...)
	_, _, err := DeserializeSCKA(data)
	if err == nil {
		t.Fatal("expected error for overflowing chunk index varint")
	}
	var de *ErrSCKADecode
	if !errors.As(err, &de) {
		t.Fatalf("expected *ErrSCKADecode, got %T: %v", err, err)
	}
}

// TestDeserializeSCKA_ChunkIndexExceeds65535 exercises the chunk index upper
// bound check (message.go:191) for a chunk-bearing message type.
func TestDeserializeSCKA_ChunkIndexExceeds65535(t *testing.T) {
	data := []byte{SPQRVersion, 0x01, 0x00, byte(MessageTypeHdr)}
	// chunk index = 70000 (> 65535) as varint, then 32 chunk bytes.
	var ci uint64 = 70000
	for ci >= 0x80 {
		data = append(data, byte(ci)|0x80)
		ci >>= 7
	}
	data = append(data, byte(ci))
	data = append(data, make([]byte, 32)...)
	_, _, err := DeserializeSCKA(data)
	if err == nil {
		t.Fatal("expected error for chunk index exceeding 65535")
	}
	var de *ErrSCKADecode
	if !errors.As(err, &de) {
		t.Fatalf("expected *ErrSCKADecode, got %T: %v", err, err)
	}
}
