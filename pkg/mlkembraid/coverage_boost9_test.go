package mlkembraid

import (
	"encoding/binary"
	"testing"
)

// ================== readOptionalDecoder: NewDecoder failure ==================

// TestReadOptionalDecoder_ZeroOriginalLen verifies that readOptionalDecoder returns
// ErrDeserialize when the originalLen field is zero, causing NewDecoder to fail.
// This exercises serialize.go:522-525, the "decoder init failed" error branch.
func TestReadOptionalDecoder_ZeroOriginalLen(t *testing.T) {
	// flag(1) + originalLen(4)=0 + received(4) + numLogged(4) = 13 bytes.
	// originalLen=0 causes NewDecoder to fail with ErrInvalidInput.
	buf := make([]byte, 13)
	buf[0] = 0x01 // present flag
	// bytes 1-4: originalLen=0 (already zero)
	// bytes 5-8: received=0
	// bytes 9-12: numLogged=0

	_, _, err := readOptionalDecoder(buf)
	if err == nil {
		t.Fatal("expected ErrDeserialize for zero originalLen")
	}
	if _, ok := err.(*ErrDeserialize); !ok {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// ================== readOptionalDecoder: data too short for chunk length ==================

// TestReadOptionalDecoder_TruncatedChunkLength verifies that readOptionalDecoder
// returns ErrDeserialize when numLogged > 0 but there are insufficient bytes to
// read the chunk length field. This exercises serialize.go:528-530.
func TestReadOptionalDecoder_TruncatedChunkLength(t *testing.T) {
	// Build a valid 13-byte header with numLogged=1, then only 1 byte of chunk
	// data (need at least 2 bytes for the u16 chunk length).
	buf := make([]byte, 13+1) // header + 1 byte (too short for u16 chunk length)
	buf[0] = 0x01             // present flag
	// originalLen = 32 (valid)
	binary.BigEndian.PutUint32(buf[1:5], 32)
	// received = 0
	binary.BigEndian.PutUint32(buf[5:9], 0)
	// numLogged = 1
	binary.BigEndian.PutUint32(buf[9:13], 1)
	// only 1 byte for chunk entry (need 2 for u16 length)
	buf[13] = 0x00

	_, _, err := readOptionalDecoder(buf)
	if err == nil {
		t.Fatal("expected ErrDeserialize for truncated chunk length")
	}
	if _, ok := err.(*ErrDeserialize); !ok {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// ================== readOptionalDecoder: data too short for chunk data ==================

// TestReadOptionalDecoder_TruncatedChunkData verifies that readOptionalDecoder
// returns ErrDeserialize when the chunk length field claims more bytes than
// are available. This exercises serialize.go:534-536.
func TestReadOptionalDecoder_TruncatedChunkData(t *testing.T) {
	// Build a valid 13-byte header with numLogged=1, then a u16 chunk length
	// claiming 100 bytes but only 1 byte available.
	buf := make([]byte, 13+2+1)              // header + u16 length + 1 byte (too short for 100)
	buf[0] = 0x01                            // present flag
	binary.BigEndian.PutUint32(buf[1:5], 32) // originalLen = 32
	binary.BigEndian.PutUint32(buf[5:9], 0)  // received = 0
	binary.BigEndian.PutUint32(buf[9:13], 1) // numLogged = 1
	// chunk length = 100 (but only 1 byte follows)
	binary.BigEndian.PutUint16(buf[13:15], 100)
	buf[15] = 0x00 // only 1 byte of data

	_, _, err := readOptionalDecoder(buf)
	if err == nil {
		t.Fatal("expected ErrDeserialize for truncated chunk data")
	}
	if _, ok := err.(*ErrDeserialize); !ok {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// ================== readOptionalDecoder: AddChunk failure ==================

// TestReadOptionalDecoder_AddChunkFails verifies that readOptionalDecoder
// returns ErrDeserialize when AddChunk fails due to invalid chunk content.
// This exercises serialize.go:541-543.
func TestReadOptionalDecoder_AddChunkFails(t *testing.T) {
	// Build a valid header, then provide a "chunk" that fails AddChunk:
	// an empty chunk (0 bytes) triggers ErrChunkFormat("chunk is empty").
	// chunk length = 0 means AddChunk receives []byte{} → error.
	buf := make([]byte, 13+2)                // header + u16 chunk length of 0
	buf[0] = 0x01                            // present flag
	binary.BigEndian.PutUint32(buf[1:5], 32) // originalLen = 32
	binary.BigEndian.PutUint32(buf[5:9], 0)  // received = 0
	binary.BigEndian.PutUint32(buf[9:13], 1) // numLogged = 1
	// chunk length = 0 → AddChunk receives empty slice → ErrChunkFormat
	binary.BigEndian.PutUint16(buf[13:15], 0)

	_, _, err := readOptionalDecoder(buf)
	if err == nil {
		t.Fatal("expected ErrDeserialize when AddChunk fails on empty chunk")
	}
	if _, ok := err.(*ErrDeserialize); !ok {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}
