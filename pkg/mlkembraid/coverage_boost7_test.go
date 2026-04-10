package mlkembraid

import (
	"encoding/binary"
	"testing"
)

// ================== readOptionalSecret: empty data ==================

// TestReadOptionalSecretEmptyData exercises the len(data) < 1 branch in
// readOptionalSecret, covering the "data too short for optional secret flag" error.
func TestReadOptionalSecretEmptyData(t *testing.T) {
	_, _, err := readOptionalSecret([]byte{})
	if err == nil {
		t.Fatal("expected error for empty data")
	}
	if _, ok := err.(*ErrDeserialize); !ok {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// ================== readOptionalEncoder: empty data ==================

// TestReadOptionalEncoderEmptyData exercises the len(data) < 1 branch in
// readOptionalEncoder, covering the "data too short for optional encoder flag" error.
func TestReadOptionalEncoderEmptyData(t *testing.T) {
	_, _, err := readOptionalEncoder([]byte{})
	if err == nil {
		t.Fatal("expected error for empty data")
	}
	if _, ok := err.(*ErrDeserialize); !ok {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// ================== readOptionalDecoder: empty data ==================

// TestReadOptionalDecoderEmptyData exercises the len(data) < 1 branch in
// readOptionalDecoder, covering the "data too short for optional decoder flag" error.
func TestReadOptionalDecoderEmptyData(t *testing.T) {
	_, _, err := readOptionalDecoder([]byte{})
	if err == nil {
		t.Fatal("expected error for empty data")
	}
	if _, ok := err.(*ErrDeserialize); !ok {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// ================== AddChunk: chunk index exceeds u16 range ==================

// TestAddChunkIndexExceedsU16 exercises the branch in AddChunk where the varint
// index value exceeds MaxChunkIndex (65535), triggering ErrChunkFormat.
func TestAddChunkIndexExceedsU16(t *testing.T) {
	dec, err := NewDecoder(32, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	// Encode varint for 65536 (MaxChunkIndex+1 = 0x10000).
	// varint encoding: 0x80|0x00=0x80, 0x80|0x00=0x80, 0x80|0x00=0x80, 0x01
	// Actually 65536 = 0x10000: in 7-bit groups: 0x00, 0x00, 0x04 (shifted)
	// Let's use binary.PutUvarint which is authoritative.
	var varBuf [10]byte
	n := binary.PutUvarint(varBuf[:], uint64(MaxChunkIndex+1))
	chunk := make([]byte, n+ChunkDataSize)
	copy(chunk, varBuf[:n])
	// data bytes remain zero

	if err := dec.AddChunk(chunk); err == nil {
		t.Fatal("expected error for chunk index exceeding MaxChunkIndex")
	} else if _, ok := err.(*ErrChunkFormat); !ok {
		t.Errorf("expected *ErrChunkFormat, got %T: %v", err, err)
	}
}

// ================== bobCompleteEncapsulation: single-phase FullEncaps path ==================

// TestBobCompleteEncapsulationSinglePhase exercises the else branch in
// bobCompleteEncapsulation where bobEncapSecret is nil, using FullEncaps directly
// after hek verification. This covers the single-phase encapsulation code path.
func TestBobCompleteEncapsulationSinglePhase(t *testing.T) {
	ss := randomSecret(t)
	kemImpl := NewMLKEM768IncrementalKEM()
	_, ekSeed, ekVector, err := kemImpl.KeyGen()
	if err != nil {
		t.Fatal(err)
	}

	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}

	hek := computeHEK(ekSeed, ekVector)

	// Build a complete ekDecoder with the full ek_vector.
	testChunkSize := 256
	ekEnc, err := NewEncoder(ekVector, testChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	ekDec, err := NewDecoder(len(ekVector), testChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	for ekEnc.HasMore() {
		if err := ekDec.AddChunk(ekEnc.NextChunk()); err != nil {
			t.Fatal(err)
		}
	}

	state := &State{
		kind:      StateHeaderReceived,
		epoch:     5,
		auth:      auth,
		bobEkSeed: mustSecret(t, ekSeed),
		bobHek:    mustSecret(t, hek),
		// bobEncapSecret is nil → single-phase FullEncaps path
		ekDecoder: ekDec,
		chunkSize: testChunkSize,
	}

	outputKey, err := state.bobCompleteEncapsulation(kemImpl, testChunkSize)
	if err != nil {
		t.Fatalf("bobCompleteEncapsulation single-phase failed: %v", err)
	}
	if outputKey == nil {
		t.Fatal("expected non-nil output key")
	}
	if state.kind != StateCt1Sampled {
		t.Errorf("expected StateCt1Sampled, got %s", state.kind)
	}
	outputKey.Key.Destroy()
}
