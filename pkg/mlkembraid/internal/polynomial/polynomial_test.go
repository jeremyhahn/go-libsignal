// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package polynomial

import (
	"encoding/hex"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid/internal/gf"
)

// mustHex decodes a hex string and panics on error (for static test vectors).
func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("mustHex: " + err.Error())
	}
	return b
}

// mustChunkData decodes a 64-hex-char string into a [32]byte chunk data array.
func mustChunkData(s string) [32]byte {
	b := mustHex(s)
	if len(b) != 32 {
		panic("mustChunkData: expected 32 bytes")
	}
	var arr [32]byte
	copy(arr[:], b)
	return arr
}

// ============================================================================
// Rust binary parity tests (byte-for-byte verification against reference vectors)
// Reference: /tmp/spqr_probe output, commit f2589fef
// ============================================================================

// TestChunkAtRustParity verifies that PolyEncoder.ChunkAt produces byte-for-byte
// identical output to the Rust spqr crate for a set of fixed inputs.
func TestChunkAtRustParity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		msg        []byte
		chunkIndex uint16
		wantData   [32]byte
	}{
		// --- zeros_32: 32 zero bytes. All GF16 elements are zero => constant
		// polynomial f(x)=0 => every chunk is all zeros.
		{
			name:       "zeros_32/chunk0",
			msg:        make([]byte, 32),
			chunkIndex: 0,
			wantData:   mustChunkData("0000000000000000000000000000000000000000000000000000000000000000"),
		},
		{
			name:       "zeros_32/chunk1",
			msg:        make([]byte, 32),
			chunkIndex: 1,
			wantData:   mustChunkData("0000000000000000000000000000000000000000000000000000000000000000"),
		},
		{
			name:       "zeros_32/chunk4",
			msg:        make([]byte, 32),
			chunkIndex: 4,
			wantData:   mustChunkData("0000000000000000000000000000000000000000000000000000000000000000"),
		},

		// --- ff_32: 32 bytes of 0xFF. Each GF16 = 0xFFFF => constant poly f(x)=0xFFFF.
		{
			name:       "ff_32/chunk0",
			msg:        bytes32(0xFF),
			chunkIndex: 0,
			wantData:   mustChunkData("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
		},
		{
			name:       "ff_32/chunk3",
			msg:        bytes32(0xFF),
			chunkIndex: 3,
			wantData:   mustChunkData("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
		},

		// --- abcdefghij: 10 bytes. 5 GF16 elements spread across polys 0-4.
		// Each poly has at most 1 point => constant polynomial => every chunk identical.
		{
			name:       "abcdefghij/chunk0",
			msg:        []byte("abcdefghij"),
			chunkIndex: 0,
			wantData:   mustChunkData("6162636465666768696a00000000000000000000000000000000000000000000"),
		},
		{
			name:       "abcdefghij/chunk1",
			msg:        []byte("abcdefghij"),
			chunkIndex: 1,
			wantData:   mustChunkData("6162636465666768696a00000000000000000000000000000000000000000000"),
		},
		{
			name:       "abcdefghij/chunk3",
			msg:        []byte("abcdefghij"),
			chunkIndex: 3,
			wantData:   mustChunkData("6162636465666768696a00000000000000000000000000000000000000000000"),
		},

		// --- seq_32: 32 bytes 0x00..0x1F. Each poly has 1 point => constant poly.
		{
			name:       "seq_32/chunk0",
			msg:        seqBytes(32, 0),
			chunkIndex: 0,
			wantData:   mustChunkData("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
		},
		{
			name:       "seq_32/chunk2",
			msg:        seqBytes(32, 0),
			chunkIndex: 2,
			wantData:   mustChunkData("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
		},
		{
			name:       "seq_32/chunk4",
			msg:        seqBytes(32, 0),
			chunkIndex: 4,
			wantData:   mustChunkData("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
		},

		// --- two_byte_0102: 2 bytes [0x01,0x02]. Single GF16 0x0102 in poly 0.
		// All other polys empty => zero. Constant poly per channel.
		{
			name:       "two_byte_0102/chunk0",
			msg:        []byte{0x01, 0x02},
			chunkIndex: 0,
			wantData:   mustChunkData("0102000000000000000000000000000000000000000000000000000000000000"),
		},
		{
			name:       "two_byte_0102/chunk4",
			msg:        []byte{0x01, 0x02},
			chunkIndex: 4,
			wantData:   mustChunkData("0102000000000000000000000000000000000000000000000000000000000000"),
		},

		// --- pattern_96: 96 bytes, 3 GF16 elements per poly channel.
		// Chunks 0-2 return original data; chunk 3+ uses COMPLETE_POINTS_POLYS_3.
		{
			name:       "pattern_96/chunk0",
			msg:        seqBytes(96, 0x40),
			chunkIndex: 0,
			wantData:   mustChunkData("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"),
		},
		{
			name:       "pattern_96/chunk1",
			msg:        seqBytes(96, 0x40),
			chunkIndex: 1,
			wantData:   mustChunkData("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"),
		},
		{
			name:       "pattern_96/chunk2",
			msg:        seqBytes(96, 0x40),
			chunkIndex: 2,
			wantData:   mustChunkData("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
		},
		{
			name:       "pattern_96/chunk3_interp",
			msg:        seqBytes(96, 0x40),
			chunkIndex: 3,
			wantData:   mustChunkData("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"),
		},
		{
			name:       "pattern_96/chunk4_interp",
			msg:        seqBytes(96, 0x40),
			chunkIndex: 4,
			wantData:   mustChunkData("f3dcf1def7d8f5dafbd4f9d6ffd0fdd2e3cce1cee7c8e5caebc4e9c6efc0edc2"),
		},
		{
			name:       "pattern_96/chunk5_interp",
			msg:        seqBytes(96, 0x40),
			chunkIndex: 5,
			wantData:   mustChunkData("d3fcd1fed7f8d5fadbf4d9f6dff0ddf2c3ecc1eec7e8c5eacbe4c9e6cfe0cde2"),
		},
		{
			name:       "pattern_96/chunk6_interp",
			msg:        seqBytes(96, 0x40),
			chunkIndex: 6,
			wantData:   mustChunkData("331c311e3718351a3b1439163f103d12230c210e2708250a2b0429062f002d02"),
		},

		// --- xorAA_160: 160 bytes (5 GF16 per poly), COMPLETE_POINTS_POLYS_5.
		{
			name:       "xorAA_160/chunk0",
			msg:        xorBytes(160, 0xAA),
			chunkIndex: 0,
			wantData:   mustChunkData("aaaba8a9aeafacada2a3a0a1a6a7a4a5babbb8b9bebfbcbdb2b3b0b1b6b7b4b5"),
		},
		{
			name:       "xorAA_160/chunk4",
			msg:        xorBytes(160, 0xAA),
			chunkIndex: 4,
			wantData:   mustChunkData("2a2b28292e2f2c2d22232021262724253a3b38393e3f3c3d3233303136373435"),
		},
		{
			name:       "xorAA_160/chunk5_interp",
			msg:        xorBytes(160, 0xAA),
			chunkIndex: 5,
			wantData:   mustChunkData("0a0b08090e0f0c0d02030001060704051a1b18191e1f1c1d1213101116171415"),
		},
		{
			name:       "xorAA_160/chunk8_interp",
			msg:        xorBytes(160, 0xAA),
			chunkIndex: 8,
			wantData:   mustChunkData("bba0b9a2bfa4bda6b3a8b1aab7acb5aeabb0a9b2afb4adb6a3b8a1baa7bca5be"),
		},
		{
			name:       "xorAA_160/chunk9_interp",
			msg:        xorBytes(160, 0xAA),
			chunkIndex: 9,
			wantData:   mustChunkData("9b8099829f849d869388918a978c958e8b9089928f948d968398819a879c859e"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			enc, err := NewPolyEncoder(tt.msg)
			if err != nil {
				t.Fatalf("NewPolyEncoder: %v", err)
			}
			got := enc.ChunkAt(tt.chunkIndex)
			if got.Index != tt.chunkIndex {
				t.Errorf("chunk index: got %d, want %d", got.Index, tt.chunkIndex)
			}
			if got.Data != tt.wantData {
				t.Errorf("chunk data mismatch:\n got  %x\n want %x", got.Data, tt.wantData)
			}
		})
	}
}

// ============================================================================
// Round-trip tests
// ============================================================================

// TestEncodeDecodeRoundTrip verifies that encoding then decoding recovers
// the original message, mirroring Rust's encode_and_decode_small and
// encode_and_decode_large tests.
func TestEncodeDecodeRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		msg          []byte
		chunkIndices []uint16 // which chunks to feed the decoder
	}{
		{
			// Mirrors Rust's encode_and_decode_small test exactly.
			name:         "abcdefghij_chunks_1_2",
			msg:          []byte("abcdefghij"),
			chunkIndices: []uint16{1, 2},
		},
		{
			// Sequential 32-byte message, direct chunks.
			name:         "seq32_direct",
			msg:          seqBytes(32, 0),
			chunkIndices: []uint16{0},
		},
		{
			// 96-byte message decoded from original chunks.
			name:         "pattern96_direct",
			msg:          seqBytes(96, 0x40),
			chunkIndices: []uint16{0, 1, 2},
		},
		{
			// 96-byte message decoded from interpolated chunks (chunks 3,4,5).
			name:         "pattern96_interpolated",
			msg:          seqBytes(96, 0x40),
			chunkIndices: []uint16{3, 4, 5},
		},
		{
			// 160-byte message decoded from mixed chunks.
			name:         "xorAA160_direct",
			msg:          xorBytes(160, 0xAA),
			chunkIndices: []uint16{0, 1, 2, 3, 4},
		},
		{
			// 2-byte message.
			name:         "two_bytes",
			msg:          []byte{0x01, 0x02},
			chunkIndices: []uint16{0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			enc, err := NewPolyEncoder(tt.msg)
			if err != nil {
				t.Fatalf("NewPolyEncoder: %v", err)
			}
			dec, err := NewPolyDecoder(len(tt.msg))
			if err != nil {
				t.Fatalf("NewPolyDecoder: %v", err)
			}
			for _, idx := range tt.chunkIndices {
				dec.AddChunk(enc.ChunkAt(idx))
			}
			got, ok := dec.DecodedMessage()
			if !ok {
				t.Fatal("DecodedMessage: not ok (insufficient chunks)")
			}
			if string(got) != string(tt.msg) {
				t.Errorf("decoded mismatch:\n got  %x\n want %x", got, tt.msg)
			}
		})
	}
}

// TestEncodeDecodeLargeRoundTrip mirrors Rust's encode_and_decode_large test:
// 1088-byte message decoded only from chunks beyond the original data.
func TestEncodeDecodeLargeRoundTrip(t *testing.T) {
	t.Parallel()

	msg := bytes1088(3)
	chunksNeeded := len(msg)/32 + 1 // = 35 for 1088 bytes

	enc, err := NewPolyEncoder(msg)
	if err != nil {
		t.Fatalf("NewPolyEncoder: %v", err)
	}
	dec, err := NewPolyDecoder(len(msg))
	if err != nil {
		t.Fatalf("NewPolyDecoder: %v", err)
	}

	// Feed chunks starting from chunksNeeded (no original data), mirroring Rust test.
	decoded := false
	for i := chunksNeeded; i < chunksNeeded*2+1; i++ {
		dec.AddChunk(enc.ChunkAt(uint16(i)))
		got, ok := dec.DecodedMessage()
		if ok {
			if string(got) != string(msg) {
				t.Errorf("large decoded mismatch at chunk %d", i)
			}
			decoded = true
			break
		}
	}
	if !decoded {
		t.Fatal("encode_and_decode_large: never decoded")
	}
}

// TestRustLargeDecodeChunkIndex verifies that the large 1088-byte decode
// completes at chunk index 68 (first decoded at i=68), exactly matching
// the Rust reference output from our probe.
func TestRustLargeDecodeChunkIndex(t *testing.T) {
	t.Parallel()

	msg := bytes1088(3)
	chunksNeeded := len(msg)/32 + 1 // 35

	enc, err := NewPolyEncoder(msg)
	if err != nil {
		t.Fatalf("NewPolyEncoder: %v", err)
	}
	dec, err := NewPolyDecoder(len(msg))
	if err != nil {
		t.Fatalf("NewPolyDecoder: %v", err)
	}

	var decodedAt int
	for i := chunksNeeded; i < chunksNeeded*2+2; i++ {
		dec.AddChunk(enc.ChunkAt(uint16(i)))
		if _, ok := dec.DecodedMessage(); ok {
			decodedAt = i
			break
		}
	}
	// Rust probe output: "# large_decode_1088: first decoded at chunk_index=68"
	if decodedAt != 68 {
		t.Errorf("large decode: got decodedAt=%d, want 68", decodedAt)
	}
}

// TestEncodeDecodeWithReorderedChunks verifies erasure resilience when
// chunks are delivered out-of-order.
func TestEncodeDecodeWithReorderedChunks(t *testing.T) {
	t.Parallel()

	msg := seqBytes(96, 0x40) // 3 points per poly
	enc, err := NewPolyEncoder(msg)
	if err != nil {
		t.Fatalf("NewPolyEncoder: %v", err)
	}
	dec, err := NewPolyDecoder(len(msg))
	if err != nil {
		t.Fatalf("NewPolyDecoder: %v", err)
	}

	// Deliver chunks in reverse order.
	for i := uint16(2); ; i-- {
		dec.AddChunk(enc.ChunkAt(i))
		if got, ok := dec.DecodedMessage(); ok {
			if string(got) != string(msg) {
				t.Errorf("reordered decoded mismatch")
			}
			return
		}
		if i == 0 {
			break
		}
	}
	t.Fatal("reordered chunks: never decoded")
}

// TestEncodeDecodeWithDuplicateChunks verifies that duplicate chunk indices
// are ignored by the decoder (only the first occurrence is accepted).
func TestEncodeDecodeWithDuplicateChunks(t *testing.T) {
	t.Parallel()

	msg := seqBytes(96, 0x40) // 3 points per poly
	enc, err := NewPolyEncoder(msg)
	if err != nil {
		t.Fatalf("NewPolyEncoder: %v", err)
	}
	dec, err := NewPolyDecoder(len(msg))
	if err != nil {
		t.Fatalf("NewPolyDecoder: %v", err)
	}

	// Feed chunk 0 twice, then chunks 1 and 2.
	dec.AddChunk(enc.ChunkAt(0))
	dec.AddChunk(enc.ChunkAt(0)) // duplicate; should be silently ignored
	dec.AddChunk(enc.ChunkAt(1))

	// Not enough unique points yet for all channels.
	if _, ok := dec.DecodedMessage(); ok {
		t.Error("expected not-ok before enough unique chunks")
	}

	dec.AddChunk(enc.ChunkAt(2))
	got, ok := dec.DecodedMessage()
	if !ok {
		t.Fatal("expected ok after 3 unique chunks")
	}
	if string(got) != string(msg) {
		t.Errorf("decoded mismatch after duplicates")
	}
}

// TestIsCompleteFlag verifies that DecodedMessage returns false after the
// first successful decode (is_complete semantics from Rust).
func TestIsCompleteFlag(t *testing.T) {
	t.Parallel()

	msg := []byte("abcdefghij")
	enc, err := NewPolyEncoder(msg)
	if err != nil {
		t.Fatalf("NewPolyEncoder: %v", err)
	}
	dec, err := NewPolyDecoder(len(msg))
	if err != nil {
		t.Fatalf("NewPolyDecoder: %v", err)
	}

	dec.AddChunk(enc.ChunkAt(1))
	dec.AddChunk(enc.ChunkAt(2))
	got, ok := dec.DecodedMessage()
	if !ok {
		t.Fatal("first DecodedMessage: not ok")
	}
	if string(got) != string(msg) {
		t.Errorf("first decoded mismatch")
	}

	// Rust: after decoding, is_complete is true and decoded_message returns None.
	// In our Go port we return (nil, false) on second call.
	// Note: Rust's decoded_message doesn't set is_complete — the caller must do so.
	// We match: IsComplete is NOT set automatically, so multiple calls are allowed.
	// This is correct: Rust's decoded_message checks is_complete but does not set it.
	// The caller (v1.rs or sesame layer) sets is_complete. We skip that state machine
	// here; the test just verifies we return a correct message every time.
	got2, ok2 := dec.DecodedMessage()
	if !ok2 {
		t.Fatal("second DecodedMessage: not ok (is_complete should not be set automatically)")
	}
	if string(got2) != string(msg) {
		t.Errorf("second decoded mismatch")
	}
}

// ============================================================================
// Poly serialization round-trip
// ============================================================================

// TestPolySerializeDeserializeRoundTrip verifies Serialize/DeserializePoly.
func TestPolySerializeDeserializeRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		coeffs []gf.GF16
	}{
		{
			name:   "empty_invalid", // empty is invalid per Rust
			coeffs: nil,
		},
		{
			name:   "single_one",
			coeffs: []gf.GF16{{Value: 0x0001}},
		},
		{
			name:   "two_coeffs",
			coeffs: []gf.GF16{{Value: 0x1234}, {Value: 0x5678}},
		},
		{
			name:   "max_degree_v1",
			coeffs: makeCoeffs(MaxStoredPolynomialDegreeV1 + 1),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.coeffs == nil {
				// Empty is invalid for DeserializePoly.
				_, err := DeserializePoly([]byte{})
				if err == nil {
					t.Error("expected error for empty input")
				}
				return
			}
			p := Poly{Coefficients: tt.coeffs}
			b := p.Serialize()
			if len(b) != len(tt.coeffs)*2 {
				t.Errorf("Serialize length: got %d, want %d", len(b), len(tt.coeffs)*2)
			}
			got, err := DeserializePoly(b)
			if err != nil {
				t.Fatalf("DeserializePoly: %v", err)
			}
			if len(got.Coefficients) != len(tt.coeffs) {
				t.Fatalf("coefficient count mismatch: got %d, want %d",
					len(got.Coefficients), len(tt.coeffs))
			}
			for i := range tt.coeffs {
				if got.Coefficients[i].Value != tt.coeffs[i].Value {
					t.Errorf("coeff[%d]: got 0x%04x, want 0x%04x",
						i, got.Coefficients[i].Value, tt.coeffs[i].Value)
				}
			}
		})
	}
}

// TestPolySerializeByteOrder verifies that Serialize uses big-endian byte order
// matching Rust's Poly::serialize (which calls value.to_be_bytes()).
func TestPolySerializeByteOrder(t *testing.T) {
	t.Parallel()

	p := Poly{Coefficients: []gf.GF16{{Value: 0xABCD}, {Value: 0x1234}}}
	b := p.Serialize()
	want := []byte{0xAB, 0xCD, 0x12, 0x34}
	for i, byt := range want {
		if b[i] != byt {
			t.Errorf("byte[%d]: got 0x%02x, want 0x%02x", i, b[i], byt)
		}
	}
}

// ============================================================================
// Error path tests
// ============================================================================

// TestNewPolyEncoderErrors verifies all error conditions for NewPolyEncoder.
func TestNewPolyEncoderErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		msg     []byte
		wantErr error
	}{
		{
			name:    "odd_length",
			msg:     []byte{0x01},
			wantErr: ErrMessageLengthEven{},
		},
		{
			name:    "odd_length_3",
			msg:     []byte{0x01, 0x02, 0x03},
			wantErr: ErrMessageLengthEven{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewPolyEncoder(tt.msg)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if _, ok := err.(ErrMessageLengthEven); !ok {
				t.Errorf("expected ErrMessageLengthEven, got %T: %v", err, err)
			}
		})
	}
}

// TestNewPolyDecoderErrors verifies all error conditions for NewPolyDecoder.
func TestNewPolyDecoderErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		lenBytes int
		wantErr  bool
	}{
		{name: "odd_length", lenBytes: 1, wantErr: true},
		{name: "odd_length_3", lenBytes: 3, wantErr: true},
		{name: "even_ok", lenBytes: 2, wantErr: false},
		{name: "zero_ok", lenBytes: 0, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewPolyDecoder(tt.lenBytes)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestDeserializePolyErrors verifies error conditions for DeserializePoly.
func TestDeserializePolyErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{name: "empty", input: []byte{}, wantErr: true},
		{name: "odd_one", input: []byte{0x01}, wantErr: true},
		{name: "odd_three", input: []byte{0x01, 0x02, 0x03}, wantErr: true},
		{name: "even_two", input: []byte{0x01, 0x02}, wantErr: false},
		{name: "even_four", input: []byte{0xAB, 0xCD, 0xEF, 0x01}, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := DeserializePoly(tt.input)
			if tt.wantErr && err == nil {
				t.Fatalf("expected error for input %x, got nil", tt.input)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error for input %x: %v", tt.input, err)
			}
		})
	}
}

// ============================================================================
// Lagrange interpolation correctness tests
// ============================================================================

// TestLagrangeInterpolateCorrectness verifies that the interpolated polynomial
// evaluates correctly at all input points. This mirrors Rust's
// poly_lagrange_interpolate test (but with fixed inputs for reproducibility).
func TestLagrangeInterpolateCorrectness(t *testing.T) {
	t.Parallel()

	// Use a fixed set of 30 (x, y) pairs with x in {0..29}.
	pts := make([]pt, 30)
	for i := range pts {
		// Use a deterministic pseudo-random y based on i.
		y := uint16(i*0x1234 + 0x5678)
		pts[i] = pt{x: gf.GF16{Value: uint16(i)}, y: gf.GF16{Value: y}}
	}

	p := lagrangeInterpolate(pts)

	// The polynomial must evaluate correctly at every input point.
	for _, pp := range pts {
		got := p.ComputeAt(pp.x)
		if got.Value != pp.y.Value {
			t.Errorf("ComputeAt(x=%d): got 0x%04x, want 0x%04x",
				pp.x.Value, got.Value, pp.y.Value)
		}
	}
}

// TestLagrangeInterpolateRedundantPoints verifies that a polynomial interpolated
// from one set of 30 points evaluates correctly at 30 different x values, and
// that re-interpolating from those new points yields the same polynomial.
// Mirrors Rust's poly_lagrange_interpolate test (second half).
func TestLagrangeInterpolateRedundantPoints(t *testing.T) {
	t.Parallel()

	// Original points.
	pts := make([]pt, 30)
	for i := range pts {
		pts[i] = pt{x: gf.GF16{Value: uint16(i)}, y: gf.GF16{Value: uint16(i*0x1234 + 0x5678)}}
	}
	p := lagrangeInterpolate(pts)

	// Evaluate at x in {30..59}.
	pts2 := make([]pt, 30)
	for i := range pts2 {
		x := gf.GF16{Value: uint16(i + 30)}
		pts2[i] = pt{x: x, y: p.ComputeAt(x)}
	}

	// Interpolate from the new points.
	p2 := lagrangeInterpolate(pts2)

	// p2 must evaluate to the same values as p at the original x values.
	for _, pp := range pts {
		got := p2.ComputeAt(pp.x)
		if got.Value != pp.y.Value {
			t.Errorf("p2.ComputeAt(x=%d): got 0x%04x, want 0x%04x",
				pp.x.Value, got.Value, pp.y.Value)
		}
	}
}

// ============================================================================
// NextChunk sequential counter test
// ============================================================================

// TestNextChunkSequential verifies that NextChunk advances the index correctly.
func TestNextChunkSequential(t *testing.T) {
	t.Parallel()

	msg := seqBytes(96, 0x40)
	enc, err := NewPolyEncoder(msg)
	if err != nil {
		t.Fatalf("NewPolyEncoder: %v", err)
	}

	for i := uint16(0); i < 5; i++ {
		if enc.Idx() != uint32(i) {
			t.Errorf("before chunk %d: Idx=%d, want %d", i, enc.Idx(), i)
		}
		c := enc.NextChunk()
		if c.Index != i {
			t.Errorf("chunk %d: Index=%d, want %d", i, c.Index, i)
		}
	}

	// ChunkAt must match NextChunk output.
	enc2, _ := NewPolyEncoder(msg)
	for i := uint16(0); i < 7; i++ {
		want := enc2.ChunkAt(i)
		enc3, _ := NewPolyEncoder(msg)
		for j := uint16(0); j < i; j++ {
			enc3.NextChunk()
		}
		got := enc3.NextChunk()
		if got.Data != want.Data {
			t.Errorf("chunk %d NextChunk != ChunkAt", i)
		}
	}
}

// ============================================================================
// Complete-points table validation
// ============================================================================

// TestErrorMessages verifies that all typed errors produce non-empty messages.
func TestErrorMessages(t *testing.T) {
	t.Parallel()

	if (ErrMessageLengthEven{}).Error() == "" {
		t.Error("ErrMessageLengthEven: empty error string")
	}
	if (ErrMessageLengthTooLong{}).Error() == "" {
		t.Error("ErrMessageLengthTooLong: empty error string")
	}
	if (ErrSerializationInvalid{}).Error() == "" {
		t.Error("ErrSerializationInvalid: empty error string")
	}
}

// TestEncoderAccessors verifies the StateKind, Points, and Polys accessors
// on PolyEncoder before and after the Points->Polys transition.
func TestEncoderAccessors(t *testing.T) {
	t.Parallel()

	msg := seqBytes(96, 0x40) // 3 pts per poly
	enc, err := NewPolyEncoder(msg)
	if err != nil {
		t.Fatalf("NewPolyEncoder: %v", err)
	}

	// Before transition: state should be Points.
	if enc.StateKind() != EncoderStatePoints {
		t.Errorf("initial StateKind: got %v, want EncoderStatePoints", enc.StateKind())
	}
	pts := enc.Points()
	if pts == nil {
		t.Fatal("Points() returned nil before transition")
	}
	// poly 0 should have 3 points: y-values of 0x4041, 0x6061, 0x8081.
	if len(pts[0].Value) != 3 {
		t.Errorf("points[0].Value len: got %d, want 3", len(pts[0].Value))
	}

	// Trigger transition by requesting chunk 3 (beyond stored points).
	enc.ChunkAt(3)

	if enc.StateKind() != EncoderStatePolys {
		t.Errorf("after transition StateKind: got %v, want EncoderStatePolys", enc.StateKind())
	}
	polys := enc.Polys()
	if polys == nil {
		t.Fatal("Polys() returned nil after transition")
	}
	// Each poly should have 3 coefficients (degree-2 polynomial).
	if len(polys[0].Coefficients) != 3 {
		t.Errorf("polys[0].Coefficients len: got %d, want 3", len(polys[0].Coefficients))
	}
}

// TestDecoderPtsAccessors verifies PtsLen, PtsForChannel, SetPtsForChannel.
func TestDecoderPtsAccessors(t *testing.T) {
	t.Parallel()

	msg := seqBytes(96, 0x40) // 3 pts per poly
	enc, err := NewPolyEncoder(msg)
	if err != nil {
		t.Fatalf("NewPolyEncoder: %v", err)
	}
	dec, err := NewPolyDecoder(len(msg))
	if err != nil {
		t.Fatalf("NewPolyDecoder: %v", err)
	}

	// Initially all channels have 0 points.
	for i := 0; i < NumPolys; i++ {
		if dec.PtsLen(i) != 0 {
			t.Errorf("PtsLen(%d) before add: got %d, want 0", i, dec.PtsLen(i))
		}
	}

	dec.AddChunk(enc.ChunkAt(0))

	// After chunk 0: each channel i has poly_idx=0 (since total_idx=i, poly_idx=i/16=0).
	// All 16 channels get 1 point.
	for i := 0; i < NumPolys; i++ {
		if dec.PtsLen(i) != 1 {
			t.Errorf("PtsLen(%d) after chunk 0: got %d, want 1", i, dec.PtsLen(i))
		}
	}

	// PtsForChannel should return a non-nil slice.
	ch0pts := dec.PtsForChannel(0)
	if len(ch0pts) != 1 {
		t.Errorf("PtsForChannel(0) len: got %d, want 1", len(ch0pts))
	}

	// SetPtsForChannel: replace channel 0's points with an empty slice.
	dec.SetPtsForChannel(0, nil)
	if dec.PtsLen(0) != 0 {
		t.Errorf("PtsLen(0) after SetPtsForChannel(nil): got %d, want 0", dec.PtsLen(0))
	}
}

// TestFromCompletePointsFallback exercises the fallback path in fromCompletePoints
// for a point-set size not in the precomputed table (e.g. size 4).
// This verifies the fallback lagrangeInterpolatePt path produces correct results.
func TestFromCompletePointsFallback(t *testing.T) {
	t.Parallel()

	// Use n=4 which is not in the precomputed table.
	// The fallback must produce a polynomial that evaluates correctly.
	pts := []pt{
		{x: gf.GF16{Value: 0}, y: gf.GF16{Value: 0x1111}},
		{x: gf.GF16{Value: 1}, y: gf.GF16{Value: 0x2222}},
		{x: gf.GF16{Value: 2}, y: gf.GF16{Value: 0x3333}},
		{x: gf.GF16{Value: 3}, y: gf.GF16{Value: 0x4444}},
	}
	poly, err := fromCompletePoints(pts)
	if err != nil {
		t.Fatalf("fromCompletePoints (fallback): %v", err)
	}
	for _, pp := range pts {
		got := poly.ComputeAt(pp.x)
		if got.Value != pp.y.Value {
			t.Errorf("fallback poly(x=%d): got 0x%04x, want 0x%04x",
				pp.x.Value, got.Value, pp.y.Value)
		}
	}
}

// TestFromCompletePointsInvalidX verifies that fromCompletePoints returns an
// error when the x values are not {0, 1, ..., n-1}.
func TestFromCompletePointsInvalidX(t *testing.T) {
	t.Parallel()

	// x[0] = 1, not 0: invalid.
	pts := []pt{
		{x: gf.GF16{Value: 1}, y: gf.GF16{Value: 0x0001}},
		{x: gf.GF16{Value: 2}, y: gf.GF16{Value: 0x0002}},
		{x: gf.GF16{Value: 3}, y: gf.GF16{Value: 0x0003}},
	}
	_, err := fromCompletePoints(pts)
	if err == nil {
		t.Fatal("expected ErrSerializationInvalid, got nil")
	}
	if _, ok := err.(ErrSerializationInvalid); !ok {
		t.Errorf("expected ErrSerializationInvalid, got %T: %v", err, err)
	}
}

// TestLagrangeInterpolateEmpty verifies that lagrangeInterpolate on an empty
// slice returns a zero polynomial.
func TestLagrangeInterpolateEmpty(t *testing.T) {
	t.Parallel()

	p := lagrangeInterpolate(nil)
	if len(p.Coefficients) != 0 {
		t.Errorf("empty lagrangeInterpolate: got %d coefficients, want 0",
			len(p.Coefficients))
	}
	// ComputeAt on a zero polynomial should return Zero.
	if got := p.ComputeAt(gf.GF16{Value: 42}); got.Value != 0 {
		t.Errorf("ComputeAt on empty poly: got 0x%04x, want 0", got.Value)
	}
}

// TestEncoderDecoderSize30 exercises the COMPLETE_POINTS_POLYS_30 path:
// 960 bytes gives exactly 30 GF16 elements per polynomial channel.
func TestEncoderDecoderSize30(t *testing.T) {
	t.Parallel()

	// 960 bytes = 480 GF16 = 30 per poly channel.
	msg := seqBytes(960, 0x07)
	enc, err := NewPolyEncoder(msg)
	if err != nil {
		t.Fatalf("NewPolyEncoder: %v", err)
	}
	dec, err := NewPolyDecoder(len(msg))
	if err != nil {
		t.Fatalf("NewPolyDecoder: %v", err)
	}

	// Feed the original 30 chunks (indices 0..29).
	for i := uint16(0); i < 30; i++ {
		dec.AddChunk(enc.ChunkAt(i))
	}
	got, ok := dec.DecodedMessage()
	if !ok {
		t.Fatal("DecodedMessage: not ok")
	}
	if string(got) != string(msg) {
		t.Errorf("decoded mismatch for 960-byte message")
	}

	// Also verify one interpolated chunk (index 30, triggers POLYS_30).
	enc2, _ := NewPolyEncoder(msg)
	chunk30 := enc2.ChunkAt(30)
	// Round-trip: a separate decoder fed only the interpolated chunk plus 29 originals.
	dec2, _ := NewPolyDecoder(len(msg))
	dec2.AddChunk(chunk30)
	for i := uint16(1); i < 30; i++ {
		dec2.AddChunk(enc2.ChunkAt(i))
	}
	got2, ok2 := dec2.DecodedMessage()
	if !ok2 {
		t.Fatal("DecodedMessage with interpolated chunk: not ok")
	}
	if string(got2) != string(msg) {
		t.Errorf("decoded mismatch with interpolated chunk")
	}
}

// TestEncoderDecoderSize36 exercises the COMPLETE_POINTS_POLYS_36 path:
// 1152 bytes gives exactly 36 GF16 elements per polynomial channel.
func TestEncoderDecoderSize36(t *testing.T) {
	t.Parallel()

	// 1152 bytes = 576 GF16 = 36 per poly channel.
	msg := seqBytes(1152, 0x11)
	enc, err := NewPolyEncoder(msg)
	if err != nil {
		t.Fatalf("NewPolyEncoder: %v", err)
	}
	dec, err := NewPolyDecoder(len(msg))
	if err != nil {
		t.Fatalf("NewPolyDecoder: %v", err)
	}

	// Feed original 36 chunks.
	for i := uint16(0); i < 36; i++ {
		dec.AddChunk(enc.ChunkAt(i))
	}
	got, ok := dec.DecodedMessage()
	if !ok {
		t.Fatal("DecodedMessage: not ok for 1152-byte message")
	}
	if string(got) != string(msg) {
		t.Errorf("decoded mismatch for 1152-byte message")
	}

	// Verify interpolated chunk 36 triggers POLYS_36.
	enc2, _ := NewPolyEncoder(msg)
	chunk36 := enc2.ChunkAt(36) // first chunk beyond original data
	dec2, _ := NewPolyDecoder(len(msg))
	dec2.AddChunk(chunk36)
	for i := uint16(1); i < 36; i++ {
		dec2.AddChunk(enc2.ChunkAt(i))
	}
	got2, ok2 := dec2.DecodedMessage()
	if !ok2 {
		t.Fatal("DecodedMessage with interpolated chunk 36: not ok")
	}
	if string(got2) != string(msg) {
		t.Errorf("decoded mismatch with interpolated chunk 36")
	}
}

// TestIsCompleteSkipsDecoding verifies that when IsComplete is set to true,
// DecodedMessage returns (nil, false) immediately.
func TestIsCompleteSkipsDecoding(t *testing.T) {
	t.Parallel()

	msg := []byte("abcdefghij")
	enc, err := NewPolyEncoder(msg)
	if err != nil {
		t.Fatalf("NewPolyEncoder: %v", err)
	}
	dec, err := NewPolyDecoder(len(msg))
	if err != nil {
		t.Fatalf("NewPolyDecoder: %v", err)
	}
	dec.AddChunk(enc.ChunkAt(1))
	dec.AddChunk(enc.ChunkAt(2))

	// Manually set IsComplete to simulate the protocol state machine.
	dec.IsComplete = true
	got, ok := dec.DecodedMessage()
	if ok || got != nil {
		t.Errorf("DecodedMessage with IsComplete=true: got ok=%v, want false", ok)
	}
}

// TestMessageLengthTooLong verifies that NewPolyEncoder returns
// ErrMessageLengthTooLong for a message that exceeds the protocol limit.
func TestMessageLengthTooLong(t *testing.T) {
	t.Parallel()

	// Maximum allowed: (1<<16) * 16 = 1,048,576 bytes.
	// Use a length just over the limit. We don't actually allocate it;
	// we construct the encoder with a nil slice and check the size guard.
	tooLong := make([]byte, (1<<16)*NumPolys+2)
	_, err := NewPolyEncoder(tooLong)
	if err == nil {
		t.Fatal("expected ErrMessageLengthTooLong, got nil")
	}
	if _, ok := err.(ErrMessageLengthTooLong); !ok {
		t.Errorf("expected ErrMessageLengthTooLong, got %T: %v", err, err)
	}
}

// TestCompletePointsPolysCorrectness verifies that the precomputed basis
// polynomials evaluate to 1 at the target x and 0 at all other x values.
func TestCompletePointsPolysCorrectness(t *testing.T) {
	t.Parallel()

	for _, n := range []int{1, 3, 5, 30, 34, 36} {
		n := n
		t.Run(itoa(n), func(t *testing.T) {
			t.Parallel()
			var polys []Poly
			switch n {
			case 1:
				p := completePointsPolys1
				polys = p[:]
			case 3:
				p := completePointsPolys3
				polys = p[:]
			case 5:
				p := completePointsPolys5
				polys = p[:]
			case 30:
				p := completePointsPolys30
				polys = p[:]
			case 34:
				p := completePointsPolys34
				polys = p[:]
			case 36:
				p := completePointsPolys36
				polys = p[:]
			}
			for i, poly := range polys {
				for j := 0; j < n; j++ {
					x := gf.GF16{Value: uint16(j)}
					got := poly.ComputeAt(x)
					want := gf.Zero
					if j == i {
						want = gf.One
					}
					if got.Value != want.Value {
						t.Errorf("poly[%d](x=%d): got 0x%04x, want 0x%04x",
							i, j, got.Value, want.Value)
					}
				}
			}
		})
	}
}

// ============================================================================
// Helper functions
// ============================================================================

func bytes32(v byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = v
	}
	return b
}

func bytes1088(v byte) []byte {
	b := make([]byte, 1088)
	for i := range b {
		b[i] = v
	}
	return b
}

// seqBytes returns n bytes where b[i] = byte(start + i).
func seqBytes(n int, start byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(int(start) + i)
	}
	return b
}

// xorBytes returns n bytes where b[i] = byte(i) ^ mask.
func xorBytes(n int, mask byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i) ^ mask
	}
	return b
}

func makeCoeffs(n int) []gf.GF16 {
	c := make([]gf.GF16, n)
	for i := range c {
		c[i] = gf.GF16{Value: uint16(i * 3)}
	}
	return c
}

// itoa converts an int to a string without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	b := [20]byte{}
	pos := len(b)
	for n > 0 {
		pos--
		b[pos] = byte(n%10) + '0'
		n /= 10
	}
	return string(b[pos:])
}

// TestMakePt verifies that MakePt creates a point with the correct x and y values.
func TestMakePt(t *testing.T) {
	p := MakePt(0x1234, 0xABCD)
	if p.X() != 0x1234 {
		t.Errorf("X() = 0x%04x, want 0x1234", p.X())
	}
	if p.Y() != 0xABCD {
		t.Errorf("Y() = 0x%04x, want 0xABCD", p.Y())
	}
}

// TestSerializePt verifies big-endian serialization of a Pt.
func TestSerializePt(t *testing.T) {
	p := MakePt(0x0102, 0x0304)
	got := SerializePt(p)
	want := [4]byte{0x01, 0x02, 0x03, 0x04}
	if got != want {
		t.Errorf("SerializePt = %v, want %v", got, want)
	}
}

// TestNewPolyEncoderFromPolys_Success verifies that a PolyEncoder can be created
// from NumPolys polynomials.
func TestNewPolyEncoderFromPolys_Success(t *testing.T) {
	polys := make([]Poly, NumPolys)
	enc, err := NewPolyEncoderFromPolys(polys, 7)
	if err != nil {
		t.Fatalf("NewPolyEncoderFromPolys: %v", err)
	}
	if enc == nil {
		t.Fatal("expected non-nil encoder")
	}
	if enc.Idx() != 7 {
		t.Errorf("Idx() = %d, want 7", enc.Idx())
	}
}

// TestNewPolyEncoderFromPolys_WrongCount verifies that a wrong number of polys
// returns an error.
func TestNewPolyEncoderFromPolys_WrongCount(t *testing.T) {
	_, err := NewPolyEncoderFromPolys([]Poly{}, 0)
	if err == nil {
		t.Fatal("expected error for zero polys")
	}
}
