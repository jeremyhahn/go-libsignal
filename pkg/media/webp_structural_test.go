package media

// webp_structural_test.go — conformance tests for Finding #6 (WebP structural
// validation) and Finding #7 (odd-chunk padding and trailing-byte rejection).
//
// WebP spec: https://developers.google.com/speed/webp/docs/riff_container
// Rust oracle: libsignal webpsan crate (behavioral reference)
// Java oracle: WebpSanitizerTest.java (ported tests)

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// ---------------------------------------------------------------------------
// Helper: build a RIFF/WebP file with arbitrary chunk list.
// ---------------------------------------------------------------------------

// buildWebPWithChunks constructs a RIFF/WEBP file containing the given raw
// chunk data.  riffPayload = "WEBP" + chunks (already serialized).
// The RIFF size field is computed to match the payload length exactly, so that
// no trailing-byte rejection occurs (unless the caller deliberately adds extra
// bytes).
func buildWebPWithChunks(chunks []byte) []byte {
	riffPayload := make([]byte, 0, 4+len(chunks))
	riffPayload = append(riffPayload, []byte("WEBP")...)
	riffPayload = append(riffPayload, chunks...)

	riffSize := uint32(len(riffPayload))
	var buf bytes.Buffer
	buf.WriteString("RIFF")
	sizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBytes, riffSize)
	buf.Write(sizeBytes)
	buf.Write(riffPayload)
	return buf.Bytes()
}

// buildWebPChunk serializes a single RIFF chunk: 4-byte type + 4-byte LE size +
// data + optional 0x00 pad byte (if data length is odd).
func buildWebPChunk(fourcc string, data []byte) []byte {
	size := uint32(len(data))
	chunk := make([]byte, 0, 8+len(data)+1)
	chunk = append(chunk, []byte(fourcc)...)
	sizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBytes, size)
	chunk = append(chunk, sizeBytes...)
	chunk = append(chunk, data...)
	if len(data)%2 != 0 {
		chunk = append(chunk, 0x00)
	}
	return chunk
}

// buildVP8XPayload builds a valid 10-byte VP8X chunk payload.
//
// flags byte:
//
//	bit 1 = ICC, bit 2 = alpha, bit 3 = EXIF, bit 4 = XMP, bit 5 = anim
//
// canvas width/height are 24-bit LE (value = actual - 1).
func buildVP8XPayload(flags byte, width, height uint32) []byte {
	p := make([]byte, 10)
	p[0] = flags
	// reserved bytes 1-3 = 0
	// canvas width minus 1 (24-bit LE)
	p[4] = byte(width)
	p[5] = byte(width >> 8)
	p[6] = byte(width >> 16)
	// canvas height minus 1 (24-bit LE)
	p[7] = byte(height)
	p[8] = byte(height >> 8)
	p[9] = byte(height >> 16)
	return p
}

// ---------------------------------------------------------------------------
// Finding #6: VP8X structural validation tests
// ---------------------------------------------------------------------------

// TestFinding6_VP8X_Valid verifies that a well-formed VP8X extended file is
// accepted.  The VP8X chunk must be exactly 10 bytes with sane dimensions.
//
// WebP spec §Extended file format.
func TestFinding6_VP8X_Valid(t *testing.T) {
	// VP8X (10 bytes) + VP8L (minimal lossless bitstream)
	vp8xPayload := buildVP8XPayload(0x00, 0, 0) // flags=0, 1×1 canvas (0 = width-1=0)
	vp8lData := []byte{0x2f, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88, 8}

	chunks := append(buildWebPChunk("VP8X", vp8xPayload), buildWebPChunk("VP8L", vp8lData)...)
	data := buildWebPWithChunks(chunks)

	if err := SanitizeWebP(data); err != nil {
		t.Errorf("expected valid VP8X WebP, got: %v", err)
	}
}

// TestFinding6_VP8X_SizeNot10 verifies that a VP8X chunk whose size is not
// exactly 10 bytes is rejected.
//
// WebP spec §Extended file format: "The VP8X chunk MUST be 10 bytes long."
func TestFinding6_VP8X_SizeNot10(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{"too_small_0", 0},
		{"too_small_9", 9},
		{"too_large_11", 11},
		{"too_large_20", 20},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			badPayload := make([]byte, tc.size) // wrong size
			chunks := buildWebPChunk("VP8X", badPayload)
			data := buildWebPWithChunks(chunks)
			if err := SanitizeWebP(data); err == nil {
				t.Errorf("expected error for VP8X with size=%d, got nil", tc.size)
			}
		})
	}
}

// TestFinding6_VP8X_ReservedBytesNonZero verifies that a VP8X chunk with
// non-zero reserved bytes (bytes 1-3) is rejected.
//
// WebP spec §Extended file format: "Reserved (Rsv): 24 bits. MUST be 0."
func TestFinding6_VP8X_ReservedBytesNonZero(t *testing.T) {
	tests := []struct {
		name string
		b1   byte
		b2   byte
		b3   byte
	}{
		{"byte1_nonzero", 0x01, 0x00, 0x00},
		{"byte2_nonzero", 0x00, 0x01, 0x00},
		{"byte3_nonzero", 0x00, 0x00, 0x01},
		{"all_nonzero", 0xFF, 0xFF, 0xFF},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := buildVP8XPayload(0x00, 0, 0)
			p[1] = tc.b1
			p[2] = tc.b2
			p[3] = tc.b3
			chunks := buildWebPChunk("VP8X", p)
			data := buildWebPWithChunks(chunks)
			if err := SanitizeWebP(data); err == nil {
				t.Errorf("reserved bytes (%02x,%02x,%02x): expected error, got nil",
					tc.b1, tc.b2, tc.b3)
			}
		})
	}
}

// TestFinding6_VP8X_CanvasDimensionTooLarge verifies that VP8X chunks whose
// canvas width or height (minus 1) exceeds 16383 are rejected.
//
// WebP spec §Extended file format: canvas dimensions limited to 16384×16384.
func TestFinding6_VP8X_CanvasDimensionTooLarge(t *testing.T) {
	tests := []struct {
		name   string
		width  uint32
		height uint32
	}{
		{"width_max_plus_1", 16384, 0},
		{"height_max_plus_1", 0, 16384},
		{"both_max_plus_1", 16384, 16384},
		{"width_huge", 0xFFFFFF, 0},
		{"height_huge", 0, 0xFFFFFF},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := buildVP8XPayload(0x00, tc.width, tc.height)
			chunks := buildWebPChunk("VP8X", p)
			data := buildWebPWithChunks(chunks)
			if err := SanitizeWebP(data); err == nil {
				t.Errorf("VP8X(%d×%d): expected error for oversized canvas, got nil",
					tc.width, tc.height)
			}
		})
	}
}

// TestFinding6_VP8X_MaxValidDimensions verifies that VP8X with canvas
// dimensions exactly at the maximum (16383 stored = 16384 actual) is accepted
// when followed by a VP8 bitstream chunk (required by webpsan for still images).
//
// webpsan/src/parse/vp8x.rs: stored canvas dim = actual-1; max stored = 16383.
// webpsan/src/lib.rs:207-246 (sanitize_still requires VP8/VP8L).
func TestFinding6_VP8X_MaxValidDimensions(t *testing.T) {
	p := buildVP8XPayload(0x00, 16383, 16383)
	// VP8 lossy body (4 bytes) required by sanitize_still.
	vp8Data := []byte{0x9D, 0x01, 0x2A, 0x01}
	chunks := append(buildWebPChunk("VP8X", p), buildWebPChunk("VP8 ", vp8Data)...)
	data := buildWebPWithChunks(chunks)
	if err := SanitizeWebP(data); err != nil {
		t.Errorf("VP8X with max valid dimensions + VP8: expected no error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Finding #6: chunk ordering and required-chunk presence tests
// ---------------------------------------------------------------------------

// TestFinding6_ChunkOrder_VP8XNotFirst verifies that VP8X must be the first
// chunk; placing it after other chunks is rejected.
func TestFinding6_ChunkOrder_VP8XNotFirst(t *testing.T) {
	vp8lData := []byte{0x2f, 0x00, 0x00, 0x00}
	vp8xPayload := buildVP8XPayload(0x00, 0, 0)

	// VP8L first, then VP8X — invalid ordering.
	chunks := append(buildWebPChunk("VP8L", vp8lData), buildWebPChunk("VP8X", vp8xPayload)...)
	data := buildWebPWithChunks(chunks)
	if err := SanitizeWebP(data); err == nil {
		t.Error("expected error for VP8X not as first chunk")
	}
}

// TestFinding6_ChunkOrder_MultipleVP8X verifies that more than one VP8X chunk
// is rejected.
func TestFinding6_ChunkOrder_MultipleVP8X(t *testing.T) {
	vp8xPayload := buildVP8XPayload(0x00, 0, 0)
	chunks := append(buildWebPChunk("VP8X", vp8xPayload), buildWebPChunk("VP8X", vp8xPayload)...)
	data := buildWebPWithChunks(chunks)
	if err := SanitizeWebP(data); err == nil {
		t.Error("expected error for multiple VP8X chunks")
	}
}

// TestFinding6_ChunkOrder_MultipleVP8Lossy verifies that a simple file with
// more than one VP8 bitstream chunk is rejected.
func TestFinding6_ChunkOrder_MultipleVP8Lossy(t *testing.T) {
	vp8Data := []byte{0x9D, 0x01, 0x2A, 0x01}
	chunks := append(buildWebPChunk("VP8 ", vp8Data), buildWebPChunk("VP8 ", vp8Data)...)
	data := buildWebPWithChunks(chunks)
	if err := SanitizeWebP(data); err == nil {
		t.Error("expected error for multiple VP8 chunks in simple file")
	}
}

// TestFinding6_ChunkOrder_VP8FollowedByVP8X verifies that a VP8 chunk followed
// by VP8X is rejected (VP8X must be first for extended files).
func TestFinding6_ChunkOrder_VP8FollowedByVP8X(t *testing.T) {
	vp8Data := []byte{0x9D, 0x01, 0x2A, 0x01}
	vp8xPayload := buildVP8XPayload(0x00, 0, 0)
	chunks := append(buildWebPChunk("VP8 ", vp8Data), buildWebPChunk("VP8X", vp8xPayload)...)
	data := buildWebPWithChunks(chunks)
	if err := SanitizeWebP(data); err == nil {
		t.Error("expected error for VP8 followed by VP8X")
	}
}

// TestFinding6_ChunkOrder_EmptyFile verifies that a WEBP file with no chunks
// is rejected.
func TestFinding6_ChunkOrder_EmptyFile(t *testing.T) {
	data := buildWebPWithChunks(nil)
	if err := SanitizeWebP(data); err == nil {
		t.Error("expected error for WebP with no chunks")
	}
}

// TestFinding6_ChunkOrder_NonBitstreamFirst verifies that a file starting with
// a chunk that is not VP8, VP8L, or VP8X is rejected.
func TestFinding6_ChunkOrder_NonBitstreamFirst(t *testing.T) {
	exifData := []byte{0x49, 0x49, 0x2A, 0x00}
	chunks := buildWebPChunk("EXIF", exifData)
	data := buildWebPWithChunks(chunks)
	if err := SanitizeWebP(data); err == nil {
		t.Error("expected error for non-bitstream chunk as first chunk")
	}
}

// ---------------------------------------------------------------------------
// Finding #7: odd-chunk padding and trailing-byte tests
// ---------------------------------------------------------------------------

// TestFinding7_OddChunkPadByte_Valid verifies that an odd-size chunk followed
// by the mandatory 0x00 pad byte is accepted.
//
// WebP spec §RIFF file format: "If the chunk size is odd, a single padding byte
// — which MUST be 0 — is added."
// webpsan/src/reader.rs:232 — ensure_matches_attach!(pad, 0, ParseError::InvalidInput, ...)
//
// Uses a VP8 (lossy) chunk with 3 bytes (odd) to exercise the pad-byte path.
// VP8 chunks have no minimum payload size requirement in webpsan (only VP8L does).
func TestFinding7_OddChunkPadByte_Valid(t *testing.T) {
	// 3-byte VP8 data (odd) + explicit 0x00 pad.
	vp8Data := []byte{0x9D, 0x01, 0x2A} // 3 bytes (odd)
	// Manually build a padded chunk with 0x00 pad.
	size := uint32(len(vp8Data))
	sizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBytes, size)
	paddedChunk := append([]byte("VP8 "), sizeBytes...)
	paddedChunk = append(paddedChunk, vp8Data...)
	paddedChunk = append(paddedChunk, 0x00) // pad byte

	data := buildWebPWithChunks(paddedChunk)
	if err := SanitizeWebP(data); err != nil {
		t.Errorf("expected valid WebP with 0x00 pad byte, got: %v", err)
	}
}

// TestFinding7_OddChunkPadByte_NonZero verifies that a non-zero pad byte is
// rejected.
//
// WebP spec §RIFF file format: the pad byte "MUST be 0".
// webpsan/src/reader.rs:232 — ensure_matches_attach!(pad, 0, ParseError::InvalidInput, ...)
func TestFinding7_OddChunkPadByte_NonZero(t *testing.T) {
	vp8Data := []byte{0x9D, 0x01, 0x2A} // 3 bytes (odd)
	size := uint32(len(vp8Data))
	sizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBytes, size)
	paddedChunk := append([]byte("VP8 "), sizeBytes...)
	paddedChunk = append(paddedChunk, vp8Data...)
	paddedChunk = append(paddedChunk, 0xFF) // wrong pad byte

	data := buildWebPWithChunks(paddedChunk)
	if err := SanitizeWebP(data); err == nil {
		t.Error("expected error for non-zero pad byte, got nil")
	}
}

// TestFinding7_OddChunkPadByte_Missing verifies that an odd-size chunk without
// a pad byte is rejected (the padded extent would exceed the RIFF payload).
// webpsan/src/reader.rs:232 — pad byte validation occurs in read_padding.
func TestFinding7_OddChunkPadByte_Missing(t *testing.T) {
	// Build the file such that the RIFF payload ends exactly at the chunk data
	// with no room for the mandatory pad byte.
	vp8Data := []byte{0x9D, 0x01, 0x2A} // 3 bytes (odd)
	size := uint32(len(vp8Data))
	sizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBytes, size)
	// Chunk without pad: only 8 (header) + 3 (data) = 11 bytes.
	chunkNoPad := append([]byte("VP8 "), sizeBytes...)
	chunkNoPad = append(chunkNoPad, vp8Data...)

	// Build RIFF with exact declared size = "WEBP" + chunk (no room for pad).
	riffPayload := append([]byte("WEBP"), chunkNoPad...)
	riffSize := uint32(len(riffPayload))
	var buf bytes.Buffer
	buf.WriteString("RIFF")
	buf.Write(func() []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, riffSize); return b }())
	buf.Write(riffPayload)
	data := buf.Bytes()

	if err := SanitizeWebP(data); err == nil {
		t.Error("expected error for odd-size chunk with missing pad byte, got nil")
	}
}

// TestFinding7_TrailingBytesRejected verifies that bytes appearing after the
// declared RIFF payload are rejected (fail-closed against concatenated files).
//
// Java oracle: WebpSanitizerTest.java — the java sanitizer is fail-closed;
// this test mirrors that posture.  Finding #7.
func TestFinding7_TrailingBytesRejected(t *testing.T) {
	data := javaWebp() // valid minimal VP8L WebP
	// Append extra bytes beyond the declared RIFF boundary.
	withTrailing := append(data, 0x00, 0x01, 0x02)
	if err := SanitizeWebP(withTrailing); err == nil {
		t.Error("expected error for WebP with trailing bytes after RIFF payload (Finding #7)")
	}
}

// TestFinding7_OddChunkPadByte_PaddedExtentBeyondPayload verifies that an odd-
// size chunk whose padded extent (dataEnd+1) would exceed the RIFF payload is
// rejected even when the pad byte exists in the buffer but outside the payload.
// webpsan/src/lib.rs:170–174 — trailing-bytes check rejects this case.
func TestFinding7_OddChunkPadByte_PaddedExtentBeyondPayload(t *testing.T) {
	// Build a VP8 chunk of 3 bytes (odd). Declare a RIFF payload size that ends
	// exactly at the chunk data end (no room for the pad byte within payload), but
	// provide extra bytes in the actual buffer so the validator can read them.
	vp8Data := []byte{0x9D, 0x01, 0x2A} // 3 bytes
	size := uint32(3)
	sizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBytes, size)
	chunk := append([]byte("VP8 "), sizeBytes...)
	chunk = append(chunk, vp8Data...)
	// Pad byte is in the buffer but beyond the declared RIFF payload.
	chunk = append(chunk, 0x00)

	// Declare the RIFF payload as ending before the pad byte.
	// riffPayload = "WEBP" (4) + chunk header (8) + 3 bytes data = 15 bytes.
	// (The pad byte 0x00 is NOT included in the declared payload.)
	riffPayloadDeclared := 4 + 8 + 3 // = 15
	riffPayloadFull := append([]byte("WEBP"), chunk...)

	var buf bytes.Buffer
	buf.WriteString("RIFF")
	sizeField := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeField, uint32(riffPayloadDeclared))
	buf.Write(sizeField)
	buf.Write(riffPayloadFull)
	data := buf.Bytes()

	// The actual file has more bytes than the declared RIFF size+8, so it should
	// be rejected by the trailing-bytes check before even getting to the pad validation.
	if err := SanitizeWebP(data); err == nil {
		t.Error("expected error for padded extent beyond declared RIFF payload, got nil")
	}
}

// ---------------------------------------------------------------------------
// Regression guard: Java conformance tests must still pass
// ---------------------------------------------------------------------------

// TestJavaConformance_WebP_Empty — Java: WebpSanitizerTest.testEmptyWebp
func TestJavaConformance_WebP_Empty(t *testing.T) {
	if err := SanitizeWebP([]byte{}); err == nil {
		t.Error("empty WebP accepted: expected parse error")
	}
}

// TestJavaConformance_WebP_Truncated — Java: WebpSanitizerTest.testTruncatedWebp
func TestJavaConformance_WebP_Truncated(t *testing.T) {
	if err := SanitizeWebP([]byte{0, 0, 0, 0}); err == nil {
		t.Error("truncated WebP accepted: expected parse error")
	}
}

// TestJavaConformance_WebP_Minimal — Java: WebpSanitizerTest.testMinimalWebp
// The minimal VP8L WebP from the Java test must still be accepted.
func TestJavaConformance_WebP_Minimal(t *testing.T) {
	if err := SanitizeWebP(javaWebp()); err != nil {
		t.Errorf("minimal VP8L WebP rejected: %v", err)
	}
}

// TestFinding6_VP8X_WithMetadataChunks verifies that an extended VP8X file
// with a VP8 bitstream, EXIF, and XMP chunks is accepted (valid extended layout).
//
// Flags: HAS_EXIF(0x08)|HAS_XMP(0x04) = 0x0C.
// webpsan requires: VP8X → image data (VP8/VP8L) → EXIF → XMP.
// webpsan/src/lib.rs:179–204 (sanitize_extended ordering)
func TestFinding6_VP8X_WithMetadataChunks(t *testing.T) {
	vp8xPayload := buildVP8XPayload(0x0C, 0, 0) // HAS_EXIF(0x08)|HAS_XMP(0x04)
	vp8Data := []byte{0x9D, 0x01, 0x2A, 0x01}   // VP8 lossy (4 bytes)
	exifData := []byte{0x49, 0x49, 0x2A, 0x00}
	xmpData := []byte{0x3C, 0x3F, 0x78, 0x70}

	var chunkBuf bytes.Buffer
	chunkBuf.Write(buildWebPChunk("VP8X", vp8xPayload))
	chunkBuf.Write(buildWebPChunk("VP8 ", vp8Data))
	chunkBuf.Write(buildWebPChunk("EXIF", exifData))
	chunkBuf.Write(buildWebPChunk("XMP ", xmpData))

	data := buildWebPWithChunks(chunkBuf.Bytes())
	if err := SanitizeWebP(data); err != nil {
		t.Errorf("VP8X with VP8+EXIF+XMP: expected valid, got: %v", err)
	}
}
