package media

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	mp4 "github.com/Eyevinn/mp4ff/mp4"
)

// writeLE32 appends v to buf as a little-endian uint32 (test helper).
func writeLE32(buf *bytes.Buffer, v uint32) {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	buf.Write(b)
}

// buildValidProgressiveMP4 builds a valid progressive MP4 with moov before
// mdat, suitable for round-trip parsing by mp4ff.
func buildValidProgressiveMP4() []byte {
	ftyp := mp4.NewFtyp("isom", 0x200, []string{"isom", "avc1"})
	moov := mp4.NewMoovBox()
	moov.AddChild(mp4.CreateMvhd())

	var buf bytes.Buffer
	if err := ftyp.Encode(&buf); err != nil {
		panic("buildValidProgressiveMP4: ftyp: " + err.Error())
	}
	if err := moov.Encode(&buf); err != nil {
		panic("buildValidProgressiveMP4: moov: " + err.Error())
	}

	// Explicit-size mdat.
	payload := []byte{0x00, 0x01, 0x02, 0x03}
	mdatBuf := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(mdatBuf[0:4], uint32(len(mdatBuf)))
	copy(mdatBuf[4:8], "mdat")
	copy(mdatBuf[8:], payload)
	buf.Write(mdatBuf)

	return buf.Bytes()
}

// buildMdatFirstMP4 builds a valid MP4 with mdat before moov.
func buildMdatFirstMP4() []byte {
	ftyp := mp4.NewFtyp("isom", 0x200, []string{"isom", "avc1"})
	moov := mp4.NewMoovBox()
	moov.AddChild(mp4.CreateMvhd())

	// Explicit-size mdat.
	payload := []byte{0x0A, 0x0B, 0x0C, 0x0D}
	mdatBuf := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(mdatBuf[0:4], uint32(len(mdatBuf)))
	copy(mdatBuf[4:8], "mdat")
	copy(mdatBuf[8:], payload)

	var buf bytes.Buffer
	if err := ftyp.Encode(&buf); err != nil {
		panic("buildMdatFirstMP4: ftyp: " + err.Error())
	}
	buf.Write(mdatBuf) // mdat before moov
	if err := moov.Encode(&buf); err != nil {
		panic("buildMdatFirstMP4: moov: " + err.Error())
	}

	return buf.Bytes()
}

// buildValidWebP builds a minimal valid WebP lossy (VP8) file.
func buildValidWebP() []byte {
	// VP8 bitstream chunk with 4 bytes of payload (not a real VP8 frame, but
	// structurally valid for chunk-level validation).
	vp8Payload := []byte{0x9D, 0x01, 0x2A, 0x01} // 4 bytes
	chunkSize := uint32(len(vp8Payload))

	// Pad to even boundary if needed (chunkSize is 4, already even).
	riffPayload := make([]byte, 0, 4+8+len(vp8Payload))
	riffPayload = append(riffPayload, []byte("WEBP")...)
	riffPayload = append(riffPayload, []byte("VP8 ")...)
	riffPayload = append(riffPayload, byte(chunkSize), byte(chunkSize>>8), byte(chunkSize>>16), byte(chunkSize>>24))
	riffPayload = append(riffPayload, vp8Payload...)

	riffSize := uint32(len(riffPayload))
	var buf bytes.Buffer
	buf.WriteString("RIFF")
	writeLE32(&buf, riffSize)
	buf.Write(riffPayload)
	return buf.Bytes()
}

// buildValidWebPLossless builds a minimal valid WebP lossless (VP8L) file.
// Uses DEFAULT_VP8L_DATA = {0x2f,0x00,0x00,0x00,0x00,0x88,0x88,0x08} which
// encodes a 1x1 lossless image and passes full bitstream validation.
// webpsan/src/util/test/webp.rs:121-131 — DEFAULT_VP8L_DATA.
func buildValidWebPLossless() []byte {
	// DEFAULT_VP8L_DATA: 8 bytes (even length, no pad needed).
	// Conforms to: vp8l.rs header (5 bytes) + valid 1x1 image stream (3 bytes).
	vp8lPayload := []byte{0x2f, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88, 0x08}
	chunkSize := uint32(len(vp8lPayload))

	// Chunk: header(8) + data(8) = 16 bytes (no pad, even length).
	chunkBytes := make([]byte, 0, 16)
	chunkBytes = append(chunkBytes, []byte("VP8L")...)
	chunkBytes = append(chunkBytes, byte(chunkSize), byte(chunkSize>>8), byte(chunkSize>>16), byte(chunkSize>>24))
	chunkBytes = append(chunkBytes, vp8lPayload...)

	// RIFF payload = "WEBP"(4) + chunk(16) = 20 bytes.
	riffPayload := make([]byte, 0, 4+len(chunkBytes))
	riffPayload = append(riffPayload, []byte("WEBP")...)
	riffPayload = append(riffPayload, chunkBytes...)

	riffSize := uint32(len(riffPayload))
	var buf bytes.Buffer
	buf.WriteString("RIFF")
	writeLE32(&buf, riffSize)
	buf.Write(riffPayload)
	return buf.Bytes()
}

// ---- MP4 deep-parse acceptance tests ----------------------------------------

// TestValidateMP4_DeepParse_ValidProgressiveFile verifies that a well-formed
// progressive MP4 (ftyp → moov → mdat) passes deep parsing and produces a
// non-empty validated output.
func TestValidateMP4_DeepParse_ValidProgressiveFile(t *testing.T) {
	data := buildValidProgressiveMP4()

	result, err := Validate(data)
	if err != nil {
		t.Fatalf("Validate(valid progressive MP4) returned error: %v", err)
	}
	if result.MediaType != MediaTypeMP4 {
		t.Errorf("MediaType = %v, want MediaTypeMP4", result.MediaType)
	}
	if len(result.Validated) == 0 {
		t.Error("Validated must be non-empty")
	}
	if result.OriginalSize != int64(len(data)) {
		t.Errorf("OriginalSize = %d, want %d", result.OriginalSize, len(data))
	}
}

// TestValidateMP4_DeepParse_MoovRelocation verifies that when mdat precedes
// moov in the input, the sanitizer re-encodes the file with moov before mdat
// (faststart layout) and sets MetadataStripped=true.
func TestValidateMP4_DeepParse_MoovRelocation(t *testing.T) {
	data := buildMdatFirstMP4()

	result, err := Validate(data)
	if err != nil {
		t.Fatalf("Validate(mdat-first MP4) returned error: %v", err)
	}
	if result.MediaType != MediaTypeMP4 {
		t.Errorf("MediaType = %v, want MediaTypeMP4", result.MediaType)
	}
	// moov must now come before mdat in the output.
	if !result.MetadataStripped {
		t.Error("MetadataStripped must be true when moov was relocated before mdat")
	}
	// Verify moov actually precedes mdat in the re-encoded output.
	if result.MoovOffset >= result.MdatOffset {
		t.Errorf("moov offset (%d) must be < mdat offset (%d) after faststart relocation",
			result.MoovOffset, result.MdatOffset)
	}
	if len(result.Validated) == 0 {
		t.Error("Validated must be non-empty")
	}
}

// TestValidateMP4_DeepParse_AlreadyFaststart verifies that when moov already
// precedes mdat, MetadataStripped is false (no relocation occurred).
func TestValidateMP4_DeepParse_AlreadyFaststart(t *testing.T) {
	data := buildValidProgressiveMP4()

	result, err := Validate(data)
	if err != nil {
		t.Fatalf("Validate(faststart MP4) returned error: %v", err)
	}
	if result.MetadataStripped {
		t.Error("MetadataStripped must be false when moov was already before mdat")
	}
	// moov must still precede mdat in the output.
	if result.MoovOffset >= result.MdatOffset {
		t.Errorf("moov offset (%d) must be < mdat offset (%d)",
			result.MoovOffset, result.MdatOffset)
	}
}

// TestValidateMP4_DeepParse_MissingMoov verifies that an MP4 without a moov
// box is rejected with a MediaValidationError.
func TestValidateMP4_DeepParse_MissingMoov(t *testing.T) {
	// ftyp box only — no moov.
	ftyp := mp4.NewFtyp("isom", 0x200, []string{"isom"})
	var buf bytes.Buffer
	if err := ftyp.Encode(&buf); err != nil {
		t.Fatalf("ftyp encode: %v", err)
	}

	err := ValidateMP4(buf.Bytes())
	if err == nil {
		t.Fatal("expected error for MP4 without moov box")
	}
	var mve *MediaValidationError
	if !errors.As(err, &mve) {
		t.Errorf("expected *MediaValidationError, got %T: %v", err, err)
	}
}

// TestValidateMP4_DeepParse_TruncatedFile verifies that truncated MP4 data
// is rejected by the deep parser.
func TestValidateMP4_DeepParse_TruncatedFile(t *testing.T) {
	data := buildValidProgressiveMP4()
	truncated := data[:len(data)/2]

	err := ValidateMP4(truncated)
	if err == nil {
		t.Fatal("expected error for truncated MP4")
	}
}

// TestValidateMP4_DeepParse_CorruptedBoxTree verifies that an MP4 whose box
// tree contains a box that extends beyond the file boundary is rejected.
func TestValidateMP4_DeepParse_CorruptedBoxTree(t *testing.T) {
	ftyp := mp4.NewFtyp("isom", 0x200, []string{"isom"})
	var buf bytes.Buffer
	if err := ftyp.Encode(&buf); err != nil {
		t.Fatalf("ftyp encode: %v", err)
	}
	// Append a box header claiming a size far larger than the remaining data.
	overflow := make([]byte, 8)
	binary.BigEndian.PutUint32(overflow[0:4], 0x7FFFFFFF)
	copy(overflow[4:8], "moov")
	buf.Write(overflow)

	err := ValidateMP4(buf.Bytes())
	if err == nil {
		t.Fatal("expected error for MP4 with oversized box")
	}
}

// TestValidateMP4_DeepParse_MetadataSizeLimit verifies that ErrMP4MetadataTooLarge
// is returned for its error type (integration: actual moov > 300 MiB cannot be
// built cheaply, so we test the error type definition only here).
func TestValidateMP4_DeepParse_MetadataSizeLimit(t *testing.T) {
	tooLarge := &ErrMP4MetadataTooLarge{Size: maxMetadataSize + 1}
	if tooLarge.Error() != "media: MP4 metadata size exceeds maximum allowed limit" {
		t.Errorf("unexpected error message: %q", tooLarge.Error())
	}
	var target *ErrMP4MetadataTooLarge
	if !errors.As(tooLarge, &target) {
		t.Error("errors.As should find *ErrMP4MetadataTooLarge")
	}
	if target.Size != maxMetadataSize+1 {
		t.Errorf("Size = %d, want %d", target.Size, maxMetadataSize+1)
	}
}

// TestValidateMP4_DeepParse_RoundTrip verifies that the output of sanitizeMP4
// is itself parseable by mp4ff, confirming the re-encoded box tree is valid.
func TestValidateMP4_DeepParse_RoundTrip(t *testing.T) {
	data := buildMdatFirstMP4() // mdat-first → triggers relocation

	result, err := Validate(data)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	// Re-parse the output with mp4ff to confirm it is valid.
	f, err := mp4.DecodeFile(bytes.NewReader(result.Validated))
	if err != nil {
		t.Fatalf("re-parsing sanitized output failed: %v", err)
	}
	if f.Ftyp == nil {
		t.Error("re-parsed output is missing ftyp")
	}
	if f.Moov == nil {
		t.Error("re-parsed output is missing moov")
	}
}

// ---- WebP deep-parse acceptance tests ---------------------------------------

// TestValidateWebP_DeepParse_VP8Lossy verifies that a well-formed VP8 (lossy)
// WebP file passes the full RIFF chunk-structure walk.
func TestValidateWebP_DeepParse_VP8Lossy(t *testing.T) {
	data := buildValidWebP()

	result, err := Validate(data)
	if err != nil {
		t.Fatalf("Validate(VP8 WebP) returned error: %v", err)
	}
	if result.MediaType != MediaTypeWebP {
		t.Errorf("MediaType = %v, want MediaTypeWebP", result.MediaType)
	}
	if len(result.Validated) == 0 {
		t.Error("Validated must be non-empty")
	}
	if result.OriginalSize != int64(len(data)) {
		t.Errorf("OriginalSize = %d, want %d", result.OriginalSize, len(data))
	}
	// WebP: structural validation only, no metadata removal.
	if result.MetadataStripped {
		t.Error("MetadataStripped must be false for WebP")
	}
}

// TestValidateWebP_DeepParse_VP8Lossless verifies that a VP8L lossless WebP
// passes the full chunk-structure walk.
func TestValidateWebP_DeepParse_VP8Lossless(t *testing.T) {
	data := buildValidWebPLossless()

	result, err := Validate(data)
	if err != nil {
		t.Fatalf("Validate(VP8L WebP) returned error: %v", err)
	}
	if result.MediaType != MediaTypeWebP {
		t.Errorf("MediaType = %v, want MediaTypeWebP", result.MediaType)
	}
}

// TestValidateWebP_DeepParse_TruncatedChunk verifies that a WebP file with a
// chunk whose size extends beyond the declared RIFF payload is rejected.
func TestValidateWebP_DeepParse_TruncatedChunk(t *testing.T) {
	vp8Payload := []byte{0xAB, 0xCD}
	// Lie about chunk size: claim 1000 bytes, only provide 2.
	chunkSize := uint32(1000)

	riffPayload := make([]byte, 0, 4+8+len(vp8Payload))
	riffPayload = append(riffPayload, []byte("WEBP")...)
	riffPayload = append(riffPayload, []byte("VP8 ")...)
	riffPayload = append(riffPayload, byte(chunkSize), byte(chunkSize>>8), byte(chunkSize>>16), byte(chunkSize>>24))
	riffPayload = append(riffPayload, vp8Payload...)

	// RIFF declared size matches the actual payload (not the inflated chunk).
	riffSize := uint32(len(riffPayload))
	var buf bytes.Buffer
	buf.WriteString("RIFF")
	writeLE32(&buf, riffSize)
	buf.Write(riffPayload)

	err := ValidateWebP(buf.Bytes())
	if err == nil {
		t.Fatal("expected error for WebP with chunk extending beyond RIFF payload")
	}
}

// TestValidateWebP_DeepParse_TruncatedHeader verifies that WebP data shorter
// than the 12-byte RIFF/WEBP header is rejected.
func TestValidateWebP_DeepParse_TruncatedHeader(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"4 bytes", []byte("RIFF")},
		{"8 bytes", []byte("RIFF\x00\x00\x00\x08")},
		{"11 bytes", []byte("RIFF\x00\x00\x00\x08WEB")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateWebP(tc.data); err == nil {
				t.Errorf("expected error for truncated WebP header (%d bytes)", len(tc.data))
			}
		})
	}
}

// TestValidateWebP_DeepParse_InvalidRIFF verifies that data not starting with
// "RIFF" is rejected.
func TestValidateWebP_DeepParse_InvalidRIFF(t *testing.T) {
	data := make([]byte, 20)
	copy(data[0:4], "XXXX")
	copy(data[8:12], "WEBP")

	if err := ValidateWebP(data); err == nil {
		t.Fatal("expected error for non-RIFF header")
	}
}

// TestValidateWebP_DeepParse_UnknownChunk verifies that an unknown chunk type
// causes a validation error under the strict validation posture.
func TestValidateWebP_DeepParse_UnknownChunk(t *testing.T) {
	unknownPayload := []byte{0x01, 0x02}
	chunkSize := uint32(len(unknownPayload))

	riffPayload := make([]byte, 0, 4+8+len(unknownPayload))
	riffPayload = append(riffPayload, []byte("WEBP")...)
	riffPayload = append(riffPayload, []byte("UNKN")...)
	riffPayload = append(riffPayload, byte(chunkSize), byte(chunkSize>>8), byte(chunkSize>>16), byte(chunkSize>>24))
	riffPayload = append(riffPayload, unknownPayload...)

	riffSize := uint32(len(riffPayload))
	var buf bytes.Buffer
	buf.WriteString("RIFF")
	writeLE32(&buf, riffSize)
	buf.Write(riffPayload)

	if err := ValidateWebP(buf.Bytes()); err == nil {
		t.Fatal("expected error for WebP with unknown chunk type")
	}
}

// TestValidateWebP_DeepParse_OddSizePadding verifies that a VP8 chunk with an
// odd-byte payload (requiring 1-byte padding) is correctly accepted.
func TestValidateWebP_DeepParse_OddSizePadding(t *testing.T) {
	// 3-byte VP8 payload (odd) → must be padded to 4 bytes total.
	vp8Payload := []byte{0x9D, 0x01, 0x2A} // 3 bytes
	chunkSize := uint32(len(vp8Payload))

	riffPayload := make([]byte, 0, 4+8+len(vp8Payload)+1)
	riffPayload = append(riffPayload, []byte("WEBP")...)
	riffPayload = append(riffPayload, []byte("VP8 ")...)
	riffPayload = append(riffPayload, byte(chunkSize), byte(chunkSize>>8), byte(chunkSize>>16), byte(chunkSize>>24))
	riffPayload = append(riffPayload, vp8Payload...)
	riffPayload = append(riffPayload, 0x00) // padding byte

	riffSize := uint32(len(riffPayload))
	var buf bytes.Buffer
	buf.WriteString("RIFF")
	writeLE32(&buf, riffSize)
	buf.Write(riffPayload)

	if err := ValidateWebP(buf.Bytes()); err != nil {
		t.Errorf("expected valid WebP with odd-size padding, got: %v", err)
	}
}

// TestValidateWebP_DeepParse_TruncatedChunkHeader verifies that a WebP file
// whose RIFF payload ends mid-chunk-header is rejected.
func TestValidateWebP_DeepParse_TruncatedChunkHeader(t *testing.T) {
	// RIFF payload: "WEBP" + 5 bytes (too short for a full chunk header of 8 bytes).
	riffPayload := []byte("WEBPVP8 \x04") // only 9 bytes after WEBP; chunk header needs 8
	riffSize := uint32(len(riffPayload))
	var buf bytes.Buffer
	buf.WriteString("RIFF")
	writeLE32(&buf, riffSize)
	buf.Write(riffPayload)

	if err := ValidateWebP(buf.Bytes()); err == nil {
		t.Fatal("expected error for WebP with truncated chunk header")
	}
}

// TestValidateWebP_DeepParse_ValidExtended verifies that a VP8X extended
// WebP file (with a lossless bitstream, EXIF, and XMP chunks) passes validation.
//
// VP8X flags: HAS_EXIF(0x08)|HAS_XMP(0x04) = 0x0C.
// webpsan requires extended files to include image data (VP8/VP8L) plus
// EXIF and XMP when the respective flags are set.
// webpsan/src/lib.rs:179–204 (sanitize_extended)
func TestValidateWebP_DeepParse_ValidExtended(t *testing.T) {
	buildChunk := func(fourcc string, payload []byte) []byte {
		size := uint32(len(payload))
		chunk := make([]byte, 0, 8+len(payload))
		chunk = append(chunk, []byte(fourcc)...)
		chunk = append(chunk, byte(size), byte(size>>8), byte(size>>16), byte(size>>24))
		chunk = append(chunk, payload...)
		if len(payload)%2 != 0 {
			chunk = append(chunk, 0x00)
		}
		return chunk
	}

	// flags = HAS_EXIF(0x08)|HAS_XMP(0x04) = 0x0C, canvas 1×1.
	vp8xPayload := []byte{0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	// VP8L: sig + w=1,h=1,alpha=0,version=0 (5 bytes).
	vp8lData := []byte{0x2f, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88, 0x08}
	exifData := []byte{0x49, 0x49, 0x2A, 0x00}
	xmpData := []byte{0x3C, 0x3F, 0x78, 0x70, 0x61, 0x63, 0x6B, 0x65}

	riffPayload := make([]byte, 0)
	riffPayload = append(riffPayload, []byte("WEBP")...)
	riffPayload = append(riffPayload, buildChunk("VP8X", vp8xPayload)...)
	riffPayload = append(riffPayload, buildChunk("VP8L", vp8lData)...)
	riffPayload = append(riffPayload, buildChunk("EXIF", exifData)...)
	riffPayload = append(riffPayload, buildChunk("XMP ", xmpData)...)

	riffSize := uint32(len(riffPayload))
	var buf bytes.Buffer
	buf.WriteString("RIFF")
	writeLE32(&buf, riffSize)
	buf.Write(riffPayload)

	if err := ValidateWebP(buf.Bytes()); err != nil {
		t.Errorf("expected valid VP8X WebP with VP8L+EXIF+XMP, got: %v", err)
	}
}

// TestValidateWebP_DeepParse_RIFFDeclaredSizeMismatch verifies that WebP
// data where the declared RIFF size is smaller than the actual file length is
// REJECTED (Finding #7: trailing bytes after declared RIFF payload are disallowed
// under webpsan's strict, fail-closed posture).
func TestValidateWebP_DeepParse_RIFFDeclaredSizeMismatch(t *testing.T) {
	data := buildValidWebP()
	// Append extra padding bytes beyond the declared RIFF boundary.
	extended := append(data, 0x00, 0x00, 0x00, 0x00)

	// Finding #7: webpsan rejects trailing bytes after the declared RIFF payload
	// to prevent concatenated-file attacks and malformed-file ingestion.
	if err := ValidateWebP(extended); err == nil {
		t.Error("expected error for WebP with trailing bytes after declared RIFF payload (Finding #7)")
	}
}

// ---- Error type tests -------------------------------------------------------

// TestErrMP4MetadataTooLarge_ErrorMessage verifies the error message of the
// ErrMP4MetadataTooLarge typed error.
func TestErrMP4MetadataTooLarge_ErrorMessage(t *testing.T) {
	err := &ErrMP4MetadataTooLarge{Size: 500 * 1024 * 1024}
	want := "media: MP4 metadata size exceeds maximum allowed limit"
	if err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}
}

// TestValidateResult_NewFields verifies that the new MoovOffset and MdatOffset
// fields in ValidateResult are set correctly for MP4 outputs.
func TestValidateResult_NewFields(t *testing.T) {
	data := buildValidProgressiveMP4()

	result, err := Validate(data)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	// For a valid moov-before-mdat MP4, both offsets must be non-negative and
	// moov must precede mdat.
	if result.MoovOffset < 0 {
		t.Errorf("MoovOffset = %d, must be >= 0", result.MoovOffset)
	}
	if result.MdatOffset <= result.MoovOffset {
		t.Errorf("MdatOffset (%d) must be > MoovOffset (%d)", result.MdatOffset, result.MoovOffset)
	}
}

// TestValidateResult_NewFields_WebP verifies that MoovOffset and MdatOffset
// are zero for WebP (not applicable).
func TestValidateResult_NewFields_WebP(t *testing.T) {
	data := buildValidWebP()

	result, err := Validate(data)
	if err != nil {
		t.Fatalf("Validate(WebP) failed: %v", err)
	}
	if result.MoovOffset != 0 {
		t.Errorf("MoovOffset = %d for WebP, want 0", result.MoovOffset)
	}
	if result.MdatOffset != 0 {
		t.Errorf("MdatOffset = %d for WebP, want 0", result.MdatOffset)
	}
}
