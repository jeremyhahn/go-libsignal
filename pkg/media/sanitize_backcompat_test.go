package media

import (
	"bytes"
	"encoding/binary"
	"testing"

	mp4 "github.com/Eyevinn/mp4ff/mp4"
)

// buildMinimalJPEG returns a structurally valid JPEG byte slice with one APP1
// (EXIF) marker so that metadata stripping is exercised.
func buildMinimalJPEG() []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0xFF, 0xD8}) // SOI

	// APP1 (EXIF) — will be stripped by goextensions.SanitizeJPEG
	exifPayload := []byte("Exif\x00\x00test")
	buf.WriteByte(0xFF)
	buf.WriteByte(0xE1)
	lb := make([]byte, 2)
	binary.BigEndian.PutUint16(lb, uint16(len(exifPayload)+2))
	buf.Write(lb)
	buf.Write(exifPayload)

	// SOS + minimal scan data
	buf.WriteByte(0xFF)
	buf.WriteByte(0xDA)
	binary.BigEndian.PutUint16(lb, 4)
	buf.Write(lb)
	buf.Write([]byte{0x00, 0x00, 0xAB, 0xCD})

	return buf.Bytes()
}

// buildMinimalPNG returns a structurally valid PNG byte slice with a tEXt chunk
// so that metadata stripping is exercised.
func buildMinimalPNG() []byte {
	var buf bytes.Buffer
	// PNG signature
	buf.Write([]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A})

	writeChunk := func(chunkType string, data []byte) {
		lb := make([]byte, 4)
		binary.BigEndian.PutUint32(lb, uint32(len(data)))
		buf.Write(lb)
		buf.WriteString(chunkType)
		buf.Write(data)
		buf.Write([]byte{0x00, 0x00, 0x00, 0x00}) // dummy CRC
	}

	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:4], 1)
	binary.BigEndian.PutUint32(ihdr[4:8], 1)
	ihdr[8] = 8
	ihdr[9] = 2
	writeChunk("IHDR", ihdr)
	writeChunk("tEXt", []byte("Comment\x00metadata"))
	writeChunk("IDAT", []byte{0x08, 0xD7, 0x63, 0x60})
	writeChunk("IEND", nil)

	return buf.Bytes()
}

// buildMinimalGIF returns a structurally valid GIF89a byte slice.
func buildMinimalGIF() []byte {
	data := make([]byte, 13)
	copy(data, "GIF89a")
	return data
}

// buildMinimalMP4 returns a structurally valid progressive MP4 built with
// mp4ff, producing a real ftyp + moov + mdat layout that DecodeFile accepts.
func buildMinimalMP4() []byte {
	return buildMP4WithLayout(false)
}

// buildMP4WithMdatFirst builds an MP4 where mdat appears before moov, so
// that sanitizeMP4 must relocate moov and MetadataStripped becomes true.
func buildMP4WithMdatFirst() []byte {
	return buildMP4WithLayout(true)
}

// buildMP4WithLayout constructs a minimal valid progressive MP4 file.
// When mdatFirst is true, mdat is written before moov (triggering relocation).
func buildMP4WithLayout(mdatFirst bool) []byte {
	ftyp := mp4.NewFtyp("isom", 0x200, []string{"isom", "avc1"})
	moov := mp4.NewMoovBox()
	moov.AddChild(mp4.CreateMvhd())

	// Minimal 4-byte mdat payload.
	mediaPayload := []byte{0x00, 0x00, 0x00, 0x01}
	mdatSize := uint32(8 + len(mediaPayload))
	mdatRaw := make([]byte, mdatSize)
	binary.BigEndian.PutUint32(mdatRaw[0:4], mdatSize)
	copy(mdatRaw[4:8], "mdat")
	copy(mdatRaw[8:], mediaPayload)

	var buf bytes.Buffer

	// Always write ftyp first.
	if err := ftyp.Encode(&buf); err != nil {
		panic("buildMP4WithLayout: ftyp encode: " + err.Error())
	}

	if mdatFirst {
		buf.Write(mdatRaw)
		if err := moov.Encode(&buf); err != nil {
			panic("buildMP4WithLayout: moov encode: " + err.Error())
		}
	} else {
		if err := moov.Encode(&buf); err != nil {
			panic("buildMP4WithLayout: moov encode: " + err.Error())
		}
		buf.Write(mdatRaw)
	}

	return buf.Bytes()
}

// TestSanitize_JPEG_BackCompat verifies that Sanitize routes JPEG data to
// goextensions.Sanitize and returns MetadataStripped=true.
func TestSanitize_JPEG_BackCompat(t *testing.T) {
	data := buildMinimalJPEG()

	result, err := Sanitize(data)
	if err != nil {
		t.Fatalf("Sanitize(JPEG) returned unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Sanitize(JPEG) returned nil result")
	}
	// goextensions.SanitizeJPEG strips metadata, so MetadataStripped must be true.
	if !result.MetadataStripped {
		t.Error("MetadataStripped should be true: goextensions strips EXIF from JPEG")
	}
	if len(result.Sanitized) == 0 {
		t.Error("Validated must be non-empty for JPEG")
	}
	if result.OriginalSize != int64(len(data)) {
		t.Errorf("OriginalSize = %d, want %d", result.OriginalSize, len(data))
	}
	// The sanitized output should not contain the APP1 (EXIF) marker.
	if bytes.Contains(result.Sanitized, []byte{0xFF, 0xE1}) {
		t.Error("sanitized JPEG should not contain APP1 (EXIF) marker")
	}
}

// TestSanitize_PNG_BackCompat verifies that Sanitize routes PNG data to
// goextensions.Sanitize and returns MetadataStripped=true.
func TestSanitize_PNG_BackCompat(t *testing.T) {
	data := buildMinimalPNG()

	result, err := Sanitize(data)
	if err != nil {
		t.Fatalf("Sanitize(PNG) returned unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Sanitize(PNG) returned nil result")
	}
	// goextensions.SanitizePNG strips metadata, so MetadataStripped must be true.
	if !result.MetadataStripped {
		t.Error("MetadataStripped should be true: goextensions strips tEXt from PNG")
	}
	if len(result.Sanitized) == 0 {
		t.Error("Validated must be non-empty for PNG")
	}
	if result.OriginalSize != int64(len(data)) {
		t.Errorf("OriginalSize = %d, want %d", result.OriginalSize, len(data))
	}
	// The sanitized output should not contain the tEXt chunk.
	if bytes.Contains(result.Sanitized, []byte("tEXt")) {
		t.Error("sanitized PNG should not contain tEXt chunk")
	}
}

// TestSanitize_GIF_BackCompat verifies that Sanitize routes GIF data to
// goextensions.Sanitize. GIF receives structural validation only, so
// MetadataStripped is false and data is returned unchanged.
func TestSanitize_GIF_BackCompat(t *testing.T) {
	data := buildMinimalGIF()

	result, err := Sanitize(data)
	if err != nil {
		t.Fatalf("Sanitize(GIF) returned unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Sanitize(GIF) returned nil result")
	}
	// GIF: structural validation only; MetadataStripped is false.
	if result.MetadataStripped {
		t.Error("MetadataStripped should be false for GIF (validation only, no stripping)")
	}
	if !bytes.Equal(result.Sanitized, data) {
		t.Error("GIF Validated data should equal input (returned as-is)")
	}
	if result.OriginalSize != int64(len(data)) {
		t.Errorf("OriginalSize = %d, want %d", result.OriginalSize, len(data))
	}
}

// TestSanitize_MP4_BackCompat verifies that Sanitize routes MP4 through
// Validate, returns MediaTypeMP4, and correctly reports MetadataStripped
// based on whether moov was relocated.
func TestSanitize_MP4_BackCompat(t *testing.T) {
	t.Run("moov_before_mdat_no_relocation", func(t *testing.T) {
		data := buildMinimalMP4() // moov precedes mdat; no relocation needed
		result, err := Sanitize(data)
		if err != nil {
			t.Fatalf("Sanitize(MP4) returned unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("Sanitize(MP4) returned nil result")
		}
		if result.MediaType != MediaTypeMP4 {
			t.Errorf("MediaType = %v, want MediaTypeMP4", result.MediaType)
		}
		// moov already before mdat → MetadataStripped must be false.
		if result.MetadataStripped {
			t.Error("MetadataStripped should be false: moov was already before mdat")
		}
		if result.OriginalSize != int64(len(data)) {
			t.Errorf("OriginalSize = %d, want %d", result.OriginalSize, len(data))
		}
	})

	t.Run("mdat_before_moov_triggers_relocation", func(t *testing.T) {
		data := buildMP4WithMdatFirst() // mdat precedes moov → relocation required
		result, err := Sanitize(data)
		if err != nil {
			t.Fatalf("Sanitize(MP4 mdat-first) returned unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("Sanitize(MP4 mdat-first) returned nil result")
		}
		if result.MediaType != MediaTypeMP4 {
			t.Errorf("MediaType = %v, want MediaTypeMP4", result.MediaType)
		}
		// mdat was before moov → MetadataStripped must be true (moov relocated).
		if !result.MetadataStripped {
			t.Error("MetadataStripped should be true: moov was relocated before mdat")
		}
	})
}

// TestSanitize_UnrecognizedType_BackCompat verifies that Sanitize returns
// ErrUnsupportedMediaType for data that matches no known magic bytes.
func TestSanitize_UnrecognizedType_BackCompat(t *testing.T) {
	data := make([]byte, 20) // all-zero bytes: not JPEG/PNG/GIF/MP4/WebP

	_, err := Sanitize(data)
	if err == nil {
		t.Fatal("Sanitize(unrecognized) should return an error")
	}
	if err != ErrUnsupportedMediaType {
		t.Errorf("expected ErrUnsupportedMediaType, got %T: %v", err, err)
	}
}

// TestSanitize_TooShort_BackCompat verifies that Sanitize returns
// ErrDataTooShort for data that is too short for any media detection.
func TestSanitize_TooShort_BackCompat(t *testing.T) {
	_, err := Sanitize([]byte{0xFF})
	if err == nil {
		t.Fatal("Sanitize(1 byte) should return an error")
	}
	// Single byte: not detected as goextensions type (needs >= 3 for JPEG);
	// Validate returns ErrDataTooShort for len < 3.
	if err != ErrDataTooShort {
		t.Errorf("expected ErrDataTooShort, got %T: %v", err, err)
	}
}

// TestSanitize_MediaType_JPEG verifies that Sanitize sets MediaType to
// MediaTypeJPEG (not MediaTypeUnknown) for JPEG inputs.
func TestSanitize_MediaType_JPEG(t *testing.T) {
	data := buildMinimalJPEG()
	result, err := Sanitize(data)
	if err != nil {
		t.Fatalf("Sanitize(JPEG) returned unexpected error: %v", err)
	}
	if result.MediaType != MediaTypeJPEG {
		t.Errorf("MediaType = %v (%d), want MediaTypeJPEG (%d)", result.MediaType, result.MediaType, MediaTypeJPEG)
	}
}

// TestSanitize_MediaType_PNG verifies that Sanitize sets MediaType to
// MediaTypePNG (not MediaTypeUnknown) for PNG inputs.
func TestSanitize_MediaType_PNG(t *testing.T) {
	data := buildMinimalPNG()
	result, err := Sanitize(data)
	if err != nil {
		t.Fatalf("Sanitize(PNG) returned unexpected error: %v", err)
	}
	if result.MediaType != MediaTypePNG {
		t.Errorf("MediaType = %v (%d), want MediaTypePNG (%d)", result.MediaType, result.MediaType, MediaTypePNG)
	}
}

// TestSanitize_MediaType_GIF verifies that Sanitize sets MediaType to
// MediaTypeGIF (not MediaTypeUnknown) for GIF inputs.
func TestSanitize_MediaType_GIF(t *testing.T) {
	data := buildMinimalGIF()
	result, err := Sanitize(data)
	if err != nil {
		t.Fatalf("Sanitize(GIF) returned unexpected error: %v", err)
	}
	if result.MediaType != MediaTypeGIF {
		t.Errorf("MediaType = %v (%d), want MediaTypeGIF (%d)", result.MediaType, result.MediaType, MediaTypeGIF)
	}
}

// TestSanitizeReader_JPEG verifies that SanitizeReader routes JPEG through
// goextensions.Sanitize: MetadataStripped=true, MediaType=MediaTypeJPEG.
func TestSanitizeReader_JPEG(t *testing.T) {
	data := buildMinimalJPEG()
	result, err := SanitizeReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("SanitizeReader(JPEG) returned unexpected error: %v", err)
	}
	if result.MediaType != MediaTypeJPEG {
		t.Errorf("MediaType = %v, want MediaTypeJPEG", result.MediaType)
	}
	if !result.MetadataStripped {
		t.Error("MetadataStripped should be true for JPEG")
	}
	if len(result.Sanitized) == 0 {
		t.Error("Validated must be non-empty for JPEG")
	}
	if result.OriginalSize != int64(len(data)) {
		t.Errorf("OriginalSize = %d, want %d", result.OriginalSize, len(data))
	}
}

// TestSanitizeReader_PNG verifies that SanitizeReader routes PNG through
// goextensions.Sanitize: MetadataStripped=true, MediaType=MediaTypePNG.
func TestSanitizeReader_PNG(t *testing.T) {
	data := buildMinimalPNG()
	result, err := SanitizeReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("SanitizeReader(PNG) returned unexpected error: %v", err)
	}
	if result.MediaType != MediaTypePNG {
		t.Errorf("MediaType = %v, want MediaTypePNG", result.MediaType)
	}
	if !result.MetadataStripped {
		t.Error("MetadataStripped should be true for PNG")
	}
	if len(result.Sanitized) == 0 {
		t.Error("Validated must be non-empty for PNG")
	}
}

// TestSanitizeReader_GIF verifies that SanitizeReader routes GIF through
// goextensions.Sanitize: MetadataStripped=false, MediaType=MediaTypeGIF.
func TestSanitizeReader_GIF(t *testing.T) {
	data := buildMinimalGIF()
	result, err := SanitizeReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("SanitizeReader(GIF) returned unexpected error: %v", err)
	}
	if result.MediaType != MediaTypeGIF {
		t.Errorf("MediaType = %v, want MediaTypeGIF", result.MediaType)
	}
	if result.MetadataStripped {
		t.Error("MetadataStripped should be false for GIF (validation only)")
	}
}

// TestSanitizeReader_MP4 verifies that SanitizeReader routes MP4 through
// Validate, returns MediaTypeMP4, and sets MetadataStripped=false when moov
// is already in the correct position.
func TestSanitizeReader_MP4(t *testing.T) {
	data := buildMinimalMP4() // moov precedes mdat
	result, err := SanitizeReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("SanitizeReader(MP4) returned unexpected error: %v", err)
	}
	if result.MediaType != MediaTypeMP4 {
		t.Errorf("MediaType = %v, want MediaTypeMP4", result.MediaType)
	}
	// moov is already before mdat → no relocation → MetadataStripped=false.
	if result.MetadataStripped {
		t.Error("MetadataStripped should be false: moov was already before mdat")
	}
}

// buildMinimalWebP returns a structurally valid WebP byte slice.
func buildMinimalWebP() []byte {
	// RIFF header (12 bytes) + minimal WEBP VP8 chunk (8 bytes payload).
	payload := []byte("VP8 \x04\x00\x00\x00\xAB\xCD\xEF\x01")
	fileSize := uint32(4 + len(payload)) // "WEBP" + chunks
	buf := make([]byte, 0, 12+len(payload))
	buf = append(buf, []byte("RIFF")...)
	buf = append(buf, byte(fileSize), byte(fileSize>>8), byte(fileSize>>16), byte(fileSize>>24))
	buf = append(buf, []byte("WEBP")...)
	buf = append(buf, payload...)
	return buf
}

// TestSanitizeReader_WebP verifies that SanitizeReader routes WebP through
// Validate and returns the correct MediaType.
func TestSanitizeReader_WebP(t *testing.T) {
	data := buildMinimalWebP()
	result, err := SanitizeReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("SanitizeReader(WebP) returned unexpected error: %v", err)
	}
	if result.MediaType != MediaTypeWebP {
		t.Errorf("MediaType = %v, want MediaTypeWebP", result.MediaType)
	}
}

// TestSanitizeReader_Unrecognized verifies that SanitizeReader returns
// ErrUnsupportedMediaType for unrecognized input.
func TestSanitizeReader_Unrecognized(t *testing.T) {
	data := make([]byte, 20) // all-zero bytes
	_, err := SanitizeReader(bytes.NewReader(data))
	if err == nil {
		t.Fatal("SanitizeReader(unrecognized) should return an error")
	}
	if err != ErrUnsupportedMediaType {
		t.Errorf("expected ErrUnsupportedMediaType, got %T: %v", err, err)
	}
}
