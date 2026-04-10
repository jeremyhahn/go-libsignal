package media

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func TestDetectMediaType_ShortJPEG(t *testing.T) {
	// JPEG with exactly 3 bytes (below minDetectionSize)
	data := []byte{0xFF, 0xD8, 0xFF}
	got := DetectMediaType(data)
	if got != MediaTypeJPEG {
		t.Errorf("expected JPEG, got %v", got)
	}
}

func TestDetectMediaType_ShortGIF(t *testing.T) {
	// GIF header with 6 bytes (below minDetectionSize)
	data := []byte("GIF89a")
	got := DetectMediaType(data)
	if got != MediaTypeGIF {
		t.Errorf("expected GIF, got %v", got)
	}
}

func TestDetectMediaType_ShortPNG(t *testing.T) {
	// PNG header with 8 bytes (below minDetectionSize)
	data := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	got := DetectMediaType(data)
	if got != MediaTypePNG {
		t.Errorf("expected PNG, got %v", got)
	}
}

func TestDetectMediaType_ShortUnknown(t *testing.T) {
	// 5 bytes, not matching any short signatures
	data := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	got := DetectMediaType(data)
	if got != MediaTypeUnknown {
		t.Errorf("expected Unknown, got %v", got)
	}
}

func TestSanitizeGIF(t *testing.T) {
	data := make([]byte, 13)
	copy(data, "GIF89a")
	result, err := Sanitize(data)
	if err != nil {
		t.Fatalf("Sanitize GIF failed: %v", err)
	}
	if result.MediaType != MediaTypeGIF {
		t.Errorf("MediaType = %v, want GIF", result.MediaType)
	}
	if !bytes.Equal(result.Sanitized, data) {
		t.Error("GIF sanitization should return data as-is")
	}
	if result.MetadataStripped {
		t.Error("GIF MetadataStripped should be false (validation only)")
	}
}

func TestSanitizeGIF_Invalid(t *testing.T) {
	data := []byte("GIF00a0000000")
	_, err := Sanitize(data)
	if err == nil {
		t.Fatal("expected error for invalid GIF")
	}
}

func TestSanitizeMP4(t *testing.T) {
	var buf bytes.Buffer
	ftypData := []byte("isom\x00\x00\x02\x00isomavc1")
	ftypLen := make([]byte, 4)
	binary.BigEndian.PutUint32(ftypLen, uint32(8+len(ftypData)))
	buf.Write(ftypLen)
	buf.WriteString("ftyp")
	buf.Write(ftypData)
	// mdat box extends to EOF
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	buf.WriteString("mdat")

	result, err := Sanitize(buf.Bytes())
	if err != nil {
		t.Fatalf("Sanitize MP4 failed: %v", err)
	}
	if result.MediaType != MediaTypeMP4 {
		t.Errorf("MediaType = %v, want MP4", result.MediaType)
	}
	if !bytes.Equal(result.Sanitized, buf.Bytes()) {
		t.Error("MP4 sanitization should return data as-is")
	}
	if result.MetadataStripped {
		t.Error("MP4 MetadataStripped should be false (validation only)")
	}
}

func TestSanitizeMP4_Invalid(t *testing.T) {
	data := []byte{0x00, 0x00, 0x00, 0x08, 'f', 't', 'y', 'p'}
	// Box size is 8, total data is 8, but no proper ftyp payload
	// Let's make it invalid by adding a truncated box after ftyp
	data = append(data, 0x00, 0x00, 0x00, 0x20) // box size 32
	data = append(data, 'm', 'd', 'a', 't')     // but only 4 bytes of payload
	_, err := Sanitize(data)
	if err == nil {
		t.Fatal("expected error for truncated MP4")
	}
}

func TestSanitizeWebP(t *testing.T) {
	data := make([]byte, 20)
	copy(data[0:4], "RIFF")
	binary.LittleEndian.PutUint32(data[4:8], 12) // file size - 8
	copy(data[8:12], "WEBP")
	copy(data[12:16], "VP8 ")
	binary.LittleEndian.PutUint32(data[16:20], 0)

	result, err := Sanitize(data)
	if err != nil {
		t.Fatalf("Sanitize WebP failed: %v", err)
	}
	if result.MediaType != MediaTypeWebP {
		t.Errorf("MediaType = %v, want WebP", result.MediaType)
	}
	if result.MetadataStripped {
		t.Error("WebP MetadataStripped should be false (validation only)")
	}
}

func TestSanitizeWebP_Invalid(t *testing.T) {
	data := make([]byte, 12)
	copy(data[0:4], "RIFF")
	binary.LittleEndian.PutUint32(data[4:8], 100) // declared size too large
	copy(data[8:12], "WEBP")

	_, err := Sanitize(data)
	if err == nil {
		t.Fatal("expected error for WebP with declared size exceeding actual")
	}
}

func TestValidateMP4_BoxSizeTooSmall(t *testing.T) {
	// ftyp box with size 8, then another box with size < 8
	var buf bytes.Buffer
	ftypLen := make([]byte, 4)
	binary.BigEndian.PutUint32(ftypLen, 8)
	buf.Write(ftypLen)
	buf.WriteString("ftyp")
	// A box with size 4 (invalid, < 8)
	badLen := make([]byte, 4)
	binary.BigEndian.PutUint32(badLen, 4)
	buf.Write(badLen)
	buf.WriteString("mdat")

	err := ValidateMP4(buf.Bytes())
	if err == nil {
		t.Fatal("expected error for box size too small")
	}
	got := err.Error()
	if got == "" {
		t.Fatal("expected non-empty error message")
	}
}

func TestValidateMP4_TruncatedBoxHeader(t *testing.T) {
	// ftyp box then only 4 bytes (incomplete box header)
	var buf bytes.Buffer
	ftypLen := make([]byte, 4)
	binary.BigEndian.PutUint32(ftypLen, 8)
	buf.Write(ftypLen)
	buf.WriteString("ftyp")
	buf.Write([]byte{0x00, 0x00, 0x00}) // only 3 bytes, need 8 for a box header

	err := ValidateMP4(buf.Bytes())
	if err == nil {
		t.Fatal("expected error for truncated box header")
	}
}

func TestValidateWebP_MissingRIFF(t *testing.T) {
	data := make([]byte, 12)
	copy(data[0:4], "XXXX")
	err := ValidateWebP(data)
	if err == nil {
		t.Fatal("expected error for missing RIFF header")
	}
}

func TestValidateGIF_TooShortForLSD(t *testing.T) {
	// Valid GIF header but too short for logical screen descriptor
	data := []byte("GIF89a1234")
	err := ValidateGIF(data)
	if err == nil {
		t.Fatal("expected error for GIF too short for logical screen descriptor")
	}
}

func TestSanitizeJPEG_EOI(t *testing.T) {
	// JPEG with SOI, a kept marker (DQT), then EOI
	var buf bytes.Buffer
	buf.Write([]byte{0xFF, 0xD8}) // SOI
	// DQT marker
	buf.WriteByte(0xFF)
	buf.WriteByte(0xDB)
	dqtData := make([]byte, 64)
	dqtLen := make([]byte, 2)
	binary.BigEndian.PutUint16(dqtLen, uint16(len(dqtData)+2+1))
	buf.Write(dqtLen)
	buf.WriteByte(0x00)
	buf.Write(dqtData)
	// EOI
	buf.WriteByte(0xFF)
	buf.WriteByte(0xD9)
	// Trailing data after EOI
	buf.Write([]byte{0xAA, 0xBB})

	result, err := Sanitize(buf.Bytes())
	if err != nil {
		t.Fatalf("Sanitize JPEG with EOI: %v", err)
	}
	if result.MediaType != MediaTypeJPEG {
		t.Errorf("MediaType = %v, want JPEG", result.MediaType)
	}
	// Should contain EOI marker
	if !bytes.Contains(result.Sanitized, []byte{0xFF, 0xD9}) {
		t.Error("sanitized JPEG should contain EOI marker")
	}
}

func TestSanitizeJPEG_APP2andAPP13(t *testing.T) {
	// JPEG with APP2 (ICC) and APP13 (IPTC) - both should be stripped
	var buf bytes.Buffer
	buf.Write([]byte{0xFF, 0xD8}) // SOI

	// APP2 (ICC profile) - strip
	buf.WriteByte(0xFF)
	buf.WriteByte(0xE2)
	app2Data := []byte("ICC_PROFILE")
	app2Len := make([]byte, 2)
	binary.BigEndian.PutUint16(app2Len, uint16(len(app2Data)+2))
	buf.Write(app2Len)
	buf.Write(app2Data)

	// APP13 (IPTC) - strip
	buf.WriteByte(0xFF)
	buf.WriteByte(0xED)
	app13Data := []byte("Photoshop 3.0")
	app13Len := make([]byte, 2)
	binary.BigEndian.PutUint16(app13Len, uint16(len(app13Data)+2))
	buf.Write(app13Len)
	buf.Write(app13Data)

	// SOS
	buf.WriteByte(0xFF)
	buf.WriteByte(0xDA)
	sosLen := make([]byte, 2)
	binary.BigEndian.PutUint16(sosLen, 4)
	buf.Write(sosLen)
	buf.Write([]byte{0x00, 0x00})
	buf.Write([]byte{0x12, 0x34})

	result, err := Sanitize(buf.Bytes())
	if err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	if bytes.Contains(result.Sanitized, []byte{0xFF, 0xE2}) {
		t.Error("should not contain APP2")
	}
	if bytes.Contains(result.Sanitized, []byte{0xFF, 0xED}) {
		t.Error("should not contain APP13")
	}
}

func TestSanitizeJPEG_TruncatedMarkerLength(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0xFF, 0xD8}) // SOI
	buf.WriteByte(0xFF)
	buf.WriteByte(0xDB) // DQT
	buf.WriteByte(0x00) // Only 1 byte of length (need 2)

	_, err := Sanitize(buf.Bytes())
	if err == nil {
		t.Fatal("expected error for truncated marker length")
	}
}

func TestSanitizeJPEG_InvalidMarkerLength(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0xFF, 0xD8}) // SOI
	buf.WriteByte(0xFF)
	buf.WriteByte(0xDB) // DQT
	buf.Write([]byte{0x00, 0x01}) // length = 1 (< 2, invalid)

	_, err := Sanitize(buf.Bytes())
	if err == nil {
		t.Fatal("expected error for invalid marker length")
	}
}

func TestSanitizeJPEG_MarkerExtendsBeforeData(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0xFF, 0xD8}) // SOI
	buf.WriteByte(0xFF)
	buf.WriteByte(0xDB)            // DQT
	buf.Write([]byte{0x00, 0xFF}) // length = 255 (extends beyond data)

	_, err := Sanitize(buf.Bytes())
	if err == nil {
		t.Fatal("expected error for marker extending beyond data")
	}
}

func TestSanitizeJPEG_ByteStuffing(t *testing.T) {
	// JPEG with 0xFF 0x00 (byte stuffing) - should be copied
	var buf bytes.Buffer
	buf.Write([]byte{0xFF, 0xD8}) // SOI
	// Simulate hitting a 0xFF followed by 0x00 outside of scan data
	buf.WriteByte(0xFF)
	buf.WriteByte(0x00) // byte stuffing

	result, err := sanitizeJPEG(buf.Bytes())
	if err != nil {
		t.Fatalf("sanitizeJPEG: %v", err)
	}
	if !bytes.Contains(result, []byte{0xFF, 0x00}) {
		t.Error("should preserve byte stuffing")
	}
}

func TestSanitizeJPEG_PaddingFF(t *testing.T) {
	// JPEG with multiple 0xFF padding bytes before a marker
	var buf bytes.Buffer
	buf.Write([]byte{0xFF, 0xD8}) // SOI
	buf.Write([]byte{0xFF, 0xFF, 0xFF}) // padding
	buf.WriteByte(0xDA)                  // SOS marker byte
	sosLen := make([]byte, 2)
	binary.BigEndian.PutUint16(sosLen, 2)
	buf.Write(sosLen)
	buf.Write([]byte{0xAB, 0xCD})

	result, err := sanitizeJPEG(buf.Bytes())
	if err != nil {
		t.Fatalf("sanitizeJPEG: %v", err)
	}
	if !bytes.HasPrefix(result, []byte{0xFF, 0xD8}) {
		t.Error("should start with SOI")
	}
}

func TestSanitizeJPEG_NonMarkerByte(t *testing.T) {
	// JPEG where we encounter a non-0xFF byte outside markers (scan data)
	var buf bytes.Buffer
	buf.Write([]byte{0xFF, 0xD8, 0xFF, 0xE0}) // SOI + start of APP0
	// Add length and data for APP0
	app0Len := make([]byte, 2)
	binary.BigEndian.PutUint16(app0Len, 4) // length=4
	buf.Write(app0Len)
	buf.Write([]byte{0x00, 0x00})
	// Now non-marker data
	buf.Write([]byte{0x12, 0x34, 0x56})

	result, err := sanitizeJPEG(buf.Bytes())
	if err != nil {
		t.Fatalf("sanitizeJPEG: %v", err)
	}
	// Should copy rest as scan data
	if !bytes.Contains(result, []byte{0x12, 0x34, 0x56}) {
		t.Error("should copy non-marker data")
	}
}

func TestSanitizeJPEG_InvalidHeader(t *testing.T) {
	_, err := sanitizeJPEG([]byte{0x00, 0x01})
	if err != ErrInvalidJPEG {
		t.Errorf("expected ErrInvalidJPEG, got %v", err)
	}
}

func TestSanitizePNG_InvalidHeader(t *testing.T) {
	_, err := sanitizePNG([]byte{0x00, 0x01, 0x02, 0x03})
	if err != ErrInvalidPNG {
		t.Errorf("expected ErrInvalidPNG, got %v", err)
	}
}

func TestSanitizePNG_ChunkExtendsBeforeData(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(pngMagic)
	// Chunk with length that extends beyond data
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, 9999)
	buf.Write(lenBuf)
	buf.WriteString("IHDR")
	// Need at least 12 bytes after the PNG magic for the loop to enter
	// We have 8 bytes (4 len + 4 type). Need CRC area too.
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00}) // fake CRC to make 12 bytes total

	_, err := sanitizePNG(buf.Bytes())
	if err == nil {
		t.Fatal("expected error for PNG chunk extending beyond data")
	}
}

func TestSanitizePNG_StripEXIF(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(pngMagic)

	writeChunk := func(chunkType string, data []byte) {
		lenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))
		buf.Write(lenBuf)
		buf.WriteString(chunkType)
		buf.Write(data)
		buf.Write([]byte{0x00, 0x00, 0x00, 0x00}) // CRC
	}

	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:4], 1)
	binary.BigEndian.PutUint32(ihdr[4:8], 1)
	ihdr[8] = 8
	ihdr[9] = 2
	writeChunk("IHDR", ihdr)
	writeChunk("eXIf", []byte("exif data"))
	writeChunk("iCCP", []byte("icc profile"))
	writeChunk("zTXt", []byte("compressed text"))
	writeChunk("iTXt", []byte("international text"))
	writeChunk("IDAT", []byte{0x08, 0xD7, 0x63, 0x60})
	writeChunk("IEND", nil)

	result, err := sanitizePNG(buf.Bytes())
	if err != nil {
		t.Fatalf("sanitizePNG: %v", err)
	}
	if bytes.Contains(result, []byte("eXIf")) {
		t.Error("should strip eXIf chunk")
	}
	if bytes.Contains(result, []byte("iCCP")) {
		t.Error("should strip iCCP chunk")
	}
	if bytes.Contains(result, []byte("zTXt")) {
		t.Error("should strip zTXt chunk")
	}
	if bytes.Contains(result, []byte("iTXt")) {
		t.Error("should strip iTXt chunk")
	}
	if !bytes.Contains(result, []byte("IHDR")) {
		t.Error("should keep IHDR chunk")
	}
	if !bytes.Contains(result, []byte("IDAT")) {
		t.Error("should keep IDAT chunk")
	}
}

func TestSanitizeReaderError(t *testing.T) {
	r := &errorReader{}
	_, err := SanitizeReader(r)
	if err == nil {
		t.Fatal("expected error from SanitizeReader")
	}
}

type errorReader struct{}

func (e *errorReader) Read(p []byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func TestSanitize_EmptyData(t *testing.T) {
	_, err := Sanitize([]byte{})
	if err != ErrDataTooShort {
		t.Errorf("expected ErrDataTooShort, got %v", err)
	}
}

func TestSanitize_TwoBytes(t *testing.T) {
	_, err := Sanitize([]byte{0x00, 0x01})
	if err != ErrDataTooShort {
		t.Errorf("expected ErrDataTooShort, got %v", err)
	}
}

func TestValidateMP4_LargeBoxSize(t *testing.T) {
	// Test that large box sizes (near uint32 max) are handled correctly
	// without integer overflow. On 32-bit platforms, casting uint32 to int
	// could produce a negative value, causing incorrect bounds checks.
	var buf bytes.Buffer

	// ftyp box (valid, small)
	ftypLen := make([]byte, 4)
	binary.BigEndian.PutUint32(ftypLen, 8)
	buf.Write(ftypLen)
	buf.WriteString("ftyp")

	// Box with size 0xFFFFFFF0 (just under uint32 max) -- should fail with
	// "box extends beyond file" rather than passing due to negative wrap.
	bigLen := make([]byte, 4)
	binary.BigEndian.PutUint32(bigLen, 0xFFFFFFF0)
	buf.Write(bigLen)
	buf.WriteString("moov")

	err := ValidateMP4(buf.Bytes())
	if err == nil {
		t.Fatal("expected error for box size exceeding file length")
	}
}

func TestValidateMP4_ExtendedSize64(t *testing.T) {
	// Test that boxSize==1 triggers 64-bit extended size parsing.
	var buf bytes.Buffer

	// ftyp box using 64-bit extended size.
	// boxSize = 1 (signals 64-bit), type = "ftyp", then 8-byte extended size.
	if err := binary.Write(&buf, binary.BigEndian, uint32(1)); err != nil { // boxSize = 1
		t.Fatal(err)
	}
	buf.WriteString("ftyp")                   // type
	if err := binary.Write(&buf, binary.BigEndian, uint64(24)); err != nil { // extended size (24 = 4+4+8+8 payload)
		t.Fatal(err)
	}
	buf.Write([]byte("isom\x00\x00\x02\x00")) // ftyp payload (8 bytes)

	// mdat box extending to end of file.
	if err := binary.Write(&buf, binary.BigEndian, uint32(0)); err != nil { // extends to EOF
		t.Fatal(err)
	}
	buf.WriteString("mdat")

	err := ValidateMP4(buf.Bytes())
	if err != nil {
		t.Fatalf("expected valid MP4 with 64-bit extended size, got error: %v", err)
	}
}

func TestValidateMP4_ExtendedSizeTruncated(t *testing.T) {
	// boxSize=1 but not enough bytes for the 64-bit extended size.
	var buf bytes.Buffer

	if err := binary.Write(&buf, binary.BigEndian, uint32(1)); err != nil {
		t.Fatal(err)
	}
	buf.WriteString("ftyp")
	// Only 4 bytes of the 8-byte extended size.
	buf.Write([]byte{0x00, 0x00, 0x00, 0x18})

	err := ValidateMP4(buf.Bytes())
	if err == nil {
		t.Fatal("expected error for truncated 64-bit extended size")
	}
}

func TestValidateMP4_ExtendedSizeTooSmall(t *testing.T) {
	// boxSize=1 with 64-bit size < 16 (invalid).
	var buf bytes.Buffer

	if err := binary.Write(&buf, binary.BigEndian, uint32(1)); err != nil {
		t.Fatal(err)
	}
	buf.WriteString("ftyp")
	if err := binary.Write(&buf, binary.BigEndian, uint64(8)); err != nil { // Too small for extended box
		t.Fatal(err)
	}

	err := ValidateMP4(buf.Bytes())
	if err == nil {
		t.Fatal("expected error for 64-bit box size too small")
	}
}

func TestValidateWebP_LargeRIFFSize(t *testing.T) {
	// Test that large RIFF sizes near uint32 max don't cause integer overflow.
	// On 32-bit, int(0xFFFFFFFF) + 8 would overflow to 7, incorrectly passing.
	data := make([]byte, 20)
	copy(data[0:4], "RIFF")
	binary.LittleEndian.PutUint32(data[4:8], 0xFFFFFFFF) // near-max riff size
	copy(data[8:12], "WEBP")

	err := ValidateWebP(data)
	if err == nil {
		t.Fatal("expected error for WebP with RIFF size exceeding data")
	}
}

func TestValidateMP4_BoxSizeExactlyAtEnd(t *testing.T) {
	// A valid MP4 where each box's size lines up exactly with the data length.
	var buf bytes.Buffer

	// ftyp box with 16 bytes total (8 header + 8 payload)
	ftypLen := make([]byte, 4)
	binary.BigEndian.PutUint32(ftypLen, 16)
	buf.Write(ftypLen)
	buf.WriteString("ftyp")
	buf.Write([]byte("isom\x00\x00\x02\x00"))

	// moov box with 8 bytes (just header, no payload)
	moovLen := make([]byte, 4)
	binary.BigEndian.PutUint32(moovLen, 8)
	buf.Write(moovLen)
	buf.WriteString("moov")

	err := ValidateMP4(buf.Bytes())
	if err != nil {
		t.Fatalf("expected valid MP4, got error: %v", err)
	}
}
