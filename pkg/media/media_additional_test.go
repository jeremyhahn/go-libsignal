package media

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func TestDetectMediaType_ShortData(t *testing.T) {
	// Data shorter than minDetectionSize returns Unknown.
	data := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	got := DetectMediaType(data)
	if got != MediaTypeUnknown {
		t.Errorf("expected Unknown for short data, got %v", got)
	}
}

func TestValidate_EmptyData(t *testing.T) {
	_, err := Validate([]byte{})
	if err != ErrDataTooShort {
		t.Errorf("expected ErrDataTooShort, got %v", err)
	}
}

func TestValidate_TwoBytes(t *testing.T) {
	_, err := Validate([]byte{0x00, 0x01})
	if err != ErrDataTooShort {
		t.Errorf("expected ErrDataTooShort, got %v", err)
	}
}

func TestValidateMP4_BoxSizeTooSmall(t *testing.T) {
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

	if err := ValidateMP4(buf.Bytes()); err == nil {
		t.Fatal("expected error for box size too small")
	}
}

func TestValidateMP4_TruncatedBoxHeader(t *testing.T) {
	var buf bytes.Buffer
	ftypLen := make([]byte, 4)
	binary.BigEndian.PutUint32(ftypLen, 8)
	buf.Write(ftypLen)
	buf.WriteString("ftyp")
	buf.Write([]byte{0x00, 0x00, 0x00}) // only 3 bytes, need 8 for a box header

	if err := ValidateMP4(buf.Bytes()); err == nil {
		t.Fatal("expected error for truncated box header")
	}
}

func TestValidateWebP_MissingRIFF(t *testing.T) {
	data := make([]byte, 12)
	copy(data[0:4], "XXXX")
	if err := ValidateWebP(data); err == nil {
		t.Fatal("expected error for missing RIFF header")
	}
}

func TestValidateMP4_LargeBoxSize(t *testing.T) {
	var buf bytes.Buffer
	ftypLen := make([]byte, 4)
	binary.BigEndian.PutUint32(ftypLen, 8)
	buf.Write(ftypLen)
	buf.WriteString("ftyp")
	// Box with size 0xFFFFFFF0 should fail with "box extends beyond file".
	bigLen := make([]byte, 4)
	binary.BigEndian.PutUint32(bigLen, 0xFFFFFFF0)
	buf.Write(bigLen)
	buf.WriteString("moov")

	if err := ValidateMP4(buf.Bytes()); err == nil {
		t.Fatal("expected error for box size exceeding file length")
	}
}

func TestValidateMP4_ExtendedSize64(t *testing.T) {
	// mp4ff rejects 64-bit extended size on ftyp because no real-world MP4
	// file uses largesize for the mandatory ftyp box. ValidateMP4 must return
	// a non-nil error for this malformed input.
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, uint32(1)); err != nil {
		t.Fatal(err)
	}
	buf.WriteString("ftyp")
	if err := binary.Write(&buf, binary.BigEndian, uint64(24)); err != nil {
		t.Fatal(err)
	}
	buf.Write([]byte("isom\x00\x00\x02\x00"))

	if err := binary.Write(&buf, binary.BigEndian, uint32(8)); err != nil {
		t.Fatal(err)
	}
	buf.WriteString("moov")

	// Extended-size ftyp is not valid per mp4ff; expect an error.
	if err := ValidateMP4(buf.Bytes()); err == nil {
		t.Fatal("expected error for MP4 with 64-bit extended ftyp size (not supported)")
	}
}

func TestValidateMP4_ExtendedSizeTruncated(t *testing.T) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, uint32(1)); err != nil {
		t.Fatal(err)
	}
	buf.WriteString("ftyp")
	buf.Write([]byte{0x00, 0x00, 0x00, 0x18}) // only 4 of 8 extended size bytes

	if err := ValidateMP4(buf.Bytes()); err == nil {
		t.Fatal("expected error for truncated 64-bit extended size")
	}
}

func TestValidateMP4_ExtendedSizeTooSmall(t *testing.T) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, uint32(1)); err != nil {
		t.Fatal(err)
	}
	buf.WriteString("ftyp")
	if err := binary.Write(&buf, binary.BigEndian, uint64(8)); err != nil {
		t.Fatal(err)
	}

	if err := ValidateMP4(buf.Bytes()); err == nil {
		t.Fatal("expected error for 64-bit box size too small")
	}
}

func TestValidateWebP_LargeRIFFSize(t *testing.T) {
	data := make([]byte, 20)
	copy(data[0:4], "RIFF")
	binary.LittleEndian.PutUint32(data[4:8], 0xFFFFFFFF)
	copy(data[8:12], "WEBP")

	if err := ValidateWebP(data); err == nil {
		t.Fatal("expected error for WebP with RIFF size exceeding data")
	}
}

// TestValidateMP4_BoxSizeExactlyAtEnd verifies that box size arithmetic is
// correct when the last box's declared size is exactly the remaining buffer
// length. The fail-closed core (SanitizeMP4) requires ftyp+moov+mdat; we
// provide those three boxes and verify no boundary error occurs.
//
// Java oracle: Mp4Sanitizer.java — all three boxes are required.
func TestValidateMP4_BoxSizeExactlyAtEnd(t *testing.T) {
	// ftyp: size=20, major="isom", minor=0, compatible=["isom"]
	var buf bytes.Buffer
	binary.BigEndian.PutUint32(writeBytes(&buf, 4), 20)
	buf.WriteString("ftyp")
	buf.WriteString("isom") // major_brand
	binary.BigEndian.PutUint32(writeBytes(&buf, 4), 0)
	buf.WriteString("isom") // compatible_brand[0]

	// moov: minimal empty moov (8 bytes, size exactly at end of box)
	binary.BigEndian.PutUint32(writeBytes(&buf, 4), 8)
	buf.WriteString("moov")

	// mdat: 8 bytes, size exactly fills the remaining input
	binary.BigEndian.PutUint32(writeBytes(&buf, 4), 8)
	buf.WriteString("mdat")

	if err := ValidateMP4(buf.Bytes()); err != nil {
		t.Fatalf("expected valid MP4, got error: %v", err)
	}
}

// writeBytes appends n zero bytes to buf and returns the slice to write into.
func writeBytes(buf *bytes.Buffer, n int) []byte {
	start := buf.Len()
	buf.Write(make([]byte, n))
	return buf.Bytes()[start : start+n]
}

func TestValidateMP4_InvalidAfterFtyp(t *testing.T) {
	data := []byte{0x00, 0x00, 0x00, 0x08, 'f', 't', 'y', 'p'}
	// Add a truncated box after ftyp
	data = append(data, 0x00, 0x00, 0x00, 0x20)
	data = append(data, 'm', 'd', 'a', 't')
	_, err := Validate(data)
	if err == nil {
		t.Fatal("expected error for truncated MP4 box")
	}
}

func TestValidate_WebP_Invalid(t *testing.T) {
	data := make([]byte, 12)
	copy(data[0:4], "RIFF")
	binary.LittleEndian.PutUint32(data[4:8], 100) // declared size too large
	copy(data[8:12], "WEBP")

	_, err := Validate(data)
	if err == nil {
		t.Fatal("expected error for WebP with declared size exceeding actual")
	}
}

func TestValidateReaderError(t *testing.T) {
	r := &errorReader{}
	_, err := ValidateReader(r)
	if err == nil {
		t.Fatal("expected error from ValidateReader with failing reader")
	}
}

type errorReader struct{}

func (e *errorReader) Read(p []byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}
