package media

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestDetectMediaType(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected MediaType
	}{
		{
			name:     "JPEG",
			data:     []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00, 0x01},
			expected: MediaTypeJPEG,
		},
		{
			name:     "PNG",
			data:     []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D},
			expected: MediaTypePNG,
		},
		{
			name:     "GIF87a",
			data:     []byte("GIF87a" + "      "),
			expected: MediaTypeGIF,
		},
		{
			name:     "GIF89a",
			data:     []byte("GIF89a" + "      "),
			expected: MediaTypeGIF,
		},
		{
			name:     "WebP",
			data:     append([]byte("RIFF"), append([]byte{0x00, 0x00, 0x00, 0x00}, []byte("WEBP")...)...),
			expected: MediaTypeWebP,
		},
		{
			name:     "MP4",
			data:     []byte{0x00, 0x00, 0x00, 0x20, 'f', 't', 'y', 'p', 'i', 's', 'o', 'm'},
			expected: MediaTypeMP4,
		},
		{
			name:     "Unknown",
			data:     []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B},
			expected: MediaTypeUnknown,
		},
		{
			name:     "TooShort",
			data:     []byte{0x00},
			expected: MediaTypeUnknown,
		},
		{
			name:     "Empty",
			data:     []byte{},
			expected: MediaTypeUnknown,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectMediaType(tc.data)
			if got != tc.expected {
				t.Errorf("DetectMediaType() = %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestMediaTypeString(t *testing.T) {
	tests := []struct {
		mt   MediaType
		str  string
		mime string
	}{
		{MediaTypeMP4, "MP4", "video/mp4"},
		{MediaTypeWebP, "WebP", "image/webp"},
		{MediaTypeJPEG, "JPEG", "image/jpeg"},
		{MediaTypePNG, "PNG", "image/png"},
		{MediaTypeGIF, "GIF", "image/gif"},
		{MediaTypeUnknown, "Unknown", "application/octet-stream"},
	}

	for _, tc := range tests {
		t.Run(tc.str, func(t *testing.T) {
			if got := tc.mt.String(); got != tc.str {
				t.Errorf("String() = %q, want %q", got, tc.str)
			}
			if got := tc.mt.MIMEType(); got != tc.mime {
				t.Errorf("MIMEType() = %q, want %q", got, tc.mime)
			}
		})
	}
}

func TestSanitizeJPEG(t *testing.T) {
	// Build a minimal JPEG with SOI, APP1 (EXIF), DQT, and SOS markers.
	var buf bytes.Buffer

	// SOI
	buf.Write([]byte{0xFF, 0xD8})

	// APP1 (EXIF) - should be stripped
	exifData := []byte("Exif\x00\x00test metadata that should be stripped")
	buf.WriteByte(0xFF)
	buf.WriteByte(0xE1)
	exifLen := make([]byte, 2)
	binary.BigEndian.PutUint16(exifLen, uint16(len(exifData)+2))
	buf.Write(exifLen)
	buf.Write(exifData)

	// COM (comment) - should be stripped
	comment := []byte("This is a comment")
	buf.WriteByte(0xFF)
	buf.WriteByte(0xFE)
	comLen := make([]byte, 2)
	binary.BigEndian.PutUint16(comLen, uint16(len(comment)+2))
	buf.Write(comLen)
	buf.Write(comment)

	// DQT marker - should be kept
	dqtData := make([]byte, 64)
	buf.WriteByte(0xFF)
	buf.WriteByte(0xDB)
	dqtLen := make([]byte, 2)
	binary.BigEndian.PutUint16(dqtLen, uint16(len(dqtData)+2+1)) // +1 for table spec byte
	buf.Write(dqtLen)
	buf.WriteByte(0x00) // table spec
	buf.Write(dqtData)

	// SOS marker followed by scan data
	buf.WriteByte(0xFF)
	buf.WriteByte(0xDA)
	sosLen := make([]byte, 2)
	binary.BigEndian.PutUint16(sosLen, 2+1+1) // minimal SOS
	buf.Write(sosLen)
	buf.WriteByte(0x00) // component count
	buf.WriteByte(0x00) // dummy
	buf.Write([]byte{0x12, 0x34, 0x56}) // scan data

	result, err := Sanitize(buf.Bytes())
	if err != nil {
		t.Fatalf("Sanitize failed: %v", err)
	}

	if result.MediaType != MediaTypeJPEG {
		t.Errorf("MediaType = %v, want JPEG", result.MediaType)
	}

	if !result.MetadataStripped {
		t.Error("JPEG MetadataStripped should be true")
	}

	// The sanitized data should be smaller (EXIF and comment stripped).
	if int64(len(result.Sanitized)) >= result.OriginalSize {
		t.Errorf("sanitized size (%d) should be smaller than original (%d)",
			len(result.Sanitized), result.OriginalSize)
	}

	// The sanitized data should still start with SOI.
	if !bytes.HasPrefix(result.Sanitized, []byte{0xFF, 0xD8}) {
		t.Error("sanitized JPEG should start with SOI marker")
	}

	// Should not contain APP1 marker.
	if bytes.Contains(result.Sanitized, []byte{0xFF, 0xE1}) {
		t.Error("sanitized JPEG should not contain APP1 (EXIF)")
	}

	// Should not contain COM marker.
	if bytes.Contains(result.Sanitized, []byte{0xFF, 0xFE}) {
		t.Error("sanitized JPEG should not contain COM (comment)")
	}

	// Should contain DQT marker.
	if !bytes.Contains(result.Sanitized, []byte{0xFF, 0xDB}) {
		t.Error("sanitized JPEG should contain DQT marker")
	}
}

func TestSanitizePNG(t *testing.T) {
	// Build a minimal PNG with IHDR, tEXt (metadata), IDAT, and IEND.
	var buf bytes.Buffer

	// PNG signature
	buf.Write([]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A})

	writeChunk := func(chunkType string, data []byte) {
		lenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))
		buf.Write(lenBuf)
		buf.WriteString(chunkType)
		buf.Write(data)
		// CRC (dummy - we don't validate CRC in sanitization)
		buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	}

	// IHDR (13 bytes minimum)
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:4], 1)  // width
	binary.BigEndian.PutUint32(ihdr[4:8], 1)  // height
	ihdr[8] = 8                                // bit depth
	ihdr[9] = 2                                // color type (RGB)
	writeChunk("IHDR", ihdr)

	// tEXt (metadata - should be stripped)
	writeChunk("tEXt", []byte("Comment\x00Test metadata"))

	// IDAT (image data - should be kept)
	writeChunk("IDAT", []byte{0x08, 0xD7, 0x63, 0x60, 0x60, 0x60, 0x00, 0x00})

	// tIME (time - should be stripped)
	writeChunk("tIME", []byte{0x07, 0xE8, 0x01, 0x01, 0x00, 0x00, 0x00})

	// IEND
	writeChunk("IEND", nil)

	result, err := Sanitize(buf.Bytes())
	if err != nil {
		t.Fatalf("Sanitize failed: %v", err)
	}

	if result.MediaType != MediaTypePNG {
		t.Errorf("MediaType = %v, want PNG", result.MediaType)
	}

	if !result.MetadataStripped {
		t.Error("PNG MetadataStripped should be true")
	}

	// Should be smaller (tEXt and tIME stripped).
	if int64(len(result.Sanitized)) >= result.OriginalSize {
		t.Errorf("sanitized size (%d) should be smaller than original (%d)",
			len(result.Sanitized), result.OriginalSize)
	}

	// Should still have PNG signature.
	if !bytes.HasPrefix(result.Sanitized, pngMagic) {
		t.Error("sanitized PNG should start with PNG signature")
	}

	// Should contain IHDR, IDAT, IEND but not tEXt or tIME.
	if bytes.Contains(result.Sanitized, []byte("tEXt")) {
		t.Error("sanitized PNG should not contain tEXt chunk")
	}
	if bytes.Contains(result.Sanitized, []byte("tIME")) {
		t.Error("sanitized PNG should not contain tIME chunk")
	}
	if !bytes.Contains(result.Sanitized, []byte("IHDR")) {
		t.Error("sanitized PNG should contain IHDR chunk")
	}
	if !bytes.Contains(result.Sanitized, []byte("IDAT")) {
		t.Error("sanitized PNG should contain IDAT chunk")
	}
}

func TestValidateMP4(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		// Build a minimal valid MP4 with ftyp and mdat boxes.
		var buf bytes.Buffer

		// ftyp box
		ftypData := []byte("isom\x00\x00\x02\x00isomavc1")
		ftypLen := make([]byte, 4)
		binary.BigEndian.PutUint32(ftypLen, uint32(8+len(ftypData)))
		buf.Write(ftypLen)
		buf.WriteString("ftyp")
		buf.Write(ftypData)

		// mdat box (size 0 = extends to EOF)
		buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
		buf.WriteString("mdat")

		err := ValidateMP4(buf.Bytes())
		if err != nil {
			t.Errorf("ValidateMP4() returned error for valid MP4: %v", err)
		}
	})

	t.Run("missing ftyp", func(t *testing.T) {
		data := []byte{0x00, 0x00, 0x00, 0x08, 'm', 'd', 'a', 't'}
		err := ValidateMP4(data)
		if err == nil {
			t.Error("ValidateMP4() should fail without ftyp box")
		}
	})

	t.Run("too short", func(t *testing.T) {
		err := ValidateMP4([]byte{0x00, 0x01})
		if err == nil {
			t.Error("ValidateMP4() should fail for short data")
		}
	})
}

func TestValidateWebP(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		data := make([]byte, 20)
		copy(data[0:4], "RIFF")
		binary.LittleEndian.PutUint32(data[4:8], 12) // file size - 8
		copy(data[8:12], "WEBP")
		copy(data[12:16], "VP8 ")
		binary.LittleEndian.PutUint32(data[16:20], 0)

		err := ValidateWebP(data)
		if err != nil {
			t.Errorf("ValidateWebP() returned error for valid WebP: %v", err)
		}
	})

	t.Run("missing WEBP", func(t *testing.T) {
		data := make([]byte, 12)
		copy(data[0:4], "RIFF")
		binary.LittleEndian.PutUint32(data[4:8], 4)
		copy(data[8:12], "XXXX")

		err := ValidateWebP(data)
		if err == nil {
			t.Error("ValidateWebP() should fail without WEBP signature")
		}
	})

	t.Run("too short", func(t *testing.T) {
		err := ValidateWebP([]byte("RIFF"))
		if err == nil {
			t.Error("ValidateWebP() should fail for short data")
		}
	})
}

func TestValidateGIF(t *testing.T) {
	t.Run("GIF87a", func(t *testing.T) {
		data := make([]byte, 13)
		copy(data, "GIF87a")
		err := ValidateGIF(data)
		if err != nil {
			t.Errorf("ValidateGIF() returned error for valid GIF87a: %v", err)
		}
	})

	t.Run("GIF89a", func(t *testing.T) {
		data := make([]byte, 13)
		copy(data, "GIF89a")
		err := ValidateGIF(data)
		if err != nil {
			t.Errorf("ValidateGIF() returned error for valid GIF89a: %v", err)
		}
	})

	t.Run("invalid header", func(t *testing.T) {
		err := ValidateGIF([]byte("GIF00a0000000"))
		if err == nil {
			t.Error("ValidateGIF() should fail for invalid header")
		}
	})

	t.Run("too short", func(t *testing.T) {
		err := ValidateGIF([]byte("GIF"))
		if err == nil {
			t.Error("ValidateGIF() should fail for short data")
		}
	})
}

func TestSanitize_Errors(t *testing.T) {
	t.Run("too short", func(t *testing.T) {
		_, err := Sanitize([]byte{0x00})
		if err != ErrDataTooShort {
			t.Errorf("expected ErrDataTooShort, got %v", err)
		}
	})

	t.Run("unknown type", func(t *testing.T) {
		_, err := Sanitize(make([]byte, 20))
		if err != ErrUnsupportedMediaType {
			t.Errorf("expected ErrUnsupportedMediaType, got %v", err)
		}
	})
}

func TestSanitizeReader(t *testing.T) {
	// Build a minimal JPEG.
	var buf bytes.Buffer
	buf.Write([]byte{0xFF, 0xD8}) // SOI
	buf.WriteByte(0xFF)
	buf.WriteByte(0xDA) // SOS
	buf.Write([]byte{0x00, 0x02}) // length = 2 (minimal)
	buf.Write([]byte{0x12, 0x34}) // scan data

	result, err := SanitizeReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("SanitizeReader failed: %v", err)
	}

	if result.MediaType != MediaTypeJPEG {
		t.Errorf("MediaType = %v, want JPEG", result.MediaType)
	}
}
