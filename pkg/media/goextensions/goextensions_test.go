package goextensions

import (
	"bytes"
	"encoding/binary"
	"errors"
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
			data:     []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10},
			expected: MediaTypeJPEG,
		},
		{
			name:     "PNG",
			data:     []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00},
			expected: MediaTypePNG,
		},
		{
			name:     "GIF87a",
			data:     []byte("GIF87a      "),
			expected: MediaTypeGIF,
		},
		{
			name:     "GIF89a",
			data:     []byte("GIF89a      "),
			expected: MediaTypeGIF,
		},
		{
			name:     "unknown",
			data:     []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			expected: MediaTypeUnknown,
		},
		{
			name:     "too short",
			data:     []byte{0x00, 0x01},
			expected: MediaTypeUnknown,
		},
		{
			name:     "empty",
			data:     []byte{},
			expected: MediaTypeUnknown,
		},
		{
			name:     "JPEG short (3 bytes)",
			data:     []byte{0xFF, 0xD8, 0xFF},
			expected: MediaTypeJPEG,
		},
		{
			name:     "GIF short (6 bytes)",
			data:     []byte("GIF89a"),
			expected: MediaTypeGIF,
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

func TestMediaType_StringAndMIME(t *testing.T) {
	tests := []struct {
		mt   MediaType
		str  string
		mime string
	}{
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

func TestSanitize_JPEG(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0xFF, 0xD8}) // SOI

	// APP1 (EXIF) — should be stripped
	exifData := []byte("Exif\x00\x00test metadata")
	buf.WriteByte(0xFF)
	buf.WriteByte(0xE1)
	exifLen := make([]byte, 2)
	binary.BigEndian.PutUint16(exifLen, uint16(len(exifData)+2))
	buf.Write(exifLen)
	buf.Write(exifData)

	// DQT — should be kept
	dqtData := make([]byte, 64)
	buf.WriteByte(0xFF)
	buf.WriteByte(0xDB)
	dqtLen := make([]byte, 2)
	binary.BigEndian.PutUint16(dqtLen, uint16(len(dqtData)+3))
	buf.Write(dqtLen)
	buf.WriteByte(0x00)
	buf.Write(dqtData)

	// SOS + scan data
	buf.WriteByte(0xFF)
	buf.WriteByte(0xDA)
	sosLen := make([]byte, 2)
	binary.BigEndian.PutUint16(sosLen, 4)
	buf.Write(sosLen)
	buf.Write([]byte{0x00, 0x00, 0x12, 0x34})

	result, err := Sanitize(buf.Bytes())
	if err != nil {
		t.Fatalf("Sanitize(JPEG) failed: %v", err)
	}
	if result.MediaType != MediaTypeJPEG {
		t.Errorf("MediaType = %v, want JPEG", result.MediaType)
	}
	if !result.MetadataStripped {
		t.Error("MetadataStripped should be true for JPEG")
	}
	if bytes.Contains(result.Sanitized, []byte{0xFF, 0xE1}) {
		t.Error("sanitized JPEG should not contain APP1")
	}
	if !bytes.Contains(result.Sanitized, []byte{0xFF, 0xDB}) {
		t.Error("sanitized JPEG should contain DQT")
	}
}

func TestSanitize_PNG(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(pngMagic)

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
	writeChunk("tEXt", []byte("Comment\x00meta"))
	writeChunk("IDAT", []byte{0x08, 0xD7, 0x63, 0x60})
	writeChunk("IEND", nil)

	result, err := Sanitize(buf.Bytes())
	if err != nil {
		t.Fatalf("Sanitize(PNG) failed: %v", err)
	}
	if result.MediaType != MediaTypePNG {
		t.Errorf("MediaType = %v, want PNG", result.MediaType)
	}
	if !result.MetadataStripped {
		t.Error("MetadataStripped should be true for PNG")
	}
	if bytes.Contains(result.Sanitized, []byte("tEXt")) {
		t.Error("sanitized PNG should not contain tEXt")
	}
	if !bytes.Contains(result.Sanitized, []byte("IDAT")) {
		t.Error("sanitized PNG should contain IDAT")
	}
}

func TestSanitize_GIF(t *testing.T) {
	data := make([]byte, 13)
	copy(data, "GIF89a")

	result, err := Sanitize(data)
	if err != nil {
		t.Fatalf("Sanitize(GIF) failed: %v", err)
	}
	if result.MediaType != MediaTypeGIF {
		t.Errorf("MediaType = %v, want GIF", result.MediaType)
	}
	if result.MetadataStripped {
		t.Error("MetadataStripped should be false for GIF (validation only)")
	}
	if !bytes.Equal(result.Sanitized, data) {
		t.Error("GIF sanitization should return data as-is")
	}
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

	t.Run("invalid GIF", func(t *testing.T) {
		_, err := Sanitize([]byte("GIF00a0000000"))
		if err == nil {
			t.Fatal("expected error for invalid GIF")
		}
	})
}

func TestSanitizeJPEG(t *testing.T) {
	t.Run("strips APP2 and APP13", func(t *testing.T) {
		var buf bytes.Buffer
		buf.Write([]byte{0xFF, 0xD8})

		writeMarker := func(marker byte, data []byte) {
			buf.WriteByte(0xFF)
			buf.WriteByte(marker)
			lb := make([]byte, 2)
			binary.BigEndian.PutUint16(lb, uint16(len(data)+2))
			buf.Write(lb)
			buf.Write(data)
		}
		writeMarker(0xE2, []byte("ICC_PROFILE"))
		writeMarker(0xED, []byte("Photoshop 3.0"))
		buf.Write([]byte{0xFF, 0xDA, 0x00, 0x02, 0xAB})

		result, err := SanitizeJPEG(buf.Bytes())
		if err != nil {
			t.Fatalf("SanitizeJPEG: %v", err)
		}
		if bytes.Contains(result, []byte{0xFF, 0xE2}) {
			t.Error("should strip APP2")
		}
		if bytes.Contains(result, []byte{0xFF, 0xED}) {
			t.Error("should strip APP13")
		}
	})

	t.Run("EOI terminates output", func(t *testing.T) {
		var buf bytes.Buffer
		buf.Write([]byte{0xFF, 0xD8, 0xFF, 0xD9}) // SOI + EOI
		buf.Write([]byte{0xAA, 0xBB})             // trailing data

		result, err := SanitizeJPEG(buf.Bytes())
		if err != nil {
			t.Fatalf("SanitizeJPEG: %v", err)
		}
		if !bytes.Contains(result, []byte{0xFF, 0xD9}) {
			t.Error("should contain EOI")
		}
	})

	t.Run("invalid header", func(t *testing.T) {
		_, err := SanitizeJPEG([]byte{0x00, 0x01, 0x02})
		if err != ErrInvalidJPEG {
			t.Errorf("expected ErrInvalidJPEG, got %v", err)
		}
	})

	t.Run("truncated marker length", func(t *testing.T) {
		buf := []byte{0xFF, 0xD8, 0xFF, 0xDB, 0x00} // only 1 byte of 2-byte length
		_, err := SanitizeJPEG(buf)
		if err == nil {
			t.Fatal("expected error for truncated marker length")
		}
	})

	t.Run("invalid marker length", func(t *testing.T) {
		buf := []byte{0xFF, 0xD8, 0xFF, 0xDB, 0x00, 0x01} // length = 1 < 2
		_, err := SanitizeJPEG(buf)
		if err == nil {
			t.Fatal("expected error for invalid marker length")
		}
	})

	t.Run("marker extends beyond data", func(t *testing.T) {
		buf := []byte{0xFF, 0xD8, 0xFF, 0xDB, 0x00, 0xFF} // length = 255, data too short
		_, err := SanitizeJPEG(buf)
		if err == nil {
			t.Fatal("expected error for marker extending beyond data")
		}
	})

	t.Run("byte stuffing preserved", func(t *testing.T) {
		buf := []byte{0xFF, 0xD8, 0xFF, 0x00}
		result, err := SanitizeJPEG(buf)
		if err != nil {
			t.Fatalf("SanitizeJPEG: %v", err)
		}
		if !bytes.Contains(result, []byte{0xFF, 0x00}) {
			t.Error("byte stuffing should be preserved")
		}
	})

	t.Run("non-marker byte copies rest", func(t *testing.T) {
		// After APP0 (stripped), encounter a non-0xFF byte
		var buf bytes.Buffer
		buf.Write([]byte{0xFF, 0xD8})
		buf.WriteByte(0xFF)
		buf.WriteByte(0xE0) // APP0
		app0Len := make([]byte, 2)
		binary.BigEndian.PutUint16(app0Len, 4)
		buf.Write(app0Len)
		buf.Write([]byte{0x00, 0x00})
		buf.Write([]byte{0x12, 0x34}) // non-marker data

		result, err := SanitizeJPEG(buf.Bytes())
		if err != nil {
			t.Fatalf("SanitizeJPEG: %v", err)
		}
		if !bytes.Contains(result, []byte{0x12, 0x34}) {
			t.Error("non-marker data should be copied")
		}
	})
}

func TestSanitizePNG_Errors(t *testing.T) {
	t.Run("invalid header", func(t *testing.T) {
		_, err := SanitizePNG([]byte{0x00, 0x01, 0x02, 0x03})
		if err != ErrInvalidPNG {
			t.Errorf("expected ErrInvalidPNG, got %v", err)
		}
	})

	t.Run("chunk extends beyond data", func(t *testing.T) {
		var buf bytes.Buffer
		buf.Write(pngMagic)
		lb := make([]byte, 4)
		binary.BigEndian.PutUint32(lb, 9999)
		buf.Write(lb)
		buf.WriteString("IHDR")
		buf.Write([]byte{0x00, 0x00, 0x00, 0x00})

		_, err := SanitizePNG(buf.Bytes())
		if err == nil {
			t.Fatal("expected error for chunk extending beyond data")
		}
	})

	t.Run("strips all metadata chunk types", func(t *testing.T) {
		var buf bytes.Buffer
		buf.Write(pngMagic)

		writeChunk := func(chunkType string, data []byte) {
			lb := make([]byte, 4)
			binary.BigEndian.PutUint32(lb, uint32(len(data)))
			buf.Write(lb)
			buf.WriteString(chunkType)
			buf.Write(data)
			buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
		}

		ihdr := make([]byte, 13)
		writeChunk("IHDR", ihdr)
		writeChunk("eXIf", []byte("exif"))
		writeChunk("iCCP", []byte("icc"))
		writeChunk("zTXt", []byte("ztxt"))
		writeChunk("iTXt", []byte("itxt"))
		writeChunk("tIME", []byte{0x07, 0xE8, 0x01, 0x01, 0x00, 0x00, 0x00})
		writeChunk("IDAT", []byte{0x08, 0xD7})
		writeChunk("IEND", nil)

		result, err := SanitizePNG(buf.Bytes())
		if err != nil {
			t.Fatalf("SanitizePNG: %v", err)
		}
		for _, strip := range []string{"eXIf", "iCCP", "zTXt", "iTXt", "tIME"} {
			if bytes.Contains(result, []byte(strip)) {
				t.Errorf("should strip %s chunk", strip)
			}
		}
		if !bytes.Contains(result, []byte("IHDR")) {
			t.Error("should keep IHDR")
		}
		if !bytes.Contains(result, []byte("IDAT")) {
			t.Error("should keep IDAT")
		}
	})
}

func TestValidateGIF(t *testing.T) {
	t.Run("valid GIF87a", func(t *testing.T) {
		data := make([]byte, 13)
		copy(data, "GIF87a")
		if err := ValidateGIF(data); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("valid GIF89a", func(t *testing.T) {
		data := make([]byte, 13)
		copy(data, "GIF89a")
		if err := ValidateGIF(data); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("too short", func(t *testing.T) {
		if err := ValidateGIF([]byte("GIF")); err != ErrInvalidGIF {
			t.Errorf("expected ErrInvalidGIF, got %v", err)
		}
	})

	t.Run("invalid header", func(t *testing.T) {
		if err := ValidateGIF([]byte("GIF00a0000000")); err == nil {
			t.Fatal("expected error for invalid GIF header")
		}
	})

	t.Run("too short for LSD", func(t *testing.T) {
		if err := ValidateGIF([]byte("GIF89a1234")); err == nil {
			t.Fatal("expected error: too short for logical screen descriptor")
		}
	})
}

func TestErrorTypes(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"ErrInvalidJPEGError", &ErrInvalidJPEGError{}, "goextensions: invalid JPEG structure"},
		{"ErrInvalidPNGError", &ErrInvalidPNGError{}, "goextensions: invalid PNG structure"},
		{"ErrInvalidGIFError", &ErrInvalidGIFError{}, "goextensions: invalid GIF structure"},
		{"ErrUnsupportedMediaTypeError", &ErrUnsupportedMediaTypeError{}, "goextensions: unsupported or unrecognized media type"},
		{"ErrDataTooShortError", &ErrDataTooShortError{}, "goextensions: data too short for media detection"},
		{"MediaValidationError", &MediaValidationError{Detail: "test detail"}, "goextensions: test detail"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.want {
				t.Errorf("Error() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSentinelErrorIdentity(t *testing.T) {
	t.Run("ErrInvalidJPEG", func(t *testing.T) {
		var target *ErrInvalidJPEGError
		if !errors.As(ErrInvalidJPEG, &target) {
			t.Error("ErrInvalidJPEG should be *ErrInvalidJPEGError")
		}
	})
	t.Run("ErrInvalidPNG", func(t *testing.T) {
		var target *ErrInvalidPNGError
		if !errors.As(ErrInvalidPNG, &target) {
			t.Error("ErrInvalidPNG should be *ErrInvalidPNGError")
		}
	})
	t.Run("ErrInvalidGIF", func(t *testing.T) {
		var target *ErrInvalidGIFError
		if !errors.As(ErrInvalidGIF, &target) {
			t.Error("ErrInvalidGIF should be *ErrInvalidGIFError")
		}
	})
}
