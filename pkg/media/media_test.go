package media

import (
	"bytes"
	"encoding/binary"
	"testing"

	mp4 "github.com/Eyevinn/mp4ff/mp4"
)

func TestDetectMediaType(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected MediaType
	}{
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

func TestValidateMP4(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		// Use mp4ff to build a well-formed MP4 that DecodeFile accepts.
		ftyp := mp4.NewFtyp("isom", 0x200, []string{"isom", "avc1"})
		moov := mp4.NewMoovBox()
		moov.AddChild(mp4.CreateMvhd())

		var buf bytes.Buffer
		if err := ftyp.Encode(&buf); err != nil {
			t.Fatalf("ftyp encode: %v", err)
		}
		if err := moov.Encode(&buf); err != nil {
			t.Fatalf("moov encode: %v", err)
		}
		// Minimal mdat with explicit size.
		payload := []byte{0xAB, 0xCD}
		mdatSize := uint32(8 + len(payload))
		mdatRaw := make([]byte, mdatSize)
		binary.BigEndian.PutUint32(mdatRaw[0:4], mdatSize)
		copy(mdatRaw[4:8], "mdat")
		copy(mdatRaw[8:], payload)
		buf.Write(mdatRaw)

		if err := ValidateMP4(buf.Bytes()); err != nil {
			t.Errorf("ValidateMP4() returned error for valid MP4: %v", err)
		}
	})

	t.Run("missing ftyp", func(t *testing.T) {
		data := []byte{0x00, 0x00, 0x00, 0x08, 'm', 'd', 'a', 't'}
		if err := ValidateMP4(data); err == nil {
			t.Error("ValidateMP4() should fail without ftyp box")
		}
	})

	t.Run("too short", func(t *testing.T) {
		if err := ValidateMP4([]byte{0x00, 0x01}); err == nil {
			t.Error("ValidateMP4() should fail for short data")
		}
	})
}

func TestValidateWebP(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		data := make([]byte, 20)
		copy(data[0:4], "RIFF")
		binary.LittleEndian.PutUint32(data[4:8], 12)
		copy(data[8:12], "WEBP")
		copy(data[12:16], "VP8 ")
		binary.LittleEndian.PutUint32(data[16:20], 0)

		if err := ValidateWebP(data); err != nil {
			t.Errorf("ValidateWebP() returned error for valid WebP: %v", err)
		}
	})

	t.Run("missing WEBP", func(t *testing.T) {
		data := make([]byte, 12)
		copy(data[0:4], "RIFF")
		binary.LittleEndian.PutUint32(data[4:8], 4)
		copy(data[8:12], "XXXX")

		if err := ValidateWebP(data); err == nil {
			t.Error("ValidateWebP() should fail without WEBP signature")
		}
	})

	t.Run("too short", func(t *testing.T) {
		if err := ValidateWebP([]byte("RIFF")); err == nil {
			t.Error("ValidateWebP() should fail for short data")
		}
	})
}

func TestValidate_Errors(t *testing.T) {
	t.Run("too short", func(t *testing.T) {
		_, err := Validate([]byte{0x00})
		if err != ErrDataTooShort {
			t.Errorf("expected ErrDataTooShort, got %v", err)
		}
	})

	t.Run("unknown type", func(t *testing.T) {
		_, err := Validate(make([]byte, 20))
		if err != ErrUnsupportedMediaType {
			t.Errorf("expected ErrUnsupportedMediaType, got %v", err)
		}
	})
}

func TestValidate_MP4(t *testing.T) {
	// Build a well-formed MP4 (moov before mdat = no relocation needed).
	ftyp := mp4.NewFtyp("isom", 0x200, []string{"isom", "avc1"})
	moov := mp4.NewMoovBox()
	moov.AddChild(mp4.CreateMvhd())

	var buf bytes.Buffer
	if err := ftyp.Encode(&buf); err != nil {
		t.Fatalf("ftyp encode: %v", err)
	}
	if err := moov.Encode(&buf); err != nil {
		t.Fatalf("moov encode: %v", err)
	}
	payload := []byte{0x01, 0x02}
	mdatSize := uint32(8 + len(payload))
	mdatRaw := make([]byte, mdatSize)
	binary.BigEndian.PutUint32(mdatRaw[0:4], mdatSize)
	copy(mdatRaw[4:8], "mdat")
	copy(mdatRaw[8:], payload)
	buf.Write(mdatRaw)
	input := buf.Bytes()

	result, err := Validate(input)
	if err != nil {
		t.Fatalf("Validate(MP4) failed: %v", err)
	}
	if result.MediaType != MediaTypeMP4 {
		t.Errorf("MediaType = %v, want MP4", result.MediaType)
	}
	// moov precedes mdat in this fixture → no relocation → MetadataStripped=false.
	if result.MetadataStripped {
		t.Error("MetadataStripped should be false: moov was already before mdat")
	}
	if len(result.Validated) == 0 {
		t.Error("Validated data must be non-empty")
	}
}

func TestValidate_WebP(t *testing.T) {
	data := make([]byte, 20)
	copy(data[0:4], "RIFF")
	binary.LittleEndian.PutUint32(data[4:8], 12)
	copy(data[8:12], "WEBP")
	copy(data[12:16], "VP8 ")
	binary.LittleEndian.PutUint32(data[16:20], 0)

	result, err := Validate(data)
	if err != nil {
		t.Fatalf("Validate(WebP) failed: %v", err)
	}
	if result.MediaType != MediaTypeWebP {
		t.Errorf("MediaType = %v, want WebP", result.MediaType)
	}
	if result.MetadataStripped {
		t.Error("MetadataStripped should be false for WebP")
	}
}

func TestSanitize_BackwardCompat(t *testing.T) {
	// Sanitize is a deprecated wrapper around Validate; verify it still works.
	data := make([]byte, 20)
	copy(data[0:4], "RIFF")
	binary.LittleEndian.PutUint32(data[4:8], 12)
	copy(data[8:12], "WEBP")
	copy(data[12:16], "VP8 ")
	binary.LittleEndian.PutUint32(data[16:20], 0)

	result, err := Sanitize(data)
	if err != nil {
		t.Fatalf("Sanitize failed: %v", err)
	}
	if result.MetadataStripped {
		t.Error("Sanitize should always set MetadataStripped=false")
	}
	if result.MediaType != MediaTypeWebP {
		t.Errorf("MediaType = %v, want WebP", result.MediaType)
	}
}

func TestValidateReader(t *testing.T) {
	data := make([]byte, 20)
	copy(data[0:4], "RIFF")
	binary.LittleEndian.PutUint32(data[4:8], 12)
	copy(data[8:12], "WEBP")
	copy(data[12:16], "VP8 ")
	binary.LittleEndian.PutUint32(data[16:20], 0)

	result, err := ValidateReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ValidateReader failed: %v", err)
	}
	if result.MediaType != MediaTypeWebP {
		t.Errorf("MediaType = %v, want WebP", result.MediaType)
	}
}

func TestSanitizeReader_BackwardCompat(t *testing.T) {
	data := make([]byte, 20)
	copy(data[0:4], "RIFF")
	binary.LittleEndian.PutUint32(data[4:8], 12)
	copy(data[8:12], "WEBP")
	copy(data[12:16], "VP8 ")
	binary.LittleEndian.PutUint32(data[16:20], 0)

	result, err := SanitizeReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("SanitizeReader failed: %v", err)
	}
	if result.MediaType != MediaTypeWebP {
		t.Errorf("MediaType = %v, want WebP", result.MediaType)
	}
}
