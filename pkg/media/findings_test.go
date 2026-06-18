package media

import (
	"bytes"
	"reflect"
	"testing"
)

// TestDetectMediaType_JPEG verifies that DetectMediaType returns the deprecated
// MediaTypeJPEG constant for data beginning with the JPEG magic bytes.
func TestDetectMediaType_JPEG(t *testing.T) {
	data := buildMinimalJPEG()
	got := DetectMediaType(data)
	if got != MediaTypeJPEG {
		t.Errorf("DetectMediaType(JPEG) = %v (%d), want MediaTypeJPEG (%d)", got, got, MediaTypeJPEG)
	}
}

// TestDetectMediaType_PNG verifies that DetectMediaType returns the deprecated
// MediaTypePNG constant for data beginning with the PNG signature.
func TestDetectMediaType_PNG(t *testing.T) {
	data := buildMinimalPNG()
	got := DetectMediaType(data)
	if got != MediaTypePNG {
		t.Errorf("DetectMediaType(PNG) = %v (%d), want MediaTypePNG (%d)", got, got, MediaTypePNG)
	}
}

// TestDetectMediaType_GIF verifies that DetectMediaType returns the deprecated
// MediaTypeGIF constant for data beginning with a GIF signature.
func TestDetectMediaType_GIF(t *testing.T) {
	data := buildMinimalGIF()
	got := DetectMediaType(data)
	if got != MediaTypeGIF {
		t.Errorf("DetectMediaType(GIF) = %v (%d), want MediaTypeGIF (%d)", got, got, MediaTypeGIF)
	}
}

// TestDetectMediaType_GIF87a verifies that DetectMediaType recognises GIF87a
// in addition to GIF89a.
func TestDetectMediaType_GIF87a(t *testing.T) {
	data := make([]byte, 13)
	copy(data, "GIF87a")
	got := DetectMediaType(data)
	if got != MediaTypeGIF {
		t.Errorf("DetectMediaType(GIF87a) = %v, want MediaTypeGIF", got)
	}
}

// TestDetectMediaType_MP4 verifies that DetectMediaType still returns
// MediaTypeMP4 for MP4 data (regression guard for Finding 2).
func TestDetectMediaType_MP4(t *testing.T) {
	data := buildMinimalMP4()
	got := DetectMediaType(data)
	if got != MediaTypeMP4 {
		t.Errorf("DetectMediaType(MP4) = %v, want MediaTypeMP4", got)
	}
}

// TestDetectMediaType_WebP verifies that DetectMediaType still returns
// MediaTypeWebP for WebP data (regression guard for Finding 2).
func TestDetectMediaType_WebP(t *testing.T) {
	data := buildMinimalWebP()
	got := DetectMediaType(data)
	if got != MediaTypeWebP {
		t.Errorf("DetectMediaType(WebP) = %v, want MediaTypeWebP", got)
	}
}

// TestSanitizeResult_Sanitized_FieldPresent verifies via reflection that
// SanitizeResult has a public field named "Sanitized" of type []byte.
// This guards against the type-alias regression (Finding 1) where the field
// was named "Validated" instead.
func TestSanitizeResult_Sanitized_FieldPresent(t *testing.T) {
	rt := reflect.TypeOf(SanitizeResult{})
	field, ok := rt.FieldByName("Sanitized")
	if !ok {
		t.Fatal("SanitizeResult is missing the 'Sanitized' field; callers using result.Sanitized will fail to compile")
	}
	if field.Type != reflect.TypeOf([]byte{}) {
		t.Errorf("SanitizeResult.Sanitized has type %v, want []byte", field.Type)
	}
}

// TestSanitize_ReturnsSanitizeResultNotValidateResult verifies that Sanitize
// returns *SanitizeResult and that the .Sanitized field is accessible without
// a type assertion. This is a compile-time regression guard for Finding 1.
func TestSanitize_ReturnsSanitizeResultNotValidateResult(t *testing.T) {
	data := buildMinimalWebP()
	result, err := Sanitize(data)
	if err != nil {
		t.Fatalf("Sanitize(WebP) returned unexpected error: %v", err)
	}
	// Direct field access — fails to compile if SanitizeResult is an alias for
	// ValidateResult (which has Validated, not Sanitized).
	_ = result.Sanitized
	if len(result.Sanitized) == 0 {
		t.Error("SanitizeResult.Sanitized must be non-empty for valid WebP input")
	}
}

// TestSanitize_JPEG_SanitizedField verifies that Sanitize populates the
// Sanitized field (not Validated) for JPEG input.
func TestSanitize_JPEG_SanitizedField(t *testing.T) {
	data := buildMinimalJPEG()
	result, err := Sanitize(data)
	if err != nil {
		t.Fatalf("Sanitize(JPEG) returned unexpected error: %v", err)
	}
	if len(result.Sanitized) == 0 {
		t.Error("SanitizeResult.Sanitized must be non-empty for JPEG")
	}
	// Verify EXIF was stripped — APP1 (0xFF 0xE1) should not be present.
	if bytes.Contains(result.Sanitized, []byte{0xFF, 0xE1}) {
		t.Error("Sanitized JPEG should not contain APP1 (EXIF) marker")
	}
}
