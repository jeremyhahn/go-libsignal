package media

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	mp4 "github.com/Eyevinn/mp4ff/mp4"
)

// TestErrorMethods verifies that each typed error's Error() method returns
// the expected message string.
func TestErrorMethods(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "ErrUnsupportedMediaTypeError",
			err:  &ErrUnsupportedMediaTypeError{},
			want: "media: unsupported or unrecognized media type",
		},
		{
			name: "ErrDataTooShortError",
			err:  &ErrDataTooShortError{},
			want: "media: data too short for media detection",
		},
		{
			name: "ErrInvalidMP4Error",
			err:  &ErrInvalidMP4Error{},
			want: "media: invalid MP4 structure",
		},
		{
			name: "ErrInvalidWebPError",
			err:  &ErrInvalidWebPError{},
			want: "media: invalid WebP structure",
		},
		{
			name: "ErrMediaTooLarge",
			err:  &ErrMediaTooLarge{Size: 104857601},
			want: "media: input exceeds maximum allowed size",
		},
		{
			name: "ErrMediaTooLarge unknown size",
			err:  &ErrMediaTooLarge{Size: -1},
			want: "media: input exceeds maximum allowed size",
		},
		{
			name: "MediaValidationError",
			err:  &MediaValidationError{Detail: "test detail"},
			want: "media: test detail",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.err.Error()
			if got != tc.want {
				t.Errorf("Error() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSentinelErrorIdentity verifies that the sentinel error variables point
// to the correct typed error instances and that errors.As correctly identifies
// them.
func TestSentinelErrorIdentity(t *testing.T) {
	t.Run("ErrUnsupportedMediaType", func(t *testing.T) {
		var target *ErrUnsupportedMediaTypeError
		if !errors.As(ErrUnsupportedMediaType, &target) {
			t.Error("ErrUnsupportedMediaType should be *ErrUnsupportedMediaTypeError")
		}
	})

	t.Run("ErrDataTooShort", func(t *testing.T) {
		var target *ErrDataTooShortError
		if !errors.As(ErrDataTooShort, &target) {
			t.Error("ErrDataTooShort should be *ErrDataTooShortError")
		}
	})

	t.Run("ErrInvalidMP4", func(t *testing.T) {
		var target *ErrInvalidMP4Error
		if !errors.As(ErrInvalidMP4, &target) {
			t.Error("ErrInvalidMP4 should be *ErrInvalidMP4Error")
		}
	})

	t.Run("ErrInvalidWebP", func(t *testing.T) {
		var target *ErrInvalidWebPError
		if !errors.As(ErrInvalidWebP, &target) {
			t.Error("ErrInvalidWebP should be *ErrInvalidWebPError")
		}
	})
}

// largeFakeReader provides exactly n bytes of zeroes without allocating them.
type largeFakeReader struct {
	remaining int
}

func (r *largeFakeReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if n > r.remaining {
		n = r.remaining
	}
	for i := range p[:n] {
		p[i] = 0
	}
	r.remaining -= n
	return n, nil
}

// TestValidateReader_ExceedsMaxSize verifies that ValidateReader returns
// ErrMediaTooLarge when the input stream exceeds 100 MiB.
func TestValidateReader_ExceedsMaxSize(t *testing.T) {
	r := &largeFakeReader{remaining: maxMediaSize + 1}

	_, err := ValidateReader(r)
	if err == nil {
		t.Fatal("expected ErrMediaTooLarge for oversized input, got nil")
	}

	var tooLarge *ErrMediaTooLarge
	if !errors.As(err, &tooLarge) {
		t.Fatalf("expected *ErrMediaTooLarge, got %T: %v", err, err)
	}

	if tooLarge.Size != maxMediaSize+1 {
		t.Errorf("ErrMediaTooLarge.Size = %d, want %d", tooLarge.Size, maxMediaSize+1)
	}
}

// limitedZeroReader returns exactly limit zero bytes then stops.
type limitedZeroReader struct {
	limit int
	read  int
}

func (r *limitedZeroReader) Read(p []byte) (int, error) {
	if r.read >= r.limit {
		return 0, io.EOF
	}
	n := len(p)
	if r.read+n > r.limit {
		n = r.limit - r.read
	}
	for i := range p[:n] {
		p[i] = 0
	}
	r.read += n
	return n, nil
}

// TestValidateReader_ExactlyAtLimit verifies that ValidateReader accepts input
// that is exactly at the 100 MiB limit (it will fail as unsupported type, not
// as too large).
func TestValidateReader_ExactlyAtLimit(t *testing.T) {
	exactReader := &limitedZeroReader{limit: maxMediaSize}
	_, err := ValidateReader(exactReader)

	var tooLarge *ErrMediaTooLarge
	if errors.As(err, &tooLarge) {
		t.Errorf("input at exactly maxMediaSize should not return ErrMediaTooLarge, got size=%d", tooLarge.Size)
	}
}

// TestSanitizeReader_ExceedsMaxSize verifies backward-compat SanitizeReader
// also returns ErrMediaTooLarge when oversized.
func TestSanitizeReader_ExceedsMaxSize(t *testing.T) {
	r := &largeFakeReader{remaining: maxMediaSize + 1}

	_, err := SanitizeReader(r)
	if err == nil {
		t.Fatal("expected ErrMediaTooLarge, got nil")
	}

	var tooLarge *ErrMediaTooLarge
	if !errors.As(err, &tooLarge) {
		t.Fatalf("expected *ErrMediaTooLarge, got %T: %v", err, err)
	}
}

func TestValidate_MP4_ValidFull(t *testing.T) {
	// Build a well-formed MP4 using mp4ff (moov before mdat).
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
	payload := []byte{0xDE, 0xAD}
	mdatSize := uint32(8 + len(payload))
	mdatRaw := make([]byte, mdatSize)
	binary.BigEndian.PutUint32(mdatRaw[0:4], mdatSize)
	copy(mdatRaw[4:8], "mdat")
	copy(mdatRaw[8:], payload)
	buf.Write(mdatRaw)
	input := buf.Bytes()

	result, err := Validate(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.OriginalSize != int64(len(input)) {
		t.Errorf("OriginalSize = %d, want %d", result.OriginalSize, len(input))
	}
	if len(result.Validated) == 0 {
		t.Error("Validated data must be non-empty")
	}
}

// TestMediaTypeString_AllVariants covers the JPEG/PNG/GIF/Unknown String()
// and MIMEType() arms that the main test misses.
func TestMediaTypeString_AllVariants(t *testing.T) {
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

// TestGoextToMediaType_Unknown covers the default branch of goextToMediaType.
func TestGoextToMediaType_Unknown(t *testing.T) {
	// Pass a MediaType value not listed in the switch (e.g. 99).
	result := goextToMediaType(99)
	if result != MediaTypeUnknown {
		t.Errorf("goextToMediaType(unknown) = %v, want MediaTypeUnknown", result)
	}
}

// TestSanitizeReader_IOError verifies that a read error from the underlying
// reader causes SanitizeReader to return ErrMediaTooLarge.
func TestSanitizeReader_IOError(t *testing.T) {
	_, err := SanitizeReader(&errorReader{})
	if err == nil {
		t.Fatal("expected error from SanitizeReader with failing reader")
	}
	var tooLarge *ErrMediaTooLarge
	if !errors.As(err, &tooLarge) {
		t.Errorf("expected *ErrMediaTooLarge, got %T: %v", err, err)
	}
}

// TestValidate_SwitchDefault covers the final default branch in Validate (an
// unreachable path in normal operation but needed for completeness).
// We test via reflection: if the switch only handles MP4/WebP, any other
// value returns ErrUnsupportedMediaType before reaching the default.
// This is already covered by TestValidate_Errors/unknown_type above.

// TestValidateMP4_NoMdat verifies that an MP4 file with no mdat box is
// rejected by the fail-closed core.
//
// Java oracle: Mp4Sanitizer.java — mdat is required; missing mdat returns
// ErrMissingMdat. The old passthrough (encodeMP4Faststart) permitted no-mdat
// inputs; the new fail-closed core does not.
func TestValidateMP4_NoMdat(t *testing.T) {
	// Build ftyp + moov only, no mdat.
	ftyp := mp4.NewFtyp("isom", 0x200, []string{"isom"})
	moov := mp4.NewMoovBox()
	moov.AddChild(mp4.CreateMvhd())

	var buf bytes.Buffer
	if err := ftyp.Encode(&buf); err != nil {
		t.Fatalf("ftyp encode: %v", err)
	}
	if err := moov.Encode(&buf); err != nil {
		t.Fatalf("moov encode: %v", err)
	}

	// The fail-closed core requires mdat; absence returns ErrMissingMdat.
	err := ValidateMP4(buf.Bytes())
	if err == nil {
		t.Fatal("ValidateMP4 (no mdat) should return an error")
	}
	var target *ErrMissingMdat
	if !errors.As(err, &target) {
		t.Errorf("expected *ErrMissingMdat, got %T: %v", err, err)
	}
}

// TestValidate_MP4_FreeBoxNotPassedThrough verifies that a free/skip box
// between ftyp and moov is NOT present in the validated output.
//
// The fail-closed core reconstructs output from ftyp+moov+mdat only — it does
// not pass through arbitrary top-level boxes. This is the mp4san semantics:
// only the validated metadata (ftyp+moov) and the original mdat span are
// emitted.
//
// Java oracle: Mp4Sanitizer.java — output is strictly Metadata||mdat; no
// unknown or padding boxes are forwarded.
func TestValidate_MP4_FreeBoxNotPassedThrough(t *testing.T) {
	ftyp := mp4.NewFtyp("isom", 0x200, []string{"isom"})
	free := mp4.NewFreeBox([]byte{0x00, 0x00}) // 2-byte padding
	moov := mp4.NewMoovBox()
	moov.AddChild(mp4.CreateMvhd())

	var buf bytes.Buffer
	if err := ftyp.Encode(&buf); err != nil {
		t.Fatalf("ftyp: %v", err)
	}
	if err := free.Encode(&buf); err != nil {
		t.Fatalf("free: %v", err)
	}
	if err := moov.Encode(&buf); err != nil {
		t.Fatalf("moov: %v", err)
	}

	// Append a small mdat.
	payload := []byte{0x01, 0x02}
	mdatRaw := make([]byte, 10)
	binary.BigEndian.PutUint32(mdatRaw[0:4], uint32(len(mdatRaw)))
	copy(mdatRaw[4:8], "mdat")
	copy(mdatRaw[8:], payload)
	buf.Write(mdatRaw)

	result, err := Validate(buf.Bytes())
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	// The fail-closed core does NOT pass through the free box; only
	// ftyp+moov (as metadata) and the original mdat span appear in the output.
	if bytes.Contains(result.Validated, []byte("free")) {
		t.Error("free box must NOT be present in validated output (fail-closed: no passthrough of arbitrary boxes)")
	}
}

// TestSanitize_GIF covers the Sanitize GIF routing path through goextensions.
// This also exercises the goextToMediaType → MediaTypeGIF path.
func TestSanitize_GIF(t *testing.T) {
	// Minimal GIF87a header — real GIF, not a full image. goextensions returns
	// a sanitize result for it (or may fail). We only need the routing to occur.
	gifData := []byte("GIF87a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b")
	result, err := Sanitize(gifData)
	if err != nil {
		// goextensions may reject the minimal GIF; what matters is routing occurs.
		// If routed, the error is NOT ErrUnsupportedMediaType.
		if err == ErrUnsupportedMediaType {
			t.Errorf("GIF routing: expected goextensions error (not ErrUnsupportedMediaType), got: %v", err)
		}
		return
	}
	if result.MediaType != MediaTypeGIF {
		t.Errorf("Sanitize(GIF): MediaType = %v, want MediaTypeGIF", result.MediaType)
	}
}

// TestValidate_MP4_NilMetadata covers the sanitizeMP4 path where
// SanitizedMetadata.Metadata is nil (moov already before mdat).
// In this path sanitizeMP4 re-parses with mp4ff to produce clean output.
func TestValidate_MP4_NilMetadata(t *testing.T) {
	// Build moov-before-mdat (faststart): SanitizeMP4 returns Metadata=nil.
	mp4Data := append(javaFtyp(), append(javaMoov(), javaMdat()...)...)
	result, err := Validate(mp4Data)
	if err != nil {
		t.Fatalf("Validate(faststart MP4) returned error: %v", err)
	}
	if result.MetadataStripped {
		t.Error("MetadataStripped must be false for already-faststart input")
	}
	if len(result.Validated) == 0 {
		t.Error("Validated must be non-empty")
	}
}

// TestFindMoovOffset_NoMoov covers the findMoovOffset path when no moov box
// is present in the metadata bytes.
func TestFindMoovOffset_NoMoov(t *testing.T) {
	// Build ftyp-only bytes (no moov): findMoovOffset should return 0.
	ftypBytes := javaFtyp()
	got := findMoovOffset(ftypBytes)
	if got != 0 {
		t.Errorf("findMoovOffset without moov: got %d, want 0", got)
	}
}

// TestFindMoovOffset_CorruptedInput covers the scanBoxHeaders error path
// inside findMoovOffset when given garbage input (returns 0 on error).
func TestFindMoovOffset_CorruptedInput(t *testing.T) {
	// 5 bytes: too short for a box header (needs 8).
	corrupt := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	got := findMoovOffset(corrupt)
	if got != 0 {
		t.Errorf("findMoovOffset with corrupt input: got %d, want 0", got)
	}
}
