package media

import (
	"errors"
	"io"
	"testing"
)

// TestErrorMethods verifies that each typed error's Error() method returns
// the expected message string. These typed errors are used as sentinel values
// throughout the package and their messages must remain stable.
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
			name: "ErrInvalidJPEGError",
			err:  &ErrInvalidJPEGError{},
			want: "media: invalid JPEG structure",
		},
		{
			name: "ErrInvalidPNGError",
			err:  &ErrInvalidPNGError{},
			want: "media: invalid PNG structure",
		},
		{
			name: "ErrInvalidGIFError",
			err:  &ErrInvalidGIFError{},
			want: "media: invalid GIF structure",
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
	t.Run("ErrUnsupportedMediaType is ErrUnsupportedMediaTypeError", func(t *testing.T) {
		var target *ErrUnsupportedMediaTypeError
		if !errors.As(ErrUnsupportedMediaType, &target) {
			t.Error("ErrUnsupportedMediaType should be *ErrUnsupportedMediaTypeError")
		}
	})

	t.Run("ErrDataTooShort is ErrDataTooShortError", func(t *testing.T) {
		var target *ErrDataTooShortError
		if !errors.As(ErrDataTooShort, &target) {
			t.Error("ErrDataTooShort should be *ErrDataTooShortError")
		}
	})

	t.Run("ErrInvalidMP4 is ErrInvalidMP4Error", func(t *testing.T) {
		var target *ErrInvalidMP4Error
		if !errors.As(ErrInvalidMP4, &target) {
			t.Error("ErrInvalidMP4 should be *ErrInvalidMP4Error")
		}
	})

	t.Run("ErrInvalidWebP is ErrInvalidWebPError", func(t *testing.T) {
		var target *ErrInvalidWebPError
		if !errors.As(ErrInvalidWebP, &target) {
			t.Error("ErrInvalidWebP should be *ErrInvalidWebPError")
		}
	})

	t.Run("ErrInvalidJPEG is ErrInvalidJPEGError", func(t *testing.T) {
		var target *ErrInvalidJPEGError
		if !errors.As(ErrInvalidJPEG, &target) {
			t.Error("ErrInvalidJPEG should be *ErrInvalidJPEGError")
		}
	})

	t.Run("ErrInvalidPNG is ErrInvalidPNGError", func(t *testing.T) {
		var target *ErrInvalidPNGError
		if !errors.As(ErrInvalidPNG, &target) {
			t.Error("ErrInvalidPNG should be *ErrInvalidPNGError")
		}
	})

	t.Run("ErrInvalidGIF is ErrInvalidGIFError", func(t *testing.T) {
		var target *ErrInvalidGIFError
		if !errors.As(ErrInvalidGIF, &target) {
			t.Error("ErrInvalidGIF should be *ErrInvalidGIFError")
		}
	})
}

// largeFakeReader is a mock io.Reader that reports reading exactly n bytes of
// zeroes without allocating the full buffer. It is used to test the 100 MiB
// size limit in SanitizeReader without actually allocating 100 MiB of memory.
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

// TestSanitizeReader_ExceedsMaxSize verifies that SanitizeReader returns
// ErrMediaTooLarge when the input stream exceeds 100 MiB. The mock reader
// provides maxMediaSize+1 bytes without allocating them in memory.
func TestSanitizeReader_ExceedsMaxSize(t *testing.T) {
	// Provide exactly maxMediaSize+1 bytes so the limit check triggers.
	// LimitReader allows maxMediaSize+1 bytes through, so after ReadAll
	// len(data) == maxMediaSize+1, which is > maxMediaSize.
	r := &largeFakeReader{remaining: maxMediaSize + 1}

	_, err := SanitizeReader(r)
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

// TestSanitizeReader_ExactlyAtLimit verifies that SanitizeReader accepts
// input that is exactly at the 100 MiB limit. We use a minimal JPEG
// followed by zeroes up to the limit; since the data won't be a valid image
// we just check that the error is not ErrMediaTooLarge.
func TestSanitizeReader_ExactlyAtLimit(t *testing.T) {
	// Use the minimum 3-byte JPEG prefix in a reader that returns exactly
	// maxMediaSize bytes. The sanitizer will reject it as invalid JPEG but
	// must NOT return ErrMediaTooLarge.
	jpegPrefix := []byte{0xFF, 0xD8, 0xFF}
	// Build a fake reader: first 3 bytes are JPEG magic, rest are zeroes.
	combined := make([]byte, 3)
	copy(combined, jpegPrefix)
	// Pad to exactly maxMediaSize using the fake reader approach via a
	// pre-allocated slice (3 bytes is acceptable; we just need to verify
	// the boundary condition, not fill the whole buffer).
	// Use a 3-byte buffer at exactly the max size boundary by trimming to
	// a value that yields a valid "too short" rejection but is not > max.
	_ = combined

	// Test with exactly maxMediaSize bytes that are all zeroes (will fail
	// as unsupported type, not as too large).
	exactReader := &limitedZeroReader{limit: maxMediaSize}
	_, err := SanitizeReader(exactReader)

	var tooLarge *ErrMediaTooLarge
	if errors.As(err, &tooLarge) {
		t.Errorf("input at exactly maxMediaSize should not return ErrMediaTooLarge, got size=%d", tooLarge.Size)
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
