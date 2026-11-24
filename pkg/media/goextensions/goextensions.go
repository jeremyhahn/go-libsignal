package goextensions

import (
	"bytes"
	"encoding/binary"
)

// MediaType represents a go-libsignal extension media type.
type MediaType int

const (
	// MediaTypeUnknown indicates an unrecognized media type.
	MediaTypeUnknown MediaType = iota

	// MediaTypeJPEG indicates a JPEG image.
	// Rust source: not present in libsignal media crate; go-libsignal extension.
	MediaTypeJPEG

	// MediaTypePNG indicates a PNG image.
	// Rust source: not present in libsignal media crate; go-libsignal extension.
	MediaTypePNG

	// MediaTypeGIF indicates a GIF image (GIF87a or GIF89a).
	// Rust source: not present in libsignal media crate; go-libsignal extension.
	MediaTypeGIF
)

// String returns a human-readable name for the media type.
func (m MediaType) String() string {
	switch m {
	case MediaTypeJPEG:
		return "JPEG"
	case MediaTypePNG:
		return "PNG"
	case MediaTypeGIF:
		return "GIF"
	default:
		return "Unknown"
	}
}

// MIMEType returns the MIME type string for the media type.
func (m MediaType) MIMEType() string {
	switch m {
	case MediaTypeJPEG:
		return "image/jpeg"
	case MediaTypePNG:
		return "image/png"
	case MediaTypeGIF:
		return "image/gif"
	default:
		return "application/octet-stream"
	}
}

// SanitizeResult contains the result of media sanitization.
type SanitizeResult struct {
	// MediaType is the detected type of the input media.
	MediaType MediaType

	// Sanitized contains the output media data. When MetadataStripped is true,
	// metadata such as EXIF, ICC profiles, and comments has been removed. When
	// MetadataStripped is false, the data has only been structurally validated
	// and is returned as-is.
	Sanitized []byte

	// OriginalSize is the size of the original input data in bytes.
	OriginalSize int64

	// MetadataStripped indicates whether metadata was actually removed.
	// True for JPEG and PNG. False for GIF (structural validation only).
	MetadataStripped bool
}

// ErrInvalidJPEGError is the typed error for invalid JPEG structure.
type ErrInvalidJPEGError struct{}

func (e *ErrInvalidJPEGError) Error() string {
	return "goextensions: invalid JPEG structure"
}

// ErrInvalidPNGError is the typed error for invalid PNG structure.
type ErrInvalidPNGError struct{}

func (e *ErrInvalidPNGError) Error() string {
	return "goextensions: invalid PNG structure"
}

// ErrInvalidGIFError is the typed error for invalid GIF structure.
type ErrInvalidGIFError struct{}

func (e *ErrInvalidGIFError) Error() string {
	return "goextensions: invalid GIF structure"
}

// ErrUnsupportedMediaTypeError is the typed error for unrecognized media types.
type ErrUnsupportedMediaTypeError struct{}

func (e *ErrUnsupportedMediaTypeError) Error() string {
	return "goextensions: unsupported or unrecognized media type"
}

// ErrDataTooShortError is the typed error for input data that is too short.
type ErrDataTooShortError struct{}

func (e *ErrDataTooShortError) Error() string {
	return "goextensions: data too short for media detection"
}

// MediaValidationError indicates a structural validation failure.
type MediaValidationError struct {
	Detail string
}

func (e *MediaValidationError) Error() string {
	return "goextensions: " + e.Detail
}

// Sentinel errors for validation failures.
var (
	// ErrInvalidJPEG indicates the JPEG file has an invalid structure.
	ErrInvalidJPEG error = &ErrInvalidJPEGError{}

	// ErrInvalidPNG indicates the PNG file has an invalid structure.
	ErrInvalidPNG error = &ErrInvalidPNGError{}

	// ErrInvalidGIF indicates the GIF file has an invalid structure.
	ErrInvalidGIF error = &ErrInvalidGIFError{}

	// ErrUnsupportedMediaType indicates the media type could not be detected.
	ErrUnsupportedMediaType error = &ErrUnsupportedMediaTypeError{}

	// ErrDataTooShort indicates the input data is too short to contain valid
	// media headers.
	ErrDataTooShort error = &ErrDataTooShortError{}
)

// Magic byte sequences for media type detection.
var (
	jpegMagic   = []byte{0xFF, 0xD8, 0xFF}
	pngMagic    = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	gif87aMagic = []byte("GIF87a")
	gif89aMagic = []byte("GIF89a")
)

// minDetectionSize is the minimum number of bytes needed for reliable
// detection across all three extension types.
const minDetectionSize = 8 // PNG signature length

// DetectMediaType detects the media type from the first bytes of data.
//
// Detection is based on magic byte sequences:
//   - JPEG: 0xFF 0xD8 0xFF at offset 0
//   - PNG: 8-byte PNG signature at offset 0
//   - GIF: "GIF87a" or "GIF89a" at offset 0
//
// Returns MediaTypeUnknown if the type cannot be determined.
func DetectMediaType(data []byte) MediaType {
	if len(data) >= 3 && bytes.HasPrefix(data, jpegMagic) {
		return MediaTypeJPEG
	}
	if len(data) >= minDetectionSize && bytes.HasPrefix(data, pngMagic) {
		return MediaTypePNG
	}
	if len(data) >= 6 {
		if bytes.HasPrefix(data, gif87aMagic) || bytes.HasPrefix(data, gif89aMagic) {
			return MediaTypeGIF
		}
	}
	return MediaTypeUnknown
}

// Sanitize performs sanitization on JPEG, PNG, or GIF data.
//
// For JPEG and PNG, metadata (EXIF, ICC, comments, etc.) is stripped and
// MetadataStripped is set to true. For GIF, only structural validation is
// performed and the data is returned unmodified with MetadataStripped false.
//
// Returns ErrUnsupportedMediaType if the media type is not one of the three
// extension types. For MP4 and WebP, use pkg/media instead.
func Sanitize(data []byte) (*SanitizeResult, error) {
	if len(data) < 3 {
		return nil, ErrDataTooShort
	}

	mediaType := DetectMediaType(data)
	if mediaType == MediaTypeUnknown {
		return nil, ErrUnsupportedMediaType
	}

	result := &SanitizeResult{
		MediaType:    mediaType,
		OriginalSize: int64(len(data)),
	}

	switch mediaType {
	case MediaTypeJPEG:
		sanitized, err := SanitizeJPEG(data)
		if err != nil {
			return nil, err
		}
		result.Sanitized = sanitized
		result.MetadataStripped = true
	case MediaTypePNG:
		sanitized, err := SanitizePNG(data)
		if err != nil {
			return nil, err
		}
		result.Sanitized = sanitized
		result.MetadataStripped = true
	case MediaTypeGIF:
		if err := ValidateGIF(data); err != nil {
			return nil, err
		}
		result.Sanitized = make([]byte, len(data))
		copy(result.Sanitized, data)
	}

	return result, nil
}

// SanitizeJPEG strips EXIF and other metadata from JPEG data while preserving
// the image data. It removes APP0 (JFIF), APP1 (EXIF/XMP), APP2 (ICC),
// APP13 (IPTC/Photoshop), and COM (comment) markers.
func SanitizeJPEG(data []byte) ([]byte, error) {
	if len(data) < 3 || !bytes.HasPrefix(data, jpegMagic) {
		return nil, ErrInvalidJPEG
	}

	var out bytes.Buffer
	out.Grow(len(data))

	// Copy SOI marker.
	out.Write(data[0:2])

	pos := 2

	for pos < len(data) {
		if data[pos] != 0xFF {
			// Not a marker byte; we are in scan data. Copy the rest.
			out.Write(data[pos:])
			break
		}

		// Skip padding 0xFF bytes.
		for pos < len(data) && data[pos] == 0xFF {
			pos++
		}

		if pos >= len(data) {
			break
		}

		marker := data[pos]
		pos++

		switch marker {
		case 0x00: // Byte stuffing in scan data.
			out.WriteByte(0xFF)
			out.WriteByte(0x00)
			continue
		case 0xD8: // SOI (should not appear again).
			continue
		case 0xD9: // EOI
			out.WriteByte(0xFF)
			out.WriteByte(0xD9)
			out.Write(data[pos:])
			return out.Bytes(), nil
		}

		// SOS: copy it and everything after (scan data has no length prefix).
		if marker == 0xDA {
			out.WriteByte(0xFF)
			out.WriteByte(marker)
			out.Write(data[pos:])
			return out.Bytes(), nil
		}

		// Read marker length.
		if pos+2 > len(data) {
			return nil, &MediaValidationError{Detail: "JPEG truncated marker length"}
		}

		markerLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
		if markerLen < 2 {
			return nil, &MediaValidationError{Detail: "JPEG invalid marker length"}
		}
		if pos+markerLen > len(data) {
			return nil, &MediaValidationError{Detail: "JPEG marker extends beyond data"}
		}

		strip := false
		switch marker {
		case 0xE0: // APP0 (JFIF)
			strip = true
		case 0xE1: // APP1 (EXIF, XMP)
			strip = true
		case 0xE2: // APP2 (ICC profile)
			strip = true
		case 0xED: // APP13 (IPTC/Photoshop)
			strip = true
		case 0xFE: // COM (comment)
			strip = true
		}

		if !strip {
			out.WriteByte(0xFF)
			out.WriteByte(marker)
			out.Write(data[pos : pos+markerLen])
		}

		pos += markerLen
	}

	return out.Bytes(), nil
}

// SanitizePNG strips metadata chunks from PNG data while preserving critical
// chunks (IHDR, PLTE, IDAT, IEND) and safe ancillary chunks.
// Removes tEXt, zTXt, iTXt, eXIf, iCCP, and tIME chunks.
func SanitizePNG(data []byte) ([]byte, error) {
	if len(data) < 8 || !bytes.HasPrefix(data, pngMagic) {
		return nil, ErrInvalidPNG
	}

	var out bytes.Buffer
	out.Grow(len(data))

	// Copy the PNG signature.
	out.Write(data[0:8])

	pos := 8

	for pos+12 <= len(data) {
		chunkLen := int64(binary.BigEndian.Uint32(data[pos : pos+4]))
		chunkType := string(data[pos+4 : pos+8])

		totalChunkSize64 := 4 + 4 + chunkLen + 4
		if int64(pos)+totalChunkSize64 > int64(len(data)) {
			return nil, &MediaValidationError{Detail: "PNG chunk extends beyond data"}
		}

		keep := true
		switch chunkType {
		case "tEXt", "zTXt", "iTXt":
			keep = false
		case "eXIf":
			keep = false
		case "iCCP":
			keep = false
		case "tIME":
			keep = false
		}

		totalChunkSize := int(totalChunkSize64)
		if keep {
			out.Write(data[pos : pos+totalChunkSize])
		}

		pos += totalChunkSize

		if chunkType == "IEND" {
			break
		}
	}

	return out.Bytes(), nil
}

// ValidateGIF performs basic structural validation of a GIF file.
// It checks the GIF header signature, version, and minimum length.
func ValidateGIF(data []byte) error {
	if len(data) < 6 {
		return ErrInvalidGIF
	}

	if !bytes.HasPrefix(data, gif87aMagic) && !bytes.HasPrefix(data, gif89aMagic) {
		return &MediaValidationError{Detail: "invalid GIF header"}
	}

	if len(data) < 13 {
		return &MediaValidationError{Detail: "GIF too short for logical screen descriptor"}
	}

	return nil
}
