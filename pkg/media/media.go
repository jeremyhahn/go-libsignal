// Package media provides basic media type detection, validation, and
// sanitization for the Signal protocol. This is an intentionally minimal
// implementation; full media sanitization is a deep topic and production
// deployments should use specialized libraries for thorough metadata
// stripping and structural validation.
package media

import (
	"bytes"
	"encoding/binary"
	"io"
)

// MediaType represents a supported media type.
type MediaType int

const (
	// MediaTypeUnknown indicates an unrecognized media type.
	MediaTypeUnknown MediaType = iota

	// MediaTypeMP4 indicates an MP4/M4A/MOV container (ISO BMFF).
	MediaTypeMP4

	// MediaTypeWebP indicates a WebP image.
	MediaTypeWebP

	// MediaTypeJPEG indicates a JPEG image.
	MediaTypeJPEG

	// MediaTypePNG indicates a PNG image.
	MediaTypePNG

	// MediaTypeGIF indicates a GIF image (GIF87a or GIF89a).
	MediaTypeGIF
)

// String returns a human-readable name for the media type.
func (m MediaType) String() string {
	switch m {
	case MediaTypeMP4:
		return "MP4"
	case MediaTypeWebP:
		return "WebP"
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
	case MediaTypeMP4:
		return "video/mp4"
	case MediaTypeWebP:
		return "image/webp"
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

	// Sanitized contains the output media data. When MetadataStripped is
	// true, metadata such as EXIF, ICC profiles, and comments has been
	// removed. When MetadataStripped is false, the data has only been
	// structurally validated and is returned as-is.
	Sanitized []byte

	// OriginalSize is the size of the original input data in bytes.
	OriginalSize int64

	// MetadataStripped indicates whether metadata was actually removed from the content.
	// True for JPEG and PNG (EXIF, IPTC, ICC, comments stripped).
	// False for MP4, WebP, and GIF (structural validation only, no metadata removal).
	// Callers handling MP4/WebP/GIF should be aware that metadata such as GPS
	// coordinates may still be present in the output.
	MetadataStripped bool
}

// ErrUnsupportedMediaTypeError is the typed error for unsupported media types.
type ErrUnsupportedMediaTypeError struct{}

func (e *ErrUnsupportedMediaTypeError) Error() string {
	return "media: unsupported or unrecognized media type"
}

// ErrDataTooShortError is the typed error for input data that is too short.
type ErrDataTooShortError struct{}

func (e *ErrDataTooShortError) Error() string {
	return "media: data too short for media detection"
}

// ErrInvalidMP4Error is the typed error for invalid MP4 structure.
type ErrInvalidMP4Error struct{}

func (e *ErrInvalidMP4Error) Error() string {
	return "media: invalid MP4 structure"
}

// ErrInvalidWebPError is the typed error for invalid WebP structure.
type ErrInvalidWebPError struct{}

func (e *ErrInvalidWebPError) Error() string {
	return "media: invalid WebP structure"
}

// ErrInvalidJPEGError is the typed error for invalid JPEG structure.
type ErrInvalidJPEGError struct{}

func (e *ErrInvalidJPEGError) Error() string {
	return "media: invalid JPEG structure"
}

// ErrInvalidPNGError is the typed error for invalid PNG structure.
type ErrInvalidPNGError struct{}

func (e *ErrInvalidPNGError) Error() string {
	return "media: invalid PNG structure"
}

// ErrInvalidGIFError is the typed error for invalid GIF structure.
type ErrInvalidGIFError struct{}

func (e *ErrInvalidGIFError) Error() string {
	return "media: invalid GIF structure"
}

// Sentinel errors for validation failures. These point to typed error instances
// and support both == comparison and errors.Is matching.
var (
	// ErrUnsupportedMediaType indicates the media type could not be detected
	// or is not supported for sanitization.
	ErrUnsupportedMediaType error = &ErrUnsupportedMediaTypeError{}

	// ErrDataTooShort indicates the input data is too short to contain
	// valid media headers.
	ErrDataTooShort error = &ErrDataTooShortError{}

	// ErrInvalidMP4 indicates the MP4 file has an invalid structure.
	ErrInvalidMP4 error = &ErrInvalidMP4Error{}

	// ErrInvalidWebP indicates the WebP file has an invalid structure.
	ErrInvalidWebP error = &ErrInvalidWebPError{}

	// ErrInvalidJPEG indicates the JPEG file has an invalid structure.
	ErrInvalidJPEG error = &ErrInvalidJPEGError{}

	// ErrInvalidPNG indicates the PNG file has an invalid structure.
	ErrInvalidPNG error = &ErrInvalidPNGError{}

	// ErrInvalidGIF indicates the GIF file has an invalid structure.
	ErrInvalidGIF error = &ErrInvalidGIFError{}
)

// MediaValidationError indicates a structural validation failure
// during media file parsing.
type MediaValidationError struct {
	Detail string
}

func (e *MediaValidationError) Error() string {
	return "media: " + e.Detail
}

// ErrMediaTooLarge indicates that the input media exceeds the maximum
// allowed size for sanitization.
type ErrMediaTooLarge struct {
	// Size is the observed size in bytes, or -1 if unknown (e.g. read error).
	Size int
}

func (e *ErrMediaTooLarge) Error() string {
	return "media: input exceeds maximum allowed size"
}

// Magic byte sequences for media type detection.
var (
	jpegMagic   = []byte{0xFF, 0xD8, 0xFF}
	pngMagic    = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	gif87aMagic = []byte("GIF87a")
	gif89aMagic = []byte("GIF89a")
	riffMagic   = []byte("RIFF")
	webpMagic   = []byte("WEBP")
	ftypMagic   = []byte("ftyp")
)

// minDetectionSize is the minimum number of bytes needed for media type
// detection. WebP requires the most: 4 (RIFF) + 4 (size) + 4 (WEBP) = 12.
const minDetectionSize = 12

// maxMediaSize is the maximum allowed input size for SanitizeReader (100 MiB).
const maxMediaSize = 100 * 1024 * 1024

// DetectMediaType detects the media type from the first bytes of data.
//
// Detection is based on magic byte sequences:
//   - MP4: "ftyp" at offset 4 (ISO BMFF box structure)
//   - WebP: "RIFF" at offset 0 and "WEBP" at offset 8
//   - JPEG: 0xFF 0xD8 0xFF at offset 0
//   - PNG: 8-byte PNG signature at offset 0
//   - GIF: "GIF87a" or "GIF89a" at offset 0
//
// Returns MediaTypeUnknown if the type cannot be determined.
func DetectMediaType(data []byte) MediaType {
	if len(data) < minDetectionSize {
		// Try shorter signatures first.
		if len(data) >= 3 && bytes.HasPrefix(data, jpegMagic) {
			return MediaTypeJPEG
		}
		if len(data) >= 6 {
			if bytes.HasPrefix(data, gif87aMagic) || bytes.HasPrefix(data, gif89aMagic) {
				return MediaTypeGIF
			}
		}
		if len(data) >= 8 && bytes.HasPrefix(data, pngMagic) {
			return MediaTypePNG
		}
		return MediaTypeUnknown
	}

	// JPEG: starts with 0xFF 0xD8 0xFF
	if bytes.HasPrefix(data, jpegMagic) {
		return MediaTypeJPEG
	}

	// PNG: starts with the 8-byte PNG signature
	if bytes.HasPrefix(data, pngMagic) {
		return MediaTypePNG
	}

	// GIF: starts with "GIF87a" or "GIF89a"
	if bytes.HasPrefix(data, gif87aMagic) || bytes.HasPrefix(data, gif89aMagic) {
		return MediaTypeGIF
	}

	// WebP: starts with "RIFF" ... "WEBP"
	if bytes.HasPrefix(data, riffMagic) && bytes.Equal(data[8:12], webpMagic) {
		return MediaTypeWebP
	}

	// MP4 (ISO BMFF): "ftyp" at offset 4
	if len(data) >= 8 && bytes.Equal(data[4:8], ftypMagic) {
		return MediaTypeMP4
	}

	return MediaTypeUnknown
}

// Sanitize performs media sanitization on the given data. For JPEG and
// PNG, metadata (EXIF, ICC, comments, etc.) is stripped and
// MetadataStripped is set to true in the result. For MP4, WebP, and
// GIF, only structural validation is performed and the data is returned
// unmodified with MetadataStripped set to false.
//
// Returns ErrUnsupportedMediaType if the media type cannot be detected.
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

	var err error
	switch mediaType {
	case MediaTypeJPEG:
		result.Sanitized, err = sanitizeJPEG(data)
		result.MetadataStripped = true
	case MediaTypePNG:
		result.Sanitized, err = sanitizePNG(data)
		result.MetadataStripped = true
	case MediaTypeGIF:
		// GIF sanitization is complex; validate structure and return as-is.
		// MetadataStripped remains false: no metadata is removed.
		if err = ValidateGIF(data); err != nil {
			return nil, err
		}
		result.Sanitized = make([]byte, len(data))
		copy(result.Sanitized, data)
	case MediaTypeMP4:
		// MP4 sanitization requires deep ISO BMFF parsing; validate
		// structure and return as-is. MetadataStripped remains false.
		if err = ValidateMP4(data); err != nil {
			return nil, err
		}
		result.Sanitized = make([]byte, len(data))
		copy(result.Sanitized, data)
	case MediaTypeWebP:
		// WebP sanitization requires format-specific chunk parsing;
		// validate structure and return as-is. MetadataStripped remains false.
		if err = ValidateWebP(data); err != nil {
			return nil, err
		}
		result.Sanitized = make([]byte, len(data))
		copy(result.Sanitized, data)
	}

	if err != nil {
		return nil, err
	}

	return result, nil
}

// SanitizeReader performs streaming sanitization by reading all data from r
// and then sanitizing it. Input is capped at maxMediaSize (100 MiB); reads
// exceeding this limit return ErrMediaTooLarge.
func SanitizeReader(r io.Reader) (*SanitizeResult, error) {
	data, err := io.ReadAll(io.LimitReader(r, int64(maxMediaSize)+1))
	if err != nil {
		return nil, &ErrMediaTooLarge{Size: -1}
	}
	if len(data) > maxMediaSize {
		return nil, &ErrMediaTooLarge{Size: len(data)}
	}
	return Sanitize(data)
}

// ValidateMP4 performs basic structural validation of an MP4 file.
// It verifies the presence of the ftyp box and checks that the box
// structure (size + four-character-code pairs) is well-formed.
func ValidateMP4(data []byte) error {
	if len(data) < 8 {
		return ErrInvalidMP4
	}

	// Verify ftyp box at the start.
	if !bytes.Equal(data[4:8], ftypMagic) {
		return &MediaValidationError{Detail: "MP4 missing ftyp box"}
	}

	// Walk the top-level box structure.
	// Use int64 for box sizes to prevent overflow on 32-bit platforms where
	// int is 32 bits and a uint32 box size could wrap negative.
	offset := int64(0)
	dataLen := int64(len(data))
	foundFtyp := false

	for offset < dataLen {
		if offset+8 > dataLen {
			return &MediaValidationError{Detail: "MP4 truncated box header"}
		}

		boxSize := int64(binary.BigEndian.Uint32(data[offset : offset+4]))
		boxType := string(data[offset+4 : offset+8])

		if boxType == "ftyp" {
			foundFtyp = true
		}

		if boxSize == 0 {
			// Box extends to end of file (per ISO BMFF spec).
			break
		}

		// Per ISO BMFF, boxSize == 1 indicates a 64-bit extended size
		// stored in the next 8 bytes after the type field.
		if boxSize == 1 {
			if offset+16 > dataLen {
				return &MediaValidationError{Detail: "MP4 truncated 64-bit extended box size"}
			}
			boxSize = int64(binary.BigEndian.Uint64(data[offset+8 : offset+16]))
			if boxSize < 16 {
				return &MediaValidationError{Detail: "MP4 64-bit box size too small"}
			}
		} else if boxSize < 8 {
			return &MediaValidationError{Detail: "MP4 box size too small"}
		}

		if offset+boxSize > dataLen {
			return &MediaValidationError{Detail: "MP4 box extends beyond file"}
		}

		offset += boxSize
	}

	if !foundFtyp {
		return &MediaValidationError{Detail: "MP4 missing ftyp box"}
	}

	return nil
}

// ValidateWebP performs basic structural validation of a WebP file.
// It checks the RIFF header, WEBP signature, and verifies that the
// declared file size is consistent with the actual data length.
func ValidateWebP(data []byte) error {
	if len(data) < 12 {
		return ErrInvalidWebP
	}

	// Check RIFF header.
	if !bytes.HasPrefix(data, riffMagic) {
		return &MediaValidationError{Detail: "WebP missing RIFF header"}
	}

	// Check WEBP signature.
	if !bytes.Equal(data[8:12], webpMagic) {
		return &MediaValidationError{Detail: "WebP missing WEBP signature"}
	}

	// Check declared file size (RIFF chunk size at offset 4).
	// The RIFF chunk size is the size of the file minus 8 bytes (for the
	// RIFF header and size field itself). Use int64 to prevent overflow
	// on large WebP files where uint32 + 8 could wrap on 32-bit platforms.
	riffSize := int64(binary.LittleEndian.Uint32(data[4:8]))
	expectedTotal := riffSize + 8

	if expectedTotal > int64(len(data)) {
		return &MediaValidationError{Detail: "WebP declared size exceeds actual data"}
	}

	return nil
}

// ValidateGIF performs basic structural validation of a GIF file.
// It checks the GIF header signature and version.
func ValidateGIF(data []byte) error {
	if len(data) < 6 {
		return ErrInvalidGIF
	}

	if !bytes.HasPrefix(data, gif87aMagic) && !bytes.HasPrefix(data, gif89aMagic) {
		return &MediaValidationError{Detail: "invalid GIF header"}
	}

	// Check for Logical Screen Descriptor (minimum 13 bytes for header).
	if len(data) < 13 {
		return &MediaValidationError{Detail: "GIF too short for logical screen descriptor"}
	}

	return nil
}

// sanitizeJPEG strips EXIF and other metadata from JPEG data while
// preserving the image data. It removes APP1 (EXIF), APP2 (ICC), APP13
// (IPTC/Photoshop), and COM (comment) markers.
func sanitizeJPEG(data []byte) ([]byte, error) {
	if len(data) < 3 || !bytes.HasPrefix(data, jpegMagic) {
		return nil, ErrInvalidJPEG
	}

	// JPEG structure: SOI (0xFFD8) followed by a sequence of markers.
	// Each marker is 0xFF followed by a marker byte, then (for most
	// markers) a 2-byte big-endian length and payload.
	//
	// We copy SOI and then walk through markers, skipping metadata
	// markers and copying everything else.

	var out bytes.Buffer
	out.Grow(len(data))

	// Copy SOI marker.
	out.Write(data[0:2])

	pos := 2

	for pos < len(data) {
		if data[pos] != 0xFF {
			// Not a marker; we're likely in scan data. Copy the rest.
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

		// Markers without a length field.
		switch marker {
		case 0x00: // Byte stuffing in scan data (shouldn't be here).
			out.WriteByte(0xFF)
			out.WriteByte(0x00)
			continue
		case 0xD8: // SOI (shouldn't appear again).
			continue
		case 0xD9: // EOI
			out.WriteByte(0xFF)
			out.WriteByte(0xD9)
			out.Write(data[pos:]) // Include any trailing data.
			return out.Bytes(), nil
		}

		// SOS marker (0xDA): copy it and the rest of the file (scan data
		// is not structured with length prefixes).
		if marker == 0xDA {
			// Write the SOS marker and everything after it.
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

		// Decide whether to keep or strip this marker.
		strip := false
		switch marker {
		case 0xE0: // APP0 (JFIF header, may contain thumbnails with embedded EXIF)
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

// sanitizePNG strips metadata chunks from PNG data while preserving
// critical chunks (IHDR, PLTE, IDAT, IEND) and safe ancillary chunks.
// Removes tEXt, zTXt, iTXt, eXIf, and other metadata chunks.
func sanitizePNG(data []byte) ([]byte, error) {
	if len(data) < 8 || !bytes.HasPrefix(data, pngMagic) {
		return nil, ErrInvalidPNG
	}

	var out bytes.Buffer
	out.Grow(len(data))

	// Copy the PNG signature.
	out.Write(data[0:8])

	pos := 8

	for pos+12 <= len(data) { // Minimum chunk: 4 (length) + 4 (type) + 0 (data) + 4 (CRC)
		chunkLen := int64(binary.BigEndian.Uint32(data[pos : pos+4]))
		chunkType := string(data[pos+4 : pos+8])

		totalChunkSize64 := 4 + 4 + chunkLen + 4 // length + type + data + CRC
		if int64(pos)+totalChunkSize64 > int64(len(data)) {
			return nil, &MediaValidationError{Detail: "PNG chunk extends beyond data"}
		}

		// Decide whether to keep this chunk.
		keep := true
		switch chunkType {
		case "tEXt", "zTXt", "iTXt": // Text metadata
			keep = false
		case "eXIf": // EXIF data
			keep = false
		case "iCCP": // ICC color profile
			keep = false
		case "tIME": // Last modification time
			keep = false
		}

		totalChunkSize := int(totalChunkSize64)
		if keep {
			out.Write(data[pos : pos+totalChunkSize])
		}

		pos += totalChunkSize

		// Stop after IEND.
		if chunkType == "IEND" {
			break
		}
	}

	return out.Bytes(), nil
}
