package media

import (
	"bytes"
	"encoding/binary"
	"io"

	mp4 "github.com/Eyevinn/mp4ff/mp4"

	"github.com/jeremyhahn/go-libsignal/pkg/media/goextensions"
)

// maxMetadataSize is the upper bound on metadata/parser memory for MP4 parsing,
// matching MAX_METADATA_SIZE in the Rust libsignal mp4san config.
//
// Rust source: libsignal/rust/media/src/sanitize/mp4.rs
const maxMetadataSize = 300 * 1024 * 1024

// maxWebPFileLen is the maximum RIFF payload size permitted by WebP.
// Matches webpsan MAX_FILE_LEN = u32::MAX - 2 = 0xFFFFFFFD.
//
// webpsan/src/lib.rs:64 — `pub const MAX_FILE_LEN: u32 = u32::MAX - 2;`
const maxWebPFileLen = 0xFFFFFFFD

// VP8X flag bits — matching webpsan/src/parse/vp8x.rs Vp8xFlags.
//
// webpsan/src/parse/vp8x.rs:24-29
const (
	vp8xFlagICCP  = 0b0010_0000 // HAS_ICCP_CHUNK
	vp8xFlagAlpha = 0b0001_0000 // HAS_ALPH_CHUNK
	vp8xFlagEXIF  = 0b0000_1000 // HAS_EXIF_CHUNK
	vp8xFlagXMP   = 0b0000_0100 // HAS_XMP_CHUNK
	vp8xFlagAnim  = 0b0000_0010 // IS_ANIMATED
)

// vp8lSignature is the VP8L bitstream signature byte.
// webpsan/src/parse/vp8l.rs:42 — `const SIGNATURE: u8 = 0x2F;`
const vp8lSignature = 0x2F

// Magic byte sequences for JPEG, PNG, and GIF detection used by the
// back-compat Sanitize shim. These mirror the constants in goextensions to
// avoid a package-level dependency inversion.
var (
	shimJPEGMagic   = []byte{0xFF, 0xD8, 0xFF}
	shimPNGMagic    = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	shimGIF87aMagic = []byte("GIF87a")
	shimGIF89aMagic = []byte("GIF89a")
)

// isGoExtensionsType reports whether data starts with a JPEG, PNG, or GIF
// magic byte sequence, indicating it should be routed to goextensions.
func isGoExtensionsType(data []byte) bool {
	if len(data) >= 3 && bytes.HasPrefix(data, shimJPEGMagic) {
		return true
	}
	if len(data) >= 8 && bytes.HasPrefix(data, shimPNGMagic) {
		return true
	}
	if len(data) >= 6 {
		return bytes.HasPrefix(data, shimGIF87aMagic) || bytes.HasPrefix(data, shimGIF89aMagic)
	}
	return false
}

// MediaType represents a supported media type.
// Only MP4 and WebP are supported here; see pkg/media/goextensions for JPEG,
// PNG, and GIF support.
type MediaType int

const (
	// MediaTypeUnknown indicates an unrecognized media type.
	MediaTypeUnknown MediaType = iota

	// MediaTypeMP4 indicates an MP4/M4A/MOV container (ISO BMFF).
	MediaTypeMP4

	// MediaTypeWebP indicates a WebP image.
	MediaTypeWebP

	// MediaTypeJPEG indicates a JPEG image routed through goextensions.
	//
	// Deprecated: use pkg/media/goextensions.MediaTypeJPEG. This constant
	// exists so callers reading SanitizeResult.MediaType can still switch on
	// it without an import change.
	MediaTypeJPEG

	// MediaTypePNG indicates a PNG image routed through goextensions.
	//
	// Deprecated: use pkg/media/goextensions.MediaTypePNG. This constant
	// exists so callers reading SanitizeResult.MediaType can still switch on
	// it without an import change.
	MediaTypePNG

	// MediaTypeGIF indicates a GIF image routed through goextensions.
	//
	// Deprecated: use pkg/media/goextensions.MediaTypeGIF. This constant
	// exists so callers reading SanitizeResult.MediaType can still switch on
	// it without an import change.
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

// ValidateResult contains the result of media validation.
type ValidateResult struct {
	// MediaType is the detected type of the input media.
	MediaType MediaType

	// Validated contains the validated media data. For MP4, the box tree is
	// re-encoded with the moov box relocated before mdat (faststart layout).
	// For WebP and other types, the data is returned as-is after structural
	// validation.
	Validated []byte

	// OriginalSize is the size of the original input data in bytes.
	OriginalSize int64

	// MetadataStripped indicates whether metadata was removed or relocated.
	// True for MP4 when the moov box was relocated (faststart normalization).
	// False for WebP (structural validation only, no metadata removal).
	MetadataStripped bool

	// MoovOffset is the byte offset of the moov box in the output Validated
	// data. Only meaningful for MP4 (MediaTypeMP4); zero for all other types.
	MoovOffset int64

	// MdatOffset is the byte offset of the mdat box in the output Validated
	// data. Only meaningful for MP4 (MediaTypeMP4); zero for all other types.
	MdatOffset int64
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

// Sentinel errors for validation failures.
var (
	// ErrUnsupportedMediaType indicates the media type could not be detected
	// or is not supported for validation.
	ErrUnsupportedMediaType error = &ErrUnsupportedMediaTypeError{}

	// ErrDataTooShort indicates the input data is too short to contain
	// valid media headers.
	ErrDataTooShort error = &ErrDataTooShortError{}

	// ErrInvalidMP4 indicates the MP4 file has an invalid structure.
	ErrInvalidMP4 error = &ErrInvalidMP4Error{}

	// ErrInvalidWebP indicates the WebP file has an invalid structure.
	ErrInvalidWebP error = &ErrInvalidWebPError{}
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
// allowed size for validation.
type ErrMediaTooLarge struct {
	// Size is the observed size in bytes, or -1 if unknown (e.g. read error).
	Size int
}

func (e *ErrMediaTooLarge) Error() string {
	return "media: input exceeds maximum allowed size"
}

// ErrMP4MetadataTooLarge indicates that the MP4 moov/metadata box exceeds
// maxMetadataSize (300 MiB), matching mp4san's MAX_METADATA_SIZE limit.
//
// Rust source: libsignal/rust/media/src/sanitize/mp4.rs — MAX_METADATA_SIZE.
type ErrMP4MetadataTooLarge struct {
	// Size is the measured metadata byte count.
	Size uint64
}

func (e *ErrMP4MetadataTooLarge) Error() string {
	return "media: MP4 metadata size exceeds maximum allowed limit"
}

// Magic byte sequences for media type detection.
var (
	riffMagic = []byte("RIFF")
	webpMagic = []byte("WEBP")
	ftypMagic = []byte("ftyp")
)

// minDetectionSize is the minimum number of bytes needed for media type
// detection. WebP requires the most: 4 (RIFF) + 4 (size) + 4 (WEBP) = 12.
const minDetectionSize = 12

// maxMediaSize is the maximum allowed input size for ValidateReader (100 MiB).
const maxMediaSize = 100 * 1024 * 1024

// DetectMediaType detects the media type from the first bytes of data.
//
// Detection is based on magic byte sequences:
//   - JPEG: 0xFF 0xD8 0xFF at offset 0
//   - PNG: 8-byte PNG signature at offset 0
//   - GIF: "GIF87a" or "GIF89a" at offset 0
//   - WebP: "RIFF" at offset 0 and "WEBP" at offset 8
//   - MP4: "ftyp" at offset 4 (ISO BMFF box structure)
//
// Returns MediaTypeUnknown if the type cannot be determined.
// The deprecated MediaTypeJPEG, MediaTypePNG, and MediaTypeGIF constants are
// returned for those image types so callers can switch on the result without
// importing pkg/media/goextensions.
func DetectMediaType(data []byte) MediaType {
	// JPEG: 3-byte magic 0xFF 0xD8 0xFF
	if len(data) >= 3 && bytes.HasPrefix(data, shimJPEGMagic) {
		return MediaTypeJPEG
	}

	// PNG: 8-byte signature
	if len(data) >= 8 && bytes.HasPrefix(data, shimPNGMagic) {
		return MediaTypePNG
	}

	// GIF87a / GIF89a: 6-byte signature
	if len(data) >= 6 {
		if bytes.HasPrefix(data, shimGIF87aMagic) || bytes.HasPrefix(data, shimGIF89aMagic) {
			return MediaTypeGIF
		}
	}

	if len(data) < minDetectionSize {
		return MediaTypeUnknown
	}

	// WebP: starts with "RIFF" ... "WEBP"
	if bytes.HasPrefix(data, riffMagic) && bytes.Equal(data[8:12], webpMagic) {
		return MediaTypeWebP
	}

	// MP4 (ISO BMFF): "ftyp" at offset 4
	if bytes.Equal(data[4:8], ftypMagic) {
		return MediaTypeMP4
	}

	return MediaTypeUnknown
}

// Validate performs deep structural validation of MP4 or WebP data.
//
// For MP4, the entire ISO BMFF box tree is parsed using github.com/Eyevinn/mp4ff,
// the moov box is validated and re-encoded before mdat (faststart), and
// MAX_METADATA_SIZE (300 MiB) is enforced. MetadataStripped is set true when
// the moov box was relocated to precede mdat.
//
// For WebP, a full RIFF chunk-structure walk validates every chunk length stays
// within bounds and the container is well-formed. MetadataStripped is false
// (structural validation only, no metadata removal).
//
// Rust source: libsignal/rust/media/src/sanitize/mp4.rs and
// libsignal/rust/media/src/sanitize/webp.rs.
//
// Returns ErrUnsupportedMediaType if the media type cannot be detected.
// For JPEG, PNG, and GIF, use pkg/media/goextensions.Sanitize instead.
func Validate(data []byte) (*ValidateResult, error) {
	if len(data) < 3 {
		return nil, ErrDataTooShort
	}

	mediaType := DetectMediaType(data)
	// Validate only handles MP4 and WebP. JPEG, PNG, and GIF are handled by
	// pkg/media/goextensions.Sanitize; return ErrUnsupportedMediaType for them.
	if mediaType != MediaTypeMP4 && mediaType != MediaTypeWebP {
		return nil, ErrUnsupportedMediaType
	}

	switch mediaType {
	case MediaTypeMP4:
		return sanitizeMP4(data)
	case MediaTypeWebP:
		return sanitizeWebP(data)
	default:
		return nil, ErrUnsupportedMediaType
	}
}

// SanitizeResult contains the result of a Sanitize call.
//
// Deprecated: Use ValidateResult from Validate instead. This type exists for
// backward compatibility with callers that used the old Sanitize API.
//
// Sanitized is the legacy field name for the output media bytes. New code
// should use Validate, which returns ValidateResult with the renamed Validated
// field. The two fields carry identical data; only the name differs.
type SanitizeResult struct {
	// MediaType is the detected type of the input media.
	MediaType MediaType

	// Sanitized is the legacy field name for the output media bytes.
	// New code should use ValidateResult.Validated from Validate instead.
	Sanitized []byte

	// OriginalSize is the size of the original input data in bytes.
	OriginalSize int64

	// MetadataStripped indicates whether metadata was actually removed.
	// True for JPEG and PNG when routed through goextensions.
	// True for MP4 when the moov box was relocated to precede mdat.
	// False for WebP (structural validation only, no metadata removal).
	MetadataStripped bool
}

// goextToMediaType maps a goextensions.MediaType to the deprecated back-compat
// MediaType constants defined in this package. This lets callers that switch on
// SanitizeResult.MediaType continue to work without an import change.
func goextToMediaType(ext goextensions.MediaType) MediaType {
	switch ext {
	case goextensions.MediaTypeJPEG:
		return MediaTypeJPEG
	case goextensions.MediaTypePNG:
		return MediaTypePNG
	case goextensions.MediaTypeGIF:
		return MediaTypeGIF
	default:
		return MediaTypeUnknown
	}
}

// Sanitize is a backward-compatible shim that auto-routes by media type:
//   - JPEG, PNG, GIF: delegates to pkg/media/goextensions.Sanitize; returns
//     MetadataStripped=true for JPEG and PNG, false for GIF.  The MediaType
//     field is set to the deprecated MediaTypeJPEG/MediaTypePNG/MediaTypeGIF
//     constants so existing callers that switch on result.MediaType continue
//     to work.  Migrate new code to pkg/media/goextensions directly.
//   - MP4: delegates to Validate; MetadataStripped=true when moov was relocated.
//   - WebP: delegates to Validate; MetadataStripped=false (validation only).
//   - Unrecognized type: returns ErrUnsupportedMediaType.
//
// Deprecated: use pkg/media/goextensions for JPEG/PNG/GIF, or
// pkg/media.Validate for MP4/WebP. This wrapper auto-routes for back-compat.
func Sanitize(data []byte) (*SanitizeResult, error) {
	if isGoExtensionsType(data) {
		ext, err := goextensions.Sanitize(data)
		if err != nil {
			return nil, err
		}
		return &SanitizeResult{
			MediaType:        goextToMediaType(ext.MediaType),
			Sanitized:        ext.Sanitized,
			OriginalSize:     ext.OriginalSize,
			MetadataStripped: ext.MetadataStripped,
		}, nil
	}
	vr, err := Validate(data)
	if err != nil {
		return nil, err
	}
	return &SanitizeResult{
		MediaType:        vr.MediaType,
		Sanitized:        vr.Validated,
		OriginalSize:     vr.OriginalSize,
		MetadataStripped: vr.MetadataStripped,
	}, nil
}

// ValidateReader performs streaming validation by reading all data from r and
// then calling Validate. Input is capped at maxMediaSize (100 MiB); reads
// exceeding this limit return ErrMediaTooLarge.
func ValidateReader(r io.Reader) (*ValidateResult, error) {
	data, err := io.ReadAll(io.LimitReader(r, int64(maxMediaSize)+1))
	if err != nil {
		return nil, &ErrMediaTooLarge{Size: -1}
	}
	if len(data) > maxMediaSize {
		return nil, &ErrMediaTooLarge{Size: len(data)}
	}
	return Validate(data)
}

// SanitizeReader is a backward-compatible streaming shim. It reads all data
// from r (capped at maxMediaSize, 100 MiB) and delegates to Sanitize, which
// auto-routes JPEG/PNG/GIF through pkg/media/goextensions and MP4/WebP through
// Validate.  Input exceeding maxMediaSize returns ErrMediaTooLarge.
//
// Deprecated: for JPEG/PNG/GIF call pkg/media/goextensions.Sanitize directly;
// for MP4/WebP call ValidateReader. This wrapper auto-routes for back-compat.
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

// sanitizeMP4 is the fail-closed MP4 validation core used by the legacy
// Validate/ValidateMP4 API.  It delegates to SanitizeMP4 (the mp4san-faithful
// implementation in mp4san.go) so that the legacy path and the new API share a
// single validation core: both reject fragmented MP4, non-isom brand,
// discontiguous mdat, and external dref, and neither passes through arbitrary
// top-level boxes.
//
// The ValidateResult.Validated output is reconstructed solely from the
// validated metadata (ftyp+moov) and the original mdat span identified by
// SanitizedMetadata — no arbitrary boxes from the original file are re-emitted.
// For the already-faststart case (SanitizedMetadata.Metadata == nil) the
// metadata block is re-extracted directly from the original input so that the
// output is equally clean.
//
// Rust source: libsignal/rust/media/src/sanitize/mp4.rs
// Java oracle: Mp4Sanitizer.java:L49–L78
func sanitizeMP4(data []byte) (*ValidateResult, error) {
	sm, err := SanitizeMP4(data)
	if err != nil {
		return nil, err
	}

	// Defensive bounds check: SanitizeMP4 already validates this, but guard
	// here too so that any future refactor cannot introduce a silent panic.
	if sm.DataOffset < 0 || sm.DataLength < 0 || sm.DataLength > int64(len(data))-sm.DataOffset {
		return nil, &MediaValidationError{Detail: "MP4 mdat span exceeds input bounds"}
	}
	mdatSpan := data[sm.DataOffset : sm.DataOffset+sm.DataLength]

	var metadataBytes []byte
	if sm.Metadata != nil {
		// Rewritten: SanitizeMP4 already produced clean ftyp+moov in sm.Metadata.
		metadataBytes = sm.Metadata
	} else {
		// Already faststart: re-encode ftyp+moov from the parsed tree to strip
		// any padding boxes (free, skip) that may be interleaved in the original.
		// This ensures the output contains only ftyp+moov+mdat regardless of
		// what other top-level boxes appear in the input.
		f, parseErr := mp4.DecodeFile(bytes.NewReader(data), mp4.WithDecodeMode(mp4.DecModeLazyMdat))
		if parseErr != nil {
			return nil, &MediaValidationError{Detail: "MP4 re-parse error: " + parseErr.Error()}
		}
		if f.Ftyp == nil || f.Moov == nil {
			return nil, &MediaValidationError{Detail: "MP4 missing ftyp or moov after validation"}
		}
		metadataBytes, err = encodeFtypMoov(f.Ftyp, f.Moov)
		if err != nil {
			return nil, &MediaValidationError{Detail: "MP4 metadata encode error: " + err.Error()}
		}
	}

	validated := make([]byte, 0, int64(len(metadataBytes))+sm.DataLength)
	validated = append(validated, metadataBytes...)
	validated = append(validated, mdatSpan...)

	moovOffset := findMoovOffset(metadataBytes)
	mdatOffset := int64(len(metadataBytes))

	return &ValidateResult{
		MediaType:        MediaTypeMP4,
		Validated:        validated,
		OriginalSize:     int64(len(data)),
		MetadataStripped: sm.Metadata != nil,
		MoovOffset:       moovOffset,
		MdatOffset:       mdatOffset,
	}, nil
}

// findMoovOffset returns the byte offset of the first moov box in data by
// scanning top-level ISO BMFF box headers.  Returns 0 if not found (caller
// treats it as "start of buffer").
func findMoovOffset(data []byte) int64 {
	boxes, err := scanBoxHeaders(data)
	if err != nil {
		return 0
	}
	for _, b := range boxes {
		if b.boxType == "moov" {
			return b.startPos
		}
	}
	return 0
}

// sanitizeWebP performs structural validation of a WebP file, faithfully
// mirroring the webpsan 0.5.3 state machine.
//
// The validation follows the exact state machine from webpsan/src/lib.rs:
//  1. RIFF header + WEBP fourcc + MAX_FILE_LEN check
//  2. First chunk must be VP8, VP8L, or VP8X
//  3. VP8L: validate signature byte 0x2F and extract width/height
//  4. VP8X: parse flags+reserved+canvas dims (OneBasedU24), then enforce
//     ICCP→image→EXIF→XMP ordering with strict flag/presence checks
//  5. After image data: known repeated chunks → MultipleChunks; ANMF →
//     non-contiguous; unknown chunks → UnsupportedChunk (config-controlled)
//  6. No trailing bytes past RIFF payload; odd-length pad byte must be 0x00
//
// Rust source: webpsan/src/lib.rs (sanitize_with_config, sanitize_extended,
// sanitize_still, sanitize_animated)
func sanitizeWebP(data []byte) (*ValidateResult, error) {
	if err := validateWebPStructure(data); err != nil {
		return nil, err
	}

	out := make([]byte, len(data))
	copy(out, data)

	return &ValidateResult{
		MediaType:        MediaTypeWebP,
		Validated:        out,
		OriginalSize:     int64(len(data)),
		MetadataStripped: false,
	}, nil
}

// webpChunkReader is a cursor over a bounded RIFF payload region, providing
// chunk-by-chunk iteration matching webpsan's ChunkReader contract.
//
// The reader enforces:
//   - No reads past payloadEnd
//   - Odd-length pad byte must be 0x00 (webpsan/src/reader.rs:232)
//   - Exact payload consumption (no trailing bytes within the region)
type webpChunkReader struct {
	data       []byte
	payloadEnd int64
	pos        int64
}

// webpChunk holds the parsed header fields of a single RIFF chunk.
type webpChunk struct {
	fourcc    string
	dataStart int64
	dataEnd   int64
	nextPos   int64 // position after optional pad byte
}

// hasRemaining reports whether there are unread bytes in this reader's region.
// Mirrors webpsan ChunkReader::has_remaining.
func (r *webpChunkReader) hasRemaining() bool {
	return r.pos < r.payloadEnd
}

// readAnyHeader reads the next 8-byte chunk header and returns it.
// Returns an error if the header is truncated or the chunk body would exceed
// the payload boundary.
// Mirrors webpsan ChunkReader::read_any_header.
func (r *webpChunkReader) readAnyHeader() (webpChunk, error) {
	const headerLen = 8

	if r.pos+headerLen > r.payloadEnd {
		return webpChunk{}, &MediaValidationError{Detail: "WebP truncated chunk header"}
	}

	fourcc := string(r.data[r.pos : r.pos+4])
	chunkSize := int64(binary.LittleEndian.Uint32(r.data[r.pos+4 : r.pos+8]))
	dataStart := r.pos + headerLen
	dataEnd := dataStart + chunkSize

	if dataEnd > r.payloadEnd {
		return webpChunk{}, &MediaValidationError{
			Detail: "WebP chunk '" + fourcc + "' extends beyond RIFF payload",
		}
	}

	// Compute padded next position.
	nextPos := dataEnd
	if chunkSize%2 != 0 {
		nextPos++
	}
	if nextPos > r.payloadEnd {
		return webpChunk{}, &MediaValidationError{
			Detail: "WebP chunk '" + fourcc + "' padded extent beyond RIFF payload",
		}
	}

	r.pos = dataStart
	return webpChunk{
		fourcc:    fourcc,
		dataStart: dataStart,
		dataEnd:   dataEnd,
		nextPos:   nextPos,
	}, nil
}

// peekFourCC returns the fourcc of the next chunk without advancing the
// position, or "" if no more chunks are available.
// Mirrors webpsan ChunkReader::peek_header.
func (r *webpChunkReader) peekFourCC() (string, error) {
	if r.pos+8 > r.payloadEnd {
		if r.pos >= r.payloadEnd {
			return "", nil
		}
		return "", &MediaValidationError{Detail: "WebP truncated chunk header"}
	}
	return string(r.data[r.pos : r.pos+4]), nil
}

// skipChunk advances past the chunk body and verifies the pad byte.
// Must be called after readAnyHeader sets r.pos to dataStart.
// Mirrors webpsan ChunkReader::skip_data + read_padding.
func (r *webpChunkReader) skipChunk(ch webpChunk) error {
	if ch.nextPos > ch.dataEnd {
		// There is a pad byte — validate it.
		// webpsan/src/reader.rs:232: ensure_matches_attach!(pad, 0, ...)
		if ch.dataEnd >= r.payloadEnd {
			return &MediaValidationError{
				Detail: "WebP chunk '" + ch.fourcc + "' missing pad byte",
			}
		}
		pad := r.data[ch.dataEnd]
		if pad != 0x00 {
			return &MediaValidationError{
				Detail: "WebP chunk '" + ch.fourcc + "' pad byte is not 0x00",
			}
		}
	}
	r.pos = ch.nextPos
	return nil
}

// chunkData returns the slice of the chunk body.
func (r *webpChunkReader) chunkData(ch webpChunk) []byte {
	return r.data[ch.dataStart:ch.dataEnd]
}

// validateWebPStructure faithfully mirrors the webpsan 0.5.3 sanitize_with_config
// state machine.
//
// Oracle: webpsan/src/lib.rs:108–177 (sanitize_with_config)
func validateWebPStructure(data []byte) error {
	const riffHeaderLen = 12 // "RIFF" + 4-byte LE size + "WEBP"

	if len(data) < riffHeaderLen {
		return ErrInvalidWebP
	}

	// Validate "RIFF" magic.
	// webpsan/src/lib.rs:110 — file_reader.read_header(RIFF)
	if !bytes.HasPrefix(data, riffMagic) {
		return &MediaValidationError{Detail: "WebP: expected RIFF header"}
	}

	// Validate "WEBP" fourcc at offset 8.
	// webpsan/src/lib.rs:111 — file_reader.parse_data() → WebpChunk
	if !bytes.Equal(data[8:12], webpMagic) {
		return &MediaValidationError{Detail: "WebP: missing WEBP fourcc"}
	}

	// riffPayloadSize is the 4-byte LE field at offset 4. It covers everything
	// after the 8-byte "RIFF+size" header (i.e., starting at the "WEBP" fourcc).
	riffPayloadSize := uint64(binary.LittleEndian.Uint32(data[4:8]))

	// MAX_FILE_LEN check: webpsan/src/lib.rs:113–117
	// ensure_attach!(len <= MAX_FILE_LEN.into(), ...)
	if riffPayloadSize > maxWebPFileLen {
		return &MediaValidationError{Detail: "WebP: RIFF payload exceeds MAX_FILE_LEN"}
	}

	// Declared total file size = 8 (RIFF header) + riffPayloadSize.
	declaredTotal := int64(8) + int64(riffPayloadSize)

	if declaredTotal > int64(len(data)) {
		return &MediaValidationError{Detail: "WebP: declared RIFF size exceeds actual data length"}
	}

	// Reject extra unparsed input past the declared RIFF payload.
	// webpsan/src/lib.rs:170–174 — ensure_attach!(!file_reader.has_remaining()?, ...)
	if declaredTotal < int64(len(data)) {
		return &MediaValidationError{Detail: "WebP: trailing bytes after declared RIFF payload"}
	}

	// The RIFF payload starts at offset 12 (after "RIFF"+size+"WEBP").
	// payloadEnd is the byte boundary of the RIFF content region.
	payloadEnd := declaredTotal

	reader := &webpChunkReader{
		data:       data,
		payloadEnd: payloadEnd,
		pos:        riffHeaderLen,
	}

	// Read the first chunk. webpsan/src/lib.rs:123–151
	if !reader.hasRemaining() {
		// Empty file — no chunks at all.
		// webpsan: read_any_header returns InvalidChunkLayout when no data remains.
		return &MediaValidationError{Detail: "WebP: no chunks found (InvalidChunkLayout: expected image data or VP8X)"}
	}

	ch, err := reader.readAnyHeader()
	if err != nil {
		return err
	}

	switch ch.fourcc {
	case "VP8 ":
		// Simple lossy: skip body.
		// webpsan/src/lib.rs:125–128
		if err := reader.skipChunk(ch); err != nil {
			return err
		}

	case "VP8L":
		// Simple lossless: validate header + full bitstream.
		// webpsan/src/lib.rs:129–134
		// Vp8lChunk::parse (header) then sanitize_image_data (image stream).
		payload := reader.chunkData(ch)
		if err := validateVP8LHeader(payload); err != nil {
			return err
		}
		w, h, err := vp8lDimensions(payload)
		if err != nil {
			return err
		}
		if err := sanitizeVP8LImageData(payload, w, h); err != nil {
			return &MediaValidationError{Detail: "WebP: VP8L image data invalid: " + err.Error()}
		}
		if err := reader.skipChunk(ch); err != nil {
			return err
		}

	case "VP8X":
		// Extended file format.
		// webpsan/src/lib.rs:136–141
		vp8x, err := parseVP8XChunk(reader.chunkData(ch))
		if err != nil {
			return err
		}
		if err := reader.skipChunk(ch); err != nil {
			return err
		}
		if err := sanitizeWebPExtended(reader, vp8x); err != nil {
			return err
		}
		// Extended files consume everything in the state machine; remaining
		// chunks (trailing after XMP) fall through to the loop below.
		// After sanitize_extended returns successfully, the reader is positioned
		// past the last expected chunk; the trailing-chunk loop below handles any
		// extra data within the RIFF payload.

	default:
		// webpsan/src/lib.rs:143–149
		// bail_attach!(ParseError::InvalidChunkLayout, "expected image data or VP8X", ...)
		return &MediaValidationError{
			Detail: "WebP: InvalidChunkLayout: expected image data or VP8X, got '" + ch.fourcc + "'",
		}
	}

	// After the image data, only unknown chunks may trail (for simple-format
	// files). Known chunks that repeat → MultipleChunks; ANMF → non-contiguous.
	// webpsan/src/lib.rs:154–168
	for reader.hasRemaining() {
		ch, err := reader.readAnyHeader()
		if err != nil {
			return err
		}
		switch ch.fourcc {
		case "ALPH", "ANIM", "EXIF", "ICCP", "VP8 ", "VP8L", "VP8X", "XMP ":
			return &MediaValidationError{
				Detail: "WebP: MultipleChunks('" + ch.fourcc + "')",
			}
		case "ANMF":
			return &MediaValidationError{Detail: "WebP: non-contiguous ANMF chunk"}
		default:
			// Unknown chunk: webpsan rejects unless allow_unknown_chunks=true.
			// Go implementation uses the default config (allow_unknown_chunks=false).
			return &MediaValidationError{
				Detail: "WebP: UnsupportedChunk('" + ch.fourcc + "')",
			}
		}
	}

	return nil
}

// vp8xState holds the parsed VP8X chunk fields used by the extended sanitizer.
type vp8xState struct {
	flags        byte
	canvasWidth  uint32 // actual width (stored+1), 1..16384
	canvasHeight uint32 // actual height (stored+1), 1..16384
}

// parseVP8XChunk parses the 10-byte VP8X chunk payload.
//
// Layout (webpsan/src/parse/vp8x.rs):
//
//	byte 0:   flags
//	bytes 1-3: reserved (must be 0)
//	bytes 4-6: canvas_width  as OneBasedU24 (stored = actual-1)
//	bytes 7-9: canvas_height as OneBasedU24 (stored = actual-1)
//
// OneBasedU24: stored value is (actual-1), so actual = stored+1.
// webpsan/src/parse/vp8x.rs:49–63
func parseVP8XChunk(payload []byte) (vp8xState, error) {
	if len(payload) != 10 {
		return vp8xState{}, &MediaValidationError{Detail: "WebP: VP8X chunk must be exactly 10 bytes"}
	}

	// Reserved bytes 1-3 must be zero.
	// webpsan/src/parse/vp8x.rs:54 — Reserved::parse
	if payload[1] != 0 || payload[2] != 0 || payload[3] != 0 {
		return vp8xState{}, &MediaValidationError{Detail: "WebP: VP8X reserved bytes must be zero"}
	}

	// Canvas width: OneBasedU24 stored as (actual-1), so actual = stored+1.
	// webpsan/src/parse/vp8x.rs:55 — OneBasedU24::parse for canvas_width
	storedW := uint32(payload[4]) | uint32(payload[5])<<8 | uint32(payload[6])<<16
	storedH := uint32(payload[7]) | uint32(payload[8])<<8 | uint32(payload[9])<<16

	// webpsan 0.5.3 uses NonZeroU32 for canvas dimensions: only the zero-value
	// is rejected; there is no upper-dimension cap beyond the pixel-count check
	// below.  storedW and storedH are parsed from 24-bit fields so their maximum
	// is 0xFFFFFF; actual = stored+1 is always in [1, 16777216].
	//
	// webpsan/src/parse/vp8x.rs — OneBasedU24::parse (no dimension cap)

	// Pixel count overflow check.
	// webpsan/src/parse/vp8x.rs:57–60 — canvas_height.get().checked_mul(canvas_width.get())
	w := storedW + 1
	h := storedH + 1
	if uint64(w)*uint64(h) > uint64(0xFFFFFFFF) {
		return vp8xState{}, &MediaValidationError{Detail: "WebP: VP8X canvas pixel count overflow"}
	}

	return vp8xState{flags: payload[0], canvasWidth: w, canvasHeight: h}, nil
}

// validateVP8LHeader validates the VP8L bitstream header.
//
// VP8L header layout (webpsan/src/parse/vp8l.rs):
//
//	byte 0:    signature (must be 0x2F)
//	bits 8–21: width-1 (14 bits, LE bit order)
//	bits 22–35: height-1 (14 bits)
//	bit 36:    alpha_is_used
//	bits 37–39: version (must be 0)
//
// Width and height are extracted as (stored+1), each in range 1..16384.
// The Go implementation validates the signature byte and version field only;
// full bitstream decode is not feasible without a VP8L codec.
//
// webpsan/src/parse/vp8l.rs:64–85
func validateVP8LHeader(payload []byte) error {
	if len(payload) < 5 {
		return &MediaValidationError{Detail: "WebP: VP8L chunk too short for header"}
	}

	// Signature byte must be 0x2F.
	// webpsan/src/parse/vp8l.rs:69–75
	if payload[0] != vp8lSignature {
		return &MediaValidationError{
			Detail: "WebP: invalid VP8L signature: expected 0x2F",
		}
	}

	// Version field: bits 37-39 (within bytes 4-5), must be 0.
	// The 5 header bytes encode: sig(8) + width(14) + height(14) + alpha(1) + version(3) = 40 bits.
	// Version occupies the top 3 bits of byte 4 (bits 37-39 of the 40-bit window).
	// webpsan/src/parse/vp8l.rs:81–82 — reader.read(3) after alpha bit
	version := (payload[4] >> 5) & 0x07
	if version != 0 {
		return &MediaValidationError{
			Detail: "WebP: VP8L unsupported version",
		}
	}

	return nil
}

// sanitizeWebPExtended implements the VP8X extended-file-format state machine,
// faithfully porting webpsan/src/lib.rs:sanitize_extended.
//
// Order enforced (webpsan/src/lib.rs:179–205):
//  1. ICCP chunk — present iff HAS_ICCP_CHUNK flag
//  2. Image data — animated (ANIM + ≥1 ANMF) OR still (optional ALPH + VP8/VP8L)
//  3. EXIF chunk — present iff HAS_EXIF_CHUNK flag
//  4. XMP chunk  — present iff HAS_XMP_CHUNK flag
func sanitizeWebPExtended(reader *webpChunkReader, vp8x vp8xState) error {
	// 1. ICCP — present iff HAS_ICCP flag.
	// webpsan/src/lib.rs:180–184
	if vp8x.flags&vp8xFlagICCP != 0 {
		ch, err := reader.readAnyHeader()
		if err != nil {
			return &MediaValidationError{Detail: "WebP: expected ICCP chunk: " + err.Error()}
		}
		if ch.fourcc != "ICCP" {
			return &MediaValidationError{
				Detail: "WebP: InvalidChunkLayout: expected ICCP, got '" + ch.fourcc + "'",
			}
		}
		if err := reader.skipChunk(ch); err != nil {
			return err
		}
	}

	// 2. Image data — animated or still.
	// webpsan/src/lib.rs:186–190
	if vp8x.flags&vp8xFlagAnim != 0 {
		if err := sanitizeWebPAnimated(reader, vp8x); err != nil {
			return err
		}
	} else {
		if err := sanitizeWebPStill(reader, vp8x); err != nil {
			return err
		}
	}

	// 3. EXIF — present iff HAS_EXIF flag.
	// webpsan/src/lib.rs:192–196
	if vp8x.flags&vp8xFlagEXIF != 0 {
		ch, err := reader.readAnyHeader()
		if err != nil {
			return &MediaValidationError{Detail: "WebP: expected EXIF chunk: " + err.Error()}
		}
		if ch.fourcc != "EXIF" {
			return &MediaValidationError{
				Detail: "WebP: InvalidChunkLayout: expected EXIF, got '" + ch.fourcc + "'",
			}
		}
		if err := reader.skipChunk(ch); err != nil {
			return err
		}
	}

	// 4. XMP — present iff HAS_XMP flag.
	// webpsan/src/lib.rs:198–202
	if vp8x.flags&vp8xFlagXMP != 0 {
		ch, err := reader.readAnyHeader()
		if err != nil {
			return &MediaValidationError{Detail: "WebP: expected XMP chunk: " + err.Error()}
		}
		if ch.fourcc != "XMP " {
			return &MediaValidationError{
				Detail: "WebP: InvalidChunkLayout: expected XMP, got '" + ch.fourcc + "'",
			}
		}
		if err := reader.skipChunk(ch); err != nil {
			return err
		}
	}

	return nil
}

// sanitizeWebPStill validates still-image data in an extended WebP file.
//
// webpsan/src/lib.rs:207–247 (sanitize_still)
//
// Order:
//  1. Optional ALPH chunk — required iff HAS_ALPH flag
//  2. VP8 or VP8L bitstream chunk (required; VP8L forbidden when ALPH present)
//     When VP8L: dims must match canvas (webpsan enforces this)
func sanitizeWebPStill(reader *webpChunkReader, vp8x vp8xState) error {
	var hasAlph bool

	// 1. ALPH — present iff HAS_ALPH flag.
	// webpsan/src/lib.rs:208–216
	if vp8x.flags&vp8xFlagAlpha != 0 {
		ch, err := reader.readAnyHeader()
		if err != nil {
			return &MediaValidationError{Detail: "WebP: expected ALPH chunk: " + err.Error()}
		}
		if ch.fourcc != "ALPH" {
			return &MediaValidationError{
				Detail: "WebP: InvalidChunkLayout: expected ALPH, got '" + ch.fourcc + "'",
			}
		}
		// Validate ALPH image data if COMPRESS_LOSSLESS flag is set.
		// alph.rs:39-47 — AlphChunk::sanitize_image_data.
		if err := validateALPHChunkData(reader.chunkData(ch), vp8x); err != nil {
			return err
		}
		if err := reader.skipChunk(ch); err != nil {
			return err
		}
		hasAlph = true
	}

	// 2. Bitstream chunk — VP8 or VP8L required.
	// webpsan/src/lib.rs:218–246
	if !reader.hasRemaining() {
		return &MediaValidationError{Detail: "WebP: MissingRequiredChunk(VP8)"}
	}
	ch, err := reader.readAnyHeader()
	if err != nil {
		return err
	}
	switch ch.fourcc {
	case "VP8 ":
		// Lossy: skip body.
		if err := reader.skipChunk(ch); err != nil {
			return err
		}

	case "VP8L":
		// Lossless: VP8L must NOT appear when ALPH is present.
		// webpsan/src/lib.rs:226–227 — ensure_matches_attach!(alph, None, ...)
		if hasAlph {
			return &MediaValidationError{
				Detail: "WebP: InvalidChunkLayout: VP8L not allowed with ALPH chunk",
			}
		}
		// VP8L dims must match canvas dims.
		// webpsan/src/lib.rs:228–235
		payload := reader.chunkData(ch)
		if err := validateVP8LDimsMatchCanvas(payload, vp8x); err != nil {
			return err
		}
		// Full VP8L bitstream validation — vp8l.rs:52-56 sanitize_image_data.
		w, h, err := vp8lDimensions(payload)
		if err != nil {
			return err
		}
		if err := sanitizeVP8LImageData(payload, w, h); err != nil {
			return &MediaValidationError{Detail: "WebP: VP8L image data invalid: " + err.Error()}
		}
		if err := reader.skipChunk(ch); err != nil {
			return err
		}

	default:
		return &MediaValidationError{
			Detail: "WebP: InvalidChunkLayout: expected image data, got '" + ch.fourcc + "'",
		}
	}

	return nil
}

// sanitizeWebPAnimated validates animated WebP image data.
//
// webpsan/src/lib.rs:249–333 (sanitize_animated)
//
// Order:
//  1. ANIM chunk (required)
//  2. At least one ANMF frame (required)
//  3. Each frame: optional ALPH (if HAS_ALPH and frame has it) + VP8/VP8L
func sanitizeWebPAnimated(reader *webpChunkReader, vp8x vp8xState) error {
	// 1. ANIM — required.
	// webpsan/src/lib.rs:250–252
	ch, err := reader.readAnyHeader()
	if err != nil {
		return &MediaValidationError{Detail: "WebP: expected ANIM chunk: " + err.Error()}
	}
	if ch.fourcc != "ANIM" {
		return &MediaValidationError{
			Detail: "WebP: InvalidChunkLayout: expected ANIM, got '" + ch.fourcc + "'",
		}
	}
	// ANIM payload must be at least 6 bytes (4 bg_color + 2 loop_count).
	// webpsan/src/parse/anim.rs:23 — ENCODED_LEN = u32::ENCODED_LEN + u16::ENCODED_LEN
	if ch.dataEnd-ch.dataStart < 6 {
		return &MediaValidationError{Detail: "WebP: ANIM chunk too short"}
	}
	if err := reader.skipChunk(ch); err != nil {
		return err
	}

	// 2. At least one ANMF required.
	// webpsan/src/lib.rs:254–258
	nextFourCC, err := reader.peekFourCC()
	if err != nil {
		return err
	}
	if nextFourCC != "ANMF" {
		return &MediaValidationError{Detail: "WebP: MissingRequiredChunk(ANMF)"}
	}

	// 3. Process frames.
	// webpsan/src/lib.rs:260–332
	for {
		nextFourCC, err := reader.peekFourCC()
		if err != nil {
			return err
		}
		if nextFourCC != "ANMF" {
			break
		}

		ch, err := reader.readAnyHeader()
		if err != nil {
			return err
		}

		// ANMF payload must be at least 16 bytes: x(3)+y(3)+w(3)+h(3)+dur(3)+flags(1) = 16.
		// webpsan/src/parse/anmf.rs:60–65 — ENCODED_LEN
		if ch.dataEnd-ch.dataStart < 16 {
			return &MediaValidationError{Detail: "WebP: ANMF chunk too short"}
		}

		// Build a child reader for the ANMF frame body (after the 16-byte header).
		// webpsan/src/lib.rs:269 — reader.child_reader()
		framePayload := &webpChunkReader{
			data:       reader.data,
			payloadEnd: ch.dataEnd,
			pos:        ch.dataStart + 16,
		}

		if err := reader.skipChunk(ch); err != nil {
			return err
		}

		// Within each frame: optional ALPH + VP8/VP8L.
		// webpsan/src/lib.rs:271–311
		if err := sanitizeWebPFrame(framePayload, vp8x); err != nil {
			return err
		}

		// Remaining content within the frame: only unknown chunks allowed.
		// webpsan/src/lib.rs:313–331
		for framePayload.hasRemaining() {
			fch, err := framePayload.readAnyHeader()
			if err != nil {
				return err
			}
			switch fch.fourcc {
			case "ALPH", "ANMF", "ANIM", "EXIF", "ICCP", "VP8 ", "VP8L", "VP8X", "XMP ":
				return &MediaValidationError{
					Detail: "WebP: MultipleChunks('" + fch.fourcc + "') in ANMF",
				}
			default:
				return &MediaValidationError{
					Detail: "WebP: UnsupportedChunk('" + fch.fourcc + "') in ANMF",
				}
			}
		}
	}

	return nil
}

// sanitizeWebPFrame validates a single animation frame body.
//
// webpsan/src/lib.rs:271–311 (inside sanitize_animated ANMF loop)
//
// Frame body layout: optional ALPH (if HAS_ALPH and frame starts with ALPH) + VP8/VP8L.
func sanitizeWebPFrame(frame *webpChunkReader, vp8x vp8xState) error {
	var hasAlph bool

	// Optional ALPH — only if HAS_ALPH flag set and the frame actually has one.
	// webpsan/src/lib.rs:271–281 (alph peek)
	if vp8x.flags&vp8xFlagAlpha != 0 {
		nextFourCC, err := frame.peekFourCC()
		if err != nil {
			return err
		}
		if nextFourCC == "ALPH" {
			ch, err := frame.readAnyHeader()
			if err != nil {
				return err
			}
			// Validate ALPH image data if COMPRESS_LOSSLESS flag is set.
			// alph.rs:39-47 — AlphChunk::sanitize_image_data.
			if err := validateALPHChunkData(frame.chunkData(ch), vp8x); err != nil {
				return err
			}
			if err := frame.skipChunk(ch); err != nil {
				return err
			}
			hasAlph = true
		}
	}

	// Bitstream — VP8 or VP8L required.
	// webpsan/src/lib.rs:283–311
	if !frame.hasRemaining() {
		return &MediaValidationError{Detail: "WebP: ANMF frame missing image data"}
	}
	ch, err := frame.readAnyHeader()
	if err != nil {
		return err
	}
	switch ch.fourcc {
	case "VP8 ":
		if err := frame.skipChunk(ch); err != nil {
			return err
		}

	case "VP8L":
		// VP8L not allowed when ALPH is present.
		// webpsan/src/lib.rs:291–292
		if hasAlph {
			return &MediaValidationError{
				Detail: "WebP: InvalidChunkLayout: VP8L not allowed with ALPH chunk in ANMF",
			}
		}
		// VP8L dims must match canvas.
		// webpsan/src/lib.rs:294–301
		payload := frame.chunkData(ch)
		if err := validateVP8LDimsMatchCanvas(payload, vp8x); err != nil {
			return err
		}
		// Full VP8L bitstream validation — vp8l.rs:52-56 sanitize_image_data.
		fw, fh, err := vp8lDimensions(payload)
		if err != nil {
			return err
		}
		if err := sanitizeVP8LImageData(payload, fw, fh); err != nil {
			return &MediaValidationError{Detail: "WebP: VP8L image data invalid in ANMF: " + err.Error()}
		}
		if err := frame.skipChunk(ch); err != nil {
			return err
		}

	default:
		// Unexpected chunk order (e.g. ALPH after VP8L).
		// webpsan/src/lib.rs:306–310
		if !hasAlph && ch.fourcc == "ALPH" {
			// ALPH appeared after VP8/VP8L or out of order
			return &MediaValidationError{
				Detail: "WebP: InvalidChunkLayout: unexpected ALPH in ANMF (no HAS_ALPH flag)",
			}
		}
		return &MediaValidationError{
			Detail: "WebP: InvalidChunkLayout: expected image data in ANMF, got '" + ch.fourcc + "'",
		}
	}

	return nil
}

// validateVP8LDimsMatchCanvas checks that the VP8L bitstream width/height match
// the VP8X canvas dimensions.
//
// VP8L header bit layout (vp8l.rs:66-85, LE bit order):
//
//	bits  0– 7: signature (byte 0)
//	bits  8–21: width-1 (14 bits)
//	bits 22–35: height-1 (14 bits)
//	bit  36:    alpha_is_used
//	bits 37–39: version
//
// Width-1 spans bits 8-21: bytes 1-2 and 2 low bits of byte 3.
// Height-1 spans bits 22-35: upper 6 bits of byte 3, all of byte 4, and 2 bits of byte 5.
//
// webpsan/src/parse/vp8l.rs:67–85
// webpsan/src/lib.rs:228–235 and 294–301
func validateVP8LDimsMatchCanvas(payload []byte, vp8x vp8xState) error {
	if err := validateVP8LHeader(payload); err != nil {
		return err
	}
	if len(payload) < 5 {
		return &MediaValidationError{Detail: "WebP: VP8L chunk too short"}
	}

	// Extract width-1 from bits 8-21 (LE bit order).
	// Byte layout of the 5 header bytes, reading LE bits:
	//   payload[0] = bits  0-7  (signature)
	//   payload[1] = bits  8-15
	//   payload[2] = bits 16-23
	//   payload[3] = bits 24-31
	//   payload[4] = bits 32-39
	//
	// width-1  = bits[8..22]  = payload[1] | (payload[2] & 0x3F) << 8
	// height-1 = bits[22..36] = (payload[2] >> 6) | payload[3] << 2 | (payload[4] & 0x0F) << 10
	//
	// This matches the BitReader LE read pattern in vp8l.rs:
	//   reader.read(14) for width, reader.read(14) for height.
	widthMinus1 := uint32(payload[1]) | uint32(payload[2]&0x3F)<<8
	heightMinus1 := uint32(payload[2]>>6) | uint32(payload[3])<<2 | uint32(payload[4]&0x0F)<<10

	width := widthMinus1 + 1
	height := heightMinus1 + 1

	if width != vp8x.canvasWidth || height != vp8x.canvasHeight {
		return &MediaValidationError{
			Detail: "WebP: VP8L dimensions do not match VP8X canvas",
		}
	}
	return nil
}

// vp8lDimensions extracts width and height from the 5-byte VP8L header.
// The caller must have already validated the header via validateVP8LHeader.
// Returns width and height in the range [1, 16384].
//
// VP8L bit layout (LE bit order):
//
//	bits  0– 7: signature (byte 0)
//	bits  8–21: width-1 (14 bits)
//	bits 22–35: height-1 (14 bits)
//
// Matches vp8l.rs:76-78 — reader.read(14) for width, reader.read(14) for height.
func vp8lDimensions(payload []byte) (width, height uint32, err error) {
	if len(payload) < 5 {
		return 0, 0, &MediaValidationError{Detail: "WebP: VP8L chunk too short"}
	}
	widthMinus1 := uint32(payload[1]) | uint32(payload[2]&0x3F)<<8
	heightMinus1 := uint32(payload[2]>>6) | uint32(payload[3])<<2 | uint32(payload[4]&0x0F)<<10
	return widthMinus1 + 1, heightMinus1 + 1, nil
}

// alphCompressLossless is the ALPH chunk COMPRESS_LOSSLESS flag value.
// alph.rs:32 — COMPRESS_LOSSLESS = 0b0000_0001
const alphCompressLossless = 0x01

// validateALPHChunkData validates ALPH chunk image data.
// If the COMPRESS_LOSSLESS flag is set, the alpha plane is a VP8L lossless
// image stream (without a 0x2F VP8L header) using vp8x canvas dimensions.
//
// alph.rs:39-47 — AlphChunk::sanitize_image_data.
// ALPH chunk layout: byte 0 = flags, bytes 1.. = image stream.
func validateALPHChunkData(data []byte, vp8x vp8xState) error {
	if len(data) == 0 {
		return nil
	}
	flags := data[0]
	if flags&alphCompressLossless != 0 {
		// The alpha image stream starts at byte 1 (after the flags byte).
		// alph.rs:43-44: LosslessImage::read(&mut reader, width, height)
		alphaStream := data[1:]
		if err := sanitizeALPHImageData(alphaStream, vp8x.canvasWidth, vp8x.canvasHeight); err != nil {
			return &MediaValidationError{Detail: "WebP: ALPH image data invalid: " + err.Error()}
		}
	}
	return nil
}

// ValidateMP4 performs deep structural validation of an MP4 file using
// github.com/Eyevinn/mp4ff. It parses the full ISO BMFF box tree, enforces
// maxMetadataSize (300 MiB) on the moov box, and validates both ftyp and moov
// are present.
//
// Rust source: libsignal crate mp4san — structural validation of ISO BMFF
// containers.
func ValidateMP4(data []byte) error {
	_, err := sanitizeMP4(data)
	return err
}

// ValidateWebP performs full RIFF chunk-structure validation of a WebP file.
// It validates the RIFF header, WEBP fourcc, and walks every chunk verifying
// lengths stay within the declared RIFF payload boundary. Every chunk type
// is validated against the known WebP chunk vocabulary.
//
// Rust source: libsignal crate webpsan — structural validation of WebP
// containers.
func ValidateWebP(data []byte) error {
	return validateWebPStructure(data)
}

// SanitizeWebP validates the structural integrity of a WebP input and returns
// a typed parse error if the input is malformed.
//
// This matches the webpsan contract: the function simply checks validity; it
// does not return any data because a valid WebP file is already in the correct
// format.
//
// Java oracle: WebpSanitizer.java:L32–L37
func SanitizeWebP(input []byte) error {
	return validateWebPStructure(input)
}
