package media

import (
	"bytes"
	"encoding/binary"
	"io"

	mp4 "github.com/Eyevinn/mp4ff/mp4"

	"github.com/jeremyhahn/go-libsignal/pkg/media/goextensions"
)

// maxMetadataSize bounds MP4 metadata memory, as Rust mp4san MAX_METADATA_SIZE.
const maxMetadataSize = 300 * 1024 * 1024

// maxWebPFileLen is webpsan MAX_FILE_LEN (u32::MAX - 2).
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

// vp8lSignature is the VP8L bitstream signature byte (webpsan vp8l.rs).
const vp8lSignature = 0x2F

// JPEG, PNG and GIF magic bytes for the Sanitize shim, copied from goextensions to avoid a dependency inversion.
var (
	shimJPEGMagic   = []byte{0xFF, 0xD8, 0xFF}
	shimPNGMagic    = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	shimGIF87aMagic = []byte("GIF87a")
	shimGIF89aMagic = []byte("GIF89a")
)

// isGoExtensionsType reports whether data starts with JPEG, PNG or GIF magic bytes.
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

// MediaType is a supported media type: MP4 and WebP here; JPEG, PNG and GIF are in pkg/media/goextensions.
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
	// Deprecated: use pkg/media/goextensions.MediaTypeJPEG.
	MediaTypeJPEG

	// MediaTypePNG indicates a PNG image routed through goextensions.
	//
	// Deprecated: use pkg/media/goextensions.MediaTypePNG.
	MediaTypePNG

	// MediaTypeGIF indicates a GIF image routed through goextensions.
	//
	// Deprecated: use pkg/media/goextensions.MediaTypeGIF.
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

	// Validated is the output: MP4 re-encoded with moov before mdat, WebP returned as-is after validation.
	Validated []byte

	// OriginalSize is the size of the original input data in bytes.
	OriginalSize int64

	// MetadataStripped is true for MP4 when moov was relocated, false for WebP.
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

// ErrMP4MetadataTooLarge indicates the moov box exceeds maxMetadataSize (300 MiB), as mp4san MAX_METADATA_SIZE.
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

// minDetectionSize is the bytes WebP detection needs: RIFF, size and WEBP.
const minDetectionSize = 12

// maxMediaSize is the maximum allowed input size for ValidateReader (100 MiB).
const maxMediaSize = 100 * 1024 * 1024

// DetectMediaType detects JPEG, PNG, GIF, WebP or MP4 by magic bytes, else MediaTypeUnknown; image types use the deprecated constants.
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

// Validate validates MP4 (moov re-encoded before mdat, 300 MiB metadata cap) or WebP (RIFF chunk walk); JPEG, PNG and GIF use goextensions.
func Validate(data []byte) (*ValidateResult, error) {
	if len(data) < 3 {
		return nil, ErrDataTooShort
	}

	mediaType := DetectMediaType(data)
	// JPEG, PNG and GIF belong to goextensions.Sanitize.
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

// SanitizeResult is the result of Sanitize; Sanitized carries the same data as ValidateResult.Validated.
//
// Deprecated: Use ValidateResult from Validate.
type SanitizeResult struct {
	// MediaType is the detected type of the input media.
	MediaType MediaType

	// Sanitized is the legacy field name for the output media bytes.
	// New code should use ValidateResult.Validated from Validate instead.
	Sanitized []byte

	// OriginalSize is the size of the original input data in bytes.
	OriginalSize int64

	// MetadataStripped is true for JPEG and PNG, and for MP4 when moov was relocated; false for WebP.
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

// Sanitize routes JPEG, PNG and GIF to goextensions.Sanitize and MP4 and WebP to Validate; other types return ErrUnsupportedMediaType.
//
// Deprecated: use pkg/media/goextensions for JPEG/PNG/GIF, or Validate for MP4/WebP.
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

// SanitizeReader reads at most maxMediaSize (100 MiB) from r and calls Sanitize; larger input returns ErrMediaTooLarge.
//
// Deprecated: for JPEG/PNG/GIF call pkg/media/goextensions.Sanitize; for MP4/WebP call ValidateReader.
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

// sanitizeMP4 validates MP4 through SanitizeMP4 and emits only ftyp+moov and the original mdat span (Rust mp4san, Java Mp4Sanitizer).
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
		// Already faststart: re-encode ftyp+moov to drop padding boxes.
		f, parseErr := mp4.DecodeFile(bytes.NewReader(data), mp4.WithDecodeMode(mp4.DecModeLazyMdat))
		if parseErr != nil {
			return nil, &MediaValidationError{Detail: "MP4 re-parse error: " + parseErr.Error()}
		}
		if f.Ftyp == nil || f.Moov == nil {
			return nil, &MediaValidationError{Detail: "MP4 missing ftyp or moov after validation"}
		}
		// Dropping free/skip boxes moves mdat, so stco/co64 entries are shifted by the same delta.
		metadataBytes, err = rewriteMetadataWithOffsets(f.Ftyp, f.Moov, sm.DataOffset)
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

// findMoovOffset returns the offset of the first top-level moov box, or 0.
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

// sanitizeWebP validates a WebP file with the webpsan 0.5.3 state machine (webpsan/src/lib.rs).
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

// webpChunkReader iterates chunks within a bounded RIFF payload, enforcing zero pad bytes and exact consumption (webpsan ChunkReader).
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

// readAnyHeader reads the next chunk header, failing if it or its body overruns the payload (webpsan read_any_header).
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

// validateWebPStructure ports webpsan 0.5.3 sanitize_with_config (webpsan/src/lib.rs:108-177).
func validateWebPStructure(data []byte) error {
	const riffHeaderLen = 12 // "RIFF" + 4-byte LE size + "WEBP"

	if len(data) < riffHeaderLen {
		return ErrInvalidWebP
	}

	// "RIFF" magic (webpsan lib.rs:110).
	if !bytes.HasPrefix(data, riffMagic) {
		return &MediaValidationError{Detail: "WebP: expected RIFF header"}
	}

	// "WEBP" fourcc at offset 8 (webpsan lib.rs:111).
	if !bytes.Equal(data[8:12], webpMagic) {
		return &MediaValidationError{Detail: "WebP: missing WEBP fourcc"}
	}

	// riffPayloadSize covers everything after the 8-byte RIFF header.
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

	// Reject input past the declared RIFF payload (webpsan lib.rs:170-174).
	if declaredTotal < int64(len(data)) {
		return &MediaValidationError{Detail: "WebP: trailing bytes after declared RIFF payload"}
	}

	// The RIFF payload starts at offset 12; payloadEnd is its end.
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
		// Chunks trailing the extended state machine are handled by the loop below.

	default:
		// webpsan/src/lib.rs:143–149
		// bail_attach!(ParseError::InvalidChunkLayout, "expected image data or VP8X", ...)
		return &MediaValidationError{
			Detail: "WebP: InvalidChunkLayout: expected image data or VP8X, got '" + ch.fourcc + "'",
		}
	}

	// After the image data only unknown chunks may trail; repeated known chunks and ANMF are errors (webpsan lib.rs:154-168).
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

// parseVP8XChunk parses the 10-byte VP8X payload: flags, 3 reserved zero bytes, and OneBasedU24 canvas width and height (webpsan vp8x.rs).
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

	// Canvas dimensions are 1..16777216 with no cap beyond the pixel-count check, as webpsan OneBasedU24.

	// Pixel count overflow check.
	// webpsan/src/parse/vp8x.rs:57–60 — canvas_height.get().checked_mul(canvas_width.get())
	w := storedW + 1
	h := storedH + 1
	if uint64(w)*uint64(h) > uint64(0xFFFFFFFF) {
		return vp8xState{}, &MediaValidationError{Detail: "WebP: VP8X canvas pixel count overflow"}
	}

	return vp8xState{flags: payload[0], canvasWidth: w, canvasHeight: h}, nil
}

// validateVP8LHeader checks the VP8L signature byte and version field (webpsan vp8l.rs:64-85).
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

	// Version is the top 3 bits of byte 4 and must be 0 (webpsan vp8l.rs:81-82).
	version := (payload[4] >> 5) & 0x07
	if version != 0 {
		return &MediaValidationError{
			Detail: "WebP: VP8L unsupported version",
		}
	}

	return nil
}

// sanitizeWebPExtended enforces ICCP, image data, EXIF, XMP order with presence matching the VP8X flags (webpsan sanitize_extended).
func sanitizeWebPExtended(reader *webpChunkReader, vp8x vp8xState) error {
	// ICCP iff HAS_ICCP (webpsan lib.rs:180-184).
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

	// EXIF iff HAS_EXIF (webpsan lib.rs:192-196).
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

// sanitizeWebPStill validates optional ALPH (iff HAS_ALPH) then VP8 or VP8L matching the canvas (webpsan sanitize_still).
func sanitizeWebPStill(reader *webpChunkReader, vp8x vp8xState) error {
	var hasAlph bool

	// ALPH iff HAS_ALPH (webpsan lib.rs:208-216).
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
		// Validate lossless ALPH image data (webpsan alph.rs:39-47).
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
		// VP8L must not follow ALPH (webpsan lib.rs:226-227).
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

// sanitizeWebPAnimated validates ANIM then one or more ANMF frames (webpsan sanitize_animated).
func sanitizeWebPAnimated(reader *webpChunkReader, vp8x vp8xState) error {
	// ANIM is required (webpsan lib.rs:250-252).
	ch, err := reader.readAnyHeader()
	if err != nil {
		return &MediaValidationError{Detail: "WebP: expected ANIM chunk: " + err.Error()}
	}
	if ch.fourcc != "ANIM" {
		return &MediaValidationError{
			Detail: "WebP: InvalidChunkLayout: expected ANIM, got '" + ch.fourcc + "'",
		}
	}
	// ANIM payload is at least 6 bytes (webpsan anim.rs:23).
	if ch.dataEnd-ch.dataStart < 6 {
		return &MediaValidationError{Detail: "WebP: ANIM chunk too short"}
	}
	if err := reader.skipChunk(ch); err != nil {
		return err
	}

	// At least one ANMF (webpsan lib.rs:254-258).
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

		// ANMF header is 16 bytes (webpsan anmf.rs:60-65).
		if ch.dataEnd-ch.dataStart < 16 {
			return &MediaValidationError{Detail: "WebP: ANMF chunk too short"}
		}

		// Child reader for the frame body (webpsan lib.rs:269).
		framePayload := &webpChunkReader{
			data:       reader.data,
			payloadEnd: ch.dataEnd,
			pos:        ch.dataStart + 16,
		}

		if err := reader.skipChunk(ch); err != nil {
			return err
		}

		// Each frame: optional ALPH then VP8 or VP8L (webpsan lib.rs:271-311).
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

// sanitizeWebPFrame validates one frame body: optional ALPH then VP8 or VP8L (webpsan lib.rs:271-311).
func sanitizeWebPFrame(frame *webpChunkReader, vp8x vp8xState) error {
	var hasAlph bool

	// Optional ALPH when HAS_ALPH is set and the frame has one (webpsan lib.rs:271-281).
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
			// Validate lossless ALPH image data (webpsan alph.rs:39-47).
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
		// VP8L must not follow ALPH (webpsan lib.rs:291-292).
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
		// Unexpected chunk order (webpsan lib.rs:306-310).
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

// validateVP8LDimsMatchCanvas checks the VP8L width and height equal the VP8X canvas (webpsan vp8l.rs:67-85, lib.rs:228-235).
func validateVP8LDimsMatchCanvas(payload []byte, vp8x vp8xState) error {
	if err := validateVP8LHeader(payload); err != nil {
		return err
	}
	if len(payload) < 5 {
		return &MediaValidationError{Detail: "WebP: VP8L chunk too short"}
	}

	// width-1 and height-1 are 14-bit little-endian fields at bits 8 and 22 (webpsan vp8l.rs).
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

// vp8lDimensions returns width and height (1..16384) from a validated 5-byte VP8L header.
func vp8lDimensions(payload []byte) (width, height uint32, err error) {
	if len(payload) < 5 {
		return 0, 0, &MediaValidationError{Detail: "WebP: VP8L chunk too short"}
	}
	widthMinus1 := uint32(payload[1]) | uint32(payload[2]&0x3F)<<8
	heightMinus1 := uint32(payload[2]>>6) | uint32(payload[3])<<2 | uint32(payload[4]&0x0F)<<10
	return widthMinus1 + 1, heightMinus1 + 1, nil
}

// alphCompressLossless is the ALPH COMPRESS_LOSSLESS flag (webpsan alph.rs:32).
const alphCompressLossless = 0x01

// validateALPHChunkData validates a lossless ALPH image stream at the canvas dimensions (webpsan alph.rs:39-47).
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

// ValidateMP4 parses the ISO BMFF box tree with mp4ff, requires ftyp and moov, and caps moov at 300 MiB.
func ValidateMP4(data []byte) error {
	_, err := sanitizeMP4(data)
	return err
}

// ValidateWebP validates the RIFF header, WEBP fourcc and every chunk's type and bounds.
func ValidateWebP(data []byte) error {
	return validateWebPStructure(data)
}

// SanitizeWebP returns a typed parse error if the WebP input is malformed (Java WebpSanitizer).
func SanitizeWebP(input []byte) error {
	return validateWebPStructure(input)
}
