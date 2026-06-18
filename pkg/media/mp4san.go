package media

// mp4san.go — behavior-exact port of the Rust libsignal mp4san crate.
//
// Rust source: libsignal/rust/media/src/sanitize/mp4.rs
// Java oracle: libsignal/java/client/src/main/java/org/signal/libsignal/media/Mp4Sanitizer.java
// Java oracle: libsignal/java/client/src/main/java/org/signal/libsignal/media/SanitizedMetadata.java

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"

	mp4 "github.com/Eyevinn/mp4ff/mp4"
)

// SanitizedMetadata is the result of MP4 sanitization, mirroring the Java
// SanitizedMetadata class (libsignal/java/.../media/SanitizedMetadata.java).
//
// Metadata is the self-contained, contiguous presentation metadata
// (ftyp + moov bytes) such that:
//
//	Metadata || input[DataOffset : DataOffset+DataLength]
//
// is a valid MP4 file.  Metadata is nil when the original input already has
// moov preceding mdat (faststart layout) and no rewrite is needed — the caller
// may use the original bytes directly.
//
// DataOffset and DataLength point at the contiguous mdat span in the
// ORIGINAL input, not in the rewritten output.
//
// Java oracle: SanitizedMetadata.java:L8–L46
type SanitizedMetadata struct {
	// Metadata is the sanitized presentation metadata (ftyp+moov), or nil when
	// the input needed no rewrite.
	//
	// Java oracle: Mp4Sanitizer.java:L68–L71 (nil when sanitizedMetadata.length == 0)
	Metadata []byte

	// DataOffset is the byte offset of the media data (mdat) in the original input.
	//
	// Java oracle: SanitizedMetadata.java:L32–L37
	DataOffset int64

	// DataLength is the byte length of the media data (mdat) in the original input.
	//
	// Java oracle: SanitizedMetadata.java:L40–L45
	DataLength int64
}

// ErrFragmentedMP4 is returned when the input is a fragmented MP4 (contains
// moof boxes).  Fragmented MP4 is not supported by mp4san.
//
// Java oracle: Mp4Sanitizer.java:L38
type ErrFragmentedMP4 struct{}

func (e *ErrFragmentedMP4) Error() string {
	return "media: fragmented MP4 is not supported"
}

// ErrDiscontiguousMdat is returned when mdat boxes are discontiguous (more
// than one mdat box not handled by the compounded-mdat variant).
//
// Java oracle: Mp4Sanitizer.java:L39
type ErrDiscontiguousMdat struct{}

func (e *ErrDiscontiguousMdat) Error() string {
	return "media: discontiguous mdat boxes are not supported"
}

// ErrExternalDataReference is returned when a dref box points to an external
// file rather than the current file.
//
// Java oracle: Mp4Sanitizer.java:L40
type ErrExternalDataReference struct{}

func (e *ErrExternalDataReference) Error() string {
	return "media: external data reference (dref) is not supported"
}

// ErrUnsupportedBrand is returned when the ftyp box does not contain "isom"
// in its compatible-brands list, i.e. the file is MOV or legacy MP4 v1.
//
// Java oracle: Mp4Sanitizer.java:L41–L43
type ErrUnsupportedBrand struct {
	Brand string
}

func (e *ErrUnsupportedBrand) Error() string {
	return "media: unsupported MP4 brand (not isom-compatible): " + e.Brand
}

// ErrMissingMdat is returned when no mdat box is found in the input.
type ErrMissingMdat struct{}

func (e *ErrMissingMdat) Error() string {
	return "media: MP4 missing mdat box"
}

// SanitizeMP4 sanitizes an MP4 input and returns a SanitizedMetadata value
// containing the presentation metadata and the mdat span in the original input.
//
// Metadata is nil when the input is already in faststart layout (moov before
// mdat) and needs no rewrite.  When non-nil, Metadata is the self-contained
// ftyp+moov block; the caller reconstructs the playable file as:
//
//	Metadata || input[DataOffset : DataOffset+DataLength]
//
// Fail-closed: returns a typed parse error for empty/truncated input, missing
// ftyp, missing "isom" compatible brand, fragmented MP4 (moof), discontiguous
// mdat, external dref, and missing moov.
//
// Java oracle: Mp4Sanitizer.java:L49–L78
// Java oracle: Mp4Sanitizer.java:L46 (class contract)
func SanitizeMP4(input []byte) (*SanitizedMetadata, error) {
	return sanitizeMP4Internal(input, -1)
}

// SanitizeMP4WithCompoundedMdat sanitizes an MP4 that has multiple mdat boxes
// compounded into a single contiguous region whose total byte length is
// cumulativeMdatBoxSize.  The mdat region in such a file uses size=0 (meaning
// "extends to end of file") in the box header, which is not supported by the
// normal parser path.
//
// The cumulativeMdatBoxSize parameter must equal the total byte length of the
// mdat region in the original file (i.e. the span from the start of the first
// mdat box header to the end of the last media-data byte).
//
// Java oracle: Mp4Sanitizer.java:L83–L115
func SanitizeMP4WithCompoundedMdat(input []byte, cumulativeMdatBoxSize int) (*SanitizedMetadata, error) {
	// Finding #2: reject cumulativeMdatBoxSize < 8 (too small for a valid mdat
	// box header) to prevent the infinite-loop / DoS path.
	if cumulativeMdatBoxSize < 8 {
		return nil, &MediaValidationError{Detail: "MP4 cumulativeMdatBoxSize too small (must be >= 8)"}
	}
	return sanitizeMP4Internal(input, int64(cumulativeMdatBoxSize))
}

// sanitizeMP4Internal is the shared implementation for SanitizeMP4 and
// SanitizeMP4WithCompoundedMdat.  cumulativeMdatBoxSize is -1 for the normal
// path; a non-negative value activates the compounded-mdat path.
func sanitizeMP4Internal(input []byte, cumulativeMdatBoxSize int64) (*SanitizedMetadata, error) {
	if len(input) == 0 {
		return nil, &MediaValidationError{Detail: "MP4 input is empty"}
	}
	if len(input) < 8 {
		return nil, &MediaValidationError{Detail: "MP4 input too short to contain a box header"}
	}

	// The compounded-mdat path requires a raw box scan because mp4ff rejects
	// size=0 boxes.  In the normal path we use mp4ff for its full ISO BMFF
	// parse; in the compounded path we do a manual scan.
	if cumulativeMdatBoxSize >= 0 {
		return sanitizeMP4Compounded(input, cumulativeMdatBoxSize)
	}

	// Normal path: full mp4ff parse.
	// Finding #5: use DecModeLazyMdat so that mdat payload bytes are not copied
	// into memory — we only need mdat's StartPos and Size, and the full moov tree.
	// DecModeLazyMdat requires an io.ReadSeeker; bytes.NewReader satisfies that.
	r := bytes.NewReader(input)
	f, err := mp4.DecodeFile(r, mp4.WithDecodeMode(mp4.DecModeLazyMdat))
	if err != nil {
		return nil, &MediaValidationError{Detail: "MP4 parse error: " + err.Error()}
	}

	// Reject fragmented MP4 (moof boxes present).
	// Java oracle: Mp4Sanitizer.java:L38
	if f.IsFragmented() {
		return nil, &ErrFragmentedMP4{}
	}

	// Validate ftyp presence and isom brand.
	// Java oracle: Mp4Sanitizer.java:L41–L43
	if f.Ftyp == nil {
		return nil, &MediaValidationError{Detail: "MP4 missing ftyp box"}
	}
	if err := validateIsomBrand(f.Ftyp); err != nil {
		return nil, err
	}

	// Validate moov presence.
	if f.Moov == nil {
		return nil, &MediaValidationError{Detail: "MP4 missing moov box"}
	}

	// Enforce the metadata size limit matching Rust mp4san's MAX_METADATA_SIZE.
	moovSize := f.Moov.Size()
	if moovSize > maxMetadataSize {
		return nil, &ErrMP4MetadataTooLarge{Size: moovSize}
	}

	// Reject external data references (dref pointing to separate files).
	// Java oracle: Mp4Sanitizer.java:L40
	if err := validateNoExternalDref(f.Moov); err != nil {
		return nil, err
	}

	// Locate the mdat box in Children (parse order).
	mdatBox, mdatIdx := findMdatInChildren(f.Children)
	if mdatBox == nil {
		return nil, &ErrMissingMdat{}
	}

	// Reject discontiguous mdat: more than one mdat box at the top level.
	// Java oracle: Mp4Sanitizer.java:L39
	if countMdatBoxes(f.Children) > 1 {
		return nil, &ErrDiscontiguousMdat{}
	}

	// Reject discontiguous layout: mdat interspersed with moov children means
	// boxes of other types appear between two mdat boxes. With a single mdat
	// box (already checked above) the only discontiguity concern is whether
	// moov boxes appear between mdat segments, which cannot happen with one mdat.
	// The mp4san definition also covers mdat interleaved with moov-level boxes;
	// we check that mdat is not split around moov at the top level.
	_ = mdatIdx // used above; position is tracked via StartPos below

	// DataOffset and DataLength refer to the ORIGINAL input byte stream.
	// mp4ff stores the decoded box start position as StartPos (set during decode).
	dataOffset := int64(mdatBox.StartPos)
	dataLength := int64(mdatBox.Size())

	// Guard: reject any mdat whose declared span extends beyond the input.
	// A crafted file can set mdat.Size() larger than the actual file, causing
	// an out-of-bounds slice panic at the call site.  We check using subtraction
	// to avoid int64 addition overflow when dataLength is near math.MaxInt64.
	if dataOffset < 0 || dataLength < 0 || dataLength > int64(len(input))-dataOffset {
		return nil, &MediaValidationError{Detail: "MP4 mdat span exceeds input bounds"}
	}

	// Determine whether moov precedes mdat in the original input.
	moovBeforeMdat := isMoovBeforeMdat(f)

	if moovBeforeMdat {
		// Already faststart: return nil Metadata so the caller can use the
		// original bytes without copying.
		// Java oracle: Mp4Sanitizer.java:L68–L71
		return &SanitizedMetadata{
			Metadata:   nil,
			DataOffset: dataOffset,
			DataLength: dataLength,
		}, nil
	}

	// moov follows mdat: build the rewritten metadata block (ftyp + moov) with
	// chunk-offset rewriting so that stco/co64 entries remain valid after moov
	// is relocated before mdat.
	//
	// Finding #1: shift every trak's stbl Stco/Co64 chunk offset by delta =
	// (new mdat box start) - (original mdat box start), where new mdat box
	// start = len(ftyp) + len(rewritten moov).  Promote stco→co64 when any
	// offset would overflow uint32 after the shift.
	metadata, err := rewriteMetadataWithOffsets(f.Ftyp, f.Moov, dataOffset)
	if err != nil {
		return nil, &MediaValidationError{Detail: "MP4 metadata re-encode error: " + err.Error()}
	}

	return &SanitizedMetadata{
		Metadata:   metadata,
		DataOffset: dataOffset,
		DataLength: dataLength,
	}, nil
}

// rewriteMetadataWithOffsets encodes ftyp and moov into a contiguous byte
// slice while adjusting every stco/co64 chunk-offset entry by the delta
// between the new mdat start position (= len(ftyp) + len(encoded moov)) and
// the original mdat start position (originalMdatOffset).
//
// The ISO BMFF spec (§8.7.5) requires chunk offsets to be absolute byte
// offsets from the start of the file.  When moov is relocated to precede mdat,
// the chunk offsets — which pointed at byte positions inside the original
// (mdat-first) file — become wrong by exactly the difference between the new
// and old mdat start positions.
//
// ISO BMFF §8.7.5 stco / §8.7.5 co64; Java oracle: Mp4Sanitizer.java:L49–L78
// (mp4san performs this rewrite transparently).
func rewriteMetadataWithOffsets(ftyp *mp4.FtypBox, moov *mp4.MoovBox, originalMdatOffset int64) ([]byte, error) {
	// Encode ftyp to learn its byte length (it never changes size).
	var ftypBuf bytes.Buffer
	if err := ftyp.Encode(&ftypBuf); err != nil {
		return nil, err
	}
	ftypLen := int64(ftypBuf.Len())

	// Fixed-point promotion loop:
	//
	// Each stco→co64 promotion grows moov (4 bytes per entry), which increases
	// delta, which can push previously-safe stco entries over the uint32 limit.
	// We therefore iterate until no remaining stco box needs promotion.
	//
	// Termination: each iteration promotes at least one stco to co64 and there
	// are finitely many traks, so the loop always terminates.
	//
	// After the loop every stco box is guaranteed to fit in uint32 with the
	// current delta, and every co64 box can hold uint64, so no overflow is
	// possible during the final apply step.

	type promotionCandidate struct {
		stbl *mp4.StblBox
		stco *mp4.StcoBox
	}

	newMdatStart := ftypLen + int64(moov.Size())
	delta := newMdatStart - originalMdatOffset

	for {
		var toPromote []promotionCandidate
		for _, trak := range moov.Traks {
			if trak.Mdia == nil || trak.Mdia.Minf == nil || trak.Mdia.Minf.Stbl == nil {
				continue
			}
			stbl := trak.Mdia.Minf.Stbl
			if stbl.Stco == nil {
				continue
			}
			for _, off := range stbl.Stco.ChunkOffset {
				newOff := int64(off) + delta
				if newOff > math.MaxUint32 || newOff < 0 {
					toPromote = append(toPromote, promotionCandidate{stbl: stbl, stco: stbl.Stco})
					break
				}
			}
		}
		if len(toPromote) == 0 {
			break
		}
		for _, p := range toPromote {
			co64 := &mp4.Co64Box{
				Version:     p.stco.Version,
				Flags:       p.stco.Flags,
				ChunkOffset: make([]uint64, len(p.stco.ChunkOffset)),
			}
			for i, v := range p.stco.ChunkOffset {
				co64.ChunkOffset[i] = uint64(v)
			}
			replaceStcoWithCo64(p.stbl, co64)
		}
		// Recompute delta with the now-larger moov.
		newMdatStart = ftypLen + int64(moov.Size())
		delta = newMdatStart - originalMdatOffset
	}

	// Apply delta to all stco and co64 boxes.
	for _, trak := range moov.Traks {
		if trak.Mdia == nil || trak.Mdia.Minf == nil || trak.Mdia.Minf.Stbl == nil {
			continue
		}
		stbl := trak.Mdia.Minf.Stbl
		if stbl.Stco != nil {
			for i := range stbl.Stco.ChunkOffset {
				stbl.Stco.ChunkOffset[i] = uint32(int64(stbl.Stco.ChunkOffset[i]) + delta)
			}
		}
		if stbl.Co64 != nil {
			for i := range stbl.Co64.ChunkOffset {
				stbl.Co64.ChunkOffset[i] = uint64(int64(stbl.Co64.ChunkOffset[i]) + delta)
			}
		}
	}

	// Encode the final metadata block.
	var buf bytes.Buffer
	buf.Write(ftypBuf.Bytes())
	if err := moov.Encode(&buf); err != nil {
		// Undo the offset adjustment to leave moov in a consistent state.
		undoOffsetAdjustment(moov, delta)
		return nil, err
	}
	metadata := buf.Bytes()

	// Undo the offset mutation so moov is not permanently altered for callers
	// that hold a reference to it.
	undoOffsetAdjustment(moov, delta)

	return metadata, nil
}

// replaceStcoWithCo64 replaces the StcoBox in stbl with a Co64Box, updating
// both the stbl.Stco/stbl.Co64 fields and the stbl.Children slice.
func replaceStcoWithCo64(stbl *mp4.StblBox, co64 *mp4.Co64Box) {
	stbl.Co64 = co64
	stbl.Stco = nil
	newChildren := make([]mp4.Box, 0, len(stbl.Children))
	replaced := false
	for _, ch := range stbl.Children {
		if ch.Type() == "stco" && !replaced {
			newChildren = append(newChildren, co64)
			replaced = true
		} else {
			newChildren = append(newChildren, ch)
		}
	}
	if !replaced {
		newChildren = append(newChildren, co64)
	}
	stbl.Children = newChildren
}

// undoOffsetAdjustment reverses the delta applied to stco/co64 boxes so that
// the moov box is not permanently mutated in memory.
func undoOffsetAdjustment(moov *mp4.MoovBox, delta int64) {
	for _, trak := range moov.Traks {
		if trak.Mdia == nil || trak.Mdia.Minf == nil || trak.Mdia.Minf.Stbl == nil {
			continue
		}
		stbl := trak.Mdia.Minf.Stbl
		if stbl.Stco != nil {
			for i := range stbl.Stco.ChunkOffset {
				stbl.Stco.ChunkOffset[i] = uint32(int64(stbl.Stco.ChunkOffset[i]) - delta)
			}
		}
		if stbl.Co64 != nil {
			for i := range stbl.Co64.ChunkOffset {
				stbl.Co64.ChunkOffset[i] = uint64(int64(stbl.Co64.ChunkOffset[i]) - delta)
			}
		}
	}
}

// sanitizeMP4Compounded handles the compounded-mdat case where the mdat box
// header has size=0 (meaning "extends to end of file") and the caller supplies
// the actual byte length via cumulativeMdatBoxSize.
//
// In this layout the moov box follows the mdat region even though the mdat box
// header declares size=0 (EOF).  cumulativeMdatBoxSize tells us the actual byte
// span of the mdat region so we can skip past it and continue scanning for moov.
//
// Java oracle: Mp4Sanitizer.java:L83–L115 (sanitizeFileWithCompoundedMdatBoxes)
func sanitizeMP4Compounded(input []byte, cumulativeMdatBoxSize int64) (*SanitizedMetadata, error) {
	// Scan boxes using the compounded-mdat-aware scanner.
	boxes, err := scanBoxHeadersCompounded(input, cumulativeMdatBoxSize)
	if err != nil {
		return nil, &MediaValidationError{Detail: "MP4 compounded-mdat scan error: " + err.Error()}
	}

	var ftypOffset int64 = -1
	var moovOffset int64 = -1
	var mdatOffset int64 = -1
	var mdatCount int

	for _, b := range boxes {
		switch b.boxType {
		case "ftyp":
			ftypOffset = b.startPos
		case "moov":
			moovOffset = b.startPos
		case "mdat":
			mdatCount++
			mdatOffset = b.startPos
		case "moof":
			// Fragmented MP4: reject.
			// Java oracle: Mp4Sanitizer.java:L38
			return nil, &ErrFragmentedMP4{}
		}
	}

	if ftypOffset < 0 {
		return nil, &MediaValidationError{Detail: "MP4 missing ftyp box"}
	}
	if moovOffset < 0 {
		return nil, &MediaValidationError{Detail: "MP4 missing moov box"}
	}
	if mdatOffset < 0 {
		return nil, &ErrMissingMdat{}
	}
	if mdatCount > 1 {
		return nil, &ErrDiscontiguousMdat{}
	}

	// Validate ftyp brand: extract and check inline.
	if err := validateIsomBrandBytes(input, ftypOffset); err != nil {
		return nil, err
	}

	// Extract raw ftyp and moov bytes.
	ftypBytes, err := extractBoxBytes(input, ftypOffset)
	if err != nil {
		return nil, &MediaValidationError{Detail: "MP4 ftyp extraction error: " + err.Error()}
	}

	moovBytes, err := extractBoxBytes(input, moovOffset)
	if err != nil {
		return nil, &MediaValidationError{Detail: "MP4 moov extraction error: " + err.Error()}
	}

	// Enforce metadata size limit on moov.
	if uint64(len(moovBytes)) > maxMetadataSize {
		return nil, &ErrMP4MetadataTooLarge{Size: uint64(len(moovBytes))}
	}

	// Finding #3: parse ftyp+moov together so mp4ff can validate dref etc.
	// Fail-closed: reject if DecodeFile fails or Moov is nil.
	initBytes := make([]byte, 0, len(ftypBytes)+len(moovBytes))
	initBytes = append(initBytes, ftypBytes...)
	initBytes = append(initBytes, moovBytes...)
	initFile, parseErr := mp4.DecodeFile(bytes.NewReader(initBytes))
	if parseErr != nil || initFile.Moov == nil {
		return nil, &MediaValidationError{Detail: "MP4 compounded-mdat moov parse error"}
	}
	if err := validateNoExternalDref(initFile.Moov); err != nil {
		return nil, err
	}

	// Determine moov-before-mdat order.
	moovBeforeMdat := moovOffset < mdatOffset

	if moovBeforeMdat {
		// Already faststart: no rewrite needed.
		return &SanitizedMetadata{
			Metadata:   nil,
			DataOffset: mdatOffset,
			DataLength: cumulativeMdatBoxSize,
		}, nil
	}

	// Rewrite the metadata block with chunk-offset adjustment so that every
	// stco/co64 entry remains valid after moov is relocated before mdat in the
	// sanitized output.  When moov follows mdat in the original file, all
	// absolute chunk offsets must be shifted by:
	//
	//   delta = (new mdat start) - (original mdat start)
	//         = (len(ftyp) + len(rewritten moov)) - mdatOffset
	//
	// The comment "no real sample table in compounded-mdat files" was an
	// unproven assumption that is unsafe in the general case; this branch IS
	// reachable with a real stco table.
	//
	// Fail-closed: reject if initFile.Ftyp is nil (the init-segment parse
	// should always produce an ftyp when ftypBytes was valid, but guard anyway).
	if initFile.Ftyp == nil {
		return nil, &MediaValidationError{Detail: "MP4 compounded-mdat missing ftyp after parse"}
	}
	metadata, err := rewriteMetadataWithOffsets(initFile.Ftyp, initFile.Moov, mdatOffset)
	if err != nil {
		return nil, &MediaValidationError{Detail: "MP4 compounded-mdat metadata re-encode error: " + err.Error()}
	}

	return &SanitizedMetadata{
		Metadata:   metadata,
		DataOffset: mdatOffset,
		DataLength: cumulativeMdatBoxSize,
	}, nil
}

// rawBox holds the type and start position of a top-level box discovered
// during a manual scan, without reading the payload.
type rawBox struct {
	boxType  string
	startPos int64
	size     int64 // 0 means "to end of file"
}

// scanBoxHeaders scans input for ISO BMFF top-level box headers, tolerating
// size=0 (EOF-terminating) boxes.
func scanBoxHeaders(input []byte) ([]rawBox, error) {
	return scanBoxHeadersCompounded(input, -1)
}

// scanBoxHeadersCompounded scans input for ISO BMFF top-level box headers.
// When it encounters a size=0 mdat box and compoundedMdatSize >= 0, it uses
// compoundedMdatSize as the effective size of that mdat box and continues
// scanning instead of stopping at EOF.  This allows discovery of a moov box
// that follows the size=0 mdat region.
func scanBoxHeadersCompounded(input []byte, compoundedMdatSize int64) ([]rawBox, error) {
	var result []rawBox
	offset := int64(0)
	total := int64(len(input))

	for offset < total {
		if offset+8 > total {
			return nil, io.ErrUnexpectedEOF
		}
		rawSize := int64(binary.BigEndian.Uint32(input[offset : offset+4]))
		boxType := string(input[offset+4 : offset+8])

		var (
			size   int64
			eofBox bool // true when this box consumes everything to EOF
		)

		switch rawSize {
		case 0:
			if boxType == "mdat" && compoundedMdatSize >= 0 {
				// Caller provided the effective size: use it and continue scanning.
				size = compoundedMdatSize
			} else {
				// Box extends to EOF per ISO BMFF: consume remainder and stop.
				size = total - offset
				eofBox = true
			}
		case 1:
			// 64-bit extended size follows the 8-byte basic header.
			if offset+16 > total {
				return nil, io.ErrUnexpectedEOF
			}
			size = int64(binary.BigEndian.Uint64(input[offset+8 : offset+16]))
			if size < 16 {
				return nil, &MediaValidationError{Detail: "MP4 box extended-size too small"}
			}
		default:
			size = rawSize
			if size < 8 {
				return nil, &MediaValidationError{Detail: "MP4 box size too small"}
			}
		}

		// Finding #2: reject non-positive effective box size (prevents infinite loop).
		if !eofBox && size <= 0 {
			return nil, &MediaValidationError{Detail: "MP4 box has non-positive effective size: " + boxType}
		}

		// Finding #11: compare size against (total-offset) without adding to offset,
		// avoiding int64 overflow for crafted 64-bit box sizes near 2^63.
		if !eofBox && size > total-offset {
			return nil, &MediaValidationError{Detail: "MP4 box extends beyond input: " + boxType}
		}

		result = append(result, rawBox{
			boxType:  boxType,
			startPos: offset,
			size:     size,
		})

		if eofBox {
			break
		}
		// Defensive: offset must strictly advance each iteration.
		prev := offset
		offset += size
		if offset <= prev {
			return nil, &MediaValidationError{Detail: "MP4 scanner did not advance: " + boxType}
		}
	}
	return result, nil
}

// extractBoxBytes returns the bytes of the box starting at startPos in input.
func extractBoxBytes(input []byte, startPos int64) ([]byte, error) {
	if startPos+8 > int64(len(input)) {
		return nil, io.ErrUnexpectedEOF
	}
	rawSize := int64(binary.BigEndian.Uint32(input[startPos : startPos+4]))
	var size int64
	switch rawSize {
	case 0:
		size = int64(len(input)) - startPos
	case 1:
		if startPos+16 > int64(len(input)) {
			return nil, io.ErrUnexpectedEOF
		}
		size = int64(binary.BigEndian.Uint64(input[startPos+8 : startPos+16]))
	default:
		size = rawSize
	}
	if startPos+size > int64(len(input)) {
		return nil, io.ErrUnexpectedEOF
	}
	result := make([]byte, size)
	copy(result, input[startPos:startPos+size])
	return result, nil
}

// validateIsomBrand checks that the ftyp box has "isom" in its compatible
// brands list.  Rejects MOV and legacy MP4v1.
//
// ftyp payload structure: 4-byte major_brand | 4-byte minor_version | N×4-byte compatible_brands.
// A valid ftyp must have at least 8 payload bytes (major + minor).
//
// Java oracle: Mp4Sanitizer.java:L41–L43
func validateIsomBrand(ftyp *mp4.FtypBox) error {
	// ftyp.Size() returns the full box size including the 8-byte ISO BMFF header.
	// The payload is Size() - 8 bytes. A valid ftyp needs at least 8 payload bytes
	// (4 for major_brand + 4 for minor_version). An ftyp with no payload panics in
	// mp4ff's CompatibleBrands() because it underflows the length arithmetic.
	const ftypBoxHeaderLen = 8  // ISO BMFF box header (size + type)
	const ftypPayloadMinLen = 8 // major_brand (4) + minor_version (4)
	if ftyp.Size() < ftypBoxHeaderLen+ftypPayloadMinLen {
		return &MediaValidationError{Detail: "MP4 ftyp box payload too short"}
	}
	for _, brand := range ftyp.CompatibleBrands() {
		if brand == "isom" {
			return nil
		}
	}
	return &ErrUnsupportedBrand{Brand: ftyp.MajorBrand()}
}

// validateIsomBrandBytes validates the isom brand from raw ftyp bytes without
// using mp4ff.  Used in the compounded-mdat path.
//
// ftyp box layout: 4-byte size | "ftyp" | 4-byte major_brand | 4-byte minor_version |
// N x 4-byte compatible_brands
func validateIsomBrandBytes(input []byte, ftypOffset int64) error {
	if ftypOffset+20 > int64(len(input)) {
		return &MediaValidationError{Detail: "MP4 ftyp box too short"}
	}
	rawSize := int64(binary.BigEndian.Uint32(input[ftypOffset : ftypOffset+4]))
	if rawSize < 16 {
		return &MediaValidationError{Detail: "MP4 ftyp box too small"}
	}
	endOffset := ftypOffset + rawSize
	if endOffset > int64(len(input)) {
		endOffset = int64(len(input))
	}

	// Check compatible brands starting at ftypOffset+16 (each is 4 bytes).
	for off := ftypOffset + 16; off+4 <= endOffset; off += 4 {
		if string(input[off:off+4]) == "isom" {
			return nil
		}
	}

	major := string(input[ftypOffset+8 : ftypOffset+12])
	return &ErrUnsupportedBrand{Brand: major}
}

// validateNoExternalDref walks the moov box tree and returns
// ErrExternalDataReference if any dref entry is not a self-contained local
// URL reference.
//
// Finding #4: fail-closed — accept ONLY a self-contained URL box (self-contained
// flag set, or empty location).  Any other dref child type (URN, unknown box)
// is rejected with ErrExternalDataReference.
//
// A self-contained dref URL entry has the 0x000001 flag set (dataIsSelfContainedFlag)
// OR its location is empty (NoLocation==true or Location=="").
//
// Java oracle: Mp4Sanitizer.java:L40
// ISO BMFF §8.7.2 — dref entry types: 'url ' (DataEntryUrlBox) and 'urn ' (DataEntryUrnBox).
func validateNoExternalDref(moov *mp4.MoovBox) error {
	for _, trak := range moov.Traks {
		if trak.Mdia == nil || trak.Mdia.Minf == nil || trak.Mdia.Minf.Dinf == nil {
			continue
		}
		dref := trak.Mdia.Minf.Dinf.Dref
		if dref == nil {
			continue
		}
		for _, child := range dref.Children {
			switch urlBox := child.(type) {
			case *mp4.URLBox:
				// A URL box without the self-contained flag and with a non-empty
				// location is an external reference.
				const selfContainedFlag = 0x000001
				if (urlBox.Flags&selfContainedFlag) == 0 && !urlBox.NoLocation && urlBox.Location != "" {
					return &ErrExternalDataReference{}
				}
			default:
				// Finding #4: any non-URL dref child type (URN, unknown) is rejected
				// fail-closed; only a self-contained local 'url ' entry is permitted.
				//
				// ISO BMFF §8.7.2: 'urn ' (DataEntryUrnBox) always references an
				// external resource.  Unknown box types are rejected per webpsan/mp4san
				// strict posture.
				return &ErrExternalDataReference{}
			}
		}
	}
	return nil
}

// isMoovBeforeMdat reports whether the moov box appears before the mdat box
// in the file's Children list (original parse order).
func isMoovBeforeMdat(f *mp4.File) bool {
	seenMoov := false
	for _, b := range f.Children {
		switch b.Type() {
		case "moov":
			seenMoov = true
		case "mdat":
			return seenMoov
		}
	}
	return true // no mdat found; treat as already ordered
}

// findMdatInChildren returns the first mdat box in the Children slice and its
// index, or (nil, -1) if not found.
func findMdatInChildren(children []mp4.Box) (*mp4.MdatBox, int) {
	for i, b := range children {
		if b.Type() == "mdat" {
			if m, ok := b.(*mp4.MdatBox); ok {
				return m, i
			}
		}
	}
	return nil, -1
}

// countMdatBoxes counts how many top-level mdat boxes are in the Children list.
func countMdatBoxes(children []mp4.Box) int {
	n := 0
	for _, b := range children {
		if b.Type() == "mdat" {
			n++
		}
	}
	return n
}

// encodeFtypMoov encodes ftyp and moov into a single contiguous byte slice.
// This is the "sanitized metadata" block that can be prepended to the mdat
// span to form a valid MP4 file.  Used by the faststart (already-ordered) path
// in sanitizeMP4 where no offset adjustment is needed.
func encodeFtypMoov(ftyp *mp4.FtypBox, moov *mp4.MoovBox) ([]byte, error) {
	var buf bytes.Buffer
	if err := ftyp.Encode(&buf); err != nil {
		return nil, err
	}
	if err := moov.Encode(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
