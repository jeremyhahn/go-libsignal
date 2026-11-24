package media

// Port of Rust libsignal mp4san (rust/media/src/sanitize/mp4.rs), checked against Java Mp4Sanitizer and SanitizedMetadata.

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"

	mp4 "github.com/Eyevinn/mp4ff/mp4"
)

// maxBoxDepth caps container nesting before mp4.DecodeFile, whose recursion can overflow the stack unrecoverably.
const maxBoxDepth = 32

// containerBoxTypes is the set of ISO BMFF box types whose payload contains
// child boxes. checkMP4BoxDepth descends into these during its iterative scan.
var containerBoxTypes = map[string]bool{
	"moov": true, "trak": true, "mdia": true, "minf": true,
	"stbl": true, "edts": true, "dinf": true, "udta": true,
	"mvex": true, "moof": true, "traf": true, "mfra": true,
	"skip": true, "meta": true, "ilst": true, "meco": true,
	"sinf": true, "schi": true, "rinf": true,
}

// depthFrame is one entry in the iterative DFS worklist used by checkMP4BoxDepth.
type depthFrame struct {
	offset int64
	end    int64
	depth  int
}

// checkMP4BoxDepth iteratively rejects nesting deeper than maxBoxDepth; it must run before mp4.DecodeFile.
func checkMP4BoxDepth(input []byte) error {
	total := int64(len(input))
	worklist := []depthFrame{{offset: 0, end: total, depth: 1}}
	for len(worklist) > 0 {
		frame := worklist[len(worklist)-1]
		worklist = worklist[:len(worklist)-1]

		offset := frame.offset
		end := frame.end

		for offset < end {
			if end-offset < 8 {
				break // truncated box header; mp4ff will handle it
			}
			rawSize := int64(binary.BigEndian.Uint32(input[offset : offset+4]))

			var (
				size      int64
				headerLen int64 = 8
				eofBox    bool
				invalid   bool
			)
			switch rawSize {
			case 0:
				size = end - offset
				eofBox = true
			case 1:
				if offset+16 > end {
					invalid = true
				} else {
					size = int64(binary.BigEndian.Uint64(input[offset+8 : offset+16]))
					headerLen = 16
					if size < 16 {
						invalid = true
					}
				}
			default:
				size = rawSize
				if size < 8 {
					invalid = true
				}
			}

			if invalid {
				break // malformed box; mp4ff will reject
			}
			if !eofBox && size > end-offset {
				break // box extends beyond boundary; mp4ff will reject
			}

			// Kept inline rather than hoisted into a local: the compiler
			// elides the allocation only for a conversion used directly as a
			// map key.
			if containerBoxTypes[string(input[offset+4:offset+8])] {
				childDepth := frame.depth + 1
				if childDepth > maxBoxDepth {
					return &MediaValidationError{Detail: "MP4 box nesting depth exceeds maximum allowed depth"}
				}
				childStart := offset + headerLen
				childEnd := offset + size
				if childStart < childEnd {
					worklist = append(worklist, depthFrame{
						offset: childStart,
						end:    childEnd,
						depth:  childDepth,
					})
				}
			}

			if eofBox {
				break
			}
			offset += size
		}
	}
	return nil
}

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

	// mp4ff rejects size=0 boxes, so the compounded path scans boxes by hand.
	if cumulativeMdatBoxSize >= 0 {
		return sanitizeMP4Compounded(input, cumulativeMdatBoxSize)
	}

	// Depth-guard before mp4ff's recursive decoder.
	if err := checkMP4BoxDepth(input); err != nil {
		return nil, err
	}

	// DecModeLazyMdat avoids copying the mdat payload.
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

	// Reject mdat split around moov at the top level.
	_ = mdatIdx // used above; position is tracked via StartPos below

	// DataOffset and DataLength refer to the original input.
	dataOffset := int64(mdatBox.StartPos)
	dataLength := int64(mdatBox.Size())

	// Reject an mdat span past the input, using subtraction to avoid overflow.
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

	// moov follows mdat: rewrite ftyp+moov with stco/co64 shifted by the mdat move, promoting to co64 on overflow.
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

// rewriteMetadataWithOffsets encodes ftyp+moov and shifts every chunk offset by the mdat move (ISO BMFF §8.7.5).
func rewriteMetadataWithOffsets(ftyp *mp4.FtypBox, moov *mp4.MoovBox, originalMdatOffset int64) ([]byte, error) {
	// Encode ftyp to learn its byte length (it never changes size).
	var ftypBuf bytes.Buffer
	if err := ftyp.Encode(&ftypBuf); err != nil {
		return nil, err
	}
	ftypLen := int64(ftypBuf.Len())

	// Promote stco to co64 until every stco fits; each promotion grows moov and the delta, and the loop ends because traks are finite.

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
				// Finding (LOW): reject negative post-shift values instead of
				// promoting to co64; uint64(negative_int64) wraps to a huge bogus offset.
				if newOff < 0 {
					return nil, &MediaValidationError{Detail: "MP4 stco chunk offset underflows after relocation"}
				}
				if newOff > math.MaxUint32 {
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

	// Reject any co64 offset that would go negative before mutating.
	for _, trak := range moov.Traks {
		if trak.Mdia == nil || trak.Mdia.Minf == nil || trak.Mdia.Minf.Stbl == nil {
			continue
		}
		stbl := trak.Mdia.Minf.Stbl
		if stbl.Co64 != nil {
			for _, off := range stbl.Co64.ChunkOffset {
				if int64(off)+delta < 0 {
					return nil, &MediaValidationError{Detail: "MP4 co64 chunk offset underflows after relocation"}
				}
			}
		}
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

// sanitizeMP4Compounded skips the size=0 mdat region by cumulativeMdatBoxSize to find the following moov (Java sanitizeFileWithCompoundedMdatBoxes).
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

	// Depth-guard the init segment before mp4ff's recursive decoder.
	initBytes := make([]byte, 0, len(ftypBytes)+len(moovBytes))
	initBytes = append(initBytes, ftypBytes...)
	initBytes = append(initBytes, moovBytes...)
	if err := checkMP4BoxDepth(initBytes); err != nil {
		return nil, &MediaValidationError{Detail: "MP4 compounded-mdat box depth error: " + err.Error()}
	}
	// Finding #3: parse ftyp+moov together so mp4ff can validate dref etc.
	// Fail-closed: reject if DecodeFile fails or Moov is nil.
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

	// Rewrite ftyp+moov with chunk offsets shifted by the mdat move; fail if the init segment has no ftyp.
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

// scanBoxHeaders scans top-level box headers, allowing size=0 boxes.
func scanBoxHeaders(input []byte) ([]rawBox, error) {
	return scanBoxHeadersCompounded(input, -1)
}

// scanBoxHeadersCompounded scans top-level box headers, treating a size=0 mdat as compoundedMdatSize bytes so a later moov is found.
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
		// Reject a largesize that is negative as int64 or below 16.
		if startPos+16 > int64(len(input)) {
			return nil, io.ErrUnexpectedEOF
		}
		size = int64(binary.BigEndian.Uint64(input[startPos+8 : startPos+16]))
		if size < 16 {
			return nil, &MediaValidationError{Detail: "MP4 box extended-size too small"}
		}
	default:
		size = rawSize
	}
	// Use subtraction to avoid int64 overflow when size is near MaxInt64.
	if size > int64(len(input))-startPos {
		return nil, &MediaValidationError{Detail: "MP4 box extends beyond input"}
	}
	result := make([]byte, size)
	copy(result, input[startPos:startPos+size])
	return result, nil
}

// validateIsomBrand requires "isom" among the ftyp compatible brands and at least 8 payload bytes.
func validateIsomBrand(ftyp *mp4.FtypBox) error {
	// An ftyp with under 8 payload bytes would panic in mp4ff CompatibleBrands.
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

// validateIsomBrandBytes checks the isom brand in raw ftyp bytes for the compounded path.
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

// validateNoExternalDref accepts only self-contained 'url ' dref entries and returns ErrExternalDataReference otherwise (ISO BMFF §8.7.2).
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
				// Any non-URL dref entry is external or unknown, so reject it.
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
