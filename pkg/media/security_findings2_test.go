package media

// Regression tests: deep box nesting, faststart padding offsets, negative co64 shifts and the largesize guard.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	mp4 "github.com/Eyevinn/mp4ff/mp4"
)

// ---------------------------------------------------------------------------
// Finding 1 — bounded box-depth pre-scan rejects deeply nested containers
// ---------------------------------------------------------------------------

// buildNestedUdtaChain returns a byte sequence of n udta boxes nested
// inside one another, built iteratively from the innermost outward.
func buildNestedUdtaChain(n int) []byte {
	// Innermost: empty udta (8-byte header, no payload).
	inner := make([]byte, 8)
	binary.BigEndian.PutUint32(inner[0:4], 8)
	copy(inner[4:8], "udta")

	for i := 1; i < n; i++ {
		size := uint32(8 + len(inner))
		outer := make([]byte, size)
		binary.BigEndian.PutUint32(outer[0:4], size)
		copy(outer[4:8], "udta")
		copy(outer[8:], inner)
		inner = outer
	}
	return inner
}

// buildMP4WithNestedUdta builds a minimal ftyp+moov+mdat MP4 where moov
// contains a chain of n nested udta boxes.
func buildMP4WithNestedUdta(udtaCount int) []byte {
	nested := buildNestedUdtaChain(udtaCount)

	moovSize := uint32(8 + len(nested))
	moov := make([]byte, moovSize)
	binary.BigEndian.PutUint32(moov[0:4], moovSize)
	copy(moov[4:8], "moov")
	copy(moov[8:], nested)

	mdat := make([]byte, 8)
	binary.BigEndian.PutUint32(mdat[0:4], 8)
	copy(mdat[4:8], "mdat")

	var buf bytes.Buffer
	buf.Write(javaFtyp())
	buf.Write(moov)
	buf.Write(mdat)
	return buf.Bytes()
}

// TestFinding1_Security_DeeplyNestedContainerBoxes_Rejected checks 40 nested udta boxes return a typed error instead of overflowing the stack.
func TestFinding1_Security_DeeplyNestedContainerBoxes_Rejected(t *testing.T) {
	data := buildMP4WithNestedUdta(40)

	_, err := SanitizeMP4(data)
	if err == nil {
		t.Fatal("expected error for deeply nested MP4 (40 udta levels), got nil")
	}
	var mvErr *MediaValidationError
	if !errors.As(err, &mvErr) {
		t.Errorf("expected *MediaValidationError, got %T: %v", err, err)
	}
}

// TestFinding1_Security_DeeplyNestedContainerBoxes_Rejected_ViaValidate verifies
// the same via the public Validate entry point.
func TestFinding1_Security_DeeplyNestedContainerBoxes_Rejected_ViaValidate(t *testing.T) {
	data := buildMP4WithNestedUdta(40)

	_, err := Validate(data)
	if err == nil {
		t.Fatal("expected error for deeply nested MP4 via Validate, got nil")
	}
	var mvErr *MediaValidationError
	if !errors.As(err, &mvErr) {
		t.Errorf("expected *MediaValidationError, got %T: %v", err, err)
	}
}

// TestFinding1_Security_NormalNestingDepth_Accepted verifies that a
// legitimately-nested MP4 (5 udta boxes inside moov, well under maxBoxDepth=32)
// is accepted and does not return a depth error.
func TestFinding1_Security_NormalNestingDepth_Accepted(t *testing.T) {
	data := buildMP4WithNestedUdta(5)

	_, err := SanitizeMP4(data)
	// The file may be rejected for other structural reasons (e.g. missing mdat
	// payload, ErrMissingMdat for the empty mdat) but must NOT fail with a depth
	// error, and must NOT crash.
	if err != nil {
		var mvErr *MediaValidationError
		if errors.As(err, &mvErr) && mvErr.Detail == "MP4 box nesting depth exceeds maximum allowed depth" {
			t.Errorf("normal 5-level nesting incorrectly rejected as too deep: %v", err)
		}
		// Any other error (e.g. missing mdat payload) is acceptable.
	}
}

// TestFinding1_Security_ExactlyAtDepthLimit_Accepted verifies that a file with
// exactly maxBoxDepth-1 container levels is accepted (not rejected for depth).
// maxBoxDepth=32; the root scan is at depth 1, moov children at depth 2,
// so (maxBoxDepth-2) nested udta boxes keep the deepest push at depth≤32.
func TestFinding1_Security_ExactlyAtDepthLimit_Accepted(t *testing.T) {
	// 30 nested udta boxes put the deepest children at depth 32, which is allowed.
	const udtaAtLimit = maxBoxDepth - 2 // 30

	data := buildMP4WithNestedUdta(udtaAtLimit)
	_, err := SanitizeMP4(data)
	if err != nil {
		var mvErr *MediaValidationError
		if errors.As(err, &mvErr) && mvErr.Detail == "MP4 box nesting depth exceeds maximum allowed depth" {
			t.Errorf("file at exactly depth limit was incorrectly rejected: %v", err)
		}
	}
}

// TestFinding1_Security_OneOverDepthLimit_Rejected verifies that a file with
// exactly one more container level than maxBoxDepth is rejected.
func TestFinding1_Security_OneOverDepthLimit_Rejected(t *testing.T) {
	// udtaAtLimit+1 = 31 udta boxes → deepest push would be at depth 33 > 32
	const udtaOverLimit = maxBoxDepth - 1 // 31

	data := buildMP4WithNestedUdta(udtaOverLimit)
	_, err := SanitizeMP4(data)
	if err == nil {
		t.Fatal("expected depth error for one-over-limit nesting, got nil")
	}
	var mvErr *MediaValidationError
	if !errors.As(err, &mvErr) {
		t.Errorf("expected *MediaValidationError, got %T: %v", err, err)
	}
}

// TestFinding1_Security_CompoundedMdat_DeeplyNested verifies that the
// compounded-mdat path also rejects deeply-nested container boxes.
func TestFinding1_Security_CompoundedMdat_DeeplyNested(t *testing.T) {
	// Build deeply-nested moov (40 udta) with compounded mdat layout.
	nested := buildNestedUdtaChain(40)
	moovSize := uint32(8 + len(nested))
	moov := make([]byte, moovSize)
	binary.BigEndian.PutUint32(moov[0:4], moovSize)
	copy(moov[4:8], "moov")
	copy(moov[8:], nested)

	// Compounded mdat: size=0 header + payload.
	mdatHdr := make([]byte, 8)
	copy(mdatHdr[4:], "mdat")
	payload := []byte{0x01, 0x02}

	var buf bytes.Buffer
	buf.Write(javaFtyp())
	buf.Write(mdatHdr)
	buf.Write(payload)
	buf.Write(moov)
	input := buf.Bytes()

	cumSize := 8 + len(payload)
	_, err := SanitizeMP4WithCompoundedMdat(input, cumSize)
	if err == nil {
		t.Fatal("expected error for deeply nested compounded-mdat MP4, got nil")
	}
}

// ---------------------------------------------------------------------------
// Finding 2 — faststart free/skip stripping must rewrite stco/co64 offsets
// ---------------------------------------------------------------------------

// buildFaststartWithFreeBox builds ftyp | moov | free(8) | mdat, so dropping free shifts stco entries by -8.
func buildFaststartWithFreeBox(payload []byte) (data []byte, origChunkOff uint32) {
	// Offsets: ftyp 0, moov 20, free 80, mdat header 88, payload 96.
	const (
		ftypLen    = 20
		moovLen    = 60
		freeLen    = 8
		mdatHdrLen = 8
	)
	origChunkOff = ftypLen + moovLen + freeLen + mdatHdrLen // = 96

	moovBytes := buildMoovWithStco([]uint32{origChunkOff})

	freeBox := make([]byte, freeLen)
	binary.BigEndian.PutUint32(freeBox[0:4], freeLen)
	copy(freeBox[4:8], "free")

	mdatSize := uint32(mdatHdrLen + len(payload))
	mdatBox := make([]byte, mdatSize)
	binary.BigEndian.PutUint32(mdatBox[0:4], mdatSize)
	copy(mdatBox[4:8], "mdat")
	copy(mdatBox[8:], payload)

	var buf bytes.Buffer
	buf.Write(javaFtyp())
	buf.Write(moovBytes)
	buf.Write(freeBox)
	buf.Write(mdatBox)
	return buf.Bytes(), origChunkOff
}

// TestFinding2_Security_FaststartFreeBox_StcoAdjusted checks stco is shifted by -8 when the free box is dropped.
func TestFinding2_Security_FaststartFreeBox_StcoAdjusted(t *testing.T) {
	payload := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	data, _ := buildFaststartWithFreeBox(payload)

	result, err := Validate(data)
	if err != nil {
		t.Fatalf("Validate(faststart+free) returned error: %v", err)
	}

	// Re-parse the output and inspect stco.
	f, err := mp4.DecodeFile(bytes.NewReader(result.Validated))
	if err != nil {
		t.Fatalf("re-parse of sanitized output failed: %v", err)
	}
	if f.Moov == nil || len(f.Moov.Traks) == 0 {
		t.Fatal("sanitized output has no trak")
	}
	stbl := f.Moov.Traks[0].Mdia.Minf.Stbl
	if stbl == nil || stbl.Stco == nil {
		t.Fatal("sanitized output missing stco")
	}

	// Expected layout after sanitization (free stripped):
	//   ftyp(20) | moov(60) | mdat(8+4=12)
	// mdat payload starts at 20+60+8 = 88.
	const wantChunkOff = uint32(20 + 60 + 8) // 88
	gotOff := stbl.Stco.ChunkOffset[0]
	if gotOff != wantChunkOff {
		t.Errorf("stco[0] = %d, want %d (free-box delta not applied)", gotOff, wantChunkOff)
	}

	// Byte-level: output[gotOff] must equal payload[0].
	if int(gotOff) >= len(result.Validated) {
		t.Fatalf("stco[0]=%d out of bounds (output len=%d)", gotOff, len(result.Validated))
	}
	if result.Validated[gotOff] != payload[0] {
		t.Errorf("output[stco[0]]=0x%02x, want payload[0]=0x%02x (offset points at wrong byte)",
			result.Validated[gotOff], payload[0])
	}
}

// TestFinding2_Security_CleanFaststart_UnchangedOffsets verifies that a clean
// faststart file (no free/skip boxes, delta==0) is handled correctly and that
// stco offsets remain valid after re-encoding.
func TestFinding2_Security_CleanFaststart_UnchangedOffsets(t *testing.T) {
	// ftyp(20) | moov(60, stco→88) | mdat(12, payload at 88)
	payload := []byte{0x11, 0x22, 0x33, 0x44}
	const chunkOff = uint32(20 + 60 + 8) // = 88

	moovBytes := buildMoovWithStco([]uint32{chunkOff})
	mdatSize := uint32(8 + len(payload))
	mdatBox := make([]byte, mdatSize)
	binary.BigEndian.PutUint32(mdatBox[0:4], mdatSize)
	copy(mdatBox[4:8], "mdat")
	copy(mdatBox[8:], payload)

	var buf bytes.Buffer
	buf.Write(javaFtyp())
	buf.Write(moovBytes)
	buf.Write(mdatBox)
	data := buf.Bytes()

	result, err := Validate(data)
	if err != nil {
		t.Fatalf("Validate(clean faststart) returned error: %v", err)
	}

	f, err := mp4.DecodeFile(bytes.NewReader(result.Validated))
	if err != nil {
		t.Fatalf("re-parse failed: %v", err)
	}
	stbl := f.Moov.Traks[0].Mdia.Minf.Stbl
	if stbl == nil || stbl.Stco == nil {
		t.Fatal("missing stco in re-parsed output")
	}
	gotOff := stbl.Stco.ChunkOffset[0]
	if gotOff != chunkOff {
		t.Errorf("clean faststart: stco[0] = %d, want %d (should be unchanged)", gotOff, chunkOff)
	}
	if int(gotOff) >= len(result.Validated) || result.Validated[gotOff] != payload[0] {
		t.Errorf("stco[0] does not point at correct payload byte")
	}
}

// ---------------------------------------------------------------------------
// Finding 3 — negative post-shift offset must be rejected, not wrapped
// ---------------------------------------------------------------------------

// buildFaststartWithFreeBoxAndStco builds a faststart MP4 with a free box
// and a custom stco offset, allowing control over the offset value.
func buildFaststartWithCustomStco(stcoOffset uint32, freeLen int) []byte {
	moovBytes := buildMoovWithStco([]uint32{stcoOffset})
	freeBox := make([]byte, freeLen)
	binary.BigEndian.PutUint32(freeBox[0:4], uint32(freeLen))
	copy(freeBox[4:8], "free")

	mdat := make([]byte, 8)
	binary.BigEndian.PutUint32(mdat[0:4], 8)
	copy(mdat[4:8], "mdat")

	var buf bytes.Buffer
	buf.Write(javaFtyp())
	buf.Write(moovBytes)
	buf.Write(freeBox)
	buf.Write(mdat)
	return buf.Bytes()
}

// TestFinding3_Security_NegativeStcoPostShift_Rejected checks an stco of 50 with delta -200 is rejected, not promoted to co64.
func TestFinding3_Security_NegativeStcoPostShift_Rejected(t *testing.T) {
	// stco[0] = 50 < 200, so it underflows with delta = -200.
	const stcoOff = uint32(50)
	const freeLen = 200

	data := buildFaststartWithCustomStco(stcoOff, freeLen)

	_, err := Validate(data)
	if err == nil {
		t.Fatal("expected error for negative stco post-shift, got nil")
	}
	var mvErr *MediaValidationError
	if !errors.As(err, &mvErr) {
		t.Errorf("expected *MediaValidationError, got %T: %v", err, err)
	}
}

// TestFinding3_Security_ValidNegativeDelta_Accepted checks an stco of 96 with delta -8 is accepted.
func TestFinding3_Security_ValidNegativeDelta_Accepted(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03, 0x04}
	data, _ := buildFaststartWithFreeBox(payload)

	_, err := Validate(data)
	if err != nil {
		t.Errorf("expected valid faststart file with negative delta to be accepted, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Finding 4 — extractBoxBytes largesize guard
// ---------------------------------------------------------------------------

// TestFinding4_Security_ExtractBoxBytes_NegativeLargesize checks a largesize with the high bit set returns a MediaValidationError.
func TestFinding4_Security_ExtractBoxBytes_NegativeLargesize(t *testing.T) {
	// 16-byte largesize header: rawSize=1, type="udta", largesize=0x8000000000000010
	// (negative as int64, but > 16 as uint64 — the pre-fix code only checked
	// startPos+size > len(input) which passes for a negative size near zero).
	input := make([]byte, 20)
	binary.BigEndian.PutUint32(input[0:4], 1) // rawSize=1 → extended
	copy(input[4:8], "udta")
	binary.BigEndian.PutUint64(input[8:16], 0x8000000000000010) // negative as int64
	copy(input[16:20], "xxxx")

	_, err := extractBoxBytes(input, 0)
	if err == nil {
		t.Fatal("expected error for negative largesize in extractBoxBytes, got nil")
	}
	var mvErr *MediaValidationError
	if !errors.As(err, &mvErr) {
		t.Errorf("expected *MediaValidationError, got %T: %v", err, err)
	}
}

// TestFinding4_Security_ExtractBoxBytes_TooSmallLargesize verifies that
// extractBoxBytes rejects an extended-size value smaller than 16 (the minimum
// valid largesize, which must cover the 8-byte basic header + 8-byte size field).
func TestFinding4_Security_ExtractBoxBytes_TooSmallLargesize(t *testing.T) {
	input := make([]byte, 24)
	binary.BigEndian.PutUint32(input[0:4], 1) // rawSize=1 → extended
	copy(input[4:8], "udta")
	binary.BigEndian.PutUint64(input[8:16], 4) // size=4 < 16: invalid largesize
	copy(input[16:24], "payload!")

	_, err := extractBoxBytes(input, 0)
	if err == nil {
		t.Fatal("expected error for largesize < 16, got nil")
	}
	var mvErr *MediaValidationError
	if !errors.As(err, &mvErr) {
		t.Errorf("expected *MediaValidationError, got %T: %v", err, err)
	}
}

// TestFinding4_Security_ExtractBoxBytes_ValidLargesize verifies that a valid
// largesize box is still accepted by extractBoxBytes after the guard is added.
func TestFinding4_Security_ExtractBoxBytes_ValidLargesize(t *testing.T) {
	// largesize box: 16-byte header + 4-byte payload = 20 total.
	const totalSize = uint64(20)
	input := make([]byte, totalSize)
	binary.BigEndian.PutUint32(input[0:4], 1) // rawSize=1 → extended
	copy(input[4:8], "udta")
	binary.BigEndian.PutUint64(input[8:16], totalSize)
	copy(input[16:20], "data")

	got, err := extractBoxBytes(input, 0)
	if err != nil {
		t.Fatalf("unexpected error for valid largesize box: %v", err)
	}
	if len(got) != int(totalSize) {
		t.Errorf("extractBoxBytes returned %d bytes, want %d", len(got), totalSize)
	}
	if !bytes.Equal(got, input) {
		t.Errorf("extractBoxBytes returned unexpected bytes")
	}
}

// TestFinding4_Security_ExtractBoxBytes_OversizedLargesize verifies that a
// largesize whose declared size exceeds the remaining input is rejected.
func TestFinding4_Security_ExtractBoxBytes_OversizedLargesize(t *testing.T) {
	input := make([]byte, 20)
	binary.BigEndian.PutUint32(input[0:4], 1) // rawSize=1 → extended
	copy(input[4:8], "udta")
	// Declare 1 MiB but we only have 20 bytes.
	binary.BigEndian.PutUint64(input[8:16], 1<<20)

	_, err := extractBoxBytes(input, 0)
	if err == nil {
		t.Fatal("expected error for oversized largesize box, got nil")
	}
}
