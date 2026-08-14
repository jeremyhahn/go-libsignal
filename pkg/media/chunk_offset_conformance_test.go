package media

// chunk_offset_conformance_test.go — conformance tests for Finding #1:
// stco/co64 chunk-offset rewriting when moov is relocated before mdat
// (faststart normalization).
//
// ISO BMFF §8.7.5: stco/co64 chunk offsets are absolute byte offsets from the
// start of the file.  When moov is relocated to precede mdat, every offset in
// every stbl's stco/co64 must be shifted by:
//
//	delta = (new mdat box start) - (original mdat box start)
//	      = len(ftyp) + len(new moov) - original_mdat_start_pos
//
// This test file builds a synthetic MP4 containing a real stbl with stco
// entries pointing at sample data inside the original mdat, runs SanitizeMP4,
// then reconstructs the file from the returned metadata and mdat span, parses
// it with mp4ff, and asserts that each chunk offset resolves correctly.
//
// A second test forces stco→co64 promotion by placing the original mdat at a
// position such that the original stco entries are large enough that adding the
// relocation delta would overflow uint32.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	mp4 "github.com/Eyevinn/mp4ff/mp4"
)

// buildMP4WithStco builds a synthetic MP4 in mdat-first layout:
//
//	ftyp | mdat (payload bytes) | moov (containing stbl with stco pointing at payload)
//
// sampleOffsets are absolute byte offsets inside the mdat payload (relative to
// the file start).  Each offset must point at a valid byte within the mdat payload.
//
// The ftyp is the standard 20-byte Java-oracle ftyp (isom/isom).
// The moov contains: moov→trak→mdia→minf→stbl→stco.
// This mirrors the Java oracle Mp4SanitizerTest.moov() structure.
//
// Java oracle: Mp4SanitizerTest.java:L126–L157
func buildMP4WithStco(payload []byte, absoluteChunkOffsets []uint32) []byte {
	ftyp := javaFtyp() // 20 bytes

	// mdat box: 8-byte header + payload bytes.
	mdatSize := uint32(8 + len(payload))
	mdatBox := make([]byte, mdatSize)
	binary.BigEndian.PutUint32(mdatBox[0:4], mdatSize)
	copy(mdatBox[4:8], "mdat")
	copy(mdatBox[8:], payload)

	// Build moov with a stco box containing the provided chunk offsets.
	moov := buildMoovWithStco(absoluteChunkOffsets)

	var buf bytes.Buffer
	buf.Write(ftyp)
	buf.Write(mdatBox)
	buf.Write(moov)
	return buf.Bytes()
}

// buildMoovWithStco builds a minimal moov box containing:
//
//	moov → trak → mdia → minf → stbl → stco(entries)
//
// The stco box contains the provided absolute chunk offsets.
// Box sizes are computed bottom-up.
func buildMoovWithStco(chunkOffsets []uint32) []byte {
	// stco: 8-byte header + 4 (version/flags) + 4 (entry_count) + 4*n (offsets)
	stcoPayloadLen := 4 + 4 + 4*len(chunkOffsets)
	stcoSize := 8 + stcoPayloadLen

	// stbl: 8 + stco
	stblSize := 8 + stcoSize

	// minf: 8 + stbl
	minfSize := 8 + stblSize

	// mdia: 8 + minf
	mdiaSize := 8 + minfSize

	// trak: 8 + mdia
	trakSize := 8 + mdiaSize

	// moov: 8 + trak
	moovSize := 8 + trakSize

	var buf bytes.Buffer
	writeBoxHdr := func(size int, fourcc string) {
		hdr := make([]byte, 4)
		binary.BigEndian.PutUint32(hdr, uint32(size))
		buf.Write(hdr)
		buf.WriteString(fourcc)
	}
	writeUint32BE := func(v uint32) {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, v)
		buf.Write(b)
	}

	writeBoxHdr(moovSize, "moov")
	writeBoxHdr(trakSize, "trak")
	writeBoxHdr(mdiaSize, "mdia")
	writeBoxHdr(minfSize, "minf")
	writeBoxHdr(stblSize, "stbl")
	writeBoxHdr(stcoSize, "stco")
	writeUint32BE(0) // version=0, flags=0
	writeUint32BE(uint32(len(chunkOffsets)))
	for _, off := range chunkOffsets {
		writeUint32BE(off)
	}

	return buf.Bytes()
}

// buildMP4WithCo64 builds a synthetic MP4 in mdat-first layout where the
// moov contains a co64 box (64-bit chunk offsets) instead of stco.
func buildMP4WithCo64(payload []byte, absoluteChunkOffsets []uint64) []byte {
	ftyp := javaFtyp()

	mdatSize := uint32(8 + len(payload))
	mdatBox := make([]byte, mdatSize)
	binary.BigEndian.PutUint32(mdatBox[0:4], mdatSize)
	copy(mdatBox[4:8], "mdat")
	copy(mdatBox[8:], payload)

	moov := buildMoovWithCo64(absoluteChunkOffsets)

	var buf bytes.Buffer
	buf.Write(ftyp)
	buf.Write(mdatBox)
	buf.Write(moov)
	return buf.Bytes()
}

// buildMoovWithCo64 builds moov → trak → mdia → minf → stbl → co64(entries).
func buildMoovWithCo64(chunkOffsets []uint64) []byte {
	// co64: 8-byte header + 4 (version/flags) + 4 (entry_count) + 8*n (offsets)
	co64PayloadLen := 4 + 4 + 8*len(chunkOffsets)
	co64Size := 8 + co64PayloadLen

	stblSize := 8 + co64Size
	minfSize := 8 + stblSize
	mdiaSize := 8 + minfSize
	trakSize := 8 + mdiaSize
	moovSize := 8 + trakSize

	var buf bytes.Buffer
	writeBoxHdr := func(size int, fourcc string) {
		hdr := make([]byte, 4)
		binary.BigEndian.PutUint32(hdr, uint32(size))
		buf.Write(hdr)
		buf.WriteString(fourcc)
	}
	writeUint32BE := func(v uint32) {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, v)
		buf.Write(b)
	}
	writeUint64BE := func(v uint64) {
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, v)
		buf.Write(b)
	}

	writeBoxHdr(moovSize, "moov")
	writeBoxHdr(trakSize, "trak")
	writeBoxHdr(mdiaSize, "mdia")
	writeBoxHdr(minfSize, "minf")
	writeBoxHdr(stblSize, "stbl")
	writeBoxHdr(co64Size, "co64")
	writeUint32BE(0)
	writeUint32BE(uint32(len(chunkOffsets)))
	for _, off := range chunkOffsets {
		writeUint64BE(off)
	}

	return buf.Bytes()
}

// TestFinding1_StcoOffsetRewriting verifies that SanitizeMP4 correctly adjusts
// stco chunk offsets when moov is relocated before mdat.
//
// Test plan:
//  1. Build a mdat-first MP4 with stco entries pointing at specific byte offsets
//     inside the mdat payload.
//  2. Run SanitizeMP4; expect non-nil Metadata (relocation occurred).
//  3. Reconstruct the file as Metadata || input[DataOffset:DataOffset+DataLength].
//  4. Parse the reconstructed file with mp4ff.
//  5. Assert that the stco offsets in the parsed file resolve to the correct
//     sample data within the reconstructed mdat.
//
// Java oracle: Mp4SanitizerTest.java:L64–L73 (testMinimalMp4 structure);
// ISO BMFF §8.7.5 chunk-offset box.
func TestFinding1_StcoOffsetRewriting(t *testing.T) {
	// Sample payload: 8 bytes, two 4-byte "chunks" at positions 0 and 4.
	payload := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	// ftyp is 20 bytes. mdat box = 8 (header) + 8 (payload) = 16 bytes.
	// In the original mdat-first file:
	//   offset 0:  ftyp (20 bytes)
	//   offset 20: mdat box (16 bytes)
	//   offset 36: moov
	//
	// The mdat payload starts at offset 28 (20 + 8).
	// Chunk 1 is at payload byte 0 → absolute offset 28.
	// Chunk 2 is at payload byte 4 → absolute offset 32.
	mdatPayloadStart := uint32(20 + 8) // ftyp(20) + mdat_header(8)
	chunkOffsets := []uint32{
		mdatPayloadStart,     // chunk 1 at payload[0]
		mdatPayloadStart + 4, // chunk 2 at payload[4]
	}

	input := buildMP4WithStco(payload, chunkOffsets)

	got, err := SanitizeMP4(input)
	if err != nil {
		t.Fatalf("SanitizeMP4 returned error: %v", err)
	}
	if got.Metadata == nil {
		t.Fatal("Metadata should be non-nil (moov was after mdat)")
	}

	// Reconstruct the output file: Metadata || mdat span.
	mdatSpan := input[got.DataOffset : got.DataOffset+got.DataLength]
	reconstructed := append(got.Metadata, mdatSpan...)

	// Parse the reconstructed file with mp4ff and verify offsets.
	f, err := mp4.DecodeFile(bytes.NewReader(reconstructed))
	if err != nil {
		t.Fatalf("re-parsing reconstructed MP4 failed: %v", err)
	}
	if len(f.Moov.Traks) == 0 {
		t.Fatal("reconstructed MP4 has no trak boxes")
	}
	stbl := f.Moov.Traks[0].Mdia.Minf.Stbl
	if stbl.Stco == nil {
		t.Fatal("reconstructed stbl has no stco box")
	}

	// In the reconstructed file the layout is:
	//   ftyp (20) | moov (...) | mdat (16)
	// The mdat payload starts at len(ftyp) + len(moov) + 8 (mdat header).
	ftypLen := int64(20)
	moovLen := int64(f.Moov.Size())
	newMdatPayloadStart := ftypLen + moovLen + 8 // 8 = mdat header

	for i, off := range stbl.Stco.ChunkOffset {
		absOff := int64(off)
		// The offset must fall within the mdat payload in the reconstructed file.
		mdatEnd := int64(len(reconstructed))
		if absOff < newMdatPayloadStart || absOff >= mdatEnd {
			t.Errorf("chunk[%d] offset %d is outside mdat payload [%d, %d)",
				i, absOff, newMdatPayloadStart, mdatEnd)
			continue
		}
		// Verify that the byte at this offset matches the original payload.
		payloadIdx := absOff - newMdatPayloadStart
		got := reconstructed[absOff]
		want := payload[payloadIdx]
		if got != want {
			t.Errorf("chunk[%d] at offset %d: got byte 0x%02x, want 0x%02x",
				i, absOff, got, want)
		}
	}
}

// TestFinding1_Co64OffsetRewriting verifies that SanitizeMP4 correctly adjusts
// co64 (64-bit) chunk offsets when moov is relocated before mdat.
//
// ISO BMFF §8.7.5 co64 (Chunk Large Offset Box).
func TestFinding1_Co64OffsetRewriting(t *testing.T) {
	payload := []byte{0xAA, 0xBB, 0xCC, 0xDD}

	// ftyp=20, mdat_header=8, payload=4 → mdat payload starts at 28.
	mdatPayloadStart := uint64(20 + 8)
	chunkOffsets := []uint64{mdatPayloadStart}

	input := buildMP4WithCo64(payload, chunkOffsets)

	got, err := SanitizeMP4(input)
	if err != nil {
		t.Fatalf("SanitizeMP4 returned error: %v", err)
	}
	if got.Metadata == nil {
		t.Fatal("Metadata should be non-nil (moov was after mdat)")
	}

	mdatSpan := input[got.DataOffset : got.DataOffset+got.DataLength]
	reconstructed := append(got.Metadata, mdatSpan...)

	f, err := mp4.DecodeFile(bytes.NewReader(reconstructed))
	if err != nil {
		t.Fatalf("re-parsing reconstructed MP4 failed: %v", err)
	}
	stbl := f.Moov.Traks[0].Mdia.Minf.Stbl
	if stbl.Co64 == nil {
		t.Fatal("reconstructed stbl has no co64 box")
	}

	ftypLen := int64(20)
	moovLen := int64(f.Moov.Size())
	newMdatPayloadStart := ftypLen + moovLen + 8

	for i, off := range stbl.Co64.ChunkOffset {
		absOff := int64(off)
		mdatEnd := int64(len(reconstructed))
		if absOff < newMdatPayloadStart || absOff >= mdatEnd {
			t.Errorf("chunk[%d] offset %d is outside mdat payload [%d, %d)",
				i, absOff, newMdatPayloadStart, mdatEnd)
			continue
		}
		payloadIdx := absOff - newMdatPayloadStart
		gotByte := reconstructed[absOff]
		wantByte := payload[payloadIdx]
		if gotByte != wantByte {
			t.Errorf("chunk[%d] at offset %d: got byte 0x%02x, want 0x%02x",
				i, absOff, gotByte, wantByte)
		}
	}
}

// TestFinding1_StcoToCoPromotion verifies that stco->co64 promotion occurs
// when the chunk offset + relocation delta would overflow uint32.
//
// Layout analysis:
//
//	ftyp(20) | mdat(8+4=12) | moov
//
// moov size with 1-entry stco = 60 bytes (see buildMoovWithStco).
// original mdat start = 20 (right after ftyp).
// new mdat start = 20 (ftyp) + 60 (moov) = 80.
// delta = 80 - 20 = 60.
//
// After promotion co64(24 bytes) replaces stco(20 bytes), moov grows to 64.
// new mdat start = 20 + 64 = 84; delta = 84 - 20 = 64.
// nearMax = 0xFFFFFFF0: 0xFFFFFFF0 + 64 = 4294967344 > math.MaxUint32 -> promotion.
//
// ISO BMFF §8.7.5; Finding #1 stco->co64 promotion cycle.
func TestFinding1_StcoToCoPromotion(t *testing.T) {
	// nearMax + delta(60) = 0xFFFFFFF0 + 60 = 4294967344 > 4294967295 (MaxUint32)
	nearMax := uint32(0xFFFFFFF0)
	chunkOffsets := []uint32{nearMax}

	payload := []byte{0x01, 0x02, 0x03, 0x04} // 4 fake bytes (mdat payload)
	input := buildMP4WithStco(payload, chunkOffsets)

	got, err := SanitizeMP4(input)
	if err != nil {
		t.Fatalf("SanitizeMP4 returned error: %v", err)
	}
	if got.Metadata == nil {
		t.Fatal("Metadata should be non-nil (moov was after mdat)")
	}

	// Reconstruct and re-parse.
	mdatSpan := input[got.DataOffset : got.DataOffset+got.DataLength]
	reconstructed := append(got.Metadata, mdatSpan...)

	f, err := mp4.DecodeFile(bytes.NewReader(reconstructed))
	if err != nil {
		t.Fatalf("re-parsing reconstructed MP4 (promotion case) failed: %v", err)
	}

	if len(f.Moov.Traks) == 0 || f.Moov.Traks[0].Mdia == nil ||
		f.Moov.Traks[0].Mdia.Minf == nil || f.Moov.Traks[0].Mdia.Minf.Stbl == nil {
		t.Fatal("reconstructed MP4 missing trak/mdia/minf/stbl")
	}
	stbl := f.Moov.Traks[0].Mdia.Minf.Stbl

	// After promotion, the stbl must have a co64 box and no stco box.
	if stbl.Stco != nil {
		t.Error("expected stco to be promoted to co64, but stco is still present")
	}
	if stbl.Co64 == nil {
		t.Fatal("expected co64 box after stco->co64 promotion, but co64 is absent")
	}

	if len(stbl.Co64.ChunkOffset) == 0 {
		t.Fatal("co64 has no entries after promotion")
	}
	newOffset := stbl.Co64.ChunkOffset[0]
	// delta = (ftypLen + moovSizeAfterPromotion) - originalMdatStart
	//       = (20 + 64) - 20 = 64
	// After promotion stco(20 bytes) becomes co64(24 bytes), growing moov from 60 to 64.
	// Expected: nearMax + delta = 0xFFFFFFF0 + 64 = 4294967344
	const expectedDelta = 64
	expectedOffset := uint64(nearMax) + expectedDelta
	if newOffset != expectedOffset {
		t.Errorf("promoted co64 offset = %d, want %d (nearMax=%d + delta=%d)",
			newOffset, expectedOffset, nearMax, expectedDelta)
	}
}

// TestFinding1_NoOffsetRewritingForFaststartLayout verifies that when moov
// already precedes mdat (faststart), no offset rewriting occurs and Metadata
// is nil.
//
// Java oracle: Mp4SanitizerTest.java:L52–L61 (testNoopMinimalMp4).
func TestFinding1_NoOffsetRewritingForFaststartLayout(t *testing.T) {
	// Build moov-first (faststart) with stco entries.
	ftyp := javaFtyp() // 20 bytes

	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	// In moov-first layout:
	//   offset 0:  ftyp (20)
	//   offset 20: moov
	//   offset 20+moovLen: mdat
	//
	// We don't know moovLen yet, so we compute a dummy offset for the stco.
	// The actual value doesn't matter for the noop test — we just verify Metadata=nil.
	moovBytes := buildMoovWithStco([]uint32{0x1234}) // placeholder offset

	mdatSize := uint32(8 + len(payload))
	mdatBox := make([]byte, mdatSize)
	binary.BigEndian.PutUint32(mdatBox[0:4], mdatSize)
	copy(mdatBox[4:8], "mdat")
	copy(mdatBox[8:], payload)

	var buf bytes.Buffer
	buf.Write(ftyp)
	buf.Write(moovBytes)
	buf.Write(mdatBox)
	input := buf.Bytes()

	got, err := SanitizeMP4(input)
	if err != nil {
		t.Fatalf("SanitizeMP4 (faststart) returned error: %v", err)
	}
	if got.Metadata != nil {
		t.Errorf("Metadata should be nil for faststart layout, got %d bytes", len(got.Metadata))
	}
}

// TestCompoundedMdat_MoovAfterMdat_StcoOffsetRewriting is a regression test for
// the moov-after-mdat branch of sanitizeMP4Compounded.  The original code
// concatenated raw ftyp||moov bytes without adjusting stco/co64 entries, leaving
// absolute chunk offsets stale after moov is relocated before mdat.
//
// Layout under test:
//
//	ftyp(20) | mdat_header(8, size=0) | payload(8) | moov(60, stco→offset 28)
//
// After SanitizeMP4WithCompoundedMdat the sanitized file layout is:
//
//	Metadata(ftyp+moov) | mdat_header | payload
//
// ISO BMFF §8.7.5 requires every stco/co64 entry to equal the byte position of
// the corresponding chunk in the SANITIZED file.  The test verifies that:
//  1. stco[0] == originalChunkOffset + (len(Metadata) - originalMdatOffset)
//  2. reconstructed[stco[0]] == payload[0]  (byte-level correctness)
//
// Rust mp4san oracle; ISO BMFF §8.7.5.
func TestCompoundedMdat_MoovAfterMdat_StcoOffsetRewriting(t *testing.T) {
	// Build ftyp(20) | mdat_header(8,size=0) | payload(8) | moov(60).
	//
	//   offset  0: ftyp — 20 bytes
	//   offset 20: mdat box header (size=0) — 8 bytes
	//   offset 28: mdat payload — 8 bytes   ← chunk 0 lives here
	//   offset 36: moov with one-entry stco pointing at offset 28
	payload := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	// mdat header with size=0 (compounded form).  [0:4] left zero by make.
	mdatHdr := make([]byte, 8)
	copy(mdatHdr[4:], "mdat")

	const originalMdatOffset = int64(20)   // ftyp is 20 bytes
	const originalChunkOffset = uint32(28) // mdat payload byte 0 = ftyp(20)+hdr(8)

	moovRaw := buildMoovWithStco([]uint32{originalChunkOffset})

	var buf bytes.Buffer
	buf.Write(javaFtyp())
	buf.Write(mdatHdr)
	buf.Write(payload)
	buf.Write(moovRaw)
	input := buf.Bytes()

	cumulativeSize := 8 + len(payload) // 16

	got, err := SanitizeMP4WithCompoundedMdat(input, cumulativeSize)
	if err != nil {
		t.Fatalf("SanitizeMP4WithCompoundedMdat returned error: %v", err)
	}
	if got.Metadata == nil {
		t.Fatal("Metadata must be non-nil: moov follows mdat in compounded layout")
	}
	if got.DataOffset != originalMdatOffset {
		t.Errorf("DataOffset = %d, want %d", got.DataOffset, originalMdatOffset)
	}
	if got.DataLength != int64(cumulativeSize) {
		t.Errorf("DataLength = %d, want %d", got.DataLength, cumulativeSize)
	}

	// Decode the returned Metadata (ftyp + rewritten moov) to extract the stco.
	mf, parseErr := mp4.DecodeFile(bytes.NewReader(got.Metadata))
	if parseErr != nil {
		t.Fatalf("mp4.DecodeFile(Metadata): %v", parseErr)
	}
	if mf.Moov == nil || len(mf.Moov.Traks) == 0 {
		t.Fatal("Metadata moov is missing or has no traks")
	}
	stbl := mf.Moov.Traks[0].Mdia.Minf.Stbl
	if stbl == nil {
		t.Fatal("Metadata moov trak missing stbl")
	}
	if stbl.Stco == nil {
		t.Fatal("Metadata moov stbl missing stco (expected stco with one entry)")
	}
	if len(stbl.Stco.ChunkOffset) == 0 {
		t.Fatal("stco in Metadata has no entries")
	}

	// The sanitized file layout is: Metadata || input[DataOffset:DataOffset+DataLength].
	// The mdat box starts at byte offset len(Metadata) in the sanitized file.
	// delta = len(Metadata) - originalMdatOffset.
	// Corrected chunk offset must equal originalChunkOffset + delta.
	newMdatStart := int64(len(got.Metadata))
	delta := newMdatStart - originalMdatOffset
	wantOffset := uint32(int64(originalChunkOffset) + delta)

	gotOffset := stbl.Stco.ChunkOffset[0]
	if gotOffset != wantOffset {
		t.Errorf("stco[0] = %d, want %d (originalChunkOffset=%d + delta=%d)",
			gotOffset, wantOffset, originalChunkOffset, delta)
	}

	// Byte-level verification: the offset must index the first byte of the
	// mdat payload in the reconstructed file.
	//   Metadata(n) | mdat_header(8) | payload(8)
	// mdat payload byte 0 lives at offset newMdatStart + 8 = wantOffset.
	mdatSpan := input[got.DataOffset : got.DataOffset+got.DataLength]
	reconstructed := append(got.Metadata, mdatSpan...)

	if int(gotOffset) >= len(reconstructed) {
		t.Fatalf("stco[0] = %d is beyond reconstructed file length %d", gotOffset, len(reconstructed))
	}
	if reconstructed[gotOffset] != payload[0] {
		t.Errorf("reconstructed[stco[0]] = 0x%02x, want payload[0] = 0x%02x",
			reconstructed[gotOffset], payload[0])
	}
}

// TestFinding1_EmptyStco verifies that an empty stco (entry_count=0) is handled
// correctly — no offset adjustments, no panic.
//
// Java oracle: Mp4SanitizerTest.java:L126–L157 (moov has entry_count=0 stco).
func TestFinding1_EmptyStco(t *testing.T) {
	// Java oracle moov has an empty stco; use ftyp+mdat+moov layout to trigger rewrite.
	input := append(javaFtyp(), append(javaMdat(), javaMoov()...)...)

	got, err := SanitizeMP4(input)
	if err != nil {
		t.Fatalf("SanitizeMP4 (empty stco) returned error: %v", err)
	}
	if got.Metadata == nil {
		t.Fatal("Metadata should be non-nil (moov was after mdat)")
	}

	// Parse the reconstructed file; the stco must have 0 entries.
	mdatSpan := input[got.DataOffset : got.DataOffset+got.DataLength]
	reconstructed := append(got.Metadata, mdatSpan...)

	f, err := mp4.DecodeFile(bytes.NewReader(reconstructed))
	if err != nil {
		t.Fatalf("re-parsing reconstructed MP4 (empty stco) failed: %v", err)
	}
	stbl := f.Moov.Traks[0].Mdia.Minf.Stbl
	if stbl.Stco == nil {
		t.Fatal("expected stco in reconstructed stbl for empty-entry case")
	}
	if len(stbl.Stco.ChunkOffset) != 0 {
		t.Errorf("expected 0 stco entries, got %d", len(stbl.Stco.ChunkOffset))
	}
}

// TestFinding2_InfiniteLoopGuard verifies that SanitizeMP4WithCompoundedMdat
// rejects cumulativeMdatBoxSize < 8, which previously caused an infinite loop.
//
// Java oracle: Mp4Sanitizer.java:L83–L115 (sanitizeFileWithCompoundedMdatBoxes).
// Finding #2.
func TestFinding2_InfiniteLoopGuard(t *testing.T) {
	input := append(javaFtyp(), javaMoov()...)
	for _, size := range []int{-1, 0, 1, 7} {
		_, err := SanitizeMP4WithCompoundedMdat(input, size)
		if err == nil {
			t.Errorf("cumulativeMdatBoxSize=%d: expected error (DoS guard), got nil", size)
		}
		var mve *MediaValidationError
		if !errors.As(err, &mve) {
			t.Errorf("cumulativeMdatBoxSize=%d: expected *MediaValidationError, got %T: %v",
				size, err, err)
		}
	}
}

// TestFinding3_CompoundedPathFailClosedOnParseError verifies that the compounded-mdat
// path returns a MediaValidationError when the moov bytes cannot be parsed.
//
// Finding #3: the old code only ran dref validation when parse succeeded;
// now it is fail-closed.
func TestFinding3_CompoundedPathFailClosedOnParseError(t *testing.T) {
	// Build a "moov" whose content is garbage (it will fail mp4ff parsing).
	garbledMoov := make([]byte, 16)
	binary.BigEndian.PutUint32(garbledMoov[0:4], 16) // correct size
	copy(garbledMoov[4:8], "moov")
	// Fill payload with garbage bytes that will fail box-level decode.
	copy(garbledMoov[8:16], []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})

	mdat := javaCompoundedMdat()
	var buf bytes.Buffer
	buf.Write(javaFtyp())
	buf.Write(mdat)
	buf.Write(garbledMoov)
	input := buf.Bytes()

	_, err := SanitizeMP4WithCompoundedMdat(input, len(mdat))
	if err == nil {
		t.Fatal("expected error for compounded-mdat path with garbled moov")
	}
	var mve *MediaValidationError
	if !errors.As(err, &mve) {
		t.Errorf("expected *MediaValidationError, got %T: %v", err, err)
	}
}
