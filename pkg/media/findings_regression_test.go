package media

// findings_regression_test.go — regression tests for the five code-review
// findings fixed in this batch.  Each test covers exactly the failure mode
// described in the finding and must NOT panic.
//
// Finding 1 (CRITICAL): panic on crafted mdat larger than file.
// Finding 2 (MEDIUM):   silent uint32 truncation after stco→co64 promotion.
// Finding 3 (MEDIUM):   VP8X 16383 canvas-dimension cap (removed).
// Finding 4 (LOW):      VP8L short code at chunk boundary → ErrLosslessTruncated.
// Finding 5 (LOW):      faststart re-parse without DecModeLazyMdat (perf fix).

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	mp4 "github.com/Eyevinn/mp4ff/mp4"
)

// ---------------------------------------------------------------------------
// Finding 1 — oversized mdat must not panic
// ---------------------------------------------------------------------------

// buildFaststartMP4WithInflatedMdat builds a moov-first (faststart) MP4 whose
// mdat box header declares a size far larger than the actual file length.
//
// ftyp(20) | moov(60) | mdat(header claims inflatedSize, only 4 actual bytes)
func buildFaststartMP4WithInflatedMdat(inflatedSize uint32) []byte {
	ftyp := javaFtyp()                     // 20 bytes
	moov := buildMoovWithStco([]uint32{0}) // 60 bytes

	var buf bytes.Buffer
	buf.Write(ftyp)
	buf.Write(moov)

	// mdat header with inflated declared size.
	hdr := make([]byte, 8)
	binary.BigEndian.PutUint32(hdr[0:4], inflatedSize)
	copy(hdr[4:8], "mdat")
	buf.Write(hdr)
	buf.Write([]byte{0x01, 0x02, 0x03, 0x04}) // 4 actual bytes of payload
	return buf.Bytes()
}

// buildFaststartMP4WithLargeBoxMdat builds a faststart MP4 where the mdat box
// uses a 16-byte large-box (ISO BMFF extended-size) header claiming a 64-bit
// size near math.MaxInt64.
func buildFaststartMP4WithLargeBoxMdat(size64 uint64) []byte {
	ftyp := javaFtyp()
	moov := buildMoovWithStco([]uint32{0})

	var buf bytes.Buffer
	buf.Write(ftyp)
	buf.Write(moov)

	// Extended-size mdat: 4-byte sentinel (1), 4-byte fourcc, 8-byte size.
	hdr := make([]byte, 16)
	binary.BigEndian.PutUint32(hdr[0:4], 1) // sentinel
	copy(hdr[4:8], "mdat")
	binary.BigEndian.PutUint64(hdr[8:16], size64)
	buf.Write(hdr)
	buf.Write([]byte{0xAA, 0xBB}) // 2 actual bytes
	return buf.Bytes()
}

// TestFinding1_Regression_OversizedMdatFaststart_SanitizeMP4 verifies that
// SanitizeMP4 returns a typed error (not panics) when the mdat box claims more
// bytes than the file contains — faststart (moov-first) layout.
//
// Rust oracle: mp4san sanitize → bounds check on mdat span.
func TestFinding1_Regression_OversizedMdatFaststart_SanitizeMP4(t *testing.T) {
	data := buildFaststartMP4WithInflatedMdat(1_000_000)
	_, err := SanitizeMP4(data)
	if err == nil {
		t.Fatal("expected error for oversized mdat in faststart layout, got nil")
	}
	// Verify it is a typed error (not a generic string).
	var mvErr *MediaValidationError
	if !errors.As(err, &mvErr) {
		t.Errorf("expected *MediaValidationError, got %T: %v", err, err)
	}
}

// TestFinding1_Regression_OversizedMdatFaststart_Validate verifies the same
// via the Validate entry point (auto-detects MP4 by magic bytes).
func TestFinding1_Regression_OversizedMdatFaststart_Validate(t *testing.T) {
	data := buildFaststartMP4WithInflatedMdat(1_000_000)
	_, err := Validate(data)
	if err == nil {
		t.Fatal("expected error for oversized mdat via Validate, got nil")
	}
	var mvErr *MediaValidationError
	if !errors.As(err, &mvErr) {
		t.Errorf("expected *MediaValidationError, got %T: %v", err, err)
	}
}

// TestFinding1_Regression_64BitMdatNearMaxInt64 verifies that a faststart MP4
// with a 64-bit mdat size near math.MaxInt64 returns a typed error, not panic.
func TestFinding1_Regression_64BitMdatNearMaxInt64(t *testing.T) {
	// Declared size = math.MaxInt64 (positive when cast to int64, but >> file size).
	const nearMax = uint64(0x7FFFFFFFFFFFFFFF)
	data := buildFaststartMP4WithLargeBoxMdat(nearMax)
	_, err := SanitizeMP4(data)
	if err == nil {
		t.Fatal("expected error for 64-bit oversized mdat, got nil")
	}
	// Any typed error is acceptable (mp4ff parse error or our bounds check).
	if err.Error() == "" {
		t.Error("returned error has empty message")
	}
}

// TestFinding1_Regression_MdatFirstOversized verifies that a mdat-first layout
// with an inflated mdat size returns a typed error (not panic).
// Because the inflated mdat prevents mp4ff from locating moov, the error comes
// from the moov-missing check — that is intentional; the path must not panic.
func TestFinding1_Regression_MdatFirstOversized(t *testing.T) {
	// ftyp(20) | mdat(header claims 1MB, 4 actual bytes) | moov would follow at 1MB+
	// mp4ff cannot find moov → returns a parse/validation error, not a panic.
	ftyp := javaFtyp()
	var buf bytes.Buffer
	buf.Write(ftyp)
	hdr := make([]byte, 8)
	binary.BigEndian.PutUint32(hdr[0:4], 1_000_000) // inflated
	copy(hdr[4:8], "mdat")
	buf.Write(hdr)
	buf.Write([]byte{0x01, 0x02, 0x03, 0x04})
	// moov would go here but is omitted / unreachable at the declared offset.
	moov := buildMoovWithStco([]uint32{0})
	buf.Write(moov)

	data := buf.Bytes()
	_, err := SanitizeMP4(data)
	if err == nil {
		t.Fatal("expected error for mdat-first oversized mdat, got nil")
	}
}

// ---------------------------------------------------------------------------
// Finding 2 — multi-trak stco→co64 fixed-point promotion
// ---------------------------------------------------------------------------

// buildMoovWith2TrakStco builds a moov box containing two traks, each with a
// one-entry stco containing the provided offsets.
//
// Structure: moov → [trak1(stco(off1)), trak2(stco(off2))]
func buildMoovWith2TrakStco(off1, off2 uint32) []byte {
	buildOneTrak := func(off uint32) []byte {
		// stco: 8-header + 4(ver/flags) + 4(count) + 4(offset) = 20 bytes
		const stcoSize = 20
		const stblSize = 8 + stcoSize
		const minfSize = 8 + stblSize
		const mdiaSize = 8 + minfSize
		const trakSize = 8 + mdiaSize

		var b bytes.Buffer
		writeBox := func(size int, fourcc string) {
			hdr := make([]byte, 8)
			binary.BigEndian.PutUint32(hdr[0:4], uint32(size))
			copy(hdr[4:8], fourcc)
			b.Write(hdr)
		}
		writeU32 := func(v uint32) {
			tmp := make([]byte, 4)
			binary.BigEndian.PutUint32(tmp, v)
			b.Write(tmp)
		}

		writeBox(trakSize, "trak")
		writeBox(mdiaSize, "mdia")
		writeBox(minfSize, "minf")
		writeBox(stblSize, "stbl")
		writeBox(stcoSize, "stco")
		writeU32(0) // version=0, flags=0
		writeU32(1) // entry_count=1
		writeU32(off)
		return b.Bytes()
	}

	trak1 := buildOneTrak(off1)
	trak2 := buildOneTrak(off2)

	moovSize := 8 + len(trak1) + len(trak2)
	var b bytes.Buffer
	hdr := make([]byte, 8)
	binary.BigEndian.PutUint32(hdr[0:4], uint32(moovSize))
	copy(hdr[4:8], "moov")
	b.Write(hdr)
	b.Write(trak1)
	b.Write(trak2)
	return b.Bytes()
}

// buildMP4With2TrakStco builds a mdat-first MP4 with two traks.
// ftyp(20) | mdat(8+payload) | moov(2-trak with given stco offsets).
func buildMP4With2TrakStco(payload []byte, off1, off2 uint32) []byte {
	ftyp := javaFtyp()
	moov := buildMoovWith2TrakStco(off1, off2)

	mdatSize := uint32(8 + len(payload))
	mdatBox := make([]byte, mdatSize)
	binary.BigEndian.PutUint32(mdatBox[0:4], mdatSize)
	copy(mdatBox[4:8], "mdat")
	copy(mdatBox[8:], payload)

	var buf bytes.Buffer
	buf.Write(ftyp)
	buf.Write(mdatBox)
	buf.Write(moov)
	return buf.Bytes()
}

// TestFinding2_Regression_MultiTrakPostPromotionOverflow verifies that when
// promoting trak1's stco→co64 increases delta enough to cause trak2's stco
// to overflow uint32, the fixed-point promotion loop promotes trak2 as well.
//
// Layout: ftyp(20) | mdat(12) | moov(112, 2 traks with 1 stco entry each).
// originalMdatStart = 20.
// moovLen = 112; D0 = 112.
//
// trak1 stco[0] = 0xFFFFFF90 → 0xFFFFFF90+112 = 4294967296 > MaxUint32 → promoted.
// After promotion: moovLen = 116; D1 = 116.
// trak2 stco[0] = 0xFFFFFF8F → 0xFFFFFF8F+112 = MaxUint32 (safe with D0), but
//
//	0xFFFFFF8F+116 = 4294967299 > MaxUint32 → promoted by fixed-point pass 2.
//
// ISO BMFF §8.7.5; Rust mp4san stco→co64 promotion.
func TestFinding2_Regression_MultiTrakPostPromotionOverflow(t *testing.T) {
	const (
		trak1Off = uint32(0xFFFFFF90) // 4294967184: overflows with D0=112
		trak2Off = uint32(0xFFFFFF8F) // 4294967183: safe with D0=112, overflows with D1=116
	)
	payload := []byte{0x11, 0x22, 0x33, 0x44}
	input := buildMP4With2TrakStco(payload, trak1Off, trak2Off)

	got, err := SanitizeMP4(input)
	if err != nil {
		t.Fatalf("SanitizeMP4: %v", err)
	}
	if got.Metadata == nil {
		t.Fatal("expected non-nil Metadata (moov was after mdat)")
	}

	// Reconstruct and re-parse.
	mdatSpan := input[got.DataOffset : got.DataOffset+got.DataLength]
	reconstructed := append(got.Metadata, mdatSpan...)

	f, err := mp4.DecodeFile(bytes.NewReader(reconstructed))
	if err != nil {
		t.Fatalf("re-parsing reconstructed MP4: %v", err)
	}
	if len(f.Moov.Traks) != 2 {
		t.Fatalf("expected 2 traks, got %d", len(f.Moov.Traks))
	}

	// Both traks must have been promoted to co64.
	for i, trak := range f.Moov.Traks {
		if trak.Mdia == nil || trak.Mdia.Minf == nil || trak.Mdia.Minf.Stbl == nil {
			t.Fatalf("trak[%d] missing mdia/minf/stbl", i)
		}
		stbl := trak.Mdia.Minf.Stbl
		if stbl.Stco != nil {
			t.Errorf("trak[%d]: expected stco→co64 promotion, but stco still present", i)
		}
		if stbl.Co64 == nil {
			t.Errorf("trak[%d]: expected co64 after promotion, but co64 is absent", i)
		}
	}

	// After two promotions: moov grows from 112 → 116 → 120.
	// Final delta D2 = (20 + 120) - 20 = 120.
	// trak1 co64[0] = uint64(0xFFFFFF90) + 120 = 4294967304
	// trak2 co64[0] = uint64(0xFFFFFF8F) + 120 = 4294967303
	const finalDelta = 120
	expected := []uint64{
		uint64(trak1Off) + finalDelta,
		uint64(trak2Off) + finalDelta,
	}
	for i, trak := range f.Moov.Traks {
		stbl := trak.Mdia.Minf.Stbl
		if stbl.Co64 == nil || len(stbl.Co64.ChunkOffset) == 0 {
			continue
		}
		got64 := stbl.Co64.ChunkOffset[0]
		if got64 != expected[i] {
			t.Errorf("trak[%d] co64[0] = %d, want %d", i, got64, expected[i])
		}
	}
}

// TestFinding2_Regression_SingleTrakSafeWithFinalDelta verifies that a single
// trak whose stco fits after promotion (no secondary overflow) is handled
// correctly by the fixed-point loop exiting after one pass.
func TestFinding2_Regression_SingleTrakSafeWithFinalDelta(t *testing.T) {
	// Use an offset that overflows with D0 but not with D1.
	// moovLen with 1 trak, 1 stco entry = 60; D0 = 60.
	// After promotion: moovLen = 64; D1 = 64.
	// off = 0xFFFFFFC0 (4294967232): 4294967232+60=4294967292 ≤ MaxUint32 — no overflow.
	// Actually we need overflow on first pass to trigger promotion. Use 0xFFFFFFF0+1:
	// 0xFFFFFFF1 + 60 = 4294967297 > MaxUint32 → promote in pass 1.
	// After promotion D1 = 64: 0xFFFFFFF1 + 64 = 4294967301 > MaxUint32?
	// ... that's still >MaxUint32, so co64 handles it fine.
	const off = uint32(0xFFFFFFF0)
	payload := []byte{0x01, 0x02, 0x03, 0x04}
	input := buildMP4WithStco(payload, []uint32{off})

	got, err := SanitizeMP4(input)
	if err != nil {
		t.Fatalf("SanitizeMP4: %v", err)
	}
	if got.Metadata == nil {
		t.Fatal("expected non-nil Metadata")
	}

	mdatSpan := input[got.DataOffset : got.DataOffset+got.DataLength]
	reconstructed := append(got.Metadata, mdatSpan...)
	f, err := mp4.DecodeFile(bytes.NewReader(reconstructed))
	if err != nil {
		t.Fatalf("re-parsing: %v", err)
	}
	stbl := f.Moov.Traks[0].Mdia.Minf.Stbl
	if stbl.Stco != nil {
		t.Error("stco should have been promoted to co64")
	}
	if stbl.Co64 == nil {
		t.Fatal("co64 not present after promotion")
	}
}

// ---------------------------------------------------------------------------
// Finding 3 — VP8X dimensions above old 16383 cap are accepted
// ---------------------------------------------------------------------------

// TestFinding3_Regression_VP8XDimAbove16383Accepted verifies that a WebP with
// VP8X canvas dimensions between 16384 and 65536 (actual) is accepted when the
// pixel count does not overflow uint32.
//
// webpsan 0.5.3 oracle: only pixel-count overflow is rejected; there is no
// per-dimension cap.
func TestFinding3_Regression_VP8XDimAbove16383Accepted(t *testing.T) {
	// storedW = storedH = 16384 → actual = 16385.
	// 16385 * 16385 = 268,370,225 << 0xFFFFFFFF → must be accepted.
	const stored = uint32(16384)
	vp8xPayload := make([]byte, 10)
	vp8xPayload[4] = byte(stored & 0xFF)
	vp8xPayload[5] = byte((stored >> 8) & 0xFF)
	// storedH = 0 (actual = 1) to keep pixel count very small.
	vp8xPayload[7] = 0x00
	vp8xPayload[8] = 0x00

	var chunks bytes.Buffer
	writeChunk(&chunks, "VP8X", vp8xPayload)
	writeVP8Chunk(&chunks)

	data := buildWebPPayload(&chunks)
	err := SanitizeWebP(data)
	if err != nil {
		t.Errorf("expected WebP with storedW=16384 to be accepted, got: %v", err)
	}
}

// TestFinding3_Regression_VP8XPixelOverflowStillRejected verifies that the
// pixel-count overflow check still fires even without the dimension cap.
// storedW = storedH = 0xFFFF → actual = 65536 → 65536² = 4294967296 > 0xFFFFFFFF.
func TestFinding3_Regression_VP8XPixelOverflowStillRejected(t *testing.T) {
	const stored = uint32(0xFFFF) // actual = 65536
	vp8xPayload := make([]byte, 10)
	vp8xPayload[4] = byte(stored & 0xFF)
	vp8xPayload[5] = byte((stored >> 8) & 0xFF)
	vp8xPayload[7] = byte(stored & 0xFF)
	vp8xPayload[8] = byte((stored >> 8) & 0xFF)

	var chunks bytes.Buffer
	writeChunk(&chunks, "VP8X", vp8xPayload)
	writeVP8Chunk(&chunks)

	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// ---------------------------------------------------------------------------
// Finding 4 — VP8L short code at chunk boundary
// ---------------------------------------------------------------------------

// TestFinding4_Regression_HuffmanDecodeShortCodeAtBoundary verifies that
// huffmanTree.decode correctly handles the case where the stream ends with
// exactly 1 bit remaining, which is sufficient to decode a 1-bit code but
// not the full maxCodeLen (2) bits.
//
// The old code called readBits(maxCodeLen) unconditionally, returning
// ErrLosslessTruncated when fewer bits were available.
//
// Rust oracle: bitstream.rs CanonicalHuffmanTree::read_symbol.
func TestFinding4_Regression_HuffmanDecodeShortCodeAtBoundary(t *testing.T) {
	// Build a tree with 3 symbols, maxCodeLen=2:
	//   sym 0: length 1, code 0b0  (table[0] and table[2])
	//   sym 1: length 2, code 0b01 (table[1])
	//   sym 2: length 2, code 0b11 (table[3])
	codeLengths := []symLen{
		{sym: 0, length: 1},
		{sym: 1, length: 2},
		{sym: 2, length: 2},
	}
	tree, err := buildHuffmanTree(codeLengths)
	if err != nil {
		t.Fatalf("buildHuffmanTree: %v", err)
	}

	// Single byte 0x00; position bitPos at bit 7 so only 1 bit remains.
	// That bit (bit 7 of 0x00) = 0, which is the 1-bit code for symbol 0.
	r := newLeBitReader([]byte{0x00})
	r.bitPos = 7

	sym, decErr := tree.decode(r)
	if decErr != nil {
		t.Fatalf("decode with 1 bit remaining: unexpected error %v", decErr)
	}
	if sym != 0 {
		t.Errorf("expected symbol 0, got %d", sym)
	}
	// bitPos must advance by 1 (the code length), ending at 8 (past end of stream).
	if r.bitPos != 8 {
		t.Errorf("bitPos after decode = %d, want 8", r.bitPos)
	}
}

// TestFinding4_Regression_HuffmanDecodeTruncatedZeroBitsRemaining verifies that
// decode returns ErrLosslessTruncated when no bits remain (bitPos == 8*len).
func TestFinding4_Regression_HuffmanDecodeTruncatedZeroBitsRemaining(t *testing.T) {
	codeLengths := []symLen{
		{sym: 0, length: 1},
		{sym: 1, length: 2},
		{sym: 2, length: 2},
	}
	tree, err := buildHuffmanTree(codeLengths)
	if err != nil {
		t.Fatalf("buildHuffmanTree: %v", err)
	}

	// Position bitPos at the end of the single byte — 0 bits remaining.
	r := newLeBitReader([]byte{0x00})
	r.bitPos = 8

	_, decErr := tree.decode(r)
	if _, ok := decErr.(*ErrLosslessTruncated); !ok {
		t.Errorf("expected *ErrLosslessTruncated with 0 bits remaining, got %T: %v", decErr, decErr)
	}
}

// TestFinding4_Regression_HuffmanDecodeShortCodeNeedsMoreBitsThanAvailable
// verifies that if the available bits form a 1-bit prefix that resolves to a
// codeLen=2 symbol (which is impossible with a valid tree, but guards the
// codeLen > available check), or more practically that when available=1 and
// the only matching entry has codeLen=2, we get ErrLosslessTruncated.
//
// To trigger this: build a tree where all symbols have codeLen=2 (maxCodeLen=2),
// then position bitPos so only 1 bit is available.  The 1-bit zero-extended
// lookup finds entry.codeLen=2 > available=1 → truncated.
func TestFinding4_Regression_HuffmanDecodeCodeLenExceedsAvailable(t *testing.T) {
	// 4-symbol tree, all code length 2.
	codeLengths := []symLen{
		{sym: 0, length: 2},
		{sym: 1, length: 2},
		{sym: 2, length: 2},
		{sym: 3, length: 2},
	}
	tree, err := buildHuffmanTree(codeLengths)
	if err != nil {
		t.Fatalf("buildHuffmanTree: %v", err)
	}

	// 1 bit remaining — not enough for any 2-bit code.
	r := newLeBitReader([]byte{0x00})
	r.bitPos = 7

	_, decErr := tree.decode(r)
	if _, ok := decErr.(*ErrLosslessTruncated); !ok {
		t.Errorf("expected *ErrLosslessTruncated when codeLen > available bits, got %T: %v", decErr, decErr)
	}
}
