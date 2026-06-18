package media

// webpsan_conformance_test.go — Go port of all webpsan 0.5.3 test cases.
//
// Oracle: webpsan/src/lib.rs (test module, lines 377–779)
// Builder oracle: webpsan/src/util/test/webp.rs
//
// Each test case is labeled with the Rust source function name and the line
// range it maps to. Where the test is a "sanitize_ok" assertion in Rust, the
// Go test asserts nil error. Where it is "sanitize_invalid" or
// "sanitize_non_compliant", the test asserts a non-nil error.
//
// The Go implementation achieves ZERO parity gap with webpsan 0.5.3:
//   - VP8L full bitstream decode (lossless.go): implements the complete
//     LosslessImage::read validator including transforms, prefix codes,
//     color cache, back-references, and all error conditions.
//   - ALPH bitstream decode: when COMPRESS_LOSSLESS flag is set, the alpha
//     plane's VP8L image stream is fully validated.
//
// One structural difference (not a parity gap):
//   - file_extra_data test: webpsan manipulates the TestWebp struct's data_len
//     field independently of the actual byte buffer (simulating a mis-declared
//     RIFF size). This is reproduced by appending real trailing bytes instead,
//     which exercises the same rejection path.

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// ---------------------------------------------------------------------------
// Test-vector builders — mirrors of webpsan/src/util/test/webp.rs helpers.
// ---------------------------------------------------------------------------

// defaultVP8Data matches DEFAULT_VP8_DATA in webp.rs (24 bytes).
// webpsan/src/util/test/webp.rs:118-119
var defaultVP8Data = []byte{
	18, 1, 0, 157, 1, 42, 1, 0, 1, 0, 18, 0,
	52, 0, 0, 13, 192, 0, 254, 251, 253, 80, 0, 0,
}

// defaultVP8LData matches DEFAULT_VP8L_DATA in webpsan exactly.
// webpsan/src/util/test/webp.rs:121-131
// Encodes: signature=0x2F, width-1=0 (14 bits), height-1=0 (14 bits), alpha=0, version=0,
// followed by a minimal valid lossless image stream for a 1×1 pixel image.
// This is the CONFORMANCE ANCHOR for VP8L accept tests.
var defaultVP8LData = []byte{0x2f, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88, 0x08}

// defaultAlphImageData matches DEFAULT_ALPH_DATA in webpsan exactly.
// webpsan/src/util/test/webp.rs:134-139
// A minimal valid lossless image stream for a 1×1 alpha plane (no 0x2F header).
// This is the CONFORMANCE ANCHOR for ALPH accept tests.
var defaultAlphImageData = []byte{0x88, 0x88, 0x08}

// writeChunk serializes a RIFF chunk: fourcc(4) + LE-size(4) + data + optional pad.
func writeChunk(buf *bytes.Buffer, fourcc string, data []byte) {
	size := uint32(len(data))
	buf.WriteString(fourcc)
	le := make([]byte, 4)
	binary.LittleEndian.PutUint32(le, size)
	buf.Write(le)
	buf.Write(data)
	if size%2 != 0 {
		buf.WriteByte(0x00)
	}
}

// writeVP8Chunk writes a VP8 chunk using defaultVP8Data.
func writeVP8Chunk(buf *bytes.Buffer) { writeChunk(buf, "VP8 ", defaultVP8Data) }

// writeVP8LChunk writes a VP8L chunk using defaultVP8LData.
func writeVP8LChunk(buf *bytes.Buffer) { writeChunk(buf, "VP8L", defaultVP8LData) }

// writeVP8XChunk writes a VP8X chunk with given flags and zero canvas dims (1×1).
// flags byte layout — webpsan/src/parse/vp8x.rs:24-29:
//
//	0x20 = HAS_ICCP_CHUNK
//	0x10 = HAS_ALPH_CHUNK
//	0x08 = HAS_EXIF_CHUNK
//	0x04 = HAS_XMP_CHUNK
//	0x02 = IS_ANIMATED
//
// Canvas width and height are encoded as OneBasedU24 (stored = actual-1).
// webpsan/src/parse/vp8x.rs:49-63
func writeVP8XChunk(buf *bytes.Buffer, flags byte, storedW, storedH uint32) {
	payload := make([]byte, 10)
	payload[0] = flags
	// reserved bytes 1-3 = 0
	payload[4] = byte(storedW)
	payload[5] = byte(storedW >> 8)
	payload[6] = byte(storedW >> 16)
	payload[7] = byte(storedH)
	payload[8] = byte(storedH >> 8)
	payload[9] = byte(storedH >> 16)
	writeChunk(buf, "VP8X", payload)
}

// writeAnimChunk writes an ANIM chunk: bg_color(4LE) + loop_count(2LE).
// webpsan/src/parse/anim.rs:23 — ENCODED_LEN = 6
func writeAnimChunk(buf *bytes.Buffer) {
	payload := make([]byte, 6) // background_color=0, loop_count=0
	writeChunk(buf, "ANIM", payload)
}

// writeAnmfChunk writes an ANMF frame chunk containing the provided frame body.
// ANMF header: x(3)+y(3)+width(3)+height(3)+duration(3)+flags(1) = 16 bytes.
// webpsan/src/parse/anmf.rs:60-65
func writeAnmfChunk(buf *bytes.Buffer, frameBody []byte) {
	header := make([]byte, 16) // x=0,y=0,width=0(stored=0→actual=1),height=0,dur=0,flags=0
	payload := make([]byte, 0, 16+len(frameBody))
	payload = append(payload, header...)
	payload = append(payload, frameBody...)
	writeChunk(buf, "ANMF", payload)
}

// writeAlphChunk writes an ALPH chunk: flags(1) + image data.
// webpsan/src/parse/alph.rs:52-53 — ENCODED_LEN = AlphFlags::ENCODED_LEN = 1
func writeAlphChunk(buf *bytes.Buffer, flagsByte byte) {
	payload := make([]byte, 1+len(defaultAlphImageData))
	payload[0] = flagsByte
	copy(payload[1:], defaultAlphImageData)
	writeChunk(buf, "ALPH", payload)
}

// writeICCPChunk writes a minimal ICCP chunk.
func writeICCPChunk(buf *bytes.Buffer) { writeChunk(buf, "ICCP", []byte{0x00}) }

// writeEXIFChunk writes a minimal EXIF chunk.
func writeEXIFChunk(buf *bytes.Buffer) { writeChunk(buf, "EXIF", []byte{0x49, 0x49, 0x2A, 0x00}) }

// writeXMPChunk writes a minimal XMP chunk.
func writeXMPChunk(buf *bytes.Buffer) { writeChunk(buf, "XMP ", []byte{0x3C, 0x78, 0x6D, 0x70}) }

// buildRIFF wraps chunk bytes with the RIFF+size+WEBP header.
// The RIFF size field covers "WEBP"(4) + len(chunks), matching the webpsan
// test builder in webpsan/src/util/test/webp.rs:222-225.
// Total file = "RIFF"(4) + LE(riffSize)(4) + "WEBP"(4) + chunks.
func buildRIFF(chunks []byte) []byte {
	riffSize := uint32(4 + len(chunks)) // 4 for "WEBP"
	out := make([]byte, 0, 12+len(chunks))
	out = append(out, []byte("RIFF")...)
	le := make([]byte, 4)
	binary.LittleEndian.PutUint32(le, riffSize)
	out = append(out, le...)
	out = append(out, []byte("WEBP")...)
	out = append(out, chunks...)
	return out
}

// buildWebPSanitizeOk builds a RIFF/WEBP file from the given payload chunks
// (already serialized, not including the leading "WEBP" fourcc).
func buildWebPPayload(chunks *bytes.Buffer) []byte {
	return buildRIFF(chunks.Bytes())
}

// assertWebPAccepted asserts that SanitizeWebP returns nil for the given data.
func assertWebPAccepted(t *testing.T, data []byte) {
	t.Helper()
	if err := SanitizeWebP(data); err != nil {
		t.Errorf("expected valid WebP, got error: %v", err)
	}
}

// assertWebPRejected asserts that SanitizeWebP returns a non-nil error.
func assertWebPRejected(t *testing.T, data []byte) {
	t.Helper()
	if err := SanitizeWebP(data); err == nil {
		t.Error("expected WebP to be rejected, but SanitizeWebP returned nil")
	}
}

// ---------------------------------------------------------------------------
// Ported webpsan tests — webpsan/src/lib.rs test module (lines 377–779).
// ---------------------------------------------------------------------------

// TestWebpsan_NotRiff — webpsan test `not_riff` (lib.rs:389-395)
// Non-RIFF chunk type as the outermost container → InvalidChunkLayout.
func TestWebpsan_NotRiff(t *testing.T) {
	// Replace the "RIFF" header with "TeSt" — this violates the outermost check.
	data := make([]byte, 20)
	copy(data[0:4], "TeSt")
	binary.LittleEndian.PutUint32(data[4:8], 12)
	copy(data[8:12], "WEBP")
	copy(data[12:16], "VP8 ")
	binary.LittleEndian.PutUint32(data[16:20], 0)
	assertWebPRejected(t, data)
}

// TestWebpsan_NotWebp — webpsan test `not_webp` (lib.rs:397-403)
// RIFF container with a non-WEBP fourcc → InvalidInput.
func TestWebpsan_NotWebp(t *testing.T) {
	data := make([]byte, 20)
	copy(data[0:4], "RIFF")
	binary.LittleEndian.PutUint32(data[4:8], 12)
	copy(data[8:12], "TeSt") // not WEBP
	copy(data[12:16], "VP8 ")
	binary.LittleEndian.PutUint32(data[16:20], 0)
	assertWebPRejected(t, data)
}

// TestWebpsan_FileLenZero — webpsan test `file_len_zero` (lib.rs:405-412)
// RIFF size field = 0 means payload ends immediately after the size field.
// With only the "WEBP" fourcc needing to be read, this yields a truncated-chunk error.
func TestWebpsan_FileLenZero(t *testing.T) {
	// Build a RIFF header declaring size=0, which means no WEBP fourcc fits.
	data := make([]byte, 8)
	copy(data[0:4], "RIFF")
	binary.LittleEndian.PutUint32(data[4:8], 0)
	// Actual file is 8 bytes; declared total = 8+0 = 8 bytes = actual.
	// No WEBP fourcc is present within the declared region → parser sees 0
	// payload bytes, but needs at least 4 for "WEBP".
	assertWebPRejected(t, data)
}

// TestWebpsan_FileLenInvalid — webpsan test `file_len_invalid` (lib.rs:423-430)
// RIFF size > MAX_FILE_LEN (u32::MAX - 2 = 0xFFFFFFFD) → InvalidInput.
// webpsan/src/lib.rs:64 — MAX_FILE_LEN = u32::MAX - 2
// webpsan/src/lib.rs:113-117 — ensure_attach!(len <= MAX_FILE_LEN.into(), ...)
func TestWebpsan_FileLenInvalid(t *testing.T) {
	data := make([]byte, 12)
	copy(data[0:4], "RIFF")
	// Set size = MAX_FILE_LEN+1 = 0xFFFFFFFE, which exceeds the limit.
	binary.LittleEndian.PutUint32(data[4:8], maxWebPFileLen+1)
	copy(data[8:12], "WEBP")
	assertWebPRejected(t, data)
}

// TestWebpsan_FileLenMaxValid — webpsan test boundary: MAX_FILE_LEN is valid.
// A size exactly equal to MAX_FILE_LEN must NOT trigger the limit check.
// webpsan/src/lib.rs:64 — MAX_FILE_LEN = u32::MAX - 2 = 0xFFFFFFFD
// The check is: ensure_attach!(len <= MAX_FILE_LEN.into(), ...) → 0xFFFFFFFD is OK.
// We cannot build a real file this large; we verify the check fires at MAX_FILE_LEN+1.
func TestWebpsan_FileLenMaxValid(t *testing.T) {
	// Build a file declaring size = MAX_FILE_LEN but with actual data much smaller.
	// The declared-vs-actual mismatch error fires first (before the limit check),
	// NOT the MAX_FILE_LEN error. This is fine: we just need to confirm MAX_FILE_LEN
	// itself is not rejected by the limit guard. MAX_FILE_LEN+1 IS rejected.
	data := make([]byte, 12)
	copy(data[0:4], "RIFF")
	binary.LittleEndian.PutUint32(data[4:8], maxWebPFileLen) // exactly at limit
	copy(data[8:12], "WEBP")
	// This will fail with "declared RIFF size exceeds actual data length",
	// which means the MAX_FILE_LEN guard passed.
	err := SanitizeWebP(data)
	if err == nil {
		t.Error("expected error (declared > actual), got nil")
	}
	// Verify it is NOT a max-file-len error.
	if err != nil && err.Error() == "media: WebP: RIFF payload exceeds MAX_FILE_LEN" {
		t.Errorf("MAX_FILE_LEN should be accepted by limit guard, got: %v", err)
	}
}

// TestWebpsan_FileExtraData — webpsan test `file_extra_data` (lib.rs:432-441)
// Trailing bytes after the declared RIFF payload → ExtraUnparsedInput.
// webpsan/src/lib.rs:170-174 — ensure_attach!(!file_reader.has_remaining()?, ...)
func TestWebpsan_FileExtraData(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8LChunk(&chunks)
	valid := buildWebPPayload(&chunks)
	withExtra := append(valid, []byte("extra data")...)
	assertWebPRejected(t, withExtra)
}

// TestWebpsan_ImageDataMissing — webpsan test `image_data_missing` (lib.rs:443-450)
// Empty RIFF payload (no chunks after WEBP fourcc) → InvalidChunkLayout.
func TestWebpsan_ImageDataMissing(t *testing.T) {
	data := buildRIFF([]byte{}) // payload = only "WEBP" implied by buildRIFF...
	// buildRIFF prepends "WEBP" inside the RIFF payload, so this is fine:
	// the RIFF payload = "WEBP" + nothing. The reader sees no first chunk.
	assertWebPRejected(t, data)
}

// TestWebpsan_Lossy — webpsan test `lossy` (lib.rs:452-454)
// Simple lossy file (VP8 chunk only) → accepted.
// webpsan/src/lib.rs:125-128
func TestWebpsan_Lossy(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8Chunk(&chunks)
	assertWebPAccepted(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Lossless — webpsan test `lossless` (lib.rs:456-458)
// Simple lossless file (VP8L chunk only) → accepted.
// webpsan/src/lib.rs:129-134
func TestWebpsan_Lossless(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8LChunk(&chunks)
	assertWebPAccepted(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xLossy — webpsan test `vp8x_lossy` (lib.rs:460-462)
// Extended file: VP8X (no flags) + VP8 → accepted.
// webpsan/src/lib.rs:136-141, sanitize_still
func TestWebpsan_Vp8xLossy(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, 0x00, 0, 0)
	writeVP8Chunk(&chunks)
	assertWebPAccepted(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xLossyAlphaLossless — webpsan test `vp8x_lossy_alpha_lossless` (lib.rs:464-469)
// Extended: VP8X(HAS_ALPH) + ALPH(COMPRESS_LOSSLESS) + VP8 → accepted.
// webpsan/src/lib.rs:207-246 (sanitize_still: ALPH before VP8/VP8L)
func TestWebpsan_Vp8xLossyAlphaLossless(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagAlpha, 0, 0)
	writeAlphChunk(&chunks, 0x01) // COMPRESS_LOSSLESS = 0x01
	writeVP8Chunk(&chunks)
	assertWebPAccepted(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xLossyAlphaUncompressed — webpsan test `vp8x_lossy_alpha_uncompressed` (lib.rs:471-476)
// Extended: VP8X(HAS_ALPH) + ALPH(no compression) + VP8 → accepted.
func TestWebpsan_Vp8xLossyAlphaUncompressed(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagAlpha, 0, 0)
	writeAlphChunk(&chunks, 0x00) // uncompressed alpha flags
	writeVP8Chunk(&chunks)
	assertWebPAccepted(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xLossless — webpsan test `vp8x_lossless` (lib.rs:478-480)
// Extended: VP8X (no flags) + VP8L → accepted.
// VP8L dims (1×1) match canvas (1×1) → dim check passes.
func TestWebpsan_Vp8xLossless(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, 0x00, 0, 0) // canvas = 1×1 (stored=0)
	writeVP8LChunk(&chunks)
	assertWebPAccepted(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xLosslessAlpha — webpsan test `vp8x_lossless_alpha` (lib.rs:482-489)
// Extended: VP8X(HAS_ALPH) + ALPH + VP8L → REJECTED (VP8L not allowed with ALPH).
// webpsan/src/lib.rs:226-227 — ensure_matches_attach!(alph, None, ..., WhileParsingChunk(VP8L))
func TestWebpsan_Vp8xLosslessAlpha(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagAlpha, 0, 0)
	writeAlphChunk(&chunks, 0x01)
	writeVP8LChunk(&chunks)
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xAnimated — webpsan test `vp8x_animated` (lib.rs:491-493)
// Animated: VP8X(IS_ANIMATED) + ANIM + ANMF + ANMF → accepted.
// webpsan/src/lib.rs:249-333 (sanitize_animated)
func TestWebpsan_Vp8xAnimated(t *testing.T) {
	var frame bytes.Buffer
	writeVP8LChunk(&frame)
	frameBody := frame.Bytes()

	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagAnim, 0, 0)
	writeAnimChunk(&chunks)
	writeAnmfChunk(&chunks, frameBody)
	writeAnmfChunk(&chunks, frameBody)
	assertWebPAccepted(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xAnimatedEmpty — webpsan test `vp8x_animated_empty` (lib.rs:495-501)
// Animated with no ANMF frames → MissingRequiredChunk(ANMF).
// webpsan/src/lib.rs:254-258
func TestWebpsan_Vp8xAnimatedEmpty(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagAnim, 0, 0)
	writeAnimChunk(&chunks)
	// No ANMF frames.
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xAnimatedLossless — webpsan test `vp8x_animated_lossless` (lib.rs:503-511)
// Animated: VP8X(IS_ANIMATED) + ANIM + 2×ANMF(VP8L) → accepted.
func TestWebpsan_Vp8xAnimatedLossless(t *testing.T) {
	var frame bytes.Buffer
	writeVP8LChunk(&frame)
	frameBody := frame.Bytes()

	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagAnim, 0, 0)
	writeAnimChunk(&chunks)
	writeAnmfChunk(&chunks, frameBody)
	writeAnmfChunk(&chunks, frameBody)
	assertWebPAccepted(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xAnimatedLossy — webpsan test `vp8x_animated_lossy` (lib.rs:513-519)
// Animated: VP8X(IS_ANIMATED) + ANIM + 2×ANMF(VP8) → accepted.
func TestWebpsan_Vp8xAnimatedLossy(t *testing.T) {
	var frame bytes.Buffer
	writeVP8Chunk(&frame)
	frameBody := frame.Bytes()

	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagAnim, 0, 0)
	writeAnimChunk(&chunks)
	writeAnmfChunk(&chunks, frameBody)
	writeAnmfChunk(&chunks, frameBody)
	assertWebPAccepted(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xAnimatedLossyLossless — webpsan test `vp8x_animated_lossy_lossless` (lib.rs:521-527)
// Animated: mix of VP8 and VP8L frames → accepted.
func TestWebpsan_Vp8xAnimatedLossyLossless(t *testing.T) {
	var lossy bytes.Buffer
	writeVP8Chunk(&lossy)
	var lossless bytes.Buffer
	writeVP8LChunk(&lossless)

	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagAnim, 0, 0)
	writeAnimChunk(&chunks)
	writeAnmfChunk(&chunks, lossy.Bytes())
	writeAnmfChunk(&chunks, lossless.Bytes())
	assertWebPAccepted(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xAnimatedLosslessAlpha — webpsan test `vp8x_animated_lossless_alpha` (lib.rs:529-537)
// Animated(HAS_ALPH): ANMF frames with ALPH+VP8L → REJECTED (VP8L+ALPH forbidden).
// webpsan/src/lib.rs:291-292
func TestWebpsan_Vp8xAnimatedLosslessAlpha(t *testing.T) {
	var frame bytes.Buffer
	writeAlphChunk(&frame, 0x01)
	writeVP8LChunk(&frame)

	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagAnim|vp8xFlagAlpha, 0, 0)
	writeAnimChunk(&chunks)
	writeAnmfChunk(&chunks, frame.Bytes())
	writeAnmfChunk(&chunks, frame.Bytes())
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xAnimatedLossyAlpha — webpsan test `vp8x_animated_lossy_alpha` (lib.rs:539-545)
// Animated(HAS_ALPH): ANMF frames with ALPH+VP8 → accepted.
func TestWebpsan_Vp8xAnimatedLossyAlpha(t *testing.T) {
	var frame bytes.Buffer
	writeAlphChunk(&frame, 0x01)
	writeVP8Chunk(&frame)

	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagAnim|vp8xFlagAlpha, 0, 0)
	writeAnimChunk(&chunks)
	writeAnmfChunk(&chunks, frame.Bytes())
	writeAnmfChunk(&chunks, frame.Bytes())
	assertWebPAccepted(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xAnimatedAlphaNoAlpha — webpsan test `vp8x_animated_alpha_no_alpha` (lib.rs:547-555)
// Animated(HAS_ALPH): first frame has ALPH+VP8, second has only VP8 → accepted.
// webpsan/src/lib.rs:271-281 (ALPH is optional within each frame even when HAS_ALPH is set)
func TestWebpsan_Vp8xAnimatedAlphaNoAlpha(t *testing.T) {
	var frameWithAlpha bytes.Buffer
	writeAlphChunk(&frameWithAlpha, 0x01)
	writeVP8Chunk(&frameWithAlpha)

	var frameNoAlpha bytes.Buffer
	writeVP8Chunk(&frameNoAlpha)

	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagAnim|vp8xFlagAlpha, 0, 0)
	writeAnimChunk(&chunks)
	writeAnmfChunk(&chunks, frameWithAlpha.Bytes())
	writeAnmfChunk(&chunks, frameNoAlpha.Bytes())
	assertWebPAccepted(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xAnimatedNoAlphaAlpha — webpsan test `vp8x_animated_no_alpha_alpha` (lib.rs:557-565)
// Animated(HAS_ALPH): first frame VP8 only, second ALPH+VP8 → accepted.
func TestWebpsan_Vp8xAnimatedNoAlphaAlpha(t *testing.T) {
	var frameNoAlpha bytes.Buffer
	writeVP8Chunk(&frameNoAlpha)

	var frameWithAlpha bytes.Buffer
	writeAlphChunk(&frameWithAlpha, 0x01)
	writeVP8Chunk(&frameWithAlpha)

	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagAnim|vp8xFlagAlpha, 0, 0)
	writeAnimChunk(&chunks)
	writeAnmfChunk(&chunks, frameNoAlpha.Bytes())
	writeAnmfChunk(&chunks, frameWithAlpha.Bytes())
	assertWebPAccepted(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xAnimatedAlphMissing — webpsan test `vp8x_animated_alph_missing` (lib.rs:567-573)
// Animated(HAS_ALPH): single frame with VP8L (no ALPH) → accepted.
// HAS_ALPH means ALPH may appear, not that it must.
// webpsan/src/lib.rs:271-281 (alph is optional within ANMF even with HAS_ALPH flag)
func TestWebpsan_Vp8xAnimatedAlphMissing(t *testing.T) {
	var frame bytes.Buffer
	writeVP8LChunk(&frame)

	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagAnim|vp8xFlagAlpha, 0, 0)
	writeAnimChunk(&chunks)
	writeAnmfChunk(&chunks, frame.Bytes())
	assertWebPAccepted(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xAnimatedAlphWrongOrder — webpsan test `vp8x_animated_alph_wrong_order` (lib.rs:575-582)
// Animated: ANMF frame with VP8L then ALPH (wrong order) → InvalidChunkLayout.
// webpsan/src/lib.rs:313-331 (ALPH after bitstream is a MultipleChunks error in ANMF)
func TestWebpsan_Vp8xAnimatedAlphWrongOrder(t *testing.T) {
	var frame bytes.Buffer
	writeVP8LChunk(&frame)
	writeAlphChunk(&frame, 0x01)

	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagAnim, 0, 0)
	writeAnimChunk(&chunks)
	writeAnmfChunk(&chunks, frame.Bytes())
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xAnimatedUnexpectedAlph — webpsan test `vp8x_animated_unexpected_alph` (lib.rs:584-592)
// Animated (no HAS_ALPH flag): frame has ALPH+VP8L → InvalidChunkLayout.
// webpsan/src/lib.rs:283-311 (reads any header; ALPH without HAS_ALPH flag =
// invalid chunk order as it's not the VP8/VP8L expected next)
func TestWebpsan_Vp8xAnimatedUnexpectedAlph(t *testing.T) {
	var frame bytes.Buffer
	writeAlphChunk(&frame, 0x01)
	writeVP8LChunk(&frame)

	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagAnim, 0, 0) // no HAS_ALPH
	writeAnimChunk(&chunks)
	writeAnmfChunk(&chunks, frame.Bytes())
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xImageDataMissing — webpsan test `vp8x_image_data_missing` (lib.rs:594-600)
// Extended (no flags): VP8X only, no bitstream → MissingRequiredChunk(VP8).
// webpsan/src/lib.rs:218 — ensure_attach!(reader.has_remaining()?, ParseError::MissingRequiredChunk(VP8))
func TestWebpsan_Vp8xImageDataMissing(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, 0x00, 0, 0)
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xUnexpectedAlph — webpsan test `vp8x_unexpected_alph` (lib.rs:602-609)
// Extended (no HAS_ALPH): VP8X + ALPH + VP8L → InvalidChunkLayout.
// webpsan/src/lib.rs:218-246 (no HAS_ALPH → sanitize_still reads bitstream directly;
// seeing ALPH is "expected image data, got ALPH" error)
func TestWebpsan_Vp8xUnexpectedAlph(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, 0x00, 0, 0) // no HAS_ALPH
	writeAlphChunk(&chunks, 0x01)
	writeVP8LChunk(&chunks)
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xUnexpectedAnim — webpsan test `vp8x_unexpected_anim` (lib.rs:611-618)
// Extended (no IS_ANIMATED): VP8X + ANIM + ANMF → InvalidChunkLayout.
// sanitize_still reads the next chunk; ANIM is not VP8/VP8L → error.
func TestWebpsan_Vp8xUnexpectedAnim(t *testing.T) {
	var frame bytes.Buffer
	writeVP8Chunk(&frame)

	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, 0x00, 0, 0) // no IS_ANIMATED
	writeAnimChunk(&chunks)
	writeAnmfChunk(&chunks, frame.Bytes())
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xUnexpectedAnmf — webpsan test `vp8x_unexpected_anmf` (lib.rs:620-627)
// Extended (no IS_ANIMATED): VP8X + ANMF only → InvalidChunkLayout.
func TestWebpsan_Vp8xUnexpectedAnmf(t *testing.T) {
	var frame bytes.Buffer
	writeVP8Chunk(&frame)

	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, 0x00, 0, 0) // no IS_ANIMATED
	writeAnmfChunk(&chunks, frame.Bytes())
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xAlphMissing — webpsan test `vp8x_alph_missing` (lib.rs:629-636)
// Extended (HAS_ALPH): VP8X + VP8L (no ALPH chunk) → InvalidChunkLayout.
// sanitize_still: read_header(ALPH) but finds VP8L → expected ALPH error.
// webpsan/src/lib.rs:208-216
func TestWebpsan_Vp8xAlphMissing(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagAlpha, 0, 0)
	writeVP8LChunk(&chunks)
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xAnimMissing — webpsan test `vp8x_anim_missing` (lib.rs:638-645)
// Extended (IS_ANIMATED): VP8X + ANMF (no ANIM) → InvalidChunkLayout.
// sanitize_animated reads ANIM first; sees ANMF → expected ANIM error.
// webpsan/src/lib.rs:250-252
func TestWebpsan_Vp8xAnimMissing(t *testing.T) {
	var frame bytes.Buffer
	writeVP8Chunk(&frame)

	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagAnim, 0, 0)
	writeAnmfChunk(&chunks, frame.Bytes())
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xAnimAnmfMissing — webpsan test `vp8x_anim_anmf_missing` (lib.rs:647-654)
// Extended (IS_ANIMATED): VP8X + ANIM only (no ANMF) → MissingRequiredChunk(ANMF).
// webpsan/src/lib.rs:254-258
func TestWebpsan_Vp8xAnimAnmfMissing(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagAnim, 0, 0)
	writeAnimChunk(&chunks)
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xICCP — webpsan test `vp8x_iccp` (lib.rs:656-659)
// Extended (HAS_ICCP): VP8X + ICCP + VP8L → accepted.
// webpsan/src/lib.rs:180-184
func TestWebpsan_Vp8xICCP(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagICCP, 0, 0)
	writeICCPChunk(&chunks)
	writeVP8LChunk(&chunks)
	assertWebPAccepted(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xEXIF — webpsan test `vp8x_exif` (lib.rs:661-664)
// Extended (HAS_EXIF): VP8X + VP8L + EXIF → accepted.
// webpsan/src/lib.rs:192-196
func TestWebpsan_Vp8xEXIF(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagEXIF, 0, 0)
	writeVP8LChunk(&chunks)
	writeEXIFChunk(&chunks)
	assertWebPAccepted(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xXMP — webpsan test `vp8x_xmp` (lib.rs:666-669)
// Extended (HAS_XMP): VP8X + VP8L + XMP → accepted.
// webpsan/src/lib.rs:198-202
func TestWebpsan_Vp8xXMP(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagXMP, 0, 0)
	writeVP8LChunk(&chunks)
	writeXMPChunk(&chunks)
	assertWebPAccepted(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xAllMeta — webpsan test `vp8x_all_meta` (lib.rs:671-675)
// Extended (HAS_ICCP|HAS_EXIF|HAS_XMP): VP8X + ICCP + VP8L + EXIF + XMP → accepted.
func TestWebpsan_Vp8xAllMeta(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagICCP|vp8xFlagEXIF|vp8xFlagXMP, 0, 0)
	writeICCPChunk(&chunks)
	writeVP8LChunk(&chunks)
	writeEXIFChunk(&chunks)
	writeXMPChunk(&chunks)
	assertWebPAccepted(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xWrongOrder — webpsan test `vp8x_wrong_order` (lib.rs:677-683)
// VP8L first then VP8X → InvalidChunkLayout (VP8X not first chunk).
// webpsan/src/lib.rs:143-149 (VP8L is valid first chunk; VP8X only allowed as first)
// After VP8L is accepted, VP8X appears as a trailing chunk → MultipleChunks.
func TestWebpsan_Vp8xWrongOrder(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8LChunk(&chunks)
	// VP8X after VP8L: the trailing-chunk loop sees VP8X → MultipleChunks.
	// webpsan/src/lib.rs:160-161
	vp8xPayload := make([]byte, 10) // flags=0, dims=1×1
	writeChunk(&chunks, "VP8X", vp8xPayload)
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xAlphWrongOrder — webpsan test `vp8x_alph_wrong_order` (lib.rs:685-691)
// Extended: VP8X + VP8L + ALPH (ALPH after bitstream) → InvalidChunkLayout.
// webpsan/src/lib.rs (after image data, ALPH in trailing loop → MultipleChunks)
func TestWebpsan_Vp8xAlphWrongOrder(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, 0x00, 0, 0)
	writeVP8LChunk(&chunks)
	writeAlphChunk(&chunks, 0x01)
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xICCPWrongOrder — webpsan test `vp8x_iccp_wrong_order` (lib.rs:693-699)
// Extended: VP8X + VP8L + ICCP (ICCP after image data) → InvalidChunkLayout.
// The trailing-chunk loop sees ICCP → MultipleChunks.
func TestWebpsan_Vp8xICCPWrongOrder(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, 0x00, 0, 0)
	writeVP8LChunk(&chunks)
	writeICCPChunk(&chunks)
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xEXIFWrongOrder — webpsan test `vp8x_exif_wrong_order` (lib.rs:701-711)
// Case 1: VP8X + EXIF + VP8L → InvalidChunkLayout (EXIF before image data).
// Case 2: VP8X + VP8L + XMP + EXIF → InvalidChunkLayout (EXIF after XMP).
// webpsan/src/lib.rs:192-196 (EXIF must follow image data, before XMP)
func TestWebpsan_Vp8xEXIFWrongOrder(t *testing.T) {
	t.Run("exif_before_image", func(t *testing.T) {
		var chunks bytes.Buffer
		writeVP8XChunk(&chunks, vp8xFlagEXIF, 0, 0)
		writeEXIFChunk(&chunks)
		writeVP8LChunk(&chunks)
		assertWebPRejected(t, buildWebPPayload(&chunks))
	})
	t.Run("exif_after_xmp", func(t *testing.T) {
		var chunks bytes.Buffer
		writeVP8XChunk(&chunks, vp8xFlagEXIF|vp8xFlagXMP, 0, 0)
		writeVP8LChunk(&chunks)
		writeXMPChunk(&chunks)
		writeEXIFChunk(&chunks)
		assertWebPRejected(t, buildWebPPayload(&chunks))
	})
}

// TestWebpsan_Vp8xXMPWrongOrder — webpsan test `vp8x_xmp_wrong_order` (lib.rs:713-719)
// Extended: VP8X + XMP + VP8L → InvalidChunkLayout (XMP before image data).
func TestWebpsan_Vp8xXMPWrongOrder(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagXMP, 0, 0)
	writeXMPChunk(&chunks)
	writeVP8LChunk(&chunks)
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xICCPMissing — webpsan test `vp8x_iccp_missing` (lib.rs:721-728)
// Extended (HAS_ICCP): VP8X + VP8L (no ICCP) → InvalidChunkLayout.
// sanitize_extended reads ICCP first but finds VP8L.
func TestWebpsan_Vp8xICCPMissing(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagICCP, 0, 0)
	writeVP8LChunk(&chunks)
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xEXIFMissing — webpsan test `vp8x_exif_missing` (lib.rs:730-737)
// Extended (HAS_EXIF): VP8X + VP8L (no EXIF) → MissingRequiredChunk(EXIF).
func TestWebpsan_Vp8xEXIFMissing(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagEXIF, 0, 0)
	writeVP8LChunk(&chunks)
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xXMPMissing — webpsan test `vp8x_xmp_missing` (lib.rs:739-746)
// Extended (HAS_XMP): VP8X + VP8L (no XMP) → MissingRequiredChunk(XMP).
func TestWebpsan_Vp8xXMPMissing(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagXMP, 0, 0)
	writeVP8LChunk(&chunks)
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xICCPUnexpected — webpsan test `vp8x_iccp_unexpected` (lib.rs:748-755)
// Extended (no HAS_ICCP): VP8X + ICCP + VP8L → InvalidChunkLayout.
// sanitize_extended skips ICCP block; sanitize_still finds ICCP instead of VP8/VP8L.
func TestWebpsan_Vp8xICCPUnexpected(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, 0x00, 0, 0) // no HAS_ICCP
	writeICCPChunk(&chunks)
	writeVP8LChunk(&chunks)
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xEXIFUnexpected — webpsan test `vp8x_exif_unexpected` (lib.rs:757-764)
// Extended (no HAS_EXIF): VP8X + VP8L + EXIF → rejected.
// After image data, EXIF in trailing loop → MultipleChunks.
func TestWebpsan_Vp8xEXIFUnexpected(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, 0x00, 0, 0) // no HAS_EXIF
	writeVP8LChunk(&chunks)
	writeEXIFChunk(&chunks)
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xXMPUnexpected — webpsan test `vp8x_xmp_unexpected` (lib.rs:766-773)
// Extended (no HAS_XMP): VP8X + VP8L + XMP → rejected.
// After image data, XMP in trailing loop → MultipleChunks.
func TestWebpsan_Vp8xXMPUnexpected(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, 0x00, 0, 0) // no HAS_XMP
	writeVP8LChunk(&chunks)
	writeXMPChunk(&chunks)
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_LosslessMaxImageData — webpsan test `lossless_max_image_data` (lib.rs:775-778)
// A VP8L file with the maximum 14-bit width and height values → accepted.
// This tests the full bitstream validator against a 16384×16384 VP8L stream.
// The payload is taken directly from the Rust test (22 bytes of VP8L data).
// webpsan/src/lib.rs:775-778
func TestWebpsan_LosslessMaxImageData(t *testing.T) {
	// Rust test vector: 22-byte VP8L payload encoding a maximum-dimension image.
	// webpsan/src/lib.rs:776
	vp8lData := []byte{
		0x2f, 0xff, 0xff, 0xff, 0x0f, 0x81, 0x88, 0x88, 0x18, 0x44, 0x44,
		0xc4, 0xff, 0x45, 0x44, 0x04, 0x21, 0x22, 0x22, 0x22, 0x22, 0x02,
	}
	var chunks bytes.Buffer
	writeChunk(&chunks, "VP8L", vp8lData)
	assertWebPAccepted(t, buildWebPPayload(&chunks))
}

// ---------------------------------------------------------------------------
// Additional structural correctness tests (supplement the ported cases).
// ---------------------------------------------------------------------------

// TestWebpsan_Vp8xAllFlagsAllChunks verifies full extended layout:
// ICCP + VP8 + EXIF + XMP with all four metadata flags set.
func TestWebpsan_Vp8xAllFlagsAllChunks(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagICCP|vp8xFlagEXIF|vp8xFlagXMP, 0, 0)
	writeICCPChunk(&chunks)
	writeVP8Chunk(&chunks)
	writeEXIFChunk(&chunks)
	writeXMPChunk(&chunks)
	assertWebPAccepted(t, buildWebPPayload(&chunks))
}

// TestWebpsan_VP8LDimsMismatch verifies that a VP8L chunk whose declared
// dimensions do not match the VP8X canvas dimensions is rejected.
// webpsan/src/lib.rs:228-235 and 294-301 — FrameDimensionsMismatch error.
//
// Canvas: 2×2 (storedW=1, storedH=1). VP8L header: 1×1 (storedW=0, storedH=0).
func TestWebpsan_VP8LDimsMismatch(t *testing.T) {
	// VP8X canvas = 2×2 (stored 1,1).
	vp8xPayload := make([]byte, 10)
	vp8xPayload[0] = 0x00 // no flags
	vp8xPayload[4] = 0x01 // storedW = 1 → actual width = 2
	vp8xPayload[7] = 0x01 // storedH = 1 → actual height = 2

	// VP8L header: width-1=0 (1 px wide), height-1=0 (1 px tall) — mismatch.
	// defaultVP8LData encodes 1×1.
	var chunks bytes.Buffer
	writeChunk(&chunks, "VP8X", vp8xPayload)
	writeVP8LChunk(&chunks) // declares 1×1 canvas
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_PadByteZeroRequired verifies that an odd-size VP8 chunk with a
// non-zero pad byte is rejected.
// webpsan/src/reader.rs:232 — ensure_matches_attach!(pad, 0, ...)
func TestWebpsan_PadByteZeroRequired(t *testing.T) {
	// Build a 3-byte VP8 chunk manually with a 0xFF pad byte.
	var payload bytes.Buffer
	payload.WriteString("VP8 ")
	payload.Write([]byte{3, 0, 0, 0}) // size=3 (odd)
	payload.Write([]byte{0x01, 0x02, 0x03})
	payload.WriteByte(0xFF) // invalid pad byte

	data := buildRIFF(payload.Bytes())
	assertWebPRejected(t, data)
}

// TestWebpsan_VP8XCanvasPixelOverflow verifies that VP8X chunk with canvas
// dimensions whose product overflows uint32 is rejected.
// webpsan/src/parse/vp8x.rs:57-60 — checked_mul overflow check.
//
// webpsan 0.5.3 has no per-dimension cap; only the pixel-count overflow check
// rejects oversized canvases.  Use storedW = storedH = 0xFFFF (65535) so that
// actual = 65536 and 65536 * 65536 = 4,294,967,296 > 0xFFFFFFFF.
func TestWebpsan_VP8XCanvasPixelOverflow(t *testing.T) {
	// storedW = storedH = 0xFFFF → actual = 65536 → pixel count 65536²>u32::MAX.
	overSize := uint32(0xFFFF)
	vp8xPayload := make([]byte, 10)
	vp8xPayload[4] = byte(overSize & 0xFF)
	vp8xPayload[5] = byte((overSize >> 8) & 0xFF)
	vp8xPayload[7] = byte(overSize & 0xFF)
	vp8xPayload[8] = byte((overSize >> 8) & 0xFF)
	var chunks bytes.Buffer
	writeChunk(&chunks, "VP8X", vp8xPayload)
	writeVP8Chunk(&chunks)
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// ---------------------------------------------------------------------------
// Coverage-gap tests for internal paths not reached by the ported cases.
// ---------------------------------------------------------------------------

// TestWebpsan_VP8LInvalidSignature verifies that a VP8L chunk with a wrong
// signature byte (not 0x2F) is rejected.
// webpsan/src/parse/vp8l.rs:69-75 — InvalidSignature error.
func TestWebpsan_VP8LInvalidSignature(t *testing.T) {
	// 5-byte VP8L with signature byte 0x00 instead of 0x2F.
	badVP8L := []byte{0x00, 0x00, 0x00, 0x00, 0x00}
	var chunks bytes.Buffer
	writeChunk(&chunks, "VP8L", badVP8L)
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_VP8LVersionNonZero verifies that a VP8L chunk with a non-zero
// version field (bits 37-39) is rejected.
// webpsan/src/parse/vp8l.rs:81-82 — UnsupportedVp8lVersion error.
// Version occupies the top 3 bits of byte 4 of the 5-byte header.
func TestWebpsan_VP8LVersionNonZero(t *testing.T) {
	// Set version = 1 (bits 37-39): byte[4] = 0b00100000 = 0x20.
	badVersion := []byte{0x2F, 0x00, 0x00, 0x00, 0x20}
	var chunks bytes.Buffer
	writeChunk(&chunks, "VP8L", badVersion)
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_VP8LTooShort verifies that a VP8L chunk shorter than 5 bytes
// is rejected (cannot read the full header).
// webpsan/src/parse/vp8l.rs:63 — ENCODED_LEN = 5.
func TestWebpsan_VP8LTooShort(t *testing.T) {
	tooShort := []byte{0x2F, 0x00, 0x00} // 3 bytes — too short
	var chunks bytes.Buffer
	writeChunk(&chunks, "VP8L", tooShort)
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_AnmfMissingImageData verifies that an ANMF frame with no image
// chunk (only the 16-byte ANMF header, no VP8/VP8L inside) is rejected.
// sanitizeWebPFrame: "WebP: ANMF frame missing image data"
func TestWebpsan_AnmfMissingImageData(t *testing.T) {
	// Empty frame body (no VP8/VP8L inside the ANMF payload).
	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagAnim, 0, 0)
	writeAnimChunk(&chunks)
	writeAnmfChunk(&chunks, []byte{}) // frame body is empty
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_AnmfFrameInvalidChunk verifies that an ANMF frame body that
// starts with an unexpected chunk type (not ALPH/VP8/VP8L) is rejected.
// sanitizeWebPFrame default case: "expected image data in ANMF, got …"
func TestWebpsan_AnmfFrameInvalidChunk(t *testing.T) {
	var frameBody bytes.Buffer
	// ICCP inside frame body — totally unexpected.
	writeICCPChunk(&frameBody)

	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagAnim, 0, 0)
	writeAnimChunk(&chunks)
	writeAnmfChunk(&chunks, frameBody.Bytes())
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_AnimChunkTooShort verifies that an ANIM chunk shorter than 6
// bytes is rejected.
// webpsan/src/parse/anim.rs:23 — ENCODED_LEN = 6.
func TestWebpsan_AnimChunkTooShort(t *testing.T) {
	// Build an ANIM chunk with only 4 bytes (too short).
	shortAnim := []byte{0x00, 0x00, 0x00, 0x00} // 4 bytes, need 6

	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagAnim, 0, 0)
	writeChunk(&chunks, "ANIM", shortAnim)

	// We still need at least one ANMF to pass that check, but the ANIM
	// length check fires first.
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_VP8XSizeNot10 verifies VP8X chunks of wrong size are rejected.
// webpsan/src/parse/vp8x.rs — parse fails for ENCODED_LEN ≠ 10.
func TestWebpsan_VP8XSizeNot10(t *testing.T) {
	for _, size := range []int{0, 4, 9, 11} {
		t.Run("", func(t *testing.T) {
			var chunks bytes.Buffer
			writeChunk(&chunks, "VP8X", make([]byte, size))
			writeVP8Chunk(&chunks)
			assertWebPRejected(t, buildWebPPayload(&chunks))
		})
	}
}

// TestWebpsan_VP8LDimsMismatchInANMF verifies that a VP8L frame within an
// ANMF whose dimensions don't match the VP8X canvas dims is rejected.
// webpsan/src/lib.rs:294-301 — FrameDimensionsMismatch in animated path.
func TestWebpsan_VP8LDimsMismatchInANMF(t *testing.T) {
	// VP8X canvas = 2×2 (storedW=1, storedH=1).
	vp8xPayload := make([]byte, 10)
	vp8xPayload[0] = vp8xFlagAnim
	vp8xPayload[4] = 0x01 // storedW = 1 → actual width = 2
	vp8xPayload[7] = 0x01 // storedH = 1 → actual height = 2

	// VP8L default data encodes 1×1 — mismatch.
	var frameBody bytes.Buffer
	writeVP8LChunk(&frameBody)

	var chunks bytes.Buffer
	writeChunk(&chunks, "VP8X", vp8xPayload)
	writeAnimChunk(&chunks)
	writeAnmfChunk(&chunks, frameBody.Bytes())
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_AnmfFrameNoAlphFlag verifies that an ANMF frame with an ALPH
// chunk when HAS_ALPH is not set is rejected.
// sanitizeWebPFrame default branch: unexpected ALPH with no flag.
func TestWebpsan_AnmfFrameNoAlphFlag(t *testing.T) {
	var frameBody bytes.Buffer
	writeAlphChunk(&frameBody, 0x00) // unexpected ALPH

	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagAnim, 0, 0) // no HAS_ALPH
	writeAnimChunk(&chunks)
	writeAnmfChunk(&chunks, frameBody.Bytes())
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_SanitizeWebPNilInput verifies SanitizeWebP with a nil (empty) slice.
func TestWebpsan_SanitizeWebPNilInput(t *testing.T) {
	if err := SanitizeWebP(nil); err == nil {
		t.Error("expected error for nil input, got nil")
	}
}

// TestWebpsan_Vp8xAnimatedWithICCPFlag verifies animated file with ICCP:
// VP8X(IS_ANIMATED|HAS_ICCP) + ICCP + ANIM + ANMF → accepted.
func TestWebpsan_Vp8xAnimatedWithICCPFlag(t *testing.T) {
	var frame bytes.Buffer
	writeVP8Chunk(&frame)

	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagAnim|vp8xFlagICCP, 0, 0)
	writeICCPChunk(&chunks)
	writeAnimChunk(&chunks)
	writeAnmfChunk(&chunks, frame.Bytes())
	assertWebPAccepted(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xStillWithAllMetaFlags verifies still image with all flags:
// VP8X(HAS_ICCP|HAS_ALPH|HAS_EXIF|HAS_XMP) + ICCP + ALPH + VP8 + EXIF + XMP → accepted.
func TestWebpsan_Vp8xStillWithAllMetaFlags(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagICCP|vp8xFlagAlpha|vp8xFlagEXIF|vp8xFlagXMP, 0, 0)
	writeICCPChunk(&chunks)
	writeAlphChunk(&chunks, 0x00)
	writeVP8Chunk(&chunks)
	writeEXIFChunk(&chunks)
	writeXMPChunk(&chunks)
	assertWebPAccepted(t, buildWebPPayload(&chunks))
}

// TestWebpsan_TruncatedChunkInPeek verifies that a RIFF payload ending with
// fewer than 8 bytes remaining (not enough for a chunk header) is rejected.
// This exercises the peekFourCC truncated-header error path.
func TestWebpsan_TruncatedChunkInPeek(t *testing.T) {
	// VP8X + ANIM + truncated ANMF header (only 4 bytes).
	// The animated state machine peeks for ANMF after ANIM.
	// With 4 bytes remaining (not 8), peekFourCC returns a truncation error.
	vp8xPayload := make([]byte, 10)
	vp8xPayload[0] = vp8xFlagAnim

	animPayload := make([]byte, 6)

	// Build ANMF stub: only 4 bytes (truncated header — needs 8).
	truncatedANMF := []byte("ANMF") // 4 bytes, no size field

	var riffBody bytes.Buffer
	writeChunk(&riffBody, "VP8X", vp8xPayload)
	writeChunk(&riffBody, "ANIM", animPayload)
	// Manually append the truncated ANMF header to the RIFF payload (no chunk wrapping).
	riffBody.Write(truncatedANMF)

	// Build RIFF with correct size.
	riffSize := uint32(4 + riffBody.Len()) // 4 for "WEBP"
	var buf bytes.Buffer
	buf.WriteString("RIFF")
	le := make([]byte, 4)
	binary.LittleEndian.PutUint32(le, riffSize)
	buf.Write(le)
	buf.WriteString("WEBP")
	buf.Write(riffBody.Bytes())

	assertWebPRejected(t, buf.Bytes())
}

// TestWebpsan_Vp8xExtendedICCPError verifies that a VP8X(HAS_ICCP) file where
// the chunk after VP8X is not ICCP is rejected.
// sanitizeWebPExtended: expected ICCP, got something else.
func TestWebpsan_Vp8xExtendedICCPError(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagICCP, 0, 0)
	// Provide VP8 instead of ICCP.
	writeVP8Chunk(&chunks)
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xExtendedEXIFError verifies that a VP8X(HAS_EXIF) file where
// the chunk after the image is not EXIF is rejected.
// sanitizeWebPExtended: expected EXIF, got something else.
func TestWebpsan_Vp8xExtendedEXIFError(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagEXIF, 0, 0)
	writeVP8Chunk(&chunks)
	// Provide XMP instead of EXIF.
	writeXMPChunk(&chunks)
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xExtendedXMPError verifies that a VP8X(HAS_XMP) file where
// the chunk after EXIF is not XMP is rejected.
// sanitizeWebPExtended: expected XMP, got something else.
func TestWebpsan_Vp8xExtendedXMPError(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagEXIF|vp8xFlagXMP, 0, 0)
	writeVP8Chunk(&chunks)
	writeEXIFChunk(&chunks)
	// Provide ICCP instead of XMP.
	writeICCPChunk(&chunks)
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xAnimatedExpectedANIMError verifies that when IS_ANIMATED is
// set, the chunk after VP8X must be ANIM; anything else is rejected.
// sanitizeWebPAnimated: expected ANIM, got VP8.
func TestWebpsan_Vp8xAnimatedExpectedANIMError(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagAnim, 0, 0)
	// Provide VP8 instead of ANIM.
	writeVP8Chunk(&chunks)
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Vp8xStillExpectedAlphError verifies that when HAS_ALPH is set,
// the chunk after VP8X must be ALPH; anything else is rejected.
func TestWebpsan_Vp8xStillExpectedAlphError(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, vp8xFlagAlpha, 0, 0)
	// Provide VP8 instead of ALPH.
	writeVP8Chunk(&chunks)
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_StillVP8LDimsMismatch verifies that a VP8L chunk in a still image
// whose dimensions don't match the VP8X canvas is rejected.
// sanitizeWebPStill: FrameDimensionsMismatch error.
// webpsan/src/lib.rs:228-235
func TestWebpsan_StillVP8LDimsMismatch(t *testing.T) {
	// VP8X canvas = 2×2 (storedW=1, storedH=1).
	vp8xPayload := make([]byte, 10)
	vp8xPayload[4] = 0x01 // storedW=1 → actual 2
	vp8xPayload[7] = 0x01 // storedH=1 → actual 2

	// VP8L default = 1×1 → mismatch.
	var chunks bytes.Buffer
	writeChunk(&chunks, "VP8X", vp8xPayload)
	writeVP8LChunk(&chunks) // declares 1×1
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_StillExpectedImageError verifies that after optional ALPH the
// next chunk must be VP8 or VP8L; anything else is rejected.
// sanitizeWebPStill: "expected image data, got …"
func TestWebpsan_StillExpectedImageError(t *testing.T) {
	var chunks bytes.Buffer
	writeVP8XChunk(&chunks, 0x00, 0, 0)
	// Put EXIF where VP8/VP8L should be.
	writeEXIFChunk(&chunks)
	assertWebPRejected(t, buildWebPPayload(&chunks))
}

// TestWebpsan_Validate_RejectsJPEG verifies that Validate rejects JPEG input
// (routed to goextensions, not handled by Validate).
func TestWebpsan_Validate_RejectsJPEG(t *testing.T) {
	jpegData := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01}
	_, err := Validate(jpegData)
	if err != ErrUnsupportedMediaType {
		t.Errorf("expected ErrUnsupportedMediaType for JPEG, got: %v", err)
	}
}
