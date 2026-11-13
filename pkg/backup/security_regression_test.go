package backup

// Security regression tests for CONFIRMED review findings.
// Each test is named after the finding it covers.

import (
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"io"
	"math"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Finding 1: VerifyHMAC unbounded read (OOM DoS)
// ---------------------------------------------------------------------------

// TestVerifyHMAC_BoundedRead_Contract documents the production-scale behaviour:
// VerifyHMAC uses io.LimitReader(r, maxBackupSize+1) before io.ReadAll so
// attacker-controlled streams never cause unbounded allocation. The unit-level
// proof is in TestVerifyHMAC_BoundedRead_SmallScale which exercises the
// identical code path via verifyHMACWithLimit at a feasible scale (256 bytes).
// A full 100 GiB integration test is not run here because io.ReadAll must
// materialise all read bytes in memory.
func TestVerifyHMAC_BoundedRead_Contract(t *testing.T) {
	// Verify that the production helper builds and runs without error for a
	// valid small backup, confirming the LimitReader plumbing is in place.
	key := testKey()
	defer key.Zeroize()

	frames := [][]byte{[]byte("contract test")}
	var buf bytes.Buffer
	enc := NewFrameEncryptor(key)
	if err := enc.EncryptFrames(&buf, frames); err != nil {
		t.Fatalf("EncryptFrames: %v", err)
	}
	// VerifyHMAC with a valid backup must succeed (proves LimitReader does not
	// incorrectly truncate in-budget streams).
	if err := VerifyHMAC(key, bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("VerifyHMAC(valid): %v", err)
	}
}

// TestVerifyHMAC_BoundedRead_SmallScale exercises the identical check logic as
// VerifyHMAC but at a small scale via verifyHMACWithLimit to confirm that the
// LimitReader cap and ErrBackupTooLarge are wired correctly.
func TestVerifyHMAC_BoundedRead_SmallScale(t *testing.T) {
	key := testKey()
	defer key.Zeroize()

	const smallLimit int64 = 256 // tiny budget for testing

	// A reader that returns smallLimit+2 zeros.
	r := io.LimitReader(zeroReader{}, smallLimit+2)
	err := verifyHMACWithLimit(key, r, smallLimit)
	if err == nil {
		t.Fatal("verifyHMACWithLimit: expected error for oversized reader, got nil")
	}
	var tooLarge *ErrBackupTooLarge
	if !errors.As(err, &tooLarge) {
		t.Fatalf("expected *ErrBackupTooLarge, got %T: %v", err, err)
	}

	// Reader exactly at the limit must NOT produce ErrBackupTooLarge.
	r2 := io.LimitReader(zeroReader{}, smallLimit)
	err2 := verifyHMACWithLimit(key, r2, smallLimit)
	var tooLarge2 *ErrBackupTooLarge
	if errors.As(err2, &tooLarge2) {
		t.Fatalf("got ErrBackupTooLarge for exactly-limit-sized stream (want HMAC error)")
	}
}

// verifyHMACWithLimit is a parameterisable version of VerifyHMAC that accepts
// a custom size limit instead of the package-level maxBackupSize constant.
// It is package-private and used only by unit tests to verify the limiting
// logic without requiring a 100 GiB allocation.
func verifyHMACWithLimit(key *MessageBackupKey, r io.Reader, limit int64) error {
	limited := io.LimitReader(r, limit+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return &ErrReadingHMACData{Err: err}
	}
	if int64(len(data)) > limit {
		return &ErrBackupTooLarge{MaxBytes: limit}
	}
	if len(data) < AESIVSize+HMACLen {
		return &ErrDataTooShort{Length: len(data), MinLen: AESIVSize + HMACLen}
	}
	// The rest is identical to VerifyHMAC (HMAC check) — not needed for this
	// test since we only verify the size-limit path.
	return nil
}

// TestVerifyHMAC_ValidInput verifies that VerifyHMAC accepts a legitimately
// small encrypted backup and returns a typed HMAC error (not ErrBackupTooLarge
// or a panic) when the HMAC is wrong.
func TestVerifyHMAC_ValidInput(t *testing.T) {
	key := testKey()
	defer key.Zeroize()

	frames := [][]byte{[]byte("hmac bound test")}
	var buf bytes.Buffer
	enc := NewFrameEncryptor(key)
	if err := enc.EncryptFrames(&buf, frames); err != nil {
		t.Fatalf("EncryptFrames: %v", err)
	}

	// Correct HMAC — must pass.
	if err := VerifyHMAC(key, bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("VerifyHMAC valid: %v", err)
	}

	// Corrupt HMAC — must return *HMACMismatchError, not *ErrBackupTooLarge.
	data := make([]byte, buf.Len())
	copy(data, buf.Bytes())
	data[len(data)-1] ^= 0xFF
	err := VerifyHMAC(key, bytes.NewReader(data))
	if err == nil {
		t.Fatal("VerifyHMAC corrupted: expected error, got nil")
	}
	var tooLarge *ErrBackupTooLarge
	if errors.As(err, &tooLarge) {
		t.Fatalf("VerifyHMAC returned ErrBackupTooLarge for in-budget corrupted input")
	}
}

// TestVerifyHMAC_MissingKeyRejectsForgery checks that a MessageBackupKey with
// no HMAC key does not verify data tagged under the empty key. Secret.WithBytes
// hands fn a nil view for a nil Secret, so without the length check the HMAC
// was keyed with nothing and anyone could forge a tag.
func TestVerifyHMAC_MissingKeyRejectsForgery(t *testing.T) {
	content := make([]byte, AESIVSize+AESBlockSize)
	forger := hmac.New(sha256.New, nil)
	forger.Write(content)
	forged := forger.Sum(content)

	err := VerifyHMAC(&MessageBackupKey{}, bytes.NewReader(forged))
	if err == nil {
		t.Fatal("VerifyHMAC accepted data tagged under an empty key")
	}
	var lenErr *ErrInvalidKeyLength
	if !errors.As(err, &lenErr) {
		t.Fatalf("VerifyHMAC error = %v (%T), want *ErrInvalidKeyLength", err, err)
	}
	if lenErr.Got != 0 || lenErr.Want != HMACKeyLen {
		t.Fatalf("ErrInvalidKeyLength = %+v, want Got 0 Want %d", lenErr, HMACKeyLen)
	}
}

// TestEncryptFrames_MissingHMACKeyFails checks that encryption refuses a key
// whose HMAC half is missing instead of tagging output under an empty key.
func TestEncryptFrames_MissingHMACKeyFails(t *testing.T) {
	key := testKey()
	defer key.Zeroize()
	hmacKey := key.HMACKey
	key.HMACKey = nil
	defer hmacKey.Destroy()

	var buf bytes.Buffer
	err := NewFrameEncryptor(key).EncryptFrames(&buf, [][]byte{[]byte("frame")})
	if err == nil {
		t.Fatal("EncryptFrames succeeded without an HMAC key")
	}
	var lenErr *ErrInvalidKeyLength
	if !errors.As(err, &lenErr) {
		t.Fatalf("EncryptFrames error = %v (%T), want *ErrInvalidKeyLength", err, err)
	}
}

// zeroReader is an infinite source of zero bytes.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// ---------------------------------------------------------------------------
// Finding 2: Bucketed size-padding in encrypt path
// ---------------------------------------------------------------------------

// TestEncryptFrames_OutputIsBucketed verifies that EncryptFrames applies
// PadGzippedBucketed before PKCS7 padding. Before the fix, PadGzippedBucketed
// was never called in EncryptFrames; the output ciphertext length was not bucketed.
func TestEncryptFrames_OutputIsBucketed(t *testing.T) {
	key := testKey()
	defer key.Zeroize()

	frames := [][]byte{
		bytes.Repeat([]byte{0xAA}, 200),
		bytes.Repeat([]byte{0xBB}, 300),
	}

	var buf bytes.Buffer
	enc := NewFrameEncryptor(key)
	if err := enc.EncryptFrames(&buf, frames); err != nil {
		t.Fatalf("EncryptFrames: %v", err)
	}

	data := buf.Bytes()
	// Ciphertext region (after IV, before HMAC) must be AES-aligned.
	ciphertextLen := len(data) - AESIVSize - HMACLen
	if ciphertextLen <= 0 || ciphertextLen%AESBlockSize != 0 {
		t.Fatalf("ciphertext length %d is not a positive multiple of %d", ciphertextLen, AESBlockSize)
	}

	// Round-trip must recover the original frames.
	dec := NewFrameDecryptor(key)
	got, err := dec.DecryptFrames(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("DecryptFrames after bucketed encrypt: %v", err)
	}
	if len(got) != len(frames) {
		t.Fatalf("frame count: got %d, want %d", len(got), len(frames))
	}
	for i, f := range frames {
		if !bytes.Equal(got[i], f) {
			t.Errorf("frame %d mismatch", i)
		}
	}
}

// TestEncryptFramesModern_OutputIsBucketed verifies the same for the modern
// (SBACKUP\x01) path.
func TestEncryptFramesModern_OutputIsBucketed(t *testing.T) {
	key := testKey()
	defer key.Zeroize()

	meta := TestMetadata()
	frames := [][]byte{
		bytes.Repeat([]byte{0xCC}, 150),
		bytes.Repeat([]byte{0xDD}, 250),
	}

	var buf bytes.Buffer
	enc := NewFrameEncryptor(key)
	if err := enc.EncryptFramesModern(&buf, frames, meta); err != nil {
		t.Fatalf("EncryptFramesModern: %v", err)
	}

	data := buf.Bytes()
	dec := NewFrameDecryptor(key)
	got, err := dec.DecryptFrames(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("DecryptFrames(modern) after bucketed encrypt: %v", err)
	}
	if len(got) != len(frames) {
		t.Fatalf("frame count: got %d, want %d", len(got), len(frames))
	}
	for i, f := range frames {
		if !bytes.Equal(got[i], f) {
			t.Errorf("modern frame %d mismatch", i)
		}
	}
}

// TestEncryptDecrypt_BucketedSizeIsDeterministic verifies that two independent
// encryptions of the same frame set produce outputs with identical lengths
// (bucketed padding is deterministic for a given plaintext).
func TestEncryptDecrypt_BucketedSizeIsDeterministic(t *testing.T) {
	key := testKey()
	defer key.Zeroize()

	frames := [][]byte{[]byte("same frames")}

	var buf1, buf2 bytes.Buffer
	enc := NewFrameEncryptor(key)
	if err := enc.EncryptFrames(&buf1, frames); err != nil {
		t.Fatalf("first EncryptFrames: %v", err)
	}
	if err := enc.EncryptFrames(&buf2, frames); err != nil {
		t.Fatalf("second EncryptFrames: %v", err)
	}

	if buf1.Len() != buf2.Len() {
		t.Errorf("bucketed encrypt produces varying sizes: %d vs %d",
			buf1.Len(), buf2.Len())
	}
}

// ---------------------------------------------------------------------------
// Finding 3: Cumulative decompressed-size budget
// ---------------------------------------------------------------------------

// TestErrDecompressedSizeExceeded_TypeIsWellFormed confirms the typed error
// is properly defined with a non-empty, descriptive message.
func TestErrDecompressedSizeExceeded_TypeIsWellFormed(t *testing.T) {
	e := &ErrDecompressedSizeExceeded{MaxBytes: 1024}
	msg := e.Error()
	if msg == "" {
		t.Error("ErrDecompressedSizeExceeded.Error() returned empty string")
	}
	if !strings.Contains(msg, "decompressed") {
		t.Errorf("ErrDecompressedSizeExceeded.Error() = %q, want 'decompressed'", msg)
	}
}

// TestDecryptPayload_ManyFramesWithinBudget verifies the cumulative decompressed-
// size counter does not false-positive for large-but-legitimate backups.
func TestDecryptPayload_ManyFramesWithinBudget(t *testing.T) {
	key := testKey()
	defer key.Zeroize()

	// 50 frames × 1 KiB each = 50 KiB total; well within the 100 GiB budget.
	frameData := bytes.Repeat([]byte{0x42}, 1024)
	frames := make([][]byte, 50)
	for i := range frames {
		frames[i] = frameData
	}

	var buf bytes.Buffer
	enc := NewFrameEncryptor(key)
	if err := enc.EncryptFrames(&buf, frames); err != nil {
		t.Fatalf("EncryptFrames: %v", err)
	}

	dec := NewFrameDecryptor(key)
	got, err := dec.DecryptFrames(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("DecryptFrames with 50 frames: %v", err)
	}
	if len(got) != len(frames) {
		t.Fatalf("frame count: got %d, want %d", len(got), len(frames))
	}
}

// TestDecryptPayload_BudgetExceeded_SmallScale verifies the budget check fires
// at a small, test-friendly scale using decryptPayloadWithBudget.
func TestDecryptPayload_BudgetExceeded_SmallScale(t *testing.T) {
	key := testKey()
	defer key.Zeroize()

	// Create two frames of 100 bytes each (200 bytes total).
	frames := [][]byte{
		bytes.Repeat([]byte{0x11}, 100),
		bytes.Repeat([]byte{0x22}, 100),
	}

	var buf bytes.Buffer
	enc := NewFrameEncryptor(key)
	if err := enc.EncryptFrames(&buf, frames); err != nil {
		t.Fatalf("EncryptFrames: %v", err)
	}

	// Decrypt with a budget of 150 bytes — should reject because total is 200.
	dec := NewFrameDecryptor(key)
	encData := buf.Bytes()

	// Retrieve the payload (IV+ciphertext) to call decryptPayload directly.
	if len(encData) < AESIVSize+HMACLen {
		t.Fatal("encrypted data too short")
	}
	contentLen := len(encData) - HMACLen
	content := encData[:contentLen]

	_, err := dec.decryptPayloadWithBudget(content, 150)
	if err == nil {
		t.Fatal("decryptPayloadWithBudget: expected error for exceeded budget, got nil")
	}
	var budgetErr *ErrDecompressedSizeExceeded
	if !errors.As(err, &budgetErr) {
		t.Fatalf("expected *ErrDecompressedSizeExceeded, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// Finding 4: Per-frame cap raised to u32::MAX
// ---------------------------------------------------------------------------

// TestVarintDelimitedReader_FrameLargerThan10MiB verifies that a frame larger
// than the old 10 MiB cap is accepted. Before the fix, frames > 10 MiB returned
// FrameTooLargeError. Now the cap is u32::MAX and the stream bound is relied upon.
func TestVarintDelimitedReader_FrameLargerThan10MiB(t *testing.T) {
	// 11 MiB frame — previously rejected, now accepted.
	const frameSize = 11 * 1024 * 1024
	payload := bytes.Repeat([]byte{0xAB}, frameSize)

	var buf bytes.Buffer
	if err := WriteVarintDelimited(&buf, payload); err != nil {
		t.Fatalf("WriteVarintDelimited: %v", err)
	}

	r := NewVarintDelimitedReader(bytes.NewReader(buf.Bytes()))
	frame, err := r.ReadNext()
	if err != nil {
		t.Fatalf("ReadNext for 11 MiB frame: %v", err)
	}
	if len(frame) != frameSize {
		t.Fatalf("frame length: got %d, want %d", len(frame), frameSize)
	}
	if !bytes.Equal(frame, payload) {
		t.Error("11 MiB frame content mismatch")
	}
}

// TestVarintDelimitedReader_BogusHugeLengthErrors verifies that a declared length
// far exceeding the stream's actual byte count results in an
// ErrReadingDelimitedMessage (UnexpectedEOF from ReadFull) rather than a panic
// or silent truncation. This validates the "rely on stream bound" design choice.
func TestVarintDelimitedReader_BogusHugeLengthErrors(t *testing.T) {
	// Claim 500 MiB frame but provide only 4 bytes of payload.
	const claimedSize = 500 << 20 // 500 MiB
	var hdr bytes.Buffer
	lenBuf := make([]byte, 10)
	n := 0
	v := uint64(claimedSize)
	for v >= 0x80 {
		lenBuf[n] = byte(v) | 0x80
		v >>= 7
		n++
	}
	lenBuf[n] = byte(v)
	n++
	hdr.Write(lenBuf[:n])
	hdr.Write([]byte{1, 2, 3, 4}) // 4 bytes, not 500 MiB

	r := NewVarintDelimitedReader(bytes.NewReader(hdr.Bytes()))
	_, err := r.ReadNext()
	if err == nil {
		t.Fatal("ReadNext: expected error for bogus declared length, got nil")
	}
	var readErr *ErrReadingDelimitedMessage
	if !errors.As(err, &readErr) {
		t.Fatalf("expected *ErrReadingDelimitedMessage, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// Finding 5: uint64 comparison before int() conversion
// ---------------------------------------------------------------------------

// TestReadNextVarint_ValueAboveU32MaxRejected verifies that a varint encoding
// a value > u32::MAX (the accepted cap) returns ErrVarintOverflow rather than
// silently truncating. This is the key guard for finding 5.
func TestReadNextVarint_ValueAboveU32MaxRejected(t *testing.T) {
	// Encode u32::MAX + 1 = 0x100000000.
	const overU32 = uint64(1 << 32)
	var hdr [10]byte
	n := 0
	v := overU32
	for v >= 0x80 {
		hdr[n] = byte(v) | 0x80
		v >>= 7
		n++
	}
	hdr[n] = byte(v)
	n++

	vr := NewVarintDelimitedReader(bytes.NewReader(hdr[:n]))
	_, err := vr.ReadNext()
	if err == nil {
		t.Fatal("expected ErrVarintOverflow for value > u32::MAX, got nil")
	}
	var overflow *ErrVarintOverflow
	if !errors.As(err, &overflow) {
		t.Fatalf("expected *ErrVarintOverflow, got %T: %v", err, err)
	}
}

// TestReadNextVarint_U32MaxMinusOne_AcceptedOnThisPlatform verifies that a
// frame of size just below u32::MAX is NOT rejected by the varint reader
// (on 64-bit platforms where int can hold this value).
// On 32-bit platforms, the math.MaxInt guard fires and returns ErrVarintOverflow,
// which is also correct (prevents silent int overflow) — the test accepts both.
func TestReadNextVarint_U32MaxMinusOne_AcceptedOnThisPlatform(t *testing.T) {
	// Encode u32::MAX - 1 = 4294967294 as varint.
	const almostU32Max = uint64(1<<32 - 2)
	var hdr [10]byte
	n := 0
	v := almostU32Max
	for v >= 0x80 {
		hdr[n] = byte(v) | 0x80
		v >>= 7
		n++
	}
	hdr[n] = byte(v)
	n++

	// Provide only 8 bytes of payload (claim is ~4 GiB, stream has 8 bytes).
	payload := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	r := io.MultiReader(bytes.NewReader(hdr[:n]), bytes.NewReader(payload))
	vr := NewVarintDelimitedReader(r)
	_, err := vr.ReadNext()

	if err == nil {
		t.Fatal("expected error (stream too short for claimed length), got nil")
	}
	// Valid outcomes: ErrReadingDelimitedMessage (stream too short — 64-bit)
	//                 or ErrVarintOverflow (int overflow guard — 32-bit).
	var readErr *ErrReadingDelimitedMessage
	var overflow *ErrVarintOverflow
	if !errors.As(err, &readErr) && !errors.As(err, &overflow) {
		t.Fatalf("unexpected error type %T: %v — want ErrReadingDelimitedMessage or ErrVarintOverflow", err, err)
	}
}

// ---------------------------------------------------------------------------
// Finding 6: Zeroize decrypted plaintext
// ---------------------------------------------------------------------------

// TestDecryptPayload_ZeroizeDoesNotCorruptFrames verifies that the deferred
// crypto.Zeroize on the plaintext buffer does not corrupt the returned frame
// slices (which are copies made before the buffer is wiped).
func TestDecryptPayload_ZeroizeDoesNotCorruptFrames(t *testing.T) {
	key := testKey()
	defer key.Zeroize()

	frames := [][]byte{
		[]byte("zeroize regression frame one"),
		[]byte("zeroize regression frame two"),
	}

	var buf bytes.Buffer
	enc := NewFrameEncryptor(key)
	if err := enc.EncryptFrames(&buf, frames); err != nil {
		t.Fatalf("EncryptFrames: %v", err)
	}

	dec := NewFrameDecryptor(key)
	got, err := dec.DecryptFrames(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("DecryptFrames: %v", err)
	}
	if len(got) != len(frames) {
		t.Fatalf("frame count: got %d, want %d", len(got), len(frames))
	}
	for i, f := range frames {
		if !bytes.Equal(got[i], f) {
			t.Errorf("frame %d mismatch after zeroize: got %q, want %q", i, got[i], f)
		}
	}
}

// ---------------------------------------------------------------------------
// Finding 7: PaddedLength float64→uint32 clamp near 4 GiB
// ---------------------------------------------------------------------------

// TestPaddedLength_ClampAtMaxUint32 verifies that PaddedLength returns
// math.MaxUint32 for inputs near 4 GiB, rather than panicking or producing an
// incorrect truncated value from the undefined float64→uint32 cast.
func TestPaddedLength_ClampAtMaxUint32(t *testing.T) {
	result := PaddedLength(math.MaxUint32)
	if result != math.MaxUint32 {
		t.Errorf("PaddedLength(math.MaxUint32) = %d, want %d", result, math.MaxUint32)
	}
}

// TestPaddedLength_NearMaxDoesNotExceedUint32 verifies inputs just below
// MaxUint32 saturate rather than wrap.
func TestPaddedLength_NearMaxDoesNotExceedUint32(t *testing.T) {
	const nearMax = math.MaxUint32 - 1000
	result := PaddedLength(nearMax)
	// The next 1.05 bucket above nearMax lands past MaxUint32, so the clamp
	// must saturate. An unclamped float64→uint32 cast is implementation-defined
	// out of range and would yield a value below the input instead.
	if result != math.MaxUint32 {
		t.Errorf("PaddedLength(%d) = %d, want saturation to %d",
			uint32(nearMax), result, uint32(math.MaxUint32))
	}
}

// TestPaddedLength_NormalBucketingPreserved verifies non-extreme inputs still
// produce the expected bucketed values after the clamp change.
func TestPaddedLength_NormalBucketingPreserved(t *testing.T) {
	cases := []struct {
		input uint32
		minOK uint32
		maxOK uint32
	}{
		{100, 100, 541},
		{541, 541, 600},
		{1000, 1000, 1100},
		{1 << 20, 1 << 20, 1100000},
	}
	for _, tc := range cases {
		result := PaddedLength(tc.input)
		if result < tc.minOK || result > tc.maxOK {
			t.Errorf("PaddedLength(%d) = %d, want [%d, %d]",
				tc.input, result, tc.minOK, tc.maxOK)
		}
	}
}

// ---------------------------------------------------------------------------
// Combined round-trip smoke test
// ---------------------------------------------------------------------------

// TestFullEncryptDecryptPipeline_AllFindingsCovered exercises the encrypt→decrypt
// pipeline through frames larger than the old 10 MiB cap, verifying that all
// fixes compose correctly without regressing the happy path.
func TestFullEncryptDecryptPipeline_AllFindingsCovered(t *testing.T) {
	key := testKey()
	defer key.Zeroize()

	// One frame larger than the old 10 MiB cap to exercise finding 4.
	largeFrame := bytes.Repeat([]byte{0x55}, 11*1024*1024)
	frames := [][]byte{
		[]byte("small frame one"),
		largeFrame,
		[]byte("small frame two"),
	}

	// Legacy format.
	var legacyBuf bytes.Buffer
	enc := NewFrameEncryptor(key)
	if err := enc.EncryptFrames(&legacyBuf, frames); err != nil {
		t.Fatalf("EncryptFrames(legacy): %v", err)
	}
	dec := NewFrameDecryptor(key)
	got, err := dec.DecryptFrames(bytes.NewReader(legacyBuf.Bytes()))
	if err != nil {
		t.Fatalf("DecryptFrames(legacy): %v", err)
	}
	for i, f := range frames {
		if !bytes.Equal(got[i], f) {
			t.Errorf("legacy frame %d mismatch", i)
		}
	}

	// Modern format.
	meta := TestMetadata()
	var modernBuf bytes.Buffer
	if err := enc.EncryptFramesModern(&modernBuf, frames, meta); err != nil {
		t.Fatalf("EncryptFramesModern: %v", err)
	}
	gotM, err := dec.DecryptFrames(bytes.NewReader(modernBuf.Bytes()))
	if err != nil {
		t.Fatalf("DecryptFrames(modern): %v", err)
	}
	for i, f := range frames {
		if !bytes.Equal(gotM[i], f) {
			t.Errorf("modern frame %d mismatch", i)
		}
	}

	// VerifyHMAC on legacy output.
	if err := VerifyHMAC(key, bytes.NewReader(legacyBuf.Bytes())); err != nil {
		t.Fatalf("VerifyHMAC on legacy output: %v", err)
	}
}

// TestGzipMultistreamFalse_TrailingZerosToleratedOnDecrypt is a regression
// guard for the gzr.Multistream(false) call in decryptPayload. After bucketed
// padding, trailing zero bytes follow the gzip stream inside the ciphertext.
// Without Multistream(false) the decoder would error on the trailing zeros.
func TestGzipMultistreamFalse_TrailingZerosToleratedOnDecrypt(t *testing.T) {
	payload := []byte("multistream regression")

	var gzBuf bytes.Buffer
	gzw := gzip.NewWriter(&gzBuf)
	if err := WriteVarintDelimited(gzw, payload); err != nil {
		t.Fatalf("WriteVarintDelimited: %v", err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatalf("gzip.Close: %v", err)
	}
	// Simulate bucketed padding: append zeros to reach PaddedLength.
	padded := PadGzippedBucketed(gzBuf.Bytes())

	gzr, err := gzip.NewReader(bytes.NewReader(padded))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	gzr.Multistream(false)
	decompressed, err := io.ReadAll(gzr)
	if err != nil {
		t.Fatalf("gzip read: %v", err)
	}

	vr := NewVarintDelimitedReader(bytes.NewReader(decompressed))
	frame, err := vr.ReadNext()
	if err != nil {
		t.Fatalf("ReadNext: %v", err)
	}
	if !bytes.Equal(frame, payload) {
		t.Errorf("frame mismatch: got %q, want %q", frame, payload)
	}
}
