package backup

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret/secrettest"
)

// errWriter is an io.Writer that always returns an error.
type errWriter struct{}

func (errWriter) Write([]byte) (int, error) {
	return 0, errors.New("write error")
}

// errReader is an io.Reader that always returns an error.
type errReader struct{}

func (errReader) Read([]byte) (int, error) {
	return 0, errors.New("read error")
}

// partialErrReader returns some data then an error (not EOF).
type partialErrReader struct {
	data []byte
	pos  int
}

func (r *partialErrReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, errors.New("read error after data")
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	if r.pos >= len(r.data) {
		return n, errors.New("read error after data")
	}
	return n, nil
}

// --- ReadAll error path ---

func TestReadAllReturnsErrorFromReader(t *testing.T) {
	// Create a reader that returns a valid first frame, then an error on the
	// second read (not EOF).
	var buf bytes.Buffer
	if err := WriteVarintDelimited(&buf, []byte("frame1")); err != nil {
		t.Fatalf("WriteVarintDelimited failed: %v", err)
	}
	// Append an invalid varint (all continuation bytes, never terminates).
	buf.Write(bytes.Repeat([]byte{0x80}, 12))

	br := NewBackupReader(&buf, PurposeRemoteBackup)
	frames, err := br.ReadAll()
	if err == nil {
		t.Fatal("expected error from ReadAll")
	}
	// Should have read at least the first valid frame before error.
	if len(frames) < 1 {
		t.Errorf("expected at least 1 frame before error, got %d", len(frames))
	}
}

// --- frameSliceReader edge cases ---

func TestFrameSliceReaderEOFOnEmpty(t *testing.T) {
	fsr := newFrameSliceReader(nil)
	p := make([]byte, 10)
	n, err := fsr.Read(p)
	if n != 0 || err != io.EOF {
		t.Errorf("Read on empty reader: n=%d, err=%v, want 0, io.EOF", n, err)
	}
}

func TestFrameSliceReaderPartialReturn(t *testing.T) {
	// Use a tiny read buffer to force partial reads across the varint
	// encoding boundary.
	frames := [][]byte{[]byte("ab"), []byte("cd")}
	fsr := newFrameSliceReader(frames)

	var all []byte
	buf := make([]byte, 1) // 1-byte reads
	for {
		n, err := fsr.Read(buf)
		if n > 0 {
			all = append(all, buf[:n]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
	}

	// Verify round-trip.
	vr := NewVarintDelimitedReader(bytes.NewReader(all))
	for _, expected := range frames {
		got, err := vr.ReadNext()
		if err != nil {
			t.Fatalf("ReadNext: %v", err)
		}
		if !bytes.Equal(got, expected) {
			t.Errorf("got %q, want %q", got, expected)
		}
	}
}

// --- PaddedLength edge cases ---

func TestPaddedLengthLargeValues(t *testing.T) {
	// Test that PaddedLength handles large values correctly.
	tests := []struct {
		name  string
		input uint32
	}{
		{"1 million", 1_000_000},
		{"10 million", 10_000_000},
		{"100 million", 100_000_000},
		{"500 million", 500_000_000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PaddedLength(tt.input)
			if got < tt.input {
				t.Errorf("PaddedLength(%d) = %d, smaller than input", tt.input, got)
			}
			if got < 541 {
				t.Errorf("PaddedLength(%d) = %d, below minimum 541", tt.input, got)
			}
		})
	}
}

// --- PaddedLength edge cases (replaces removed ln/pow internal tests) ---

func TestPaddedLengthSmallInputs(t *testing.T) {
	// Any input below 541 should return 541.
	for _, input := range []uint32{0, 1, 100, 540} {
		got := PaddedLength(input)
		if got != 541 {
			t.Errorf("PaddedLength(%d) = %d, want 541", input, got)
		}
	}
}

func TestPaddedLengthMonotonicCoverage(t *testing.T) {
	// PaddedLength should be monotonically non-decreasing.
	prev := PaddedLength(541)
	for i := uint32(542); i < 10000; i += 100 {
		cur := PaddedLength(i)
		if cur < prev {
			t.Errorf("PaddedLength(%d) = %d < PaddedLength(previous) = %d", i, cur, prev)
		}
		prev = cur
	}
}

// --- readNextVarint edge cases ---

func TestReadNextVarintInvalidEncoding(t *testing.T) {
	// A varint with all continuation bits set (never terminates within 10
	// bytes) should cause an error.
	data := bytes.Repeat([]byte{0x80}, 10)
	vr := NewVarintDelimitedReader(bytes.NewReader(data))
	_, err := vr.ReadNext()
	if err == nil {
		t.Fatal("expected error for invalid varint encoding")
	}
}

func TestReadNextVarintExceedsMax(t *testing.T) {
	// Encode a value larger than maxVarintValue (2^32 - 1).
	// 2^33 = 8589934592, encoded as varint:
	// This needs 5 bytes: 0x80, 0x80, 0x80, 0x80, 0x20
	var buf [10]byte
	val := uint64(1) << 33
	n := 0
	for val >= 0x80 {
		buf[n] = byte(val) | 0x80
		val >>= 7
		n++
	}
	buf[n] = byte(val)
	n++

	vr := NewVarintDelimitedReader(bytes.NewReader(buf[:n]))
	_, err := vr.ReadNext()
	if err == nil {
		t.Fatal("expected error for varint exceeding maximum")
	}
}

// --- fillBuffer read error ---

func TestFillBufferReadError(t *testing.T) {
	// A reader that returns an error (not EOF) should propagate.
	vr := NewVarintDelimitedReader(&errReader{})
	_, err := vr.ReadNext()
	if err == nil {
		t.Fatal("expected error from fillBuffer")
	}
}

// --- WriteVarintDelimited write errors ---

func TestWriteVarintDelimitedLengthWriteError(t *testing.T) {
	err := WriteVarintDelimited(&errWriter{}, []byte("hello"))
	if err == nil {
		t.Fatal("expected error when writing varint length")
	}
}

func TestWriteVarintDelimitedDataWriteError(t *testing.T) {
	// Writer that succeeds for the first write (varint) but fails for data.
	w := &failOnNthWriter{failOn: 2}
	err := WriteVarintDelimited(w, []byte("hello"))
	if err == nil {
		t.Fatal("expected error when writing data")
	}
}

// failOnNthWriter fails on the Nth call to Write.
type failOnNthWriter struct {
	count  int
	failOn int
}

func (w *failOnNthWriter) Write(p []byte) (int, error) {
	w.count++
	if w.count >= w.failOn {
		return 0, errors.New("write error")
	}
	return len(p), nil
}

// --- DecryptFrames ciphertext alignment error ---

func TestDecryptFramesBadCiphertextAlignment(t *testing.T) {
	key := testKey()

	// Create a valid encrypted backup, then strip one byte from the
	// ciphertext to break alignment.
	frames := [][]byte{[]byte("test")}
	var buf bytes.Buffer
	enc := NewFrameEncryptor(key)
	if err := enc.EncryptFrames(&buf, frames); err != nil {
		t.Fatalf("EncryptFrames: %v", err)
	}

	data := buf.Bytes()
	// Remove one byte from the middle (between IV and HMAC) to break
	// ciphertext alignment. We need to re-compute the HMAC for the
	// modified content to pass the HMAC check and reach the alignment check.
	// Instead, use a minimal manually constructed input:
	// IV (16 bytes) + ciphertext (1 byte, not multiple of 16) + HMAC (32 bytes)
	// But the HMAC must be valid for this content.
	iv := data[:AESIVSize]
	// 1 byte of ciphertext - not a multiple of AES block size.
	ct := []byte{0x42}

	// Compute valid HMAC over iv + ct.
	var hmacDigest []byte
	secrettest.With(t, key.HMACKey, func(k []byte) { hmacDigest = HMACChecksum(k, iv, ct) })
	badData := make([]byte, 0, AESIVSize+1+HMACLen)
	badData = append(badData, iv...)
	badData = append(badData, ct...)
	badData = append(badData, hmacDigest...)

	dec := NewFrameDecryptor(key)
	_, err := dec.DecryptFrames(bytes.NewReader(badData))
	if err == nil {
		t.Fatal("expected error for misaligned ciphertext")
	}
}

// --- VerifyHMAC mismatch returns HMACMismatchError ---

func TestVerifyHMACMismatchReturnsTypedError(t *testing.T) {
	key := testKey()
	frames := [][]byte{[]byte("data")}

	var buf bytes.Buffer
	enc := NewFrameEncryptor(key)
	if err := enc.EncryptFrames(&buf, frames); err != nil {
		t.Fatal(err)
	}

	data := make([]byte, buf.Len())
	copy(data, buf.Bytes())
	data[len(data)-1] ^= 0xFF

	err := VerifyHMAC(key, bytes.NewReader(data))
	if err == nil {
		t.Fatal("expected error")
	}
	var hmacErr *HMACMismatchError
	if !errors.As(err, &hmacErr) {
		t.Errorf("expected *HMACMismatchError, got %T", err)
	}
}

// --- EncryptFrames empty frames ---

func TestEncryptDecryptEmptyFrames(t *testing.T) {
	key := testKey()
	var buf bytes.Buffer
	enc := NewFrameEncryptor(key)
	if err := enc.EncryptFrames(&buf, nil); err != nil {
		t.Fatalf("EncryptFrames with nil frames: %v", err)
	}

	dec := NewFrameDecryptor(key)
	got, err := dec.DecryptFrames(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("DecryptFrames: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 frames, got %d", len(got))
	}
}

// --- encodeVarintDelimited edge cases ---

func TestEncodeVarintDelimitedEmpty(t *testing.T) {
	encoded := encodeVarintDelimited(nil)
	// Should be just the varint 0.
	if len(encoded) != 1 || encoded[0] != 0 {
		t.Errorf("encoded nil = %v, want [0]", encoded)
	}

	vr := NewVarintDelimitedReader(bytes.NewReader(encoded))
	got, err := vr.ReadNext()
	if err != nil {
		t.Fatalf("ReadNext: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty message, got %v", got)
	}
}

// --- PaddedLength boundary tests ---

func TestPaddedLengthAtBoundary(t *testing.T) {
	// PaddedLength(541) should return >= 541.
	got := PaddedLength(541)
	if got < 541 {
		t.Errorf("PaddedLength(541) = %d, want >= 541", got)
	}
}

// --- EncryptFrames write error paths ---

func TestEncryptFramesWriteIVError(t *testing.T) {
	key := testKey()
	enc := NewFrameEncryptor(key)
	err := enc.EncryptFrames(&errWriter{}, [][]byte{[]byte("data")})
	if err == nil {
		t.Fatal("expected error when writing IV fails")
	}
}

func TestEncryptFramesCiphertextWriteError(t *testing.T) {
	key := testKey()
	enc := NewFrameEncryptor(key)
	// Succeed on IV write (16 bytes), fail on ciphertext write.
	w := &failOnNthWriter{failOn: 2}
	err := enc.EncryptFrames(w, [][]byte{[]byte("data")})
	if err == nil {
		t.Fatal("expected error when writing ciphertext fails")
	}
}

func TestEncryptFramesHMACWriteError(t *testing.T) {
	key := testKey()
	enc := NewFrameEncryptor(key)
	// Succeed on IV (1) and ciphertext (2) writes, fail on HMAC write (3).
	w := &failOnNthWriter{failOn: 3}
	err := enc.EncryptFrames(w, [][]byte{[]byte("data")})
	if err == nil {
		t.Fatal("expected error when writing HMAC fails")
	}
}

// --- fillBuffer n==0 path ---

// zeroReader returns 0 bytes without error on the first read, then EOF.
type zeroThenEOFReader struct {
	called bool
}

func (r *zeroThenEOFReader) Read(p []byte) (int, error) {
	if !r.called {
		r.called = true
		return 0, nil
	}
	return 0, io.EOF
}

func TestFillBufferZeroByteRead(t *testing.T) {
	// A reader that returns n=0, err=nil should cause fillBuffer to exit
	// without error.
	vr := NewVarintDelimitedReader(&zeroThenEOFReader{})
	frame, err := vr.ReadNext()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if frame != nil {
		t.Errorf("expected nil frame, got %v", frame)
	}
}

// --- PaddedLength result < 541 after pow ---

func TestPaddedLengthJustAbove541(t *testing.T) {
	// PaddedLength(541) should return 541 (exact match).
	got := PaddedLength(541)
	if got < 541 {
		t.Errorf("PaddedLength(541) = %d, want >= 541", got)
	}

	// PaddedLength(542) should return a bucketed value >= 542.
	got = PaddedLength(542)
	if got < 542 {
		t.Errorf("PaddedLength(542) = %d, want >= 542", got)
	}
}

// --- DecryptFrames read error ---

func TestDecryptFramesReadError(t *testing.T) {
	key := testKey()
	dec := NewFrameDecryptor(key)
	_, err := dec.DecryptFrames(&errReader{})
	if err == nil {
		t.Fatal("expected error for failing reader")
	}
}

// --- VerifyHMAC read error ---

func TestVerifyHMACReadError(t *testing.T) {
	key := testKey()
	err := VerifyHMAC(key, &errReader{})
	if err == nil {
		t.Fatal("expected error for failing reader")
	}
}

// --- ReadNext with reader that fails mid-message ---

func TestReadNextTruncatedMessage(t *testing.T) {
	// Varint says 100 bytes but only a few are available via a failing reader.
	r := &partialErrReader{data: []byte{100, 1, 2, 3}}
	vr := NewVarintDelimitedReader(r)
	_, err := vr.ReadNext()
	if err == nil {
		t.Fatal("expected error for truncated message read")
	}
}

// --- frameSliceReader Read returns data then EOF ---

func TestFrameSliceReaderExactFill(t *testing.T) {
	// Read buffer is exactly the size of the encoded data.
	frames := [][]byte{[]byte("x")}
	fsr := newFrameSliceReader(frames)

	// "x" encodes as [1, 'x'] = 2 bytes.
	buf := make([]byte, 2)
	n, err := fsr.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("Read: %v", err)
	}
	if n != 2 {
		t.Errorf("Read n=%d, want 2", n)
	}
	if buf[0] != 1 || buf[1] != 'x' {
		t.Errorf("Read data = %v, want [1, 'x']", buf)
	}
}

func TestFrameSliceReaderLargeBufferDrainsPartial(t *testing.T) {
	// Use a read buffer larger than the encoded frame to exercise the path
	// where buf drains, frames are empty, and n > 0.
	frames := [][]byte{[]byte("a")}
	fsr := newFrameSliceReader(frames)

	// "a" encodes as [1, 'a'] = 2 bytes. Use a 100-byte read buffer.
	buf := make([]byte, 100)
	n, err := fsr.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	// Should return 2 bytes (the encoded frame) without EOF.
	if n != 2 {
		t.Errorf("Read n=%d, want 2", n)
	}

	// Next read should return EOF.
	n, err = fsr.Read(buf)
	if n != 0 || err != io.EOF {
		t.Errorf("second Read: n=%d, err=%v, want 0, io.EOF", n, err)
	}
}

// --- EncryptFrames with write-error-on-specific-call ---

func TestDecryptFramesInvalidGzip(t *testing.T) {
	// Construct valid AES-CBC ciphertext with valid HMAC, but the decrypted
	// content is not valid gzip. This exercises the gzip.NewReader error path.
	key := testKey()

	// Create plaintext that is NOT gzip - just some random data.
	// Must be a multiple of AES block size for valid PKCS7 padding.
	plaintext := bytes.Repeat([]byte("not gzip data!!!"), 1) // 16 bytes = 1 block
	padded := pkcs7Pad(plaintext, AESBlockSize)

	// Encrypt with AES-CBC.
	iv := make([]byte, AESIVSize)
	for i := range iv {
		iv[i] = byte(i)
	}
	ciphertext, err := []byte(nil), error(nil)
	secrettest.With(t, key.AESKey, func(k []byte) { ciphertext, err = AESCBCEncryptExport(k, iv, padded) })
	if err != nil {
		t.Fatalf("AESCBCEncryptExport: %v", err)
	}

	// Compute HMAC over IV + ciphertext.
	var hmacDigest []byte
	secrettest.With(t, key.HMACKey, func(k []byte) { hmacDigest = HMACChecksum(k, iv, ciphertext) })

	// Assemble: IV + ciphertext + HMAC.
	var data []byte
	data = append(data, iv...)
	data = append(data, ciphertext...)
	data = append(data, hmacDigest...)

	dec := NewFrameDecryptor(key)
	_, err = dec.DecryptFrames(bytes.NewReader(data))
	if err == nil {
		t.Fatal("expected error for non-gzip decrypted content")
	}
}

func TestDecryptFramesInvalidVarintInGzip(t *testing.T) {
	// Construct valid encrypted data where the gzip-decompressed content
	// contains an invalid varint, exercising the frame read error path.
	key := testKey()

	// Create gzipped data with an invalid varint (all continuation bytes).
	plaintext := gzipCompressBytes(t, bytes.Repeat([]byte{0x80}, 15))
	padded := pkcs7Pad(plaintext, AESBlockSize)

	iv := make([]byte, AESIVSize)
	ciphertext, err := []byte(nil), error(nil)
	secrettest.With(t, key.AESKey, func(k []byte) { ciphertext, err = AESCBCEncryptExport(k, iv, padded) })
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	var hmacDigest []byte
	secrettest.With(t, key.HMACKey, func(k []byte) { hmacDigest = HMACChecksum(k, iv, ciphertext) })
	var data []byte
	data = append(data, iv...)
	data = append(data, ciphertext...)
	data = append(data, hmacDigest...)

	dec := NewFrameDecryptor(key)
	_, err = dec.DecryptFrames(bytes.NewReader(data))
	if err == nil {
		t.Fatal("expected error for invalid varint in gzip stream")
	}
}

func TestDecryptFramesBadPadding(t *testing.T) {
	// Construct valid encrypted data where the decrypted plaintext has
	// invalid PKCS7 padding, exercising the unpad error path.
	key := testKey()

	// Create a single block of plaintext with invalid padding (last byte = 0).
	// This won't match any valid PKCS7 padding.
	plaintext := make([]byte, AESBlockSize)
	for i := range plaintext {
		plaintext[i] = 0xFF
	}
	plaintext[AESBlockSize-1] = 0 // Invalid: padding byte = 0

	// Encrypt with AES-CBC (no additional padding since it's already block-aligned
	// and we want to test with bad padding).
	iv := make([]byte, AESIVSize)
	for i := range iv {
		iv[i] = byte(i + 0x10)
	}

	ciphertext, err := []byte(nil), error(nil)
	secrettest.With(t, key.AESKey, func(k []byte) { ciphertext, err = aesEncryptRaw(k, iv, plaintext) })
	if err != nil {
		t.Fatalf("aesEncryptRaw: %v", err)
	}

	var hmacDigest []byte
	secrettest.With(t, key.HMACKey, func(k []byte) { hmacDigest = HMACChecksum(k, iv, ciphertext) })
	var data []byte
	data = append(data, iv...)
	data = append(data, ciphertext...)
	data = append(data, hmacDigest...)

	dec := NewFrameDecryptor(key)
	_, err = dec.DecryptFrames(bytes.NewReader(data))
	if err == nil {
		t.Fatal("expected error for invalid PKCS7 padding")
	}
}

// aesEncryptRaw encrypts plaintext with AES-CBC without adding PKCS7 padding.
// The plaintext must already be a multiple of the block size.
func aesEncryptRaw(aesKey, iv, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

// gzipCompressBytes compresses data using gzip for test purposes.
func gzipCompressBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	compressed, err := GzipCompress(data)
	if err != nil {
		t.Fatalf("GzipCompress: %v", err)
	}
	return compressed
}

func TestEncryptFramesOnlyIVWriteSucceeds(t *testing.T) {
	// Ensure that when only the IV write succeeds and ciphertext write
	// fails, the error is properly propagated.
	key := testKey()
	enc := NewFrameEncryptor(key)
	// failOn=2: first Write (IV) succeeds, second (ciphertext) fails.
	w := &failOnNthWriter{failOn: 2}
	err := enc.EncryptFrames(w, [][]byte{[]byte("test data for encryption")})
	if err == nil {
		t.Fatal("expected error on ciphertext write")
	}
}

// TestSkipProtoField exercises all branches of skipProtoField.
func TestSkipProtoField(t *testing.T) {
	t.Run("varint success", func(t *testing.T) {
		// Single-byte varint 0x01.
		got, err := skipProtoField([]byte{0x01, 0xAA, 0xBB}, 0)
		if err != nil {
			t.Fatalf("expected success for varint wire type, got: %v", err)
		}
		if len(got) != 2 {
			t.Errorf("remaining bytes = %d, want 2", len(got))
		}
	})

	t.Run("varint overflow (empty buffer)", func(t *testing.T) {
		_, err := skipProtoField([]byte{}, 0)
		if err == nil {
			t.Fatal("expected error for empty buffer with varint type")
		}
	})

	t.Run("64-bit success", func(t *testing.T) {
		buf := make([]byte, 10)
		got, err := skipProtoField(buf, 1)
		if err != nil {
			t.Fatalf("expected success for 64-bit wire type, got: %v", err)
		}
		if len(got) != 2 {
			t.Errorf("remaining bytes = %d, want 2", len(got))
		}
	})

	t.Run("64-bit too short", func(t *testing.T) {
		_, err := skipProtoField([]byte{0x01, 0x02}, 1)
		if err == nil {
			t.Fatal("expected error for 64-bit with only 2 bytes")
		}
	})

	t.Run("length-delimited success", func(t *testing.T) {
		// Varint length=2, followed by 2 payload bytes, then 1 extra byte.
		buf := []byte{0x02, 0xAA, 0xBB, 0xCC}
		got, err := skipProtoField(buf, 2)
		if err != nil {
			t.Fatalf("expected success for length-delimited wire type, got: %v", err)
		}
		if len(got) != 1 {
			t.Errorf("remaining bytes = %d, want 1", len(got))
		}
	})

	t.Run("length-delimited varint overflow", func(t *testing.T) {
		_, err := skipProtoField([]byte{}, 2)
		if err == nil {
			t.Fatal("expected error for empty buffer with length-delimited type")
		}
	})

	t.Run("length-delimited payload too short", func(t *testing.T) {
		// Varint says 10 bytes but only 3 follow.
		buf := []byte{0x0A, 0x01, 0x02, 0x03}
		_, err := skipProtoField(buf, 2)
		if err == nil {
			t.Fatal("expected error when payload shorter than declared length")
		}
	})

	t.Run("32-bit success", func(t *testing.T) {
		buf := make([]byte, 6)
		got, err := skipProtoField(buf, 5)
		if err != nil {
			t.Fatalf("expected success for 32-bit wire type, got: %v", err)
		}
		if len(got) != 2 {
			t.Errorf("remaining bytes = %d, want 2", len(got))
		}
	})

	t.Run("32-bit too short", func(t *testing.T) {
		_, err := skipProtoField([]byte{0x01, 0x02}, 5)
		if err == nil {
			t.Fatal("expected error for 32-bit with only 2 bytes")
		}
	})

	t.Run("unknown wire type", func(t *testing.T) {
		original := []byte{0x01, 0x02, 0x03}
		got, err := skipProtoField(original, 99)
		if err == nil {
			t.Fatal("expected error for unknown wire type")
		}
		if len(got) != len(original) {
			t.Error("original bytes should be returned unchanged for unknown wire type")
		}
	})
}
