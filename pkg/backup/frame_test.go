package backup

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

func testKey() *MessageBackupKey {
	hmacBytes := []byte{
		0xf4, 0x25, 0xe2, 0x2a, 0x60, 0x7c, 0x52, 0x97,
		0x17, 0xe1, 0xe1, 0xb2, 0x9f, 0x9f, 0xe1, 0x39,
		0xf9, 0xd1, 0xc7, 0xe7, 0xd0, 0x1e, 0x37, 0x1c,
		0x77, 0x53, 0xc5, 0x44, 0xa3, 0x02, 0x66, 0x49,
	}
	aesBytes := []byte{
		0xe1, 0x43, 0xf4, 0xad, 0x56, 0x68, 0xd8, 0xbf,
		0xed, 0x2f, 0x88, 0x56, 0x2f, 0x06, 0x93, 0xf5,
		0x3b, 0xda, 0x2c, 0x0e, 0x55, 0xc9, 0xd7, 0x17,
		0x30, 0xf3, 0x0e, 0x24, 0x69, 0x5f, 0xd6, 0xdf,
	}
	// Copy bytes before passing to secret.New (move semantics zeroizes source).
	hmacCopy := make([]byte, len(hmacBytes))
	copy(hmacCopy, hmacBytes)
	aesCopy := make([]byte, len(aesBytes))
	copy(aesCopy, aesBytes)

	hmacSecret, err := secret.New(hmacCopy)
	if err != nil {
		panic("testKey: failed to create HMAC secret: " + err.Error())
	}
	aesSecret, err := secret.New(aesCopy)
	if err != nil {
		hmacSecret.Destroy()
		panic("testKey: failed to create AES secret: " + err.Error())
	}
	return &MessageBackupKey{
		HMACKey: hmacSecret,
		AESKey:  aesSecret,
	}
}

func TestFrameRoundTrip(t *testing.T) {
	key := testKey()
	defer key.Zeroize()

	frames := [][]byte{
		[]byte("this was a triumph"),
		[]byte("I'm making a note here: huge success"),
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
	for i := range frames {
		if !bytes.Equal(got[i], frames[i]) {
			t.Errorf("frame %d: got %q, want %q", i, got[i], frames[i])
		}
	}
}

func TestFrameRoundTripSingleFrame(t *testing.T) {
	key := testKey()
	defer key.Zeroize()
	frames := [][]byte{[]byte("single frame test")}

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

	if len(got) != 1 {
		t.Fatalf("frame count: got %d, want 1", len(got))
	}
	if !bytes.Equal(got[0], frames[0]) {
		t.Errorf("frame: got %q, want %q", got[0], frames[0])
	}
}

func TestFrameDecryptInvalidHMAC(t *testing.T) {
	key := testKey()
	defer key.Zeroize()
	frames := [][]byte{[]byte("test data")}

	var buf bytes.Buffer
	enc := NewFrameEncryptor(key)
	if err := enc.EncryptFrames(&buf, frames); err != nil {
		t.Fatalf("EncryptFrames: %v", err)
	}

	// Corrupt the HMAC (last 32 bytes).
	data := buf.Bytes()
	data[len(data)-1] ^= 0xFF

	dec := NewFrameDecryptor(key)
	_, err := dec.DecryptFrames(bytes.NewReader(data))
	if err == nil {
		t.Fatal("expected HMAC mismatch error")
	}
	if _, ok := err.(*HMACMismatchError); !ok {
		t.Fatalf("expected HMACMismatchError, got %T: %v", err, err)
	}
}

func TestFrameDecryptTooShort(t *testing.T) {
	key := testKey()
	defer key.Zeroize()
	dec := NewFrameDecryptor(key)
	_, err := dec.DecryptFrames(bytes.NewReader([]byte("short")))
	if err == nil {
		t.Fatal("expected error for short input")
	}
}

func TestVerifyHMAC(t *testing.T) {
	key := testKey()
	defer key.Zeroize()
	frames := [][]byte{[]byte("hmac test")}

	var buf bytes.Buffer
	enc := NewFrameEncryptor(key)
	if err := enc.EncryptFrames(&buf, frames); err != nil {
		t.Fatalf("EncryptFrames: %v", err)
	}

	// Valid HMAC.
	if err := VerifyHMAC(key, bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("VerifyHMAC should pass: %v", err)
	}

	// Corrupted HMAC.
	data := make([]byte, buf.Len())
	copy(data, buf.Bytes())
	data[len(data)-1] ^= 0xFF
	if err := VerifyHMAC(key, bytes.NewReader(data)); err == nil {
		t.Fatal("VerifyHMAC should fail with corrupted data")
	}
}

// TestStripModernHeaderMetaLenOverflow is a regression test for the uint64
// addition overflow in stripModernHeader. A maximal-varint metaLen
// (0xFFFFFFFFFFFFFFFF) previously caused `uint64(off) + metaLen` to wrap
// around and pass the bounds check, leading to a slice-bounds panic.
// The fix uses `metaLen > uint64(len(data)-off)` which is overflow-safe.
func TestStripModernHeaderMetaLenOverflow(t *testing.T) {
	// Build a minimal modern header:
	//   8-byte magic + 10-byte maximal varint (metaLen = 2^64-1) + no payload.
	// Before the fix this panicked; after the fix it must return *ErrReadingMetadata.
	header := make([]byte, 0, 18)
	header = append(header, []byte(MagicNumber)...)
	// Encode 0xFFFFFFFFFFFFFFFF as a 10-byte uvarint.
	maxVarint := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01}
	header = append(header, maxVarint...)

	key := testKey()
	defer key.Zeroize()
	dec := NewFrameDecryptor(key)
	_, err := dec.DecryptFrames(bytes.NewReader(header))
	if err == nil {
		t.Fatal("expected error for maximal-varint metaLen overflow, got nil")
	}
	var metaErr *ErrReadingMetadata
	if !errors.As(err, &metaErr) {
		t.Errorf("expected *ErrReadingMetadata (directly or wrapped), got %T: %v", err, err)
	}
}

func TestPKCS7PadUnpad(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		blockSize int
	}{
		{"empty", []byte{}, 16},
		{"one byte", []byte{0x42}, 16},
		{"exact block", make([]byte, 16), 16},
		{"two blocks minus one", make([]byte, 31), 16},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			padded := pkcs7Pad(tt.input, tt.blockSize)
			if len(padded)%tt.blockSize != 0 {
				t.Errorf("padded length %d not a multiple of %d", len(padded), tt.blockSize)
			}
			unpadded, err := pkcs7Unpad(padded, tt.blockSize)
			if err != nil {
				t.Fatalf("unpad error: %v", err)
			}
			if !bytes.Equal(unpadded, tt.input) {
				t.Errorf("round-trip failed: got %v, want %v", unpadded, tt.input)
			}
		})
	}
}
