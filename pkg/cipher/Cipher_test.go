package cipher

import (
	"bytes"
	"errors"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(i + 0x10)
	}
	plaintext := []byte("Hello, Signal!")

	ciphertext, err := Encrypt(iv, key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext should differ from plaintext")
	}

	decrypted, err := Decrypt(iv, key, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("round-trip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptInvalidKey(t *testing.T) {
	_, err := Encrypt(make([]byte, 16), []byte("short"), []byte("data"))
	if err == nil {
		t.Fatal("expected error for invalid key size")
	}
	if !errors.Is(err, ErrInvalidKeySize) {
		t.Errorf("expected ErrInvalidKeySize, got %v", err)
	}
}

func TestDecryptInvalidKey(t *testing.T) {
	_, err := Decrypt(make([]byte, 16), []byte("short"), make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for invalid key size")
	}
	if !errors.Is(err, ErrInvalidKeySize) {
		t.Errorf("expected ErrInvalidKeySize, got %v", err)
	}
}

func TestEncryptRejects16ByteKey(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	_, err := Encrypt(iv, key, []byte("data"))
	if !errors.Is(err, ErrInvalidKeySize) {
		t.Errorf("expected ErrInvalidKeySize for 16-byte key, got %v", err)
	}
}

func TestDecryptDoesNotMutateInput(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	iv := make([]byte, 16)
	plaintext := []byte("test immutability")

	ciphertext, err := Encrypt(iv, key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Save a copy of the ciphertext before decryption.
	original := make([]byte, len(ciphertext))
	copy(original, ciphertext)

	_, err = Decrypt(iv, key, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Verify ciphertext was not mutated.
	if !bytes.Equal(ciphertext, original) {
		t.Error("Decrypt mutated the input ciphertext")
	}
}

func TestDecryptTooShort(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	_, err := Decrypt(iv, key, []byte{0x01})
	if err == nil {
		t.Fatal("expected error for ciphertext too short")
	}
}

func TestPkcs7PadInvalidBlockSize(t *testing.T) {
	_, err := pkcs7Pad([]byte("data"), 0)
	if !errors.Is(err, ErrInvalidBlockSize) {
		t.Errorf("expected ErrInvalidBlockSize, got %v", err)
	}
	_, err = pkcs7Pad([]byte("data"), -1)
	if !errors.Is(err, ErrInvalidBlockSize) {
		t.Errorf("expected ErrInvalidBlockSize, got %v", err)
	}
}

// TestPkcs7PadEmptyInput verifies that nil and empty inputs produce a full
// block of PKCS#7 padding per RFC 5652 §6.3: when len(b) == 0, n == blocksize,
// so the result is exactly one block of padding bytes (e.g., 16 × 0x10).
func TestPkcs7PadEmptyInput(t *testing.T) {
	const blockSize = 16
	for _, input := range [][]byte{nil, {}} {
		got, err := pkcs7Pad(input, blockSize)
		if err != nil {
			t.Errorf("pkcs7Pad: unexpected error for empty input: %v", err)
			continue
		}
		if len(got) != blockSize {
			t.Errorf("pkcs7Pad: want %d bytes, got %d", blockSize, len(got))
			continue
		}
		for i, b := range got {
			if b != byte(blockSize) {
				t.Errorf("pkcs7Pad: byte[%d] = 0x%02x, want 0x%02x", i, b, byte(blockSize))
			}
		}
	}
}

func TestPkcs7UnpadInvalidBlockSize(t *testing.T) {
	_, err := pkcs7Unpad([]byte("data"), 0)
	if !errors.Is(err, ErrInvalidBlockSize) {
		t.Errorf("expected ErrInvalidBlockSize, got %v", err)
	}
}

func TestPkcs7UnpadNilData(t *testing.T) {
	_, err := pkcs7Unpad(nil, 16)
	if !errors.Is(err, ErrInvalidPKCS7Data) {
		t.Errorf("expected ErrInvalidPKCS7Data, got %v", err)
	}
}

func TestPkcs7UnpadNotMultiple(t *testing.T) {
	_, err := pkcs7Unpad([]byte{0x01, 0x02, 0x03}, 16)
	if !errors.Is(err, ErrInvalidPKCS7Padding) {
		t.Errorf("expected ErrInvalidPKCS7Padding, got %v", err)
	}
}

func TestPkcs7UnpadInvalidPaddingValue(t *testing.T) {
	// Padding byte = 0 (invalid)
	data := make([]byte, 16)
	data[15] = 0
	_, err := pkcs7Unpad(data, 16)
	if !errors.Is(err, ErrInvalidPKCS7Padding) {
		t.Errorf("expected ErrInvalidPKCS7Padding, got %v", err)
	}

	// Padding byte too large
	data[15] = 17
	_, err = pkcs7Unpad(data, 16)
	if !errors.Is(err, ErrInvalidPKCS7Padding) {
		t.Errorf("expected ErrInvalidPKCS7Padding, got %v", err)
	}
}

func TestPkcs7UnpadInconsistentPadding(t *testing.T) {
	data := make([]byte, 16)
	data[15] = 3
	data[14] = 3
	data[13] = 5 // wrong
	_, err := pkcs7Unpad(data, 16)
	if !errors.Is(err, ErrInvalidPKCS7Padding) {
		t.Errorf("expected ErrInvalidPKCS7Padding, got %v", err)
	}
}

func TestDecryptBadPadding(t *testing.T) {
	// Encrypt valid data, then corrupt last byte to produce bad PKCS7 padding.
	key := make([]byte, 32)
	iv := make([]byte, 16)
	ct, err := Encrypt(iv, key, []byte("valid plaintext!"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// Flip bits in last byte to corrupt padding.
	ct[len(ct)-1] ^= 0xFF
	_, err = Decrypt(iv, key, ct)
	if err == nil {
		t.Error("Decrypt should fail with corrupted padding")
	}
}

// TestEncryptEmptyPlaintext verifies that nil and empty plaintexts are valid:
// PKCS#7 pads them to a full block before encryption.
func TestEncryptEmptyPlaintext(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	for _, plain := range [][]byte{nil, {}} {
		ct, err := Encrypt(iv, key, plain)
		if err != nil {
			t.Errorf("Encrypt: unexpected error for empty plaintext: %v", err)
			continue
		}
		if len(ct) != 16 {
			t.Errorf("Encrypt: expected 16-byte ciphertext, got %d", len(ct))
		}
	}
}

func TestPkcs7RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"single byte", []byte{0x42}},
		{"exact block", bytes.Repeat([]byte{0xAA}, 16)},
		{"multi block", bytes.Repeat([]byte{0xBB}, 31)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			padded, err := pkcs7Pad(tt.data, 16)
			if err != nil {
				t.Fatalf("Pad: %v", err)
			}
			unpadded, err := pkcs7Unpad(padded, 16)
			if err != nil {
				t.Fatalf("Unpad: %v", err)
			}
			if !bytes.Equal(unpadded, tt.data) {
				t.Errorf("round-trip failed")
			}
		})
	}
}
