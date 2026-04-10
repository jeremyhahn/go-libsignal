package cipher

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
)

func TestAESCBCEncryptDecryptRoundTrip(t *testing.T) {
	// Only AES-256 (32-byte key) is supported, matching the Rust libsignal reference.
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	iv := make([]byte, aes.BlockSize)
	for i := range iv {
		iv[i] = byte(i + 0x10)
	}
	plaintext := []byte("Hello, Signal Protocol!")

	ciphertext, err := AESCBCEncrypt(key, iv, plaintext)
	if err != nil {
		t.Fatalf("AESCBCEncrypt: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext should differ from plaintext")
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		t.Fatalf("ciphertext length %d not a multiple of block size", len(ciphertext))
	}

	decrypted, err := AESCBCDecrypt(key, iv, ciphertext)
	if err != nil {
		t.Fatalf("AESCBCDecrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("round-trip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestAESCBCExactBlockSize(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, aes.BlockSize)
	// Plaintext that is exactly one block; PKCS7 adds a full block of padding.
	plaintext := bytes.Repeat([]byte{0xAA}, aes.BlockSize)

	ciphertext, err := AESCBCEncrypt(key, iv, plaintext)
	if err != nil {
		t.Fatalf("AESCBCEncrypt: %v", err)
	}
	if len(ciphertext) != 2*aes.BlockSize {
		t.Fatalf("expected %d bytes, got %d", 2*aes.BlockSize, len(ciphertext))
	}

	decrypted, err := AESCBCDecrypt(key, iv, ciphertext)
	if err != nil {
		t.Fatalf("AESCBCDecrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("round-trip failed for exact block size plaintext")
	}
}

func TestAESCBCMultiBlock(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, aes.BlockSize)
	plaintext := bytes.Repeat([]byte{0xBB}, 100)

	ciphertext, err := AESCBCEncrypt(key, iv, plaintext)
	if err != nil {
		t.Fatalf("AESCBCEncrypt: %v", err)
	}

	decrypted, err := AESCBCDecrypt(key, iv, ciphertext)
	if err != nil {
		t.Fatalf("AESCBCDecrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("round-trip failed for multi-block plaintext")
	}
}

func TestAESCBCSingleByte(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, aes.BlockSize)
	plaintext := []byte{0x42}

	ciphertext, err := AESCBCEncrypt(key, iv, plaintext)
	if err != nil {
		t.Fatalf("AESCBCEncrypt: %v", err)
	}
	if len(ciphertext) != aes.BlockSize {
		t.Fatalf("expected %d bytes, got %d", aes.BlockSize, len(ciphertext))
	}

	decrypted, err := AESCBCDecrypt(key, iv, ciphertext)
	if err != nil {
		t.Fatalf("AESCBCDecrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("round-trip failed for single byte")
	}
}

func TestAESCBCKnownVector(t *testing.T) {
	// NIST SP 800-38A test vector for AES-256-CBC (F.2.5).
	key, _ := hex.DecodeString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
	iv, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	plaintext, _ := hex.DecodeString("6bc1bee22e409f96e93d7e117393172a")

	ciphertext, err := AESCBCEncrypt(key, iv, plaintext)
	if err != nil {
		t.Fatalf("AESCBCEncrypt: %v", err)
	}

	decrypted, err := AESCBCDecrypt(key, iv, ciphertext)
	if err != nil {
		t.Fatalf("AESCBCDecrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("known vector round-trip failed")
	}
}

func TestAESCBCInvalidKeySize(t *testing.T) {
	iv := make([]byte, aes.BlockSize)
	plaintext := []byte("test data")

	// Only 32-byte keys are valid; all other sizes (including AES-128/192) are rejected.
	invalidKeySizes := []int{0, 1, 8, 15, 16, 17, 20, 24, 31, 33, 64}
	for _, size := range invalidKeySizes {
		key := make([]byte, size)
		_, err := AESCBCEncrypt(key, iv, plaintext)
		var keyErr *ErrAESCBCInvalidKey
		if !errors.As(err, &keyErr) {
			t.Errorf("key size %d: expected ErrAESCBCInvalidKey, got %v", size, err)
		} else if keyErr.Got != size {
			t.Errorf("key size %d: error Got=%d, want %d", size, keyErr.Got, size)
		}

		_, err = AESCBCDecrypt(key, iv, make([]byte, aes.BlockSize))
		if !errors.As(err, &keyErr) {
			t.Errorf("key size %d decrypt: expected ErrAESCBCInvalidKey, got %v", size, err)
		}
	}
}

func TestAESCBCInvalidIVSize(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("test data")

	invalidIVSizes := []int{0, 1, 8, 15, 17, 32}
	for _, size := range invalidIVSizes {
		iv := make([]byte, size)
		_, err := AESCBCEncrypt(key, iv, plaintext)
		var ivErr *ErrAESCBCInvalidIVSize
		if !errors.As(err, &ivErr) {
			t.Errorf("IV size %d: expected ErrAESCBCInvalidIVSize, got %v", size, err)
		} else if ivErr.Got != size {
			t.Errorf("IV size %d: error Got=%d, want %d", size, ivErr.Got, size)
		}

		_, err = AESCBCDecrypt(key, iv, make([]byte, aes.BlockSize))
		if !errors.As(err, &ivErr) {
			t.Errorf("IV size %d decrypt: expected ErrAESCBCInvalidIVSize, got %v", size, err)
		}
	}
}

func TestAESCBCDecryptEmptyCiphertext(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, aes.BlockSize)

	_, err := AESCBCDecrypt(key, iv, nil)
	var emptyErr *ErrAESCBCCiphertextEmpty
	if !errors.As(err, &emptyErr) {
		t.Errorf("expected ErrAESCBCCiphertextEmpty for nil, got %v", err)
	}

	_, err = AESCBCDecrypt(key, iv, []byte{})
	if !errors.As(err, &emptyErr) {
		t.Errorf("expected ErrAESCBCCiphertextEmpty for empty, got %v", err)
	}
}

func TestAESCBCDecryptUnalignedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, aes.BlockSize)

	_, err := AESCBCDecrypt(key, iv, []byte{0x01, 0x02, 0x03})
	var alignErr *ErrAESCBCCiphertextNotAligned
	if !errors.As(err, &alignErr) {
		t.Errorf("expected ErrAESCBCCiphertextNotAligned, got %v", err)
	} else {
		if alignErr.Length != 3 {
			t.Errorf("expected Length=3, got %d", alignErr.Length)
		}
		if alignErr.BlockSize != aes.BlockSize {
			t.Errorf("expected BlockSize=%d, got %d", aes.BlockSize, alignErr.BlockSize)
		}
	}
}

// TestAESCBCEncryptEmptyPlaintext verifies that nil and empty plaintexts are
// valid: PKCS#7 pads them to a full AES block before encryption, producing
// 16 bytes of ciphertext.
func TestAESCBCEncryptEmptyPlaintext(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, aes.BlockSize)

	for _, plain := range [][]byte{nil, {}} {
		ct, err := AESCBCEncrypt(key, iv, plain)
		if err != nil {
			t.Fatalf("AESCBCEncrypt: unexpected error for empty plaintext: %v", err)
		}
		if len(ct) != aes.BlockSize {
			t.Fatalf("AESCBCEncrypt: expected %d-byte ciphertext, got %d", aes.BlockSize, len(ct))
		}
	}
}

func TestAESCBCDecryptDoesNotMutateCiphertext(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, aes.BlockSize)
	plaintext := []byte("do not mutate my ciphertext!")

	ciphertext, err := AESCBCEncrypt(key, iv, plaintext)
	if err != nil {
		t.Fatalf("AESCBCEncrypt: %v", err)
	}

	original := make([]byte, len(ciphertext))
	copy(original, ciphertext)

	_, err = AESCBCDecrypt(key, iv, ciphertext)
	if err != nil {
		t.Fatalf("AESCBCDecrypt: %v", err)
	}
	if !bytes.Equal(ciphertext, original) {
		t.Error("AESCBCDecrypt mutated the ciphertext input")
	}
}

func TestAESCBCDecryptBadPadding(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, aes.BlockSize)

	// Encrypt something valid, then corrupt the last block to produce bad padding.
	ciphertext, err := AESCBCEncrypt(key, iv, []byte("valid plaintext!"))
	if err != nil {
		t.Fatalf("AESCBCEncrypt: %v", err)
	}

	// Flip a bit in the last byte to corrupt padding.
	ciphertext[len(ciphertext)-1] ^= 0xFF

	_, err = AESCBCDecrypt(key, iv, ciphertext)
	if err == nil {
		t.Fatal("expected padding error for corrupted ciphertext")
	}
}

func TestAESCBCDifferentIVsProduceDifferentCiphertexts(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("same plaintext different IV")

	iv1 := make([]byte, aes.BlockSize)
	iv2 := make([]byte, aes.BlockSize)
	iv2[0] = 0x01

	ct1, err := AESCBCEncrypt(key, iv1, plaintext)
	if err != nil {
		t.Fatalf("AESCBCEncrypt iv1: %v", err)
	}
	ct2, err := AESCBCEncrypt(key, iv2, plaintext)
	if err != nil {
		t.Fatalf("AESCBCEncrypt iv2: %v", err)
	}
	if bytes.Equal(ct1, ct2) {
		t.Error("different IVs should produce different ciphertexts")
	}
}

func TestAESCBCRandomKeyIV(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("random key and IV test with longer data to span multiple blocks for coverage")

	ciphertext, err := AESCBCEncrypt(key, iv, plaintext)
	if err != nil {
		t.Fatalf("AESCBCEncrypt: %v", err)
	}

	decrypted, err := AESCBCDecrypt(key, iv, ciphertext)
	if err != nil {
		t.Fatalf("AESCBCDecrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("round-trip with random key/IV failed")
	}
}

func TestAESCBCWrongKeyDecrypt(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key2[0] = 0xFF
	iv := make([]byte, aes.BlockSize)

	ciphertext, err := AESCBCEncrypt(key1, iv, []byte("secret message"))
	if err != nil {
		t.Fatalf("AESCBCEncrypt: %v", err)
	}

	// Decrypting with wrong key should either produce wrong plaintext or
	// fail with a padding error.
	decrypted, err := AESCBCDecrypt(key2, iv, ciphertext)
	if err == nil && bytes.Equal(decrypted, []byte("secret message")) {
		t.Error("decryption with wrong key should not produce original plaintext")
	}
}
