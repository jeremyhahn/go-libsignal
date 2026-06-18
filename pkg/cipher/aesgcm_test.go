package cipher

import (
	"bytes"
	"errors"
	"testing"
)

// TestAESGCMEncryptDecryptRoundTrip verifies that AESGCMEncrypt and
// AESGCMDecrypt are inverses for a random key/nonce/plaintext.
func TestAESGCMEncryptDecryptRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	nonce := make([]byte, AESGCMNonceSize)
	for i := range nonce {
		nonce[i] = byte(i + 100)
	}
	plaintext := []byte("AES-GCM streaming test")
	aad := []byte("additional data")

	ct, err := AESGCMEncrypt(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("AESGCMEncrypt: %v", err)
	}
	pt, err := AESGCMDecrypt(key, nonce, ct, aad)
	if err != nil {
		t.Fatalf("AESGCMDecrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("round-trip failed: got %q, want %q", pt, plaintext)
	}
}

// TestAESGCMEncryptInvalidKey verifies ErrInvalidKeyLength on short key.
func TestAESGCMEncryptInvalidKey(t *testing.T) {
	nonce := make([]byte, AESGCMNonceSize)
	_, err := AESGCMEncrypt(make([]byte, 16), nonce, nil, nil)
	if !errors.Is(err, &ErrInvalidKeyLength{}) {
		t.Errorf("expected ErrInvalidKeyLength, got %T: %v", err, err)
	}
}

// TestAESGCMDecryptInvalidNonce verifies ErrInvalidNonceLength on bad nonce.
func TestAESGCMDecryptInvalidNonce(t *testing.T) {
	key := make([]byte, 32)
	_, err := AESGCMDecrypt(key, make([]byte, 8), make([]byte, 32), nil)
	if !errors.Is(err, &ErrInvalidNonceLength{}) {
		t.Errorf("expected ErrInvalidNonceLength, got %T: %v", err, err)
	}
}

// TestAESGCMDecryptTooShort verifies ErrCipherCiphertextTooShort on short ciphertext.
func TestAESGCMDecryptTooShort(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, AESGCMNonceSize)
	_, err := AESGCMDecrypt(key, nonce, make([]byte, AESGCMTagSize-1), nil)
	var tooShort *ErrCipherCiphertextTooShort
	if !errors.As(err, &tooShort) {
		t.Errorf("expected ErrCipherCiphertextTooShort, got %T: %v", err, err)
	}
}

// TestAES256GCMEncryption_RoundTrip verifies the streaming encryptor/decryptor
// produce plaintext that matches what was encrypted, and that the tag
// produced by ComputeTag is accepted by VerifyTag.
// Mirrors Rust signal_crypto::Aes256GcmEncryption / Aes256GcmDecryption.
// Rust source: rust/crypto/src/aes_gcm.rs:133-191
func TestAES256GCMEncryption_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	nonce := make([]byte, AESGCMNonceSize)
	for i := range nonce {
		nonce[i] = byte(i + 50)
	}
	aad := []byte("aad bytes")
	plaintext := []byte("hello streaming AES-GCM world!")

	enc, err := NewAES256GCMEncryption(key, nonce, aad)
	if err != nil {
		t.Fatalf("NewAES256GCMEncryption: %v", err)
	}
	enc.Encrypt(plaintext)
	ciphertext, tag, err := enc.ComputeTag()
	if err != nil {
		t.Fatalf("ComputeTag: %v", err)
	}
	if len(tag) != AESGCMTagSize {
		t.Fatalf("tag length = %d, want %d", len(tag), AESGCMTagSize)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Error("ciphertext should differ from plaintext")
	}

	dec, err := NewAES256GCMDecryption(key, nonce, aad)
	if err != nil {
		t.Fatalf("NewAES256GCMDecryption: %v", err)
	}
	dec.Decrypt(ciphertext)
	got, err := dec.VerifyTag(tag[:])
	if err != nil {
		t.Fatalf("VerifyTag: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("decrypted mismatch: got %q, want %q", got, plaintext)
	}
}

// TestAES256GCMEncryption_TagMismatch verifies that VerifyTag returns
// ErrAESGCMAuthFailed when the tag is corrupted.
func TestAES256GCMEncryption_TagMismatch(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, AESGCMNonceSize)
	aad := []byte("aad")
	plaintext := []byte("some plaintext")

	enc, _ := NewAES256GCMEncryption(key, nonce, aad)
	enc.Encrypt(plaintext)
	ciphertext, tag, err := enc.ComputeTag()
	if err != nil {
		t.Fatalf("ComputeTag: %v", err)
	}

	// Corrupt the tag.
	tag[0] ^= 0xFF

	dec, _ := NewAES256GCMDecryption(key, nonce, aad)
	dec.Decrypt(ciphertext)
	_, err = dec.VerifyTag(tag[:])
	var authFailed *ErrAESGCMAuthFailed
	if !errors.As(err, &authFailed) {
		t.Errorf("expected ErrAESGCMAuthFailed, got %T: %v", err, err)
	}
}

// TestAES256GCMEncryption_MatchesOneShot verifies that the streaming API
// produces the same ciphertext as the one-shot AESGCMEncrypt function.
func TestAES256GCMEncryption_MatchesOneShot(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 7)
	}
	nonce := make([]byte, AESGCMNonceSize)
	for i := range nonce {
		nonce[i] = byte(i + 200)
	}
	aad := []byte("some additional data")
	plaintext := []byte("test plaintext for consistency check")

	// One-shot output: ciphertext || tag.
	oneShotOut, err := AESGCMEncrypt(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("AESGCMEncrypt: %v", err)
	}

	// Streaming output.
	enc, err := NewAES256GCMEncryption(key, nonce, aad)
	if err != nil {
		t.Fatalf("NewAES256GCMEncryption: %v", err)
	}
	enc.Encrypt(plaintext)
	streamCT, streamTag, err := enc.ComputeTag()
	if err != nil {
		t.Fatalf("ComputeTag: %v", err)
	}

	// One-shot output is ciphertext || tag.
	oneShotCT := oneShotOut[:len(oneShotOut)-AESGCMTagSize]
	oneShotTag := oneShotOut[len(oneShotOut)-AESGCMTagSize:]

	if !bytes.Equal(streamCT, oneShotCT) {
		t.Error("streaming ciphertext does not match one-shot ciphertext")
	}
	if !bytes.Equal(streamTag[:], oneShotTag) {
		t.Error("streaming tag does not match one-shot tag")
	}
}

// TestNewAES256GCMEncryption_InvalidKey verifies ErrInvalidKeyLength on short key.
func TestNewAES256GCMEncryption_InvalidKey(t *testing.T) {
	nonce := make([]byte, AESGCMNonceSize)
	_, err := NewAES256GCMEncryption(make([]byte, 16), nonce, nil)
	if !errors.Is(err, &ErrInvalidKeyLength{}) {
		t.Errorf("expected ErrInvalidKeyLength, got %T: %v", err, err)
	}
}

// TestNewAES256GCMDecryption_InvalidNonce verifies ErrInvalidNonceLength.
func TestNewAES256GCMDecryption_InvalidNonce(t *testing.T) {
	key := make([]byte, 32)
	_, err := NewAES256GCMDecryption(key, make([]byte, 4), nil)
	if !errors.Is(err, &ErrInvalidNonceLength{}) {
		t.Errorf("expected ErrInvalidNonceLength, got %T: %v", err, err)
	}
}

// TestAES256GCMDecryption_EmptyFeedThenVerify verifies that VerifyTag works
// on an empty message (no calls to Decrypt before VerifyTag).
func TestAES256GCMDecryption_EmptyFeedThenVerify(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, AESGCMNonceSize)

	enc, _ := NewAES256GCMEncryption(key, nonce, nil)
	// No plaintext fed — empty message.
	_, tag, err := enc.ComputeTag()
	if err != nil {
		t.Fatalf("ComputeTag on empty: %v", err)
	}

	dec, _ := NewAES256GCMDecryption(key, nonce, nil)
	// No ciphertext fed — empty message.
	got, err := dec.VerifyTag(tag[:])
	if err != nil {
		t.Fatalf("VerifyTag on empty: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty plaintext, got %d bytes", len(got))
	}
}
