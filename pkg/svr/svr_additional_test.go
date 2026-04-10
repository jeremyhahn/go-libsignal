package svr

import (
	"bytes"
	gocipher "crypto/cipher"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/cipher"
)

func newTestAEAD(key []byte) (gocipher.AEAD, error) {
	return cipher.NewAESGCMSIV(key)
}

func TestDecryptSecretShortCiphertext(t *testing.T) {
	var key [32]byte
	// AES-GCM-SIV ciphertext for 32 bytes should be 32 + 16 (tag) = 48 bytes
	_, err := DecryptSecret(key, make([]byte, 10))
	if err == nil {
		t.Fatal("expected error for short ciphertext")
	}
}

func TestDecryptSecretWrongSize(t *testing.T) {
	// Encrypt a 16-byte value using the raw GCM-SIV cipher, then try DecryptSecret
	// which expects exactly 32 bytes of plaintext.
	var key [32]byte
	copy(key[:], bytes.Repeat([]byte{0xAA}, 32))

	// Create a valid ciphertext for a 16-byte plaintext (not 32)
	aead, err := newTestAEAD(key[:])
	if err != nil {
		t.Fatalf("create cipher: %v", err)
	}
	nonce := make([]byte, aead.NonceSize())
	shortPlaintext := make([]byte, 16)
	ciphertext := aead.Seal(nil, nonce, shortPlaintext, nil)

	_, err = DecryptSecret(key, ciphertext)
	if err == nil {
		t.Fatal("expected error for wrong plaintext size")
	}
}

func TestEncryptDecryptDeterministic(t *testing.T) {
	var key [32]byte
	copy(key[:], bytes.Repeat([]byte{0x11}, 32))
	var secret Secret
	copy(secret[:], bytes.Repeat([]byte{0x22}, 32))

	// Encrypt twice with same key should produce same ciphertext (GCM-SIV with zero nonce)
	ct1, err := EncryptSecret(key, secret)
	if err != nil {
		t.Fatalf("first EncryptSecret: %v", err)
	}
	ct2, err := EncryptSecret(key, secret)
	if err != nil {
		t.Fatalf("second EncryptSecret: %v", err)
	}
	if !bytes.Equal(ct1, ct2) {
		t.Error("deterministic encryption should produce identical ciphertext")
	}
}

func TestMasterKeyDifferentPINSameSecret(t *testing.T) {
	var secret Secret
	k1, _ := MasterKey("pin1", secret)
	k2, _ := MasterKey("pin2", secret)
	if k1 == k2 {
		t.Error("different PINs should produce different keys")
	}
}

func TestDeriveStorageKeyEmptySlice(t *testing.T) {
	_, err := DeriveStorageKey([]byte{})
	if err == nil {
		t.Fatal("expected error for empty byte slice")
	}
}

func TestNewBackup4Fields(t *testing.T) {
	var secret Secret
	for i := range secret {
		secret[i] = byte(i)
	}
	b, err := NewBackup4(secret, 5)
	if err != nil {
		t.Fatalf("NewBackup4: %v", err)
	}
	if b.MaxTries != 5 {
		t.Errorf("MaxTries = %d, want 5", b.MaxTries)
	}
	if b.Secret != secret {
		t.Error("Secret mismatch")
	}
	if len(b.RequestID) != requestIDSize {
		t.Errorf("RequestID length = %d, want %d", len(b.RequestID), requestIDSize)
	}
	if len(b.Entropy) != entropySize {
		t.Errorf("Entropy length = %d, want %d", len(b.Entropy), entropySize)
	}
}
