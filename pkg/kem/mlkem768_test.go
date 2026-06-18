package kem

import (
	"bytes"
	"errors"
	"testing"
)

func TestNewMLKEM768KEM(t *testing.T) {
	k := NewMLKEM768KEM()
	if k == nil {
		t.Fatal("NewMLKEM768KEM() returned nil")
	}
}

func TestMLKEM768KEMKeyType(t *testing.T) {
	k := NewMLKEM768KEM()
	if k.KeyType() != KeyTypeMLKEM768 {
		t.Errorf("KeyType() = 0x%02x, want 0x%02x", k.KeyType(), KeyTypeMLKEM768)
	}
}

func TestMLKEM768KEMKeySizes(t *testing.T) {
	k := NewMLKEM768KEM()

	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	// NIST FIPS 203 ML-KEM-768 key sizes: pk=1184, sk seed=64, ct=1088.
	pkData := kp.Public.Data()
	if len(pkData) != 1184 {
		t.Errorf("public key size = %d, want 1184 (ML-KEM-768)", len(pkData))
	}

	skData := kp.Secret.Data()
	if len(skData) != 64 {
		t.Errorf("secret key size = %d, want 64 (ML-KEM-768 seed, FIPS 203)", len(skData))
	}

	ss, ct, err := k.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}
	_ = ss

	ctData := ct.Data()
	if len(ctData) != 1088 {
		t.Errorf("ciphertext size = %d, want 1088 (ML-KEM-768)", len(ctData))
	}
}

func TestMLKEM768KEMGenerate(t *testing.T) {
	k := NewMLKEM768KEM()

	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	if kp.Public == nil {
		t.Fatal("Generate() returned nil public key")
	}
	if kp.Secret == nil {
		t.Fatal("Generate() returned nil secret key")
	}
	if kp.Public.Type() != KeyTypeMLKEM768 {
		t.Errorf("public key type = 0x%02x, want 0x%02x", kp.Public.Type(), KeyTypeMLKEM768)
	}
	if kp.Secret.Type() != KeyTypeMLKEM768 {
		t.Errorf("secret key type = 0x%02x, want 0x%02x", kp.Secret.Type(), KeyTypeMLKEM768)
	}
}

func TestMLKEM768KEMGenerateUniqueness(t *testing.T) {
	k := NewMLKEM768KEM()

	kp1, err := k.Generate()
	if err != nil {
		t.Fatalf("first Generate() error: %v", err)
	}
	kp2, err := k.Generate()
	if err != nil {
		t.Fatalf("second Generate() error: %v", err)
	}

	if bytes.Equal(kp1.Public.Data(), kp2.Public.Data()) {
		t.Error("two generated key pairs should have different public keys")
	}
}

func TestMLKEM768KEMEncapsulateDecapsulateRoundTrip(t *testing.T) {
	k := NewMLKEM768KEM()

	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	ss, ct, err := k.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}
	if ct.Type() != KeyTypeMLKEM768 {
		t.Errorf("ciphertext type = 0x%02x, want 0x%02x", ct.Type(), KeyTypeMLKEM768)
	}

	ss2, err := k.Decapsulate(kp.Secret, ct)
	if err != nil {
		t.Fatalf("Decapsulate() error: %v", err)
	}

	if *ss != *ss2 {
		t.Error("shared secrets from Encapsulate and Decapsulate should match")
	}

	// Shared secret should not be all zeros.
	allZero := true
	for _, b := range ss[:] {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("shared secret should not be all zeros")
	}
}

func TestMLKEM768KEMEncapsulateWrongKeyType(t *testing.T) {
	k := NewMLKEM768KEM()
	pk := NewPublicKey(KeyTypeKyber1024, make([]byte, 32))

	_, _, err := k.Encapsulate(pk)
	if err == nil {
		t.Fatal("Encapsulate with wrong key type should return error")
	}
	var typeMismatch *KeyTypeMismatchError
	if !errors.As(err, &typeMismatch) {
		t.Errorf("expected KeyTypeMismatchError, got: %v", err)
	}
}

func TestMLKEM768KEMDecapsulateWrongSecretKeyType(t *testing.T) {
	k := NewMLKEM768KEM()

	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	_, ct, err := k.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	wrongSKData := make([]byte, 3168)
	wrongSK, skErr := NewSecretKey(KeyTypeKyber1024, wrongSKData)
	if skErr != nil {
		t.Fatalf("NewSecretKey() error: %v", skErr)
	}

	_, err = k.Decapsulate(wrongSK, ct)
	if err == nil {
		t.Fatal("Decapsulate with wrong secret key type should return error")
	}
	var typeMismatch *KeyTypeMismatchError
	if !errors.As(err, &typeMismatch) {
		t.Errorf("expected KeyTypeMismatchError, got: %v", err)
	}
}

func TestMLKEM768KEMDecapsulateWrongCiphertextType(t *testing.T) {
	k := NewMLKEM768KEM()

	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	_, ct, err := k.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	wrongCT := NewCiphertext(KeyTypeKyber1024, ct.Data())
	_, err = k.Decapsulate(kp.Secret, wrongCT)
	if err == nil {
		t.Fatal("Decapsulate with wrong ciphertext type should return error")
	}
	var typeMismatch *KeyTypeMismatchError
	if !errors.As(err, &typeMismatch) {
		t.Errorf("expected KeyTypeMismatchError, got: %v", err)
	}
}

func TestMLKEM768KEMPublicKeySerializeRoundTrip(t *testing.T) {
	k := NewMLKEM768KEM()
	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	serialized := kp.Public.Serialize()
	pk2, err := DeserializePublicKey(serialized)
	if err != nil {
		t.Fatalf("DeserializePublicKey() error: %v", err)
	}
	if pk2.Type() != KeyTypeMLKEM768 {
		t.Errorf("deserialized key type = 0x%02x, want 0x%02x", pk2.Type(), KeyTypeMLKEM768)
	}
	if !bytes.Equal(pk2.Data(), kp.Public.Data()) {
		t.Error("deserialized public key data does not match original")
	}
}
