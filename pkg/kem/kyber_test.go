package kem

import (
	"bytes"
	"errors"
	"testing"
)

func TestNewKyber1024KEM(t *testing.T) {
	k := NewKyber1024KEM()
	if k == nil {
		t.Fatal("NewKyber1024KEM() returned nil")
	}
}

func TestKyber1024KEMKeyType(t *testing.T) {
	k := NewKyber1024KEM()
	if k.KeyType() != KeyTypeKyber1024 {
		t.Errorf("KeyType() = 0x%02x, want 0x%02x", k.KeyType(), KeyTypeKyber1024)
	}
}

func TestKyber1024KEMGenerate(t *testing.T) {
	k := NewKyber1024KEM()

	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	if kp == nil {
		t.Fatal("Generate() returned nil key pair")
	}
	if kp.Public == nil {
		t.Fatal("Generate() returned nil public key")
	}
	if kp.Secret == nil {
		t.Fatal("Generate() returned nil secret key")
	}
	if kp.Public.Type() != KeyTypeKyber1024 {
		t.Errorf("Public key type = 0x%02x, want 0x%02x", kp.Public.Type(), KeyTypeKyber1024)
	}
	if kp.Secret.Type() != KeyTypeKyber1024 {
		t.Errorf("Secret key type = 0x%02x, want 0x%02x", kp.Secret.Type(), KeyTypeKyber1024)
	}
	if len(kp.Public.Data()) == 0 {
		t.Error("Public key data should not be empty")
	}
	if len(kp.Secret.Data()) == 0 {
		t.Error("Secret key data should not be empty")
	}
}

func TestKyber1024KEMGenerateUniqueness(t *testing.T) {
	k := NewKyber1024KEM()

	kp1, err := k.Generate()
	if err != nil {
		t.Fatalf("First Generate() error: %v", err)
	}
	kp2, err := k.Generate()
	if err != nil {
		t.Fatalf("Second Generate() error: %v", err)
	}

	if bytes.Equal(kp1.Public.Data(), kp2.Public.Data()) {
		t.Error("Two generated key pairs should have different public keys")
	}
	if bytes.Equal(kp1.Secret.Data(), kp2.Secret.Data()) {
		t.Error("Two generated key pairs should have different secret keys")
	}
}

func TestKyber1024KEMEncapsulateDecapsulateRoundTrip(t *testing.T) {
	k := NewKyber1024KEM()

	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	// Encapsulate
	ss, ct, err := k.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}
	if ss == nil {
		t.Fatal("Encapsulate() returned nil shared secret")
	}
	if ct == nil {
		t.Fatal("Encapsulate() returned nil ciphertext")
	}
	if ct.Type() != KeyTypeKyber1024 {
		t.Errorf("Ciphertext type = 0x%02x, want 0x%02x", ct.Type(), KeyTypeKyber1024)
	}

	// Decapsulate
	ss2, err := k.Decapsulate(kp.Secret, ct)
	if err != nil {
		t.Fatalf("Decapsulate() error: %v", err)
	}
	if ss2 == nil {
		t.Fatal("Decapsulate() returned nil shared secret")
	}

	// Shared secrets should match
	if *ss != *ss2 {
		t.Error("Shared secrets from Encapsulate and Decapsulate should match")
	}
}

func TestKyber1024KEMEncapsulateMultipleTimes(t *testing.T) {
	k := NewKyber1024KEM()

	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	// Multiple encapsulations with same public key should yield different shared secrets
	ss1, ct1, err := k.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("First Encapsulate() error: %v", err)
	}
	ss2, ct2, err := k.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Second Encapsulate() error: %v", err)
	}

	if *ss1 == *ss2 {
		t.Error("Multiple encapsulations should produce different shared secrets")
	}
	if bytes.Equal(ct1.Data(), ct2.Data()) {
		t.Error("Multiple encapsulations should produce different ciphertexts")
	}

	// Both should still decapsulate correctly
	dss1, err := k.Decapsulate(kp.Secret, ct1)
	if err != nil {
		t.Fatalf("First Decapsulate() error: %v", err)
	}
	if *dss1 != *ss1 {
		t.Error("First decapsulated secret does not match encapsulated")
	}

	dss2, err := k.Decapsulate(kp.Secret, ct2)
	if err != nil {
		t.Fatalf("Second Decapsulate() error: %v", err)
	}
	if *dss2 != *ss2 {
		t.Error("Second decapsulated secret does not match encapsulated")
	}
}

func TestKyber1024KEMEncapsulateWrongKeyType(t *testing.T) {
	k := NewKyber1024KEM()

	// Create a public key with wrong type
	pk := NewPublicKey(KeyTypeKyber768, make([]byte, 32))

	_, _, err := k.Encapsulate(pk)
	if err == nil {
		t.Fatal("Encapsulate with wrong key type should return error")
	}
	var typeMismatch *KeyTypeMismatchError
	if !errors.As(err, &typeMismatch) {
		t.Errorf("expected KeyTypeMismatchError, got: %v", err)
	}
}

func TestKyber1024KEMEncapsulateInvalidPublicKey(t *testing.T) {
	k := NewKyber1024KEM()

	// Create a public key with correct type but invalid data
	pk := NewPublicKey(KeyTypeKyber1024, []byte{0x01, 0x02})

	_, _, err := k.Encapsulate(pk)
	if err == nil {
		t.Fatal("Encapsulate with invalid public key data should return error")
	}
}

func TestKyber1024KEMDecapsulateWrongSecretKeyType(t *testing.T) {
	k := NewKyber1024KEM()

	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	_, ct, err := k.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	// Use wrong key type for secret key — create with correct size for Kyber768 (2400)
	wrongSKData := make([]byte, 2400)
	copy(wrongSKData, kp.Secret.Data())
	wrongSK, skErr := NewSecretKey(KeyTypeKyber768, wrongSKData)
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

func TestKyber1024KEMDecapsulateWrongCiphertextType(t *testing.T) {
	k := NewKyber1024KEM()

	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	_, ct, err := k.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	// Use wrong key type for ciphertext
	wrongCT := NewCiphertext(KeyTypeKyber768, ct.Data())
	_, err = k.Decapsulate(kp.Secret, wrongCT)
	if err == nil {
		t.Fatal("Decapsulate with wrong ciphertext type should return error")
	}
	var typeMismatch *KeyTypeMismatchError
	if !errors.As(err, &typeMismatch) {
		t.Errorf("expected KeyTypeMismatchError, got: %v", err)
	}
}

func TestKyber1024KEMDecapsulateInvalidSecretKey(t *testing.T) {
	k := NewKyber1024KEM()

	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	_, ct, err := k.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	// Use invalid secret key data — NewSecretKey now validates size,
	// so we expect an error from NewSecretKey itself.
	_, badErr := NewSecretKey(KeyTypeKyber1024, []byte{0x01, 0x02})
	if badErr == nil {
		t.Fatal("NewSecretKey with invalid data size should return error")
	}

	// Suppress unused variable warning for ct.
	_ = ct
}

func TestKyber1024KEMDecapsulateWrongKey(t *testing.T) {
	k := NewKyber1024KEM()

	// Generate two key pairs
	kp1, err := k.Generate()
	if err != nil {
		t.Fatalf("First Generate() error: %v", err)
	}
	kp2, err := k.Generate()
	if err != nil {
		t.Fatalf("Second Generate() error: %v", err)
	}

	// Encapsulate with kp1's public key
	ss1, ct, err := k.Encapsulate(kp1.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	// Decapsulate with kp2's secret key (wrong key)
	ss2, err := k.Decapsulate(kp2.Secret, ct)
	if err != nil {
		// Some KEM implementations may not error here but produce wrong secret
		t.Logf("Decapsulate with wrong key returned error: %v", err)
		return
	}

	// The shared secrets should not match
	if *ss1 == *ss2 {
		t.Error("Decapsulating with wrong secret key should yield different shared secret")
	}
}

func TestKyber1024KEMSharedSecretSize(t *testing.T) {
	k := NewKyber1024KEM()
	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	ss, _, err := k.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	if *ss == (SharedSecret{}) {
		t.Error("Encapsulate() returned all-zero shared secret")
	}
}
