package kem

import (
	"bytes"
	"errors"
	"testing"
)

func TestNewGuardedKyber1024(t *testing.T) {
	g := NewGuardedKyber1024()
	if g == nil {
		t.Fatal("NewGuardedKyber1024() returned nil")
	}
}

func TestGuardedKyber1024Generate(t *testing.T) {
	g := NewGuardedKyber1024()

	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	defer kp.Destroy()

	if kp.Public == nil {
		t.Fatal("Generate() returned nil public key")
	}
	if kp.Secret == nil {
		t.Fatal("Generate() returned nil secret key")
	}
	if kp.Public.Type() != KeyTypeKyber1024 {
		t.Errorf("public key type = 0x%02x, want 0x%02x", kp.Public.Type(), KeyTypeKyber1024)
	}
	if kp.Secret.Type() != KeyTypeKyber1024 {
		t.Errorf("secret key type = 0x%02x, want 0x%02x", kp.Secret.Type(), KeyTypeKyber1024)
	}
	if len(kp.Public.Data()) == 0 {
		t.Error("public key data should not be empty")
	}
	if kp.Secret.IsDestroyed() {
		t.Error("secret key should not be destroyed after generation")
	}
}

func TestGuardedKyber1024GenerateUniqueness(t *testing.T) {
	g := NewGuardedKyber1024()

	kp1, err := g.Generate()
	if err != nil {
		t.Fatalf("first Generate() error: %v", err)
	}
	defer kp1.Destroy()

	kp2, err := g.Generate()
	if err != nil {
		t.Fatalf("second Generate() error: %v", err)
	}
	defer kp2.Destroy()

	if bytes.Equal(kp1.Public.Data(), kp2.Public.Data()) {
		t.Error("two generated key pairs should have different public keys")
	}
}

func TestGuardedKyber1024EncapsulateDecapsulateRoundTrip(t *testing.T) {
	g := NewGuardedKyber1024()

	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	defer kp.Destroy()

	ss, ct, err := g.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}
	defer ss.Destroy()

	if ct == nil {
		t.Fatal("Encapsulate() returned nil ciphertext")
	}
	if ct.Type() != KeyTypeKyber1024 {
		t.Errorf("ciphertext type = 0x%02x, want 0x%02x", ct.Type(), KeyTypeKyber1024)
	}
	if ss.IsDestroyed() {
		t.Fatal("shared secret should not be destroyed after encapsulation")
	}

	ssBytes := ss.Bytes()
	if len(ssBytes) != 32 {
		t.Errorf("shared secret length = %d, want 32", len(ssBytes))
	}

	// Verify shared secret is not all zeros.
	allZero := true
	for _, b := range ssBytes {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("shared secret should not be all zeros")
	}

	// Decapsulate and verify match.
	ss2, err := g.Decapsulate(kp.Secret, ct)
	if err != nil {
		t.Fatalf("Decapsulate() error: %v", err)
	}
	defer ss2.Destroy()

	if !bytes.Equal(ss.Bytes(), ss2.Bytes()) {
		t.Error("shared secrets from Encapsulate and Decapsulate should match")
	}
}

func TestGuardedKyber1024EncapsulateWrongKeyType(t *testing.T) {
	g := NewGuardedKyber1024()

	pk := NewPublicKey(KeyTypeKyber768, make([]byte, 32))
	_, _, err := g.Encapsulate(pk)
	if err == nil {
		t.Fatal("Encapsulate with wrong key type should return error")
	}
	var typeMismatch *KeyTypeMismatchError
	if !errors.As(err, &typeMismatch) {
		t.Errorf("expected KeyTypeMismatchError, got: %v", err)
	}
}

func TestGuardedKyber1024EncapsulateInvalidPublicKey(t *testing.T) {
	g := NewGuardedKyber1024()

	pk := NewPublicKey(KeyTypeKyber1024, []byte{0x01, 0x02})
	_, _, err := g.Encapsulate(pk)
	if err == nil {
		t.Fatal("Encapsulate with invalid public key data should return error")
	}
}

func TestGuardedKyber1024DecapsulateWrongSecretKeyType(t *testing.T) {
	g := NewGuardedKyber1024()

	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	defer kp.Destroy()

	_, ct, err := g.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	// Copy data out of guarded memory before creating a new guarded key,
	// because NewGuardedSecretKey zeroizes the source slice via memguard.
	skData := kp.Secret.Data()
	skCopy := make([]byte, len(skData))
	copy(skCopy, skData)

	wrongSK, err := NewGuardedSecretKey(KeyTypeKyber768, skCopy)
	if err != nil {
		t.Fatalf("NewGuardedSecretKey() error: %v", err)
	}
	defer wrongSK.Destroy()

	_, err = g.Decapsulate(wrongSK, ct)
	if err == nil {
		t.Fatal("Decapsulate with wrong secret key type should return error")
	}
	var typeMismatch *KeyTypeMismatchError
	if !errors.As(err, &typeMismatch) {
		t.Errorf("expected KeyTypeMismatchError, got: %v", err)
	}
}

func TestGuardedKyber1024DecapsulateWrongCiphertextType(t *testing.T) {
	g := NewGuardedKyber1024()

	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	defer kp.Destroy()

	_, ct, err := g.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	wrongCT := NewCiphertext(KeyTypeKyber768, ct.Data())
	_, err = g.Decapsulate(kp.Secret, wrongCT)
	if err == nil {
		t.Fatal("Decapsulate with wrong ciphertext type should return error")
	}
	var typeMismatch *KeyTypeMismatchError
	if !errors.As(err, &typeMismatch) {
		t.Errorf("expected KeyTypeMismatchError, got: %v", err)
	}
}

func TestGuardedKyber1024DecapsulateDestroyedKey(t *testing.T) {
	g := NewGuardedKyber1024()

	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	_, ct, err := g.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	kp.Secret.Destroy()

	_, err = g.Decapsulate(kp.Secret, ct)
	if err == nil {
		t.Fatal("Decapsulate with destroyed key should return error")
	}
	var destroyed *GuardedKeyDestroyedError
	if !errors.As(err, &destroyed) {
		t.Errorf("expected GuardedKeyDestroyedError, got: %v", err)
	}
}

func TestGuardedKyber1024DecapsulateInvalidSecretKey(t *testing.T) {
	g := NewGuardedKyber1024()

	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	defer kp.Destroy()

	_, ct, err := g.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	badSK, err := NewGuardedSecretKey(KeyTypeKyber1024, []byte{0x01, 0x02})
	if err != nil {
		t.Fatalf("NewGuardedSecretKey() error: %v", err)
	}
	defer badSK.Destroy()

	_, err = g.Decapsulate(badSK, ct)
	if err == nil {
		t.Fatal("Decapsulate with invalid secret key data should return error")
	}
}

func TestGuardedKyber1024EncapsulateMultipleTimes(t *testing.T) {
	g := NewGuardedKyber1024()

	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	defer kp.Destroy()

	ss1, ct1, err := g.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("first Encapsulate() error: %v", err)
	}
	defer ss1.Destroy()

	ss2, ct2, err := g.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("second Encapsulate() error: %v", err)
	}
	defer ss2.Destroy()

	if bytes.Equal(ss1.Bytes(), ss2.Bytes()) {
		t.Error("multiple encapsulations should produce different shared secrets")
	}
	if bytes.Equal(ct1.Data(), ct2.Data()) {
		t.Error("multiple encapsulations should produce different ciphertexts")
	}

	// Both should decapsulate correctly.
	dss1, err := g.Decapsulate(kp.Secret, ct1)
	if err != nil {
		t.Fatalf("first Decapsulate() error: %v", err)
	}
	defer dss1.Destroy()

	if !bytes.Equal(dss1.Bytes(), ss1.Bytes()) {
		t.Error("first decapsulated secret does not match encapsulated")
	}

	dss2, err := g.Decapsulate(kp.Secret, ct2)
	if err != nil {
		t.Fatalf("second Decapsulate() error: %v", err)
	}
	defer dss2.Destroy()

	if !bytes.Equal(dss2.Bytes(), ss2.Bytes()) {
		t.Error("second decapsulated secret does not match encapsulated")
	}
}

func TestGuardedSecretKeyDecapsulate(t *testing.T) {
	g := NewGuardedKyber1024()

	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	defer kp.Destroy()

	ss, ct, err := g.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}
	defer ss.Destroy()

	serializedCT := ct.Serialize()

	// Use the keyops.Decapsulator interface method.
	s32, err := kp.Secret.Decapsulate(serializedCT)
	if err != nil {
		t.Fatalf("GuardedSecretKey.Decapsulate() error: %v", err)
	}
	defer s32.Destroy()

	if !bytes.Equal(s32.Bytes(), ss.Bytes()) {
		t.Error("decapsulated shared secret should match encapsulated")
	}
}

func TestGuardedSecretKeyDecapsulateDestroyedKey(t *testing.T) {
	g := NewGuardedKyber1024()

	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	_, ct, err := g.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	kp.Secret.Destroy()

	_, err = kp.Secret.Decapsulate(ct.Serialize())
	if err == nil {
		t.Fatal("Decapsulate on destroyed key should return error")
	}
	var destroyed *GuardedKeyDestroyedError
	if !errors.As(err, &destroyed) {
		t.Errorf("expected GuardedKeyDestroyedError, got: %v", err)
	}
}

func TestGuardedSecretKeyDecapsulateInvalidCiphertext(t *testing.T) {
	g := NewGuardedKyber1024()

	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	defer kp.Destroy()

	// Empty ciphertext.
	_, err = kp.Secret.Decapsulate([]byte{})
	if err == nil {
		t.Fatal("Decapsulate with empty ciphertext should return error")
	}

	// Single byte ciphertext (too short).
	_, err = kp.Secret.Decapsulate([]byte{0x08})
	if err == nil {
		t.Fatal("Decapsulate with single-byte ciphertext should return error")
	}

	// Invalid key type prefix.
	_, err = kp.Secret.Decapsulate([]byte{0xFF, 0x01, 0x02})
	if err == nil {
		t.Fatal("Decapsulate with invalid key type should return error")
	}
}

func TestGuardedSecretKeyDecapsulateGuarded(t *testing.T) {
	g := NewGuardedKyber1024()

	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	defer kp.Destroy()

	ss, ct, err := g.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}
	defer ss.Destroy()

	gss, err := kp.Secret.DecapsulateGuarded(ct.Serialize())
	if err != nil {
		t.Fatalf("DecapsulateGuarded() error: %v", err)
	}
	defer gss.Destroy()

	if !bytes.Equal(gss.Bytes(), ss.Bytes()) {
		t.Error("DecapsulateGuarded shared secret should match Encapsulate result")
	}
}

func TestGuardedSecretKeyDecapsulateGuardedDestroyed(t *testing.T) {
	g := NewGuardedKyber1024()

	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	_, ct, err := g.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	kp.Secret.Destroy()

	_, err = kp.Secret.DecapsulateGuarded(ct.Serialize())
	if err == nil {
		t.Fatal("DecapsulateGuarded on destroyed key should return error")
	}
	var destroyed *GuardedKeyDestroyedError
	if !errors.As(err, &destroyed) {
		t.Errorf("expected GuardedKeyDestroyedError, got: %v", err)
	}
}

func TestZeroizeSlice(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	zeroizeSlice(data)

	for i, b := range data {
		if b != 0 {
			t.Errorf("byte at index %d = 0x%02x, want 0x00", i, b)
		}
	}
}

func TestZeroizeSliceEmpty(t *testing.T) {
	data := []byte{}
	// Should not panic on empty slice.
	zeroizeSlice(data)
}
