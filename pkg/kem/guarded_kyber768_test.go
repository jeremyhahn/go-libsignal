package kem

import (
	"bytes"
	"errors"
	"testing"
)

func TestNewGuardedKyber768(t *testing.T) {
	g := NewGuardedKyber768()
	if g == nil {
		t.Fatal("NewGuardedKyber768() returned nil")
	}
}

func TestGuardedKyber768Generate(t *testing.T) {
	g := NewGuardedKyber768()

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
	if kp.Public.Type() != KeyTypeKyber768 {
		t.Errorf("public key type = 0x%02x, want 0x%02x", kp.Public.Type(), KeyTypeKyber768)
	}
	if kp.Secret.Type() != KeyTypeKyber768 {
		t.Errorf("secret key type = 0x%02x, want 0x%02x", kp.Secret.Type(), KeyTypeKyber768)
	}

	// Verify round-3 Kyber-768 key sizes.
	if len(kp.Public.Data()) != 1184 {
		t.Errorf("public key size = %d, want 1184", len(kp.Public.Data()))
	}
}

func TestGuardedKyber768GenerateUniqueness(t *testing.T) {
	g := NewGuardedKyber768()

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

func TestGuardedKyber768EncapsulateDecapsulateRoundTrip(t *testing.T) {
	g := NewGuardedKyber768()

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

	if ct.Type() != KeyTypeKyber768 {
		t.Errorf("ciphertext type = 0x%02x, want 0x%02x", ct.Type(), KeyTypeKyber768)
	}
	if len(ct.Data()) != 1088 {
		t.Errorf("ciphertext size = %d, want 1088", len(ct.Data()))
	}

	ss2, err := g.Decapsulate(kp.Secret, ct)
	if err != nil {
		t.Fatalf("Decapsulate() error: %v", err)
	}
	defer ss2.Destroy()

	if !bytes.Equal(ss.Bytes(), ss2.Bytes()) {
		t.Error("shared secrets from Encapsulate and Decapsulate should match")
	}
}

func TestGuardedKyber768EncapsulateWrongKeyType(t *testing.T) {
	g := NewGuardedKyber768()

	pk := NewPublicKey(KeyTypeKyber1024, make([]byte, 32))
	_, _, err := g.Encapsulate(pk)
	if err == nil {
		t.Fatal("Encapsulate with wrong key type should return error")
	}
	var typeMismatch *KeyTypeMismatchError
	if !errors.As(err, &typeMismatch) {
		t.Errorf("expected KeyTypeMismatchError, got: %v", err)
	}
}

func TestGuardedKyber768DecapsulateDestroyedKey(t *testing.T) {
	g := NewGuardedKyber768()

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

func TestGuardedKyber768DecapsulateWrongSecretKeyType(t *testing.T) {
	g := NewGuardedKyber768()

	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	defer kp.Destroy()

	_, ct, err := g.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	// Create a Kyber1024 guarded secret key with copied data.
	skData := kp.Secret.Data()
	skCopy := make([]byte, len(skData))
	copy(skCopy, skData)

	wrongSK, err := NewGuardedSecretKey(KeyTypeKyber1024, skCopy)
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

func TestGuardedKyber768DecapsulateWrongCiphertextType(t *testing.T) {
	g := NewGuardedKyber768()

	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	defer kp.Destroy()

	_, ct, err := g.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	wrongCT := NewCiphertext(KeyTypeKyber1024, ct.Data())
	_, err = g.Decapsulate(kp.Secret, wrongCT)
	if err == nil {
		t.Fatal("Decapsulate with wrong ciphertext type should return error")
	}
	var typeMismatch *KeyTypeMismatchError
	if !errors.As(err, &typeMismatch) {
		t.Errorf("expected KeyTypeMismatchError, got: %v", err)
	}
}

// TestDecapsulateGuardedDispatchKyber768 verifies that GuardedSecretKey.DecapsulateGuarded
// correctly dispatches to GuardedKyber768 when the key type is KeyTypeKyber768.
func TestDecapsulateGuardedDispatchKyber768(t *testing.T) {
	g := NewGuardedKyber768()

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

	// Use the DecapsulateGuarded method on GuardedSecretKey (dispatch path).
	gss, err := kp.Secret.DecapsulateGuarded(ct.Serialize())
	if err != nil {
		t.Fatalf("DecapsulateGuarded() error: %v", err)
	}
	defer gss.Destroy()

	if !bytes.Equal(gss.Bytes(), ss.Bytes()) {
		t.Error("DecapsulateGuarded shared secret should match Encapsulate result")
	}
}

// TestDecapsulateGuardedDispatchKyber1024 verifies that GuardedSecretKey.DecapsulateGuarded
// still correctly dispatches to GuardedKyber1024 for Kyber1024 keys.
func TestDecapsulateGuardedDispatchKyber1024(t *testing.T) {
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

// TestDecapsulateGuardedUnsupportedKeyType verifies that DecapsulateGuarded returns
// an UnsupportedKeyTypeError for key types without a guarded implementation.
func TestDecapsulateGuardedUnsupportedKeyType(t *testing.T) {
	// Create a guarded secret key with MLKEM1024 type. There is no GuardedMLKEM1024
	// implementation, so DecapsulateGuarded should return UnsupportedKeyTypeError.
	// We need valid-length key data for the MLKEM1024 type (3168 bytes).
	skData := make([]byte, 3168)
	gsk, err := NewGuardedSecretKey(KeyTypeMLKEM1024, skData)
	if err != nil {
		t.Fatalf("NewGuardedSecretKey() error: %v", err)
	}
	defer gsk.Destroy()

	// Create a serialized ciphertext with MLKEM1024 type prefix (1568 bytes data).
	ctData := make([]byte, 1+1568)
	ctData[0] = byte(KeyTypeMLKEM1024)

	_, err = gsk.DecapsulateGuarded(ctData)
	if err == nil {
		t.Fatal("DecapsulateGuarded with unsupported key type should return error")
	}

	var unsupported *UnsupportedKeyTypeError
	if !errors.As(err, &unsupported) {
		t.Errorf("expected UnsupportedKeyTypeError, got %T: %v", err, err)
	}
	if unsupported != nil && unsupported.KeyType != KeyTypeMLKEM1024 {
		t.Errorf("UnsupportedKeyTypeError.KeyType = 0x%02x, want 0x%02x", unsupported.KeyType, KeyTypeMLKEM1024)
	}
}

// TestDecapsulateGuardedDestroyedKeyKyber768 verifies that DecapsulateGuarded
// returns ErrGuardedKeyDestroyed for a destroyed Kyber768 key.
func TestDecapsulateGuardedDestroyedKeyKyber768(t *testing.T) {
	g := NewGuardedKyber768()

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

func TestUnsupportedKeyTypeErrorMessage(t *testing.T) {
	err := &UnsupportedKeyTypeError{KeyType: KeyType(0xFF)}
	msg := err.Error()
	if msg == "" {
		t.Fatal("UnsupportedKeyTypeError.Error() should not be empty")
	}
	if !bytes.Contains([]byte(msg), []byte("0xff")) {
		t.Errorf("error message should contain key type hex, got: %s", msg)
	}
}

func TestUnsupportedKeyTypeErrorMessageKnownType(t *testing.T) {
	err := &UnsupportedKeyTypeError{KeyType: KeyTypeMLKEM1024}
	msg := err.Error()
	if msg == "" {
		t.Fatal("UnsupportedKeyTypeError.Error() should not be empty")
	}
	if !bytes.Contains([]byte(msg), []byte("unsupported")) {
		t.Errorf("error message should contain 'unsupported', got: %s", msg)
	}
}

// TestDecapsulateInterfaceKyber768 verifies the keyops.Decapsulator interface
// method on GuardedSecretKey works for Kyber768 keys.
func TestDecapsulateInterfaceKyber768(t *testing.T) {
	g := NewGuardedKyber768()

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

	// Use the Decapsulate method (keyops.Decapsulator interface).
	s32, err := kp.Secret.Decapsulate(ct.Serialize())
	if err != nil {
		t.Fatalf("Decapsulate() error: %v", err)
	}
	defer s32.Destroy()

	if !bytes.Equal(s32.Bytes(), ss.Bytes()) {
		t.Error("Decapsulate shared secret should match Encapsulate result")
	}
}
