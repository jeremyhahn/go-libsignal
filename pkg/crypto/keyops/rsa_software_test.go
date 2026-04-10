package keyops

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"testing"
)

// Compile-time interface satisfaction check.
var _ RSASigner = (*SoftwareRSASigner)(nil)

func TestSoftwareRSASigner_ImplementsInterface(t *testing.T) {
	// This test exists to document the compile-time check above.
	// If SoftwareRSASigner does not implement RSASigner, compilation fails.
}

func TestNewSoftwareRSASigner_HappyPath(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	signer, err := NewSoftwareRSASigner(key)
	if err != nil {
		t.Fatalf("NewSoftwareRSASigner: %v", err)
	}
	if signer == nil {
		t.Fatal("expected non-nil signer")
	}

	pub := signer.Public()
	if pub == nil {
		t.Fatal("Public() returned nil")
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("Public() returned %T, want *rsa.PublicKey", pub)
	}
	if rsaPub.N.Cmp(key.N) != 0 {
		t.Fatal("public key modulus mismatch")
	}
}

func TestNewSoftwareRSASigner_NilKey(t *testing.T) {
	signer, err := NewSoftwareRSASigner(nil)
	if err == nil {
		t.Fatal("expected error for nil key, got nil")
	}
	if signer != nil {
		t.Fatal("expected nil signer for nil key")
	}
	if !errors.Is(err, ErrKeyDestroyed) {
		t.Fatalf("expected ErrKeyDestroyed, got %v", err)
	}
}

func TestSoftwareRSASigner_Sign(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	signer, err := NewSoftwareRSASigner(key)
	if err != nil {
		t.Fatalf("NewSoftwareRSASigner: %v", err)
	}

	message := []byte("test message for signing")
	hash := sha256.Sum256(message)

	sig, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("expected non-empty signature")
	}

	// Verify the signature using the public key.
	pub := signer.Public().(*rsa.PublicKey)
	err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], sig)
	if err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}
}

func TestSoftwareRSASigner_SignAfterDestroy(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	signer, err := NewSoftwareRSASigner(key)
	if err != nil {
		t.Fatalf("NewSoftwareRSASigner: %v", err)
	}

	signer.Destroy()

	hash := sha256.Sum256([]byte("after destroy"))
	_, err = signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err == nil {
		t.Fatal("expected error after destroy, got nil")
	}
	if !errors.Is(err, ErrKeyDestroyed) {
		t.Fatalf("expected ErrKeyDestroyed, got %v", err)
	}
}

func TestSoftwareRSASigner_PublicAfterDestroy(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	signer, err := NewSoftwareRSASigner(key)
	if err != nil {
		t.Fatalf("NewSoftwareRSASigner: %v", err)
	}

	signer.Destroy()

	pub := signer.Public()
	if pub != nil {
		t.Fatalf("expected nil public key after destroy, got %v", pub)
	}
}

func TestSoftwareRSASigner_DestroyIdempotent(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	signer, err := NewSoftwareRSASigner(key)
	if err != nil {
		t.Fatalf("NewSoftwareRSASigner: %v", err)
	}

	// Multiple Destroy calls must not panic.
	signer.Destroy()
	signer.Destroy()
	signer.Destroy()

	// Confirm the signer is still in destroyed state.
	pub := signer.Public()
	if pub != nil {
		t.Fatal("expected nil public key after multiple destroys")
	}
}
