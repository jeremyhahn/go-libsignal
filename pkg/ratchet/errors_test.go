package ratchet

import (
	"errors"
	"testing"
)

// TestErrMissingKyberPreKeyError_Error verifies the error message for the
// missing Kyber pre-key typed error, exercised via errors.As.
func TestErrMissingKyberPreKeyError_Error(t *testing.T) {
	err := &ErrMissingKyberPreKeyError{}
	msg := err.Error()
	if msg == "" {
		t.Fatal("Error() should return a non-empty string")
	}
	if !containsRatchetString(msg, "Kyber") {
		t.Errorf("error message should mention Kyber, got: %s", msg)
	}
}

// TestErrMissingKyberPreKeyError_ErrorsAs verifies errors.As matches
// the concrete type through the sentinel variable.
func TestErrMissingKyberPreKeyError_ErrorsAs(t *testing.T) {
	var target *ErrMissingKyberPreKeyError
	if !errors.As(ErrMissingKyberPreKey, &target) {
		t.Fatal("errors.As should match ErrMissingKyberPreKeyError via sentinel")
	}
}

// TestErrMissingKyberCiphertextError_Error verifies the error message for the
// missing Kyber ciphertext typed error.
func TestErrMissingKyberCiphertextError_Error(t *testing.T) {
	err := &ErrMissingKyberCiphertextError{}
	msg := err.Error()
	if msg == "" {
		t.Fatal("Error() should return a non-empty string")
	}
	if !containsRatchetString(msg, "ciphertext") {
		t.Errorf("error message should mention ciphertext, got: %s", msg)
	}
}

// TestErrMissingKyberCiphertextError_ErrorsAs verifies errors.As matches
// the concrete type through the sentinel variable.
func TestErrMissingKyberCiphertextError_ErrorsAs(t *testing.T) {
	var target *ErrMissingKyberCiphertextError
	if !errors.As(ErrMissingKyberCiphertext, &target) {
		t.Fatal("errors.As should match ErrMissingKyberCiphertextError via sentinel")
	}
}

// TestErrNonCanonicalBaseKeyError_Error verifies the error message for the
// non-canonical base key typed error.
func TestErrNonCanonicalBaseKeyError_Error(t *testing.T) {
	err := &ErrNonCanonicalBaseKeyError{}
	msg := err.Error()
	if msg == "" {
		t.Fatal("Error() should return a non-empty string")
	}
	if !containsRatchetString(msg, "canonical") {
		t.Errorf("error message should mention canonical, got: %s", msg)
	}
}

// TestErrNonCanonicalBaseKeyError_ErrorsAs verifies errors.As matches
// the concrete type through the sentinel variable.
func TestErrNonCanonicalBaseKeyError_ErrorsAs(t *testing.T) {
	var target *ErrNonCanonicalBaseKeyError
	if !errors.As(ErrNonCanonicalBaseKey, &target) {
		t.Fatal("errors.As should match ErrNonCanonicalBaseKeyError via sentinel")
	}
}

// TestErrNilBaseKeyError_Error verifies the error message for the nil
// base key typed error.
func TestErrNilBaseKeyError_Error(t *testing.T) {
	err := &ErrNilBaseKeyError{}
	msg := err.Error()
	if msg == "" {
		t.Fatal("Error() should return a non-empty string")
	}
	if !containsRatchetString(msg, "nil") {
		t.Errorf("error message should mention nil, got: %s", msg)
	}
}

// TestErrNilBaseKeyError_ErrorsAs verifies errors.As matches
// the concrete type through the sentinel variable.
func TestErrNilBaseKeyError_ErrorsAs(t *testing.T) {
	var target *ErrNilBaseKeyError
	if !errors.As(ErrNilBaseKey, &target) {
		t.Fatal("errors.As should match ErrNilBaseKeyError via sentinel")
	}
}

// TestCalculateReceiverSession_NilBaseKey verifies that a nil TheirBaseKey
// returns ErrNilBaseKey without panicking.
func TestCalculateReceiverSession_NilBaseKey(t *testing.T) {
	ourIdentity := genIDKeyPair(t)
	ourSignedPreKey := genKP(t)
	ourRatchetKey := genKP(t)
	theirIdentity := genIDKeyPair(t)

	params := NewReceiverParameters(
		ourIdentity,
		ourSignedPreKey,
		nil,
		ourRatchetKey,
		nil, // TheirBaseKey is nil
		theirIdentity.PublicKey(),
	)

	_, err := CalculateReceiverSession(params)
	if err == nil {
		t.Fatal("expected error for nil TheirBaseKey")
	}
	if err != ErrNilBaseKey {
		t.Fatalf("expected ErrNilBaseKey, got: %v", err)
	}
}

// TestCalculateReceiverSession_MissingKyberCiphertext verifies that
// CalculateReceiverSession returns ErrMissingKyberCiphertext when the Kyber
// ciphertext is nil but the pre-key pair is set.
func TestCalculateReceiverSession_MissingKyberCiphertext(t *testing.T) {
	ourIdentity := genIDKeyPair(t)
	ourSignedPreKey := genKP(t)
	ourRatchetKey := genKP(t)
	theirIdentity := genIDKeyPair(t)
	theirBaseKey := genKP(t)

	kyberKP := genGuardedKyberKP(t)

	params := NewReceiverParameters(
		ourIdentity,
		ourSignedPreKey,
		nil,
		ourRatchetKey,
		theirBaseKey.PublicKey(),
		theirIdentity.PublicKey(),
	)
	// Set the Kyber pre-key pair but leave the ciphertext nil.
	params.SetOurKyberPreKeyPair(kyberKP)
	// TheirKyberCiphertext is intentionally not set.

	_, err := CalculateReceiverSession(params)
	if err == nil {
		t.Fatal("expected ErrMissingKyberCiphertext when ciphertext is nil")
	}
	if err != ErrMissingKyberCiphertext {
		t.Fatalf("expected ErrMissingKyberCiphertext, got: %v", err)
	}
}

// containsRatchetString is a test helper to check for substring presence.
func containsRatchetString(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
