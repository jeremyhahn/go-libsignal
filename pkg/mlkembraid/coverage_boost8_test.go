package mlkembraid

import (
	"testing"

	imlkem "github.com/jeremyhahn/go-libsignal/pkg/mlkembraid/internal/incremental_mlkem768"
)

// ================== verifyEkVector error paths ==================

// TestVerifyEkVectorIncrementalFailure verifies that verifyEkVector returns
// ErrHeaderFormat when IncrementalVerifyEKVector fails (pk2 does not match pk1).
// This exercises state.go:1028-1030, the IncrementalVerifyEKVector error branch.
func TestVerifyEkVectorIncrementalFailure(t *testing.T) {
	// Use IncrementalMLKEM768KEM to generate a valid 64-byte pk1.
	kemImpl := NewIncrementalMLKEM768KEM()
	_, pk1, pk2, err := kemImpl.KeyGen()
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}
	if len(pk1) != imlkem.PublicKey1Size {
		t.Fatalf("expected pk1 len %d, got %d", imlkem.PublicKey1Size, len(pk1))
	}

	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt pk2 so ValidatePKBytes fails.
	corruptPk2 := make([]byte, len(pk2))
	copy(corruptPk2, pk2)
	for i := range corruptPk2 {
		corruptPk2[i] ^= 0xFF
	}

	state := &State{
		kind:      StateCt1Sampled,
		epoch:     2,
		auth:      auth,
		bobEkSeed: mustSecret(t, pk1),
		bobHek:    mustEmptySecret(t, 32),
	}

	err = state.verifyEkVector(corruptPk2)
	if err == nil {
		t.Fatal("expected ErrHeaderFormat for invalid incremental ek_vector")
	}
	if _, ok := err.(*ErrHeaderFormat); !ok {
		t.Errorf("expected *ErrHeaderFormat, got %T: %v", err, err)
	}
}

// TestVerifyEkVectorLegacyMismatch verifies that verifyEkVector returns
// ErrHeaderFormat when the legacy SHA3-256 hek check fails.
// This exercises state.go:1034-1036, the legacy mismatch path.
func TestVerifyEkVectorLegacyMismatch(t *testing.T) {
	// Use MLKEM768IncrementalKEM (legacy) to generate a 32-byte ekSeed.
	kemImpl := NewMLKEM768IncrementalKEM()
	_, ekSeed, ekVector, err := kemImpl.KeyGen()
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}
	if len(ekSeed) == imlkem.PublicKey1Size {
		t.Fatalf("expected legacy 32-byte ekSeed, got %d bytes", len(ekSeed))
	}

	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}

	// Set bobHek to all-zeros (wrong value) to trigger the mismatch.
	state := &State{
		kind:      StateCt1Sampled,
		epoch:     2,
		auth:      auth,
		bobEkSeed: mustSecret(t, ekSeed),
		bobHek:    mustEmptySecret(t, 32), // wrong hek (all zeros)
	}

	err = state.verifyEkVector(ekVector)
	if err == nil {
		t.Fatal("expected ErrHeaderFormat for mismatched legacy hek")
	}
	if _, ok := err.(*ErrHeaderFormat); !ok {
		t.Errorf("expected *ErrHeaderFormat, got %T: %v", err, err)
	}
}

// TestVerifyEkVectorLegacySuccess verifies that verifyEkVector returns nil
// when the legacy SHA3-256 hek check passes.
// This exercises state.go:1034-1038, the legacy success path.
func TestVerifyEkVectorLegacySuccess(t *testing.T) {
	// Use MLKEM768IncrementalKEM (legacy) to generate a 32-byte ekSeed.
	kemImpl := NewMLKEM768IncrementalKEM()
	_, ekSeed, ekVector, err := kemImpl.KeyGen()
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	// Compute the correct hek using the same function as the implementation.
	hek := computeHEK(ekSeed, ekVector)

	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:      StateCt1Sampled,
		epoch:     2,
		auth:      auth,
		bobEkSeed: mustSecret(t, ekSeed),
		bobHek:    mustSecret(t, hek),
	}

	err = state.verifyEkVector(ekVector)
	if err != nil {
		t.Fatalf("verifyEkVector legacy success failed: %v", err)
	}
}
