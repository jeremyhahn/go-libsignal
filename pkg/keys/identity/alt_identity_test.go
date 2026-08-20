//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 10 tests in this file exercise X25519. FIPS 140-3 does not approve that,
// but the X3DH key agreement specification (section 2.1) requires it, so the
// fips140only build tag drops this file from the FIPS gate. `make test` and
// `make coverage` still run it.

package identity

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
)

// generateTestKeyPair creates a random identity key pair for testing.
func generateTestKeyPair(t *testing.T) *KeyPair {
	t.Helper()
	kp, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generateTestKeyPair: %v", err)
	}
	identityKey := NewKey(kp.PublicKey())
	return NewKeyPair(identityKey, kp.PrivateKey())
}

// generateTestKey creates a random identity public key for testing.
func generateTestKey(t *testing.T) *Key {
	t.Helper()
	kp, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generateTestKey: %v", err)
	}
	return NewKey(kp.PublicKey())
}

func TestSignAlternateIdentity_RoundTrip(t *testing.T) {
	signer := generateTestKeyPair(t)
	other := generateTestKey(t)

	sig, err := signer.SignAlternateIdentityRandom(other)
	if err != nil {
		t.Fatalf("SignAlternateIdentityRandom: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("expected 64-byte signature, got %d", len(sig))
	}

	// Verification against the signing key's public key must succeed.
	if err := signer.PublicKey().VerifyAlternateIdentity(other, sig); err != nil {
		t.Errorf("VerifyAlternateIdentity: expected nil, got %v", err)
	}
}

func TestSignAlternateIdentity_ExplicitRandomness(t *testing.T) {
	signer := generateTestKeyPair(t)
	other := generateTestKey(t)

	var randomness [64]byte
	if _, err := rand.Read(randomness[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	sig1, err := signer.SignAlternateIdentity(other, randomness)
	if err != nil {
		t.Fatalf("SignAlternateIdentity: %v", err)
	}
	// Same randomness must produce the same signature (XEdDSA is deterministic given randomness).
	sig2, err := signer.SignAlternateIdentity(other, randomness)
	if err != nil {
		t.Fatalf("SignAlternateIdentity (2nd): %v", err)
	}
	if !bytes.Equal(sig1, sig2) {
		t.Error("identical randomness must produce identical signatures")
	}
}

func TestSignAlternateIdentity_DifferentRandomnessProducesDifferentSigs(t *testing.T) {
	signer := generateTestKeyPair(t)
	other := generateTestKey(t)

	var r1, r2 [64]byte
	if _, err := rand.Read(r1[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	if _, err := rand.Read(r2[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	sig1, _ := signer.SignAlternateIdentity(other, r1)
	sig2, _ := signer.SignAlternateIdentity(other, r2)
	if bytes.Equal(sig1, sig2) {
		t.Error("different randomness should produce different signatures")
	}
}

func TestVerifyAlternateIdentity_NotSymmetric(t *testing.T) {
	// The Rust test explicitly checks this: signing A→B does NOT verify B→A.
	signerKP := generateTestKeyPair(t)
	otherKey := generateTestKey(t)

	sig, err := signerKP.SignAlternateIdentityRandom(otherKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// signer.identity.verify(other, sig) must pass.
	if err := signerKP.PublicKey().VerifyAlternateIdentity(otherKey, sig); err != nil {
		t.Errorf("expected valid: %v", err)
	}

	// But otherKey.verify(signer.identity, sig) must fail (not symmetric).
	if err := otherKey.VerifyAlternateIdentity(signerKP.PublicKey(), sig); err == nil {
		t.Error("expected verification to fail for reversed key order")
	}
}

func TestVerifyAlternateIdentity_WrongSigner(t *testing.T) {
	signer := generateTestKeyPair(t)
	other := generateTestKey(t)
	unrelated := generateTestKey(t)

	sig, err := signer.SignAlternateIdentityRandom(other)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// An unrelated key should not verify a signature from signer.
	if err := unrelated.VerifyAlternateIdentity(other, sig); err == nil {
		t.Error("expected verification to fail for unrelated verifier key")
	}
}

func TestVerifyAlternateIdentity_MismatchedOtherKey(t *testing.T) {
	signer := generateTestKeyPair(t)
	other := generateTestKey(t)
	unrelated := generateTestKey(t)

	sig, err := signer.SignAlternateIdentityRandom(other)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Verifying with a different "other" key must fail.
	if err := signer.PublicKey().VerifyAlternateIdentity(unrelated, sig); err == nil {
		t.Error("expected failure when verifying against wrong other key")
	}
}

func TestVerifyAlternateIdentity_MalformedSignature(t *testing.T) {
	signer := generateTestKeyPair(t)
	other := generateTestKey(t)

	malformed := make([]byte, 64)
	for i := range malformed {
		malformed[i] = 0xAA
	}

	err := signer.PublicKey().VerifyAlternateIdentity(other, malformed)
	if err == nil {
		t.Error("expected error for malformed signature")
	}
	if !errors.Is(err, ErrAltIdentityVerificationFailed) {
		t.Errorf("expected ErrAltIdentityVerificationFailed, got %v", err)
	}
}

func TestVerifyAlternateIdentity_WrongLength(t *testing.T) {
	signer := generateTestKeyPair(t)
	other := generateTestKey(t)

	// Too short
	err := signer.PublicKey().VerifyAlternateIdentity(other, make([]byte, 32))
	if err == nil {
		t.Error("expected error for 32-byte signature")
	}
	var lenErr *ErrAltIdentityInvalidSignatureLength
	if !errors.As(err, &lenErr) {
		t.Errorf("expected ErrAltIdentityInvalidSignatureLength, got %T: %v", err, err)
	}
	if lenErr.Got != 32 {
		t.Errorf("expected Got=32, got Got=%d", lenErr.Got)
	}

	// Too long
	err = signer.PublicKey().VerifyAlternateIdentity(other, make([]byte, 65))
	if err == nil {
		t.Error("expected error for 65-byte signature")
	}

	// Zero length
	err = signer.PublicKey().VerifyAlternateIdentity(other, nil)
	if err == nil {
		t.Error("expected error for nil signature")
	}
}

func TestSignAlternateIdentity_NilOtherKey(t *testing.T) {
	signer := generateTestKeyPair(t)
	var randomness [64]byte
	_, err := signer.SignAlternateIdentity(nil, randomness)
	if err == nil {
		t.Error("expected error for nil other key")
	}
	if !errors.Is(err, ErrNilOtherKey) {
		t.Errorf("expected ErrNilOtherKey, got %v", err)
	}
}

func TestVerifyAlternateIdentity_NilOtherKey(t *testing.T) {
	signer := generateTestKeyPair(t)
	err := signer.PublicKey().VerifyAlternateIdentity(nil, make([]byte, 64))
	if err == nil {
		t.Error("expected error for nil other key")
	}
	if !errors.Is(err, ErrNilOtherKey) {
		t.Errorf("expected ErrNilOtherKey, got %v", err)
	}
}

func TestAltIdentityMessage_PrefixContent(t *testing.T) {
	// Verify the DST prefix bytes are exactly [0xFF]*32 || "Signal_PNI_Signature".
	for i, b := range alternateIdentityPrefix1 {
		if b != 0xFF {
			t.Errorf("prefix1[%d] = 0x%02x, want 0xFF", i, b)
		}
	}
	if len(alternateIdentityPrefix1) != 32 {
		t.Errorf("prefix1 length = %d, want 32", len(alternateIdentityPrefix1))
	}
	if string(alternateIdentityPrefix2) != "Signal_PNI_Signature" {
		t.Errorf("prefix2 = %q, want %q", alternateIdentityPrefix2, "Signal_PNI_Signature")
	}
}

func TestBuildAltIdentityMessage_Length(t *testing.T) {
	// Construct a fixed key directly so the assertion below covers the
	// exact serialized layout buildAltIdentityMessage produces:
	//   prefix1 (32) || prefix2 (20) || [0x05 || pub(32)] (33) = 85 bytes
	var pubBytes [32]byte
	pubBytes[0] = 0x42
	key := NewKey(ecc.NewDjbECPublicKey(pubBytes))
	msg := buildAltIdentityMessage(key)
	const wantLen = 32 + 20 + 33
	if len(msg) != wantLen {
		t.Errorf("message length = %d, want %d", len(msg), wantLen)
	}
	// First 32 bytes must all be 0xFF.
	for i := 0; i < 32; i++ {
		if msg[i] != 0xFF {
			t.Errorf("msg[%d] = 0x%02x, want 0xFF", i, msg[i])
		}
	}
	// Bytes 32-51 must be "Signal_PNI_Signature".
	if string(msg[32:52]) != "Signal_PNI_Signature" {
		t.Errorf("DST label = %q, want %q", msg[32:52], "Signal_PNI_Signature")
	}
	// Byte 52 must be 0x05 (DjbType).
	if msg[52] != ecc.DjbType {
		t.Errorf("type byte = 0x%02x, want 0x%02x", msg[52], ecc.DjbType)
	}
}
