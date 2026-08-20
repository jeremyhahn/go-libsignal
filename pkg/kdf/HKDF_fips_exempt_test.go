//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// CalculateSharedSecret is the X3DH/Double Ratchet DH function: X25519 over
// Curve25519, mandated by the X3DH specification section 2.1. Extract's RFC
// 5869 Test Case 1 vector fixes a 13-byte salt, which HKDF uses as the HMAC
// key. crypto/ecdh rejects X25519 and crypto/hmac rejects keys shorter than
// 112 bits under GODEBUG=fips140=only, so these tests are excluded from the
// FIPS gate by the fips140only build tag. Everything else in this package
// stays gated.

package kdf

import (
	"bytes"
	"testing"
)

func TestCalculateSharedSecret_Deterministic(t *testing.T) {
	var theirKey, ourKey [32]byte
	theirKey[0] = 9 // Curve25519 base point
	ourKey[0] = 1

	s1, err := CalculateSharedSecret(theirKey, ourKey)
	if err != nil {
		t.Fatalf("first CalculateSharedSecret failed: %v", err)
	}
	// Reset keys since they get zeroized
	theirKey[0] = 9
	ourKey[0] = 1
	s2, err := CalculateSharedSecret(theirKey, ourKey)
	if err != nil {
		t.Fatalf("second CalculateSharedSecret failed: %v", err)
	}
	if s1 != s2 {
		t.Fatal("same inputs should produce same shared secret")
	}
}

func TestCalculateSharedSecret_DifferentKeysProduceDifferentSecrets(t *testing.T) {
	var their1, their2, our [32]byte
	their1[0] = 9
	their2[0] = 10
	our[0] = 1

	s1, err := CalculateSharedSecret(their1, our)
	if err != nil {
		t.Fatalf("first CalculateSharedSecret failed: %v", err)
	}
	our[0] = 1
	s2, err := CalculateSharedSecret(their2, our)
	if err != nil {
		t.Fatalf("second CalculateSharedSecret failed: %v", err)
	}
	if s1 == s2 {
		t.Fatal("different keys should produce different shared secrets")
	}
}

// TestExtract_RFC5869_TC1 verifies Extract against RFC 5869 Test Case 1.
// Extract(ikm, salt) == HMAC-SHA256(salt, ikm) per RFC 5869 §2.2.
// Finding #7 fix: mirrors Rust Hkdf::<Sha256>::extract(salt, ikm).
// Rust source: rust/crypto/src/hpke/provider.rs:55
func TestExtract_RFC5869_TC1(t *testing.T) {
	ikm := mustDecodeHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt := mustDecodeHex("000102030405060708090a0b0c")
	// Expected PRK from RFC 5869 Appendix A.1.
	expectedPRK := mustDecodeHex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")

	prk := Extract(ikm, salt)
	if len(prk) != 32 {
		t.Fatalf("Extract returned %d bytes, want 32", len(prk))
	}
	if !bytes.Equal(prk, expectedPRK) {
		t.Errorf("PRK mismatch\n  got  %x\n  want %x", prk, expectedPRK)
	}
}
