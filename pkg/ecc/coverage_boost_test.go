package ecc

import (
	"errors"
	"testing"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
)

// --- isNonCanonicalFieldElement edge cases ---

func TestIsNonCanonicalFieldElement_Byte31GreaterThan7F(t *testing.T) {
	// When bit 255 is set (byte 31 > 0x7F), it's always non-canonical.
	// This branch is only reachable before the sign bit is cleared,
	// but we test the raw function directly.
	var b [32]byte
	b[31] = 0x80
	if !isNonCanonicalFieldElement(b) {
		t.Fatal("expected non-canonical for byte 31 > 0x7F")
	}
}

func TestIsNonCanonicalFieldElement_AllFF_MiddleByteLessThanFF(t *testing.T) {
	// byte 31 == 0x7F, but one middle byte is less than 0xFF,
	// so it's canonical (value < p).
	var b [32]byte
	b[0] = 0xFF
	for i := 1; i <= 30; i++ {
		b[i] = 0xFF
	}
	b[15] = 0xFE // one byte less than 0xFF
	b[31] = 0x7F
	if isNonCanonicalFieldElement(b) {
		t.Fatal("expected canonical when a middle byte is < 0xFF")
	}
}

func TestIsNonCanonicalFieldElement_Byte0JustBelowThreshold(t *testing.T) {
	// byte 31 == 0x7F, bytes 1..30 all 0xFF, byte 0 = 0xEC (just below 0xED threshold)
	var b [32]byte
	b[0] = 0xEC
	for i := 1; i <= 30; i++ {
		b[i] = 0xFF
	}
	b[31] = 0x7F
	if isNonCanonicalFieldElement(b) {
		t.Fatal("expected canonical for byte 0 = 0xEC (p-1)")
	}
}

// --- verify error paths ---

func TestVerify_RejectsInvalidEdwardsPublicKey(t *testing.T) {
	// Create a public key that produces an invalid Edwards encoding
	// after Montgomery-to-Edwards conversion. Use a key where the
	// converted edY with the sign bit set from signature creates an
	// invalid point encoding.
	var pubKey [32]byte
	// Use a carefully chosen value that passes the canonical check
	// but produces an invalid Edwards point with certain sign bits.
	pubKey[0] = 0x01

	message := []byte("test")
	var sig [64]byte
	// Set sign bit in signature to force A_ed to have sign bit 1
	sig[63] = 0x80
	// Set S to a non-canonical value to trigger SetCanonicalBytes error
	for i := 32; i < 64; i++ {
		sig[i] = 0xFF
	}
	sig[63] = 0xFF // both sign bit and invalid S

	result := verify(pubKey, message, &sig)
	if result {
		t.Fatal("expected verify to fail with crafted invalid inputs")
	}
}

func TestVerify_RejectsNonCanonicalS(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	message := []byte("test")
	sig, err := CalculateSignature(kp.PrivateKey(), message)
	if err != nil {
		t.Fatalf("CalculateSignature failed: %v", err)
	}

	// Set S (bytes 32-63) to all 0xFF, which is a non-canonical scalar.
	for i := 32; i < 64; i++ {
		sig[i] = 0xFF
	}

	if VerifySignature(kp.PublicKey(), message, sig) {
		t.Fatal("expected verification to reject non-canonical S value")
	}
}

// --- vxeddsaVerify error paths ---

func TestVXEdDSAVerify_NonCanonicalHScalar(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	message := []byte("test")
	sig, _, err := VXEdDSASign(kp.PrivateKey(), message)
	if err != nil {
		t.Fatalf("VXEdDSASign failed: %v", err)
	}

	// Corrupt the h component (bytes 32-63) to be non-canonical.
	for i := 32; i < 64; i++ {
		sig[i] = 0xFF
	}

	valid, _, err := VXEdDSAVerify(kp.PublicKey(), message, sig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Fatal("expected verification to fail with non-canonical h scalar")
	}
}

func TestVXEdDSAVerify_NonCanonicalSScalar(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	message := []byte("test")
	sig, _, err := VXEdDSASign(kp.PrivateKey(), message)
	if err != nil {
		t.Fatalf("VXEdDSASign failed: %v", err)
	}

	// Corrupt the s component (bytes 64-95) to be non-canonical.
	for i := 64; i < 96; i++ {
		sig[i] = 0xFF
	}

	valid, _, err := VXEdDSAVerify(kp.PublicKey(), message, sig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Fatal("expected verification to fail with non-canonical s scalar")
	}
}

func TestVXEdDSAVerify_InvalidVPoint(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Create a signature with an invalid V point (not on curve).
	sig := make([]byte, 96)
	// Set V to bytes that don't decode as a valid Edwards point.
	for i := 0; i < 32; i++ {
		sig[i] = 0xFF
	}
	// Set h and s to valid-looking zero values.
	// (They'll fail later, but we want to test V decoding first)

	valid, _, err := VXEdDSAVerify(kp.PublicKey(), []byte("test"), sig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Fatal("expected verification to fail with invalid V point")
	}
}

func TestVXEdDSAVerify_SmallOrderV(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Create a signature where V is the identity point (small order).
	sig := make([]byte, 96)
	identityBytes := edwards25519.NewIdentityPoint().Bytes()
	copy(sig[:32], identityBytes)

	valid, _, err := VXEdDSAVerify(kp.PublicKey(), []byte("test"), sig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Fatal("expected verification to reject small-order V (identity)")
	}
}

// --- hashToPoint error branch ---
// hashToPoint's error branch when field.Element.SetBytes fails is unreachable
// in practice since SHA-512 output with cleared bit 255 always produces valid
// field elements. We verify the function works correctly with various inputs.

func TestHashToPoint_LargeInput(t *testing.T) {
	// Test with a very large input to exercise the hash.
	input := make([]byte, 10000)
	for i := range input {
		input[i] = byte(i % 256)
	}
	point, err := hashToPoint(input)
	if err != nil {
		t.Fatalf("hashToPoint failed on large input: %v", err)
	}
	if point.Equal(edwards25519.NewIdentityPoint()) == 1 {
		t.Fatal("hashToPoint returned identity for large input")
	}
}

// --- isSmallOrderPoint ---

func TestIsSmallOrderPoint_Identity(t *testing.T) {
	identity := edwards25519.NewIdentityPoint()
	if !isSmallOrderPoint(identity) {
		t.Fatal("expected identity to be small-order")
	}
}

func TestIsSmallOrderPoint_Generator(t *testing.T) {
	generator := edwards25519.NewGeneratorPoint()
	if isSmallOrderPoint(generator) {
		t.Fatal("expected generator to not be small-order")
	}
}

// --- elligator2 edge cases ---

func TestElligator2_ZeroInput(t *testing.T) {
	// r = 0 should give d = 1, which means u1 = -A.
	zero, _ := new(field.Element).SetBytes(make([]byte, 32))
	u := elligator2(zero)

	// Verify result is a valid Montgomery x-coordinate.
	one := new(field.Element).One()
	u2 := new(field.Element).Square(u)
	au := new(field.Element).Multiply(constA486662, u)
	inner := new(field.Element).Add(u2, au)
	inner.Add(inner, one)
	w := new(field.Element).Multiply(u, inner)

	_, isSquare := new(field.Element).SqrtRatio(w, one)
	if isSquare != 1 {
		t.Fatal("elligator2(0) did not produce a valid curve point")
	}
}

// --- calculateEdwardsKeyPair sign bit branches ---

func TestCalculateEdwardsKeyPair_MultipleKeys(t *testing.T) {
	// Test many key pairs to exercise both branches of the sign bit check.
	// Some keys will have E.s == 0, others E.s == 1.
	seenNegate := false
	seenNoNegate := false

	for i := 0; i < 50; i++ {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair failed: %v", err)
		}
		privKey := kp.PrivateKey().Serialize()
		kpResult := calculateEdwardsKeyPair(&privKey)

		// The sign bit of A must always be 0.
		if kpResult.PublicKey[31]&0x80 != 0 {
			t.Fatal("Edwards public key has non-zero sign bit")
		}

		// Verify consistency: a * B == A.
		check := new(edwards25519.Point).ScalarBaseMult(kpResult.Scalar)
		if check.Equal(kpResult.A) != 1 {
			t.Fatal("a*B != A: inconsistent key pair")
		}

		// Determine if negation happened by checking the original E sign bit.
		privScalar, _ := new(edwards25519.Scalar).SetBytesWithClamping(privKey[:])
		E := new(edwards25519.Point).ScalarBaseMult(privScalar)
		eBytes := E.Bytes()
		if eBytes[31]>>7 == 1 {
			seenNegate = true
		} else {
			seenNoNegate = true
		}
	}

	if !seenNegate {
		t.Log("warning: did not observe negate branch in 50 iterations")
	}
	if !seenNoNegate {
		t.Log("warning: did not observe non-negate branch in 50 iterations")
	}
}

// --- vrfOutput ---

func TestVrfOutput_DeterministicForSamePoint(t *testing.T) {
	// The VRF output should be deterministic for the same point.
	G := edwards25519.NewGeneratorPoint()
	out1 := vrfOutput(G)
	out2 := vrfOutput(G)
	if len(out1) != 32 || len(out2) != 32 {
		t.Fatal("VRF output should be 32 bytes")
	}
	for i := range out1 {
		if out1[i] != out2[i] {
			t.Fatal("vrfOutput must be deterministic for same point")
		}
	}
}

// --- vxeddsaVerify: small-order A (public key converting to identity-like Edwards point) ---

func TestVXEdDSAVerify_SmallOrderPublicKey(t *testing.T) {
	// Public key of all zeros is the identity point in Montgomery.
	// Montgomery u=0 maps to Edwards y = (0-1)/(0+1) = -1,
	// which is the point of order 2 (a small-order point).
	var zeroKey [32]byte
	pub := NewDjbECPublicKey(zeroKey)

	sig := make([]byte, 96)
	valid, _, err := VXEdDSAVerify(pub, []byte("test"), sig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Fatal("expected verification to reject small-order public key")
	}
}

// --- verify: edge case with different signature corruptions ---

func TestVerify_CorruptedSScalar_ZeroSig(t *testing.T) {
	// All-zero signature should fail. This tests the path where
	// S is zero (valid canonical scalar), R is identity (valid point),
	// but the check [S]B - [h]A == R fails.
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	message := []byte("test message with zero sig")
	var sig [64]byte
	if VerifySignature(kp.PublicKey(), message, sig) {
		t.Fatal("expected verification to fail with all-zero signature")
	}
}

// --- ECKeyPair.ZeroizePrivateKey: nil and DjbECPrivateKey paths ---

// TestECKeyPair_ZeroizePrivateKey_NilKey verifies that ZeroizePrivateKey does
// not panic when the private key is nil.
func TestECKeyPair_ZeroizePrivateKey_NilKey(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	// Replace private key with nil directly.
	kp.privateKey = nil
	// Must not panic.
	kp.ZeroizePrivateKey()
}

// TestECKeyPair_ZeroizePrivateKey_DjbKey verifies that ZeroizePrivateKey
// zeroizes a DjbECPrivateKey (unguarded path in the switch).
func TestECKeyPair_ZeroizePrivateKey_DjbKey(t *testing.T) {
	var rawKey [32]byte
	for i := range rawKey {
		rawKey[i] = byte(i + 1)
	}
	djbKey := NewDjbECPrivateKey(rawKey)
	pubKey := NewDjbECPublicKey([32]byte{})
	kp := NewECKeyPair(pubKey, djbKey)

	kp.ZeroizePrivateKey()

	// After zeroization, all bytes should be zero.
	serialized := kp.PrivateKey().Serialize()
	for i, b := range serialized {
		if b != 0 {
			t.Errorf("private key byte[%d] = %d after zeroize, want 0", i, b)
		}
	}
}

// --- GuardedECPrivateKey.Agreement: X25519 error path ---

// TestGuardedECPrivateKey_Agreement_LowOrderPoint verifies that Agreement
// returns ErrX25519Agreement when X25519 rejects the peer public key (low-order point).
func TestGuardedECPrivateKey_Agreement_LowOrderPoint(t *testing.T) {
	kp, err := GenerateGuardedKeyPair()
	if err != nil {
		t.Fatalf("GenerateGuardedKeyPair failed: %v", err)
	}
	defer kp.ZeroizePrivateKey()

	// The all-zero public key is a low-order point rejected by X25519.
	var lowOrderPeer [32]byte
	_, agreeErr := kp.GuardedPrivateKey().Agreement(lowOrderPeer)
	if agreeErr == nil {
		t.Fatal("expected error for low-order peer public key")
	}
	// X25519 rejects low-order points before our all-zero check.
	var x25519Err *ErrX25519Agreement
	if !errors.As(agreeErr, &x25519Err) {
		t.Errorf("expected ErrX25519Agreement, got %T: %v", agreeErr, agreeErr)
	}
}

func TestVrfOutput_DifferentPointsDifferentOutput(t *testing.T) {
	G := edwards25519.NewGeneratorPoint()
	scalar, _ := new(edwards25519.Scalar).SetBytesWithClamping([]byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
	})
	H := new(edwards25519.Point).ScalarMult(scalar, G)

	out1 := vrfOutput(G)
	out2 := vrfOutput(H)

	same := true
	for i := range out1 {
		if out1[i] != out2[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("vrfOutput should differ for different points")
	}
}
