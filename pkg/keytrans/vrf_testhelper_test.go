package keytrans

import (
	"crypto/sha512"
	"testing"

	"filippo.io/edwards25519"
)

// testVRFKeyPair generates a VRF key pair for testing.
// Returns the public key and private scalar.
func testVRFKeyPair(t *testing.T) (*VRFPublicKey, *edwards25519.Scalar) {
	t.Helper()

	// Use a deterministic private key for reproducibility.
	seed := make([]byte, 32)
	seed[0] = 0x42
	// The edwards25519 private scalar is derived from the seed via SHA-512
	// per RFC 8032 Section 5.1.5.
	h := sha512.Sum512(seed)
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64

	sk, err := new(edwards25519.Scalar).SetBytesWithClamping(h[:32])
	if err != nil {
		t.Fatalf("failed to create scalar: %v", err)
	}

	// Compute pk = [sk]B
	pkPoint := new(edwards25519.Point).ScalarBaseMult(sk)
	var pkBytes [32]byte
	copy(pkBytes[:], pkPoint.Bytes())

	vrfPk, err := NewVRFPublicKey(pkBytes)
	if err != nil {
		t.Fatalf("failed to create VRF public key: %v", err)
	}

	return vrfPk, sk
}

// testVRFProve generates a VRF proof for the given message using the private scalar.
// Implements ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381 Section 5.1).
func testVRFProve(t *testing.T, pk *VRFPublicKey, sk *edwards25519.Scalar, msg []byte) []byte {
	t.Helper()

	// H = encode_to_curve_try_and_increment(pk, msg)
	h, err := encodeToCurveTryAndIncrement(pk.compressed[:], msg)
	if err != nil {
		t.Fatalf("encodeToCurveTryAndIncrement failed: %v", err)
	}

	// Gamma = [sk]H
	gamma := new(edwards25519.Point).ScalarMult(sk, h)

	// Generate nonce k using RFC 6979-like deterministic nonce.
	// For testing: k = SHA512(sk || H) mod L
	nonceHash := sha512.New()
	nonceHash.Write(sk.Bytes())
	nonceHash.Write(h.Bytes())
	nonceBytes := nonceHash.Sum(nil)

	k, err := new(edwards25519.Scalar).SetUniformBytes(nonceBytes)
	if err != nil {
		t.Fatalf("failed to create nonce scalar: %v", err)
	}

	// U = [k]B
	u := new(edwards25519.Point).ScalarBaseMult(k)

	// V = [k]H
	v := new(edwards25519.Point).ScalarMult(k, h)

	// c = generate_challenge(pk, H, Gamma, U, V)
	var hCompressed, gammaCompressed, uCompressed, vCompressed [32]byte
	copy(hCompressed[:], h.Bytes())
	copy(gammaCompressed[:], gamma.Bytes())
	copy(uCompressed[:], u.Bytes())
	copy(vCompressed[:], v.Bytes())

	c := generateChallenge([5]*[32]byte{
		&pk.compressed,
		&hCompressed,
		&gammaCompressed,
		&uCompressed,
		&vCompressed,
	})

	// c as full scalar
	var cFullBytes [32]byte
	copy(cFullBytes[:16], c[:])
	cScalar, err := new(edwards25519.Scalar).SetCanonicalBytes(cFullBytes[:])
	if err != nil {
		t.Fatalf("failed to create c scalar: %v", err)
	}

	// s = k + c*sk mod L
	cTimesSk := new(edwards25519.Scalar).Multiply(cScalar, sk)
	s := new(edwards25519.Scalar).Add(k, cTimesSk)

	// Build proof: gamma (32 bytes) || c_lower (16 bytes) || s (32 bytes) = 80 bytes
	proof := make([]byte, 80)
	copy(proof[:32], gamma.Bytes())
	copy(proof[32:48], c[:])
	copy(proof[48:80], s.Bytes())

	return proof
}
