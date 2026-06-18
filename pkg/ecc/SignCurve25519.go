package ecc

// Package curve25519sign implements XEdDSA: a signature scheme for Curve25519 keys
// using Ed25519 mathematics.
// See https://moderncrypto.org/mail-archive/curves/2014/000205.html for details.

import (
	"crypto/sha512"
	"runtime"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
	crypto "github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
)

// zeroScalar overwrites the scalar's internal representation with zeros.
// edwards25519.Scalar does not expose a dedicated Zeroize method; overwriting
// with a zero canonical scalar achieves the same effect.
func zeroScalar(s *edwards25519.Scalar) {
	var zero [32]byte
	_, _ = s.SetCanonicalBytes(zero[:])
	runtime.KeepAlive(s)
}

// sign signs the message with privateKey and returns a signature as a byte slice.
//
// Implements the XEdDSA spec (Section 3):
//
//	A, a = calculate_key_pair(k)
//	r = hash_1(a || M || Z) (mod q)
//	R = r*B
//	h = hash(R || A || M) using SHA-512
//	s = (r + h*a) mod order
//	Return R || s
func sign(privateKey *[32]byte, message []byte, random [64]byte) *[64]byte {

	// Step 1: Compute the Edwards key pair directly, matching the Rust/Java
	// reference implementation. Unlike calculateEdwardsKeyPair (which normalizes
	// the sign bit to 0 for VXEdDSA), here we use the scalar and Edwards public
	// key as-is, and embed the sign bit in the signature for the verifier.
	aScalar, err := new(edwards25519.Scalar).SetBytesWithClamping(privateKey[:])
	if err != nil {
		// SetBytesWithClamping only fails if input is not exactly 32 bytes,
		// which cannot happen here since privateKey is *[32]byte.
		return nil
	}
	defer zeroScalar(aScalar)
	edPubPoint := new(edwards25519.Point).ScalarBaseMult(aScalar)
	edPubBytes := edPubPoint.Bytes()
	signBit := edPubBytes[31] & 0x80

	// Step 2: r = hash_1(key_data || M || Z) (mod q)
	// The Rust reference hashes the raw (clamped) private key bytes, NOT the
	// reduced scalar representation. We must match this for deterministic
	// nonce generation and test vector compatibility.
	diversifier := [32]byte{
		0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	// Use raw clamped private key bytes for the nonce hash, matching Rust's
	// hash1.update(&key_data[..]) where key_data = self.secret.to_bytes().
	var keyData [32]byte
	copy(keyData[:], privateKey[:])
	keyData[0] &= 248
	keyData[31] &= 127
	keyData[31] |= 64
	defer crypto.Zeroize(keyData[:])

	var r [64]byte
	defer crypto.Zeroize(r[:])
	hash := sha512.New()
	hash.Write(diversifier[:])
	hash.Write(keyData[:])
	hash.Write(message)
	hash.Write(random[:])
	hash.Sum(r[:0])

	// Step 3: R = r*B
	rReduced, err := new(edwards25519.Scalar).SetUniformBytes(r[:])
	if err != nil {
		return nil
	}
	defer zeroScalar(rReduced)
	R := new(edwards25519.Point).ScalarBaseMult(rReduced)
	encodedR := R.Bytes()

	// Step 4: h = SHA2-512(R || A || M)
	// Use the full Edwards public key encoding (including sign bit), matching
	// the Rust reference which uses ed_public_key.as_bytes() directly.
	var hramDigest [64]byte
	defer crypto.Zeroize(hramDigest[:])
	hash.Reset()
	hash.Write(encodedR)
	hash.Write(edPubBytes)
	hash.Write(message)
	hash.Sum(hramDigest[:0])
	hramDigestReduced, err := new(edwards25519.Scalar).SetUniformBytes(hramDigest[:])
	if err != nil {
		return nil
	}

	// Step 5: s = (r + h*a) mod order
	s := new(edwards25519.Scalar).MultiplyAdd(hramDigestReduced, aScalar, rReduced)

	// Return R || s with the Edwards public key sign bit embedded in signature[63].
	// The Rust/Java reference implementations embed the sign bit of the Edwards
	// public key into the MSB of the last byte. This bit would otherwise always
	// be 0 for a canonical scalar < L (since L < 2^253). The verifier extracts
	// this bit to reconstruct the correct Edwards point.
	signature := new([64]byte)
	copy(signature[:32], encodedR)
	copy(signature[32:], s.Bytes())
	signature[63] &= 0x7F
	signature[63] |= signBit

	return signature
}

// isNonCanonicalFieldElement reports whether the 32-byte little-endian value
// is >= p (2^255 - 19). Raw (un-masked) bytes are accepted; a value with the
// high bit set (bit 255) is immediately non-canonical because 2^255 > p.
func isNonCanonicalFieldElement(b [32]byte) bool {
	// p = 2^255 - 19, in little-endian:
	// 0xED 0xFF ... 0xFF 0x7F
	// Any value with byte 31 > 0x7F has bit 255 set and is >= 2^255 > p.
	// If byte 31 == 0x7F, all bytes 1..30 must be 0xFF, and byte 0 must be >= 0xED.
	if b[31] > 0x7F {
		return true
	}
	if b[31] < 0x7F {
		return false
	}
	// b[31] == 0x7F; check bytes 30 down to 1
	for i := 30; i >= 1; i-- {
		if b[i] < 0xFF {
			return false
		}
	}
	// All bytes 1..30 are 0xFF; check byte 0
	return b[0] >= 0xED
}

// verify checks whether the message has a valid signature.
//
// Deliberate hardening: the pre-mask `publicKey[31] &= 0x7F` that previously
// cleared the high bit before the canonical-field-element check has been
// removed. curve25519-dalek's FieldElement::from_bytes masks bit 255 before
// decoding, so Rust silently accepts non-canonical Montgomery x-coordinates
// (value >= 2^255) by masking them to canonical values. Go intentionally
// rejects any such key outright via the `b[31] > 0x7F` branch in
// isNonCanonicalFieldElement. This has zero impact on keys generated by
// honest implementations — all such keys are canonical — but it closes the
// door on crafted non-canonical public keys that Rust would mask-and-accept.
func verify(publicKey [32]byte, message []byte, signature *[64]byte) bool {

	// XEdDSA spec: reject if u >= p (the Montgomery x-coordinate must be canonical).
	// field.Element.SetBytes reduces mod p and accepts non-canonical values,
	// so we must check explicitly before conversion. Go is stricter than Rust
	// here: non-canonical keys are rejected rather than masked to canonical form.
	if isNonCanonicalFieldElement(publicKey) {
		return false
	}

	// Extract the Edwards public key sign bit from signature[63].
	// The Rust/Java reference implementations embed the signer's Edwards public
	// key sign bit into the MSB of signature[63] during signing. This allows
	// the verifier to reconstruct the correct Edwards point from the Montgomery
	// x-coordinate, which is otherwise ambiguous (two possible y-coordinates).
	edSignBit := signature[63] >> 7

	/* Convert the Curve25519 public key into an Ed25519 public key.  In
	particular, convert Curve25519's "montgomery" x-coordinate into an
	Ed25519 "edwards" y-coordinate:

	ed_y = (mont_x - 1) / (mont_x + 1)

	NOTE: mont_x=-1 is converted to ed_y=0 since Invert is mod-exp
	*/

	montX, err := new(field.Element).SetBytes(publicKey[:])
	if err != nil {
		return false
	}
	one := new(field.Element).One()
	montXMinusOne := new(field.Element).Subtract(montX, one)
	montXPlusOne := new(field.Element).Add(montX, one)
	montXPlusOneInv := new(field.Element).Invert(montXPlusOne)
	edY := new(field.Element).Multiply(montXMinusOne, montXPlusOneInv)

	// Set the Edwards public key sign bit from the value extracted from the signature.
	// This matches the Rust/Java behavior: the sign bit embedded during signing
	// determines which of the two possible Edwards points corresponds to the
	// Montgomery x-coordinate.
	var A_ed [32]byte
	copy(A_ed[:], edY.Bytes())
	A_ed[31] &= 0x7F
	A_ed[31] |= edSignBit << 7

	// Verify using edwards25519 point operations.
	// Reconstruct the Ed25519 public key point and perform standard Ed25519 verification.
	edPubPoint, err := new(edwards25519.Point).SetBytes(A_ed[:])
	if err != nil {
		return false
	}

	// Extract R and S from signature.
	// XEdDSA spec: reject if R.y >= 2^|p|. edwards25519.Point.SetBytes rejects
	// non-canonical encodings (y >= p) and checks the point is on the curve,
	// satisfying this requirement.
	var encodedR [32]byte
	copy(encodedR[:], signature[:32])
	R, err := new(edwards25519.Point).SetBytes(encodedR[:])
	if err != nil {
		return false
	}

	// Extract s scalar, clearing the sign bit that was embedded by the signer.
	// Rust uses Scalar::from_bytes_mod_order(s) which reduces any 32-byte value
	// modulo L (the group order). We replicate this by zero-padding to 64 bytes
	// and using SetUniformBytes, which performs the same mod-L reduction.
	var sPadded [64]byte
	copy(sPadded[:32], signature[32:])
	sPadded[31] &= 0x7F

	// Reject non-canonical scalar per Rust reference (curve25519.rs:133-136).
	// After clearing the sign bit (bit 7), bits 5 and 6 must both be zero.
	// If either is set, the scalar value >= 2^253, which exceeds the group
	// order L (approx 2^252.67). The Rust code clears bit 7 first, then
	// checks: if s[31] & 0xE0 != 0 { return false }.
	if sPadded[31]&0xE0 != 0 {
		return false
	}

	S, err := new(edwards25519.Scalar).SetUniformBytes(sPadded[:])
	if err != nil {
		return false
	}

	// Compute h = SHA2-512(R || A_ed || msg) mod L
	var hramDigest [64]byte
	hash := sha512.New()
	hash.Write(encodedR[:])
	hash.Write(A_ed[:])
	hash.Write(message)
	hash.Sum(hramDigest[:0])
	h, err := new(edwards25519.Scalar).SetUniformBytes(hramDigest[:])
	if err != nil {
		return false
	}

	// Verify: [S]B == R + [h]A
	// Equivalently: [S]B - [h]A == R
	// XEdDSA (Section 5) uses non-cofactored verification.
	negH := new(edwards25519.Scalar).Negate(h)
	checkPoint := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(negH, edPubPoint, S)

	return checkPoint.Equal(R) == 1
}
