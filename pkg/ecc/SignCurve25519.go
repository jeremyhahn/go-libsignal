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

// sign returns an XEdDSA signature R || s (XEdDSA spec §3).
func sign(privateKey *[32]byte, message []byte, random [64]byte) *[64]byte {

	// Use the Edwards scalar and key as-is, like Rust and Java, and embed the sign bit in the signature.
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

	// r = hash_1(key_data || M || Z) over the clamped key bytes, as Rust does, for compatible nonces.
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

	// Return R || s with the Edwards public key sign bit in the top bit of signature[63].
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
	// p = 2^255 - 19 little-endian: byte 31 above 0x7F, or 0x7F with bytes 1..30 0xFF and byte 0 >= 0xED, is non-canonical.
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

// verify checks an XEdDSA signature; unlike Rust, it rejects non-canonical public keys instead of masking bit 255.
func verify(publicKey [32]byte, message []byte, signature *[64]byte) bool {

	// Reject u >= p explicitly, since SetBytes reduces non-canonical values.
	if isNonCanonicalFieldElement(publicKey) {
		return false
	}

	// The signer's Edwards sign bit in signature[63] selects the Edwards point for the Montgomery x-coordinate.
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

	// Apply the sign bit taken from the signature.
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

	// SetBytes rejects non-canonical R encodings and off-curve points.
	var encodedR [32]byte
	copy(encodedR[:], signature[:32])
	R, err := new(edwards25519.Point).SetBytes(encodedR[:])
	if err != nil {
		return false
	}

	// Clear the embedded sign bit and reduce s mod L, like Rust Scalar::from_bytes_mod_order.
	var sPadded [64]byte
	copy(sPadded[:32], signature[32:])
	sPadded[31] &= 0x7F

	// Reject a non-canonical scalar: bits 5 and 6 of s[31] must be zero (Rust curve25519.rs).
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
