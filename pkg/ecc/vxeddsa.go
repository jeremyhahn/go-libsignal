package ecc

// VXEdDSA: Verifiable XEdDSA signature scheme with VRF output.
// Extends XEdDSA (signing with Curve25519 keys using Ed25519 math)
// to produce a verifiable random function (VRF) output.
// See: https://signal.org/docs/specifications/xeddsa/#vxeddsa
//
// Hash function diversifiers per spec (Section 2.5):
//   hash_i(X) = hash(2^b - 1 - i || X), where b = 256 for Curve25519
//   hash_1: 0xFE prefix (XEdDSA nonce, used in SignCurve25519.go)
//   hash_2: 0xFD prefix (hash_to_point)
//   hash_3: 0xFC prefix (VXEdDSA nonce r)
//   hash_4: 0xFB prefix (VXEdDSA challenge h)
//   hash_5: 0xFA prefix (VRF output v)

import (
	"crypto/sha512"
	"crypto/subtle"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
	crypto "github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
)

// Note: zeroScalar is defined in SignCurve25519.go and is accessible within
// this package.

// VXEdDSASignatureSize is the size of a VXEdDSA signature in bytes (V || h || s).
const VXEdDSASignatureSize = 96

// VRFOutputSize is the size of the VRF output in bytes.
// Per XEdDSA spec Section 4: v = hash_5(cV) (mod 2^b) where b=256, so
// the output is truncated to the first 32 bytes of the SHA-512 digest.
// The Rust reference implementation also truncates via first_chunk().
const VRFOutputSize = 32

// diversifier2 is the hash_2 diversifier (0xFD prefix) used for hash-to-point.
var diversifier2 = [32]byte{
	0xFD, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
}

// diversifier3 is the hash_3 diversifier (0xFC prefix) used for VXEdDSA nonce generation.
var diversifier3 = [32]byte{
	0xFC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
}

// diversifier4 is the hash_4 diversifier (0xFB prefix) used for VXEdDSA challenge.
var diversifier4 = [32]byte{
	0xFB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
}

// diversifier5 is the hash_5 diversifier (0xFA prefix) used for VRF output derivation.
var diversifier5 = [32]byte{
	0xFA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
}

// constA486662 is the Montgomery curve constant A = 486662 for Curve25519.
var constA486662 *field.Element

// constNegA is -A mod p.
var constNegA *field.Element

// constTwo is the field element 2.
var constTwo *field.Element

func init() {
	// A = 486662 in little-endian
	var aBytes [32]byte
	aBytes[0] = 0x06
	aBytes[1] = 0x6D
	aBytes[2] = 0x07
	constA486662, _ = new(field.Element).SetBytes(aBytes[:])

	constNegA = new(field.Element).Negate(constA486662)

	var twoBytes [32]byte
	twoBytes[0] = 0x02
	constTwo, _ = new(field.Element).SetBytes(twoBytes[:])
}

// elligator2 maps a field element r to a Montgomery u-coordinate on Curve25519
// using the Elligator 2 map.
//
// Algorithm:
//  1. Compute u1 = -A / (1 + 2*r^2) where A = 486662
//  2. Compute w1 = u1*(u1^2 + A*u1 + 1)
//  3. If w1 is not a square, u = -A - u1; otherwise u = u1
//
// Returns the Montgomery u-coordinate as a field element.
func elligator2(r *field.Element) *field.Element {
	// d = 1 + 2*r^2
	r2 := new(field.Element).Square(r)
	twoR2 := new(field.Element).Multiply(constTwo, r2)
	one := new(field.Element).One()
	d := new(field.Element).Add(one, twoR2)

	// If d == 0, use d = 1 (this happens when r = 0, giving u = -A)
	dIsZero := d.Equal(new(field.Element).Zero())
	d.Select(one, d, dIsZero)

	// u1 = -A / d
	dInv := new(field.Element).Invert(d)
	u1 := new(field.Element).Multiply(constNegA, dInv)

	// w1 = u1*(u1^2 + A*u1 + 1)
	u1sq := new(field.Element).Square(u1)
	au1 := new(field.Element).Multiply(constA486662, u1)
	inner := new(field.Element).Add(u1sq, au1)
	inner.Add(inner, one)
	w1 := new(field.Element).Multiply(u1, inner)

	// Check if w1 is a square using SqrtRatio(w1, 1)
	_, isSquare := new(field.Element).SqrtRatio(w1, one)

	// If not a square, use u2 = -A - u1
	u2 := new(field.Element).Subtract(constNegA, u1)

	// Select: isSquare == 1 means use u1, isSquare == 0 means use u2
	finalU := new(field.Element).Select(u1, u2, isSquare)

	return finalU
}

// hashToPoint maps arbitrary input bytes to a point on the Edwards 25519 curve
// in the prime-order subgroup, using hash_2 (SHA-512 with 0xFD diversifier)
// followed by Elligator 2.
//
// Spec (Section 2.6):
//
//	h = hash_2(X)
//	r = h (mod 2^|p|)           -- field element from low 255 bits
//	s = floor((h mod 2^b) / 2^(b-1))  -- sign bit from bit 255 of hash
//	u = elligator2(r)
//	P.y = u_to_y(u)
//	P.s = s
//	return cP
func hashToPoint(input []byte) (*edwards25519.Point, error) {
	// h = hash_2(input)
	var digest [64]byte
	hash := sha512.New()
	hash.Write(diversifier2[:])
	hash.Write(input)
	hash.Sum(digest[:0])

	// s = floor((h mod 2^b) / 2^(b-1)) = bit 255 of the hash output
	// For b=256, this is the high bit of byte 31
	signBit := (digest[31] >> 7) & 1

	// r = h (mod 2^|p|) where |p|=255
	// Clear bit 255 to get a value mod 2^255
	var rBytes [32]byte
	copy(rBytes[:], digest[:32])
	rBytes[31] &= 0x7F

	r, err := new(field.Element).SetBytes(rBytes[:])
	if err != nil {
		return nil, ErrHashToPointFailed
	}

	// u = elligator2(r)
	u := elligator2(r)

	// P.y = u_to_y(u) = (u - 1) / (u + 1)
	one := new(field.Element).One()
	uMinus1 := new(field.Element).Subtract(u, one)
	uPlus1 := new(field.Element).Add(u, one)
	uPlus1Inv := new(field.Element).Invert(uPlus1)
	edY := new(field.Element).Multiply(uMinus1, uPlus1Inv)

	// Encode Edwards y-coordinate and set sign bit P.s = s
	var edBytes [32]byte
	copy(edBytes[:], edY.Bytes())
	edBytes[31] |= signBit << 7

	point, err := new(edwards25519.Point).SetBytes(edBytes[:])
	if err != nil {
		return nil, ErrHashToPointFailed
	}

	// Multiply by cofactor c=8 to project into prime-order subgroup
	result := new(edwards25519.Point).MultByCofactor(point)
	return result, nil
}

// calculateEdwardsKeyPair derives the Edwards public key and clamped scalar
// from a Curve25519 private key, matching the XEdDSA calculate_key_pair spec.
//
// Spec (Section 2.3):
//
//	E = kB
//	A.y = E.y
//	A.s = 0
//	if E.s == 1: a = -k (mod q)
//	else:        a = k (mod q)
//	return A, a
//
// edwardsKeyPairResult holds the output of calculateEdwardsKeyPair,
// including the original sign bit needed for Rust/Java interoperability.
type edwardsKeyPairResult struct {
	// A is the Edwards public key point with sign bit 0.
	A *edwards25519.Point
	// Scalar is the (possibly negated) private scalar such that Scalar*B == A.
	Scalar *edwards25519.Scalar
	// PublicKey is the 32-byte encoding of A (sign bit 0).
	PublicKey []byte
	// SignBit is the original sign bit of the Edwards public key (0 or 1).
	// This is the bit that was cleared when normalizing A to sign bit 0.
	// The Rust/Java reference implementations embed this bit in signature[63].
	SignBit byte
}

func calculateEdwardsKeyPair(privateKey *[32]byte) edwardsKeyPairResult {
	privScalar, _ := new(edwards25519.Scalar).SetBytesWithClamping(privateKey[:])

	// E = kB
	E := new(edwards25519.Point).ScalarBaseMult(privScalar)
	eBytes := E.Bytes()

	// Check if E has sign bit 1 (bit 255 of the encoding)
	eSignBit := int(eBytes[31] >> 7)

	// A.y = E.y, A.s = 0 (clear the sign bit)
	var aBytes [32]byte
	copy(aBytes[:], eBytes)
	aBytes[31] &= 0x7F

	// If E.s == 1, negate the scalar so that a*B has sign bit 0.
	// Use constant-time selection to avoid branching on secret data.
	negScalar := new(edwards25519.Scalar).Negate(privScalar)
	negBytes := negScalar.Bytes()
	origBytes := privScalar.Bytes()
	var selectedBytes [32]byte
	subtle.ConstantTimeCopy(eSignBit, selectedBytes[:], negBytes)
	subtle.ConstantTimeCopy(1-eSignBit, selectedBytes[:], origBytes)
	privScalar, _ = new(edwards25519.Scalar).SetCanonicalBytes(selectedBytes[:])
	crypto.Zeroize(negBytes)
	crypto.Zeroize(origBytes)
	crypto.Zeroize(selectedBytes[:])

	// Reconstruct A from the canonical encoding (sign bit = 0)
	A, _ := new(edwards25519.Point).SetBytes(aBytes[:])

	publicKey := A.Bytes()
	return edwardsKeyPairResult{
		A:         A,
		Scalar:    privScalar,
		PublicKey: publicKey,
		SignBit:   byte(eSignBit),
	}
}

// isSmallOrderPoint checks whether the given point has small order by
// multiplying by the cofactor and checking if the result is the identity.
// This detects points of order 1, 2, 4, or 8.
func isSmallOrderPoint(p *edwards25519.Point) bool {
	cofactored := new(edwards25519.Point).MultByCofactor(p)
	return cofactored.Equal(edwards25519.NewIdentityPoint()) == 1
}

// vrfOutput computes hash_5(cV) to produce the VRF output.
// Per spec Section 4: v = hash_5(cV) (mod 2^b) where c=8 is the cofactor
// and b=256. The (mod 2^b) truncation means we return only the first 32
// bytes of the SHA-512 digest, matching the Rust reference implementation.
func vrfOutput(V *edwards25519.Point) []byte {
	// Multiply V by cofactor c=8
	cV := new(edwards25519.Point).MultByCofactor(V)
	cVBytes := cV.Bytes()

	var digest [64]byte
	hash := sha512.New()
	hash.Write(diversifier5[:])
	hash.Write(cVBytes)
	hash.Sum(digest[:0])

	// Truncate to 32 bytes per spec: v = hash_5(cV) (mod 2^b), b=256
	out := make([]byte, 32)
	copy(out, digest[:32])
	return out
}

// vxeddsaSign performs VXEdDSA signing.
//
// Parameters:
//   - privateKey: 32-byte Curve25519 private key
//   - message: arbitrary-length message to sign
//   - random: 64 bytes of randomness for nonce generation
//
// Spec (Section 4):
//
//	A, a = calculate_key_pair(k)
//	B_v = hash_to_point(A || M)
//	V = aB_v
//	r = hash_3(a || V || Z) (mod q)
//	R = rB
//	R_v = rB_v
//	h = hash_4(A || V || R || R_v || M) (mod q)
//	s = r + ha (mod q)
//	v = hash_5(cV) (mod 2^b)
//	return (V || h || s), v
func vxeddsaSign(privateKey *[32]byte, message []byte, random [64]byte) (*[96]byte, []byte, error) {
	// Step 1: Calculate Edwards key pair (A has sign bit 0)
	kpResult := calculateEdwardsKeyPair(privateKey)
	_ = kpResult.A
	aScalar := kpResult.Scalar
	defer zeroScalar(aScalar)
	aEdBytes := kpResult.PublicKey
	clampedBytes := aScalar.Bytes()
	defer crypto.Zeroize(clampedBytes)

	// Step 2: B_v = hash_to_point(A || M)
	hashInput := make([]byte, 0, len(aEdBytes)+len(message))
	hashInput = append(hashInput, aEdBytes...)
	hashInput = append(hashInput, message...)
	Bv, err := hashToPoint(hashInput)
	if err != nil {
		return nil, nil, err
	}

	// Step 3: V = a * B_v
	V := new(edwards25519.Point).ScalarMult(aScalar, Bv)
	vBytes := V.Bytes()

	// Step 4: r = hash_3(a || V || Z) mod q
	// Note: spec says hash_3(a || V || Z) -- no message M
	var rDigest [64]byte
	defer crypto.Zeroize(rDigest[:])
	hash := sha512.New()
	hash.Write(diversifier3[:])
	hash.Write(clampedBytes)
	hash.Write(vBytes)
	hash.Write(random[:])
	hash.Sum(rDigest[:0])
	rScalar, _ := new(edwards25519.Scalar).SetUniformBytes(rDigest[:])
	defer zeroScalar(rScalar)

	// Step 5: R = r * B (standard basepoint)
	R := new(edwards25519.Point).ScalarBaseMult(rScalar)
	rBytes := R.Bytes()

	// Step 6: R_v = r * B_v
	Rv := new(edwards25519.Point).ScalarMult(rScalar, Bv)
	rvBytes := Rv.Bytes()

	// Step 7: h = hash_4(A || V || R || R_v || M) mod q
	// Note: spec order is R (basepoint) before R_v
	var hDigest [64]byte
	defer crypto.Zeroize(hDigest[:])
	hash.Reset()
	hash.Write(diversifier4[:])
	hash.Write(aEdBytes)
	hash.Write(vBytes)
	hash.Write(rBytes)
	hash.Write(rvBytes)
	hash.Write(message)
	hash.Sum(hDigest[:0])
	hScalar, _ := new(edwards25519.Scalar).SetUniformBytes(hDigest[:])

	// Step 8: s = (r + h*a) mod q
	sScalar := new(edwards25519.Scalar).MultiplyAdd(hScalar, aScalar, rScalar)

	// Step 9: VRF output = hash_5(cV) where c=8 is the cofactor
	vrf := vrfOutput(V)

	// Step 10: Return signature = V || h || s (96 bytes)
	signature := new([96]byte)
	copy(signature[:32], vBytes)
	copy(signature[32:64], hScalar.Bytes())
	copy(signature[64:96], sScalar.Bytes())

	return signature, vrf, nil
}

// vxeddsaVerify verifies a VXEdDSA signature and returns the VRF output if valid.
//
// Parameters:
//   - publicKey: 32-byte Curve25519 public key (Montgomery x-coordinate)
//   - message: the message that was signed
//   - signature: 96-byte signature (V || h || s)
//
// Spec (Section 4):
//
//	A = convert_mont(u)
//	B_v = hash_to_point(A || M)
//	if cA == I or cV == I or B_v == I: return false
//	R = sB - hA
//	R_v = sB_v - hV
//	h_check = hash_4(A || V || R || R_v || M) (mod q)
//	if h == h_check: v = hash_5(cV); return v
//	return false
func vxeddsaVerify(publicKey [32]byte, message []byte, signature *[96]byte) (bool, []byte) {
	// VXEdDSA intentionally masks bit 255 of the Montgomery x-coordinate before
	// the canonicity check. This matches the behavior of curve25519-dalek-signal's
	// FieldElement::from_bytes, which silently masks that bit when decoding, so any
	// key with bit 255 set is reduced to its canonical form rather than rejected.
	//
	// This differs deliberately from XEdDSA verify (verify() in SignCurve25519.go),
	// which skips the pre-mask and rejects non-canonical keys outright. That
	// stricter check is documented there as an intentional hardening.
	//
	// VXEdDSA retains the dalek-compatible mask because there is no Rust oracle to
	// confirm the strict-rejection behavior for VXEdDSA specifically; changing the
	// semantics here without a cross-implementation reference risks breaking
	// interoperability with peers whose public keys carry the high bit.
	publicKey[31] &= 0x7F

	// Reject keys whose value (after masking bit 255) is still >= p.
	if isNonCanonicalFieldElement(publicKey) {
		return false, nil
	}

	// Convert Montgomery x-coordinate to Edwards y-coordinate
	// A = convert_mont(u): A.y = (u-1)/(u+1), A.s = 0
	montX, _ := new(field.Element).SetBytes(publicKey[:])
	one := new(field.Element).One()
	montXMinus1 := new(field.Element).Subtract(montX, one)
	montXPlus1 := new(field.Element).Add(montX, one)
	montXPlus1Inv := new(field.Element).Invert(montXPlus1)
	edY := new(field.Element).Multiply(montXMinus1, montXPlus1Inv)

	// A.s = 0 (sign bit always 0, per convert_mont spec)
	var aEdBytes [32]byte
	copy(aEdBytes[:], edY.Bytes())
	// sign bit is already 0 since edY.Bytes() produces canonical encoding

	// Parse signature: V (32) || h (32) || s (32)
	var vBytes [32]byte
	copy(vBytes[:], signature[:32])

	hBytes := make([]byte, 32)
	copy(hBytes, signature[32:64])

	sBytes := make([]byte, 32)
	copy(sBytes, signature[64:96])

	// Decode V
	V, err := new(edwards25519.Point).SetBytes(vBytes[:])
	if err != nil {
		return false, nil
	}

	// Decode h as scalar
	hScalar, err := new(edwards25519.Scalar).SetCanonicalBytes(hBytes)
	if err != nil {
		return false, nil
	}

	// Decode s as scalar
	sScalar, err := new(edwards25519.Scalar).SetCanonicalBytes(sBytes)
	if err != nil {
		return false, nil
	}

	// Decode A (Edwards public key with sign bit = 0)
	A, err := new(edwards25519.Point).SetBytes(aEdBytes[:])
	if err != nil {
		return false, nil
	}

	// B_v = hash_to_point(A || M)
	hashInput := make([]byte, 0, 32+len(message))
	hashInput = append(hashInput, aEdBytes[:]...)
	hashInput = append(hashInput, message...)
	Bv, err := hashToPoint(hashInput)
	if err != nil {
		return false, nil
	}

	// Small-order point checks per spec:
	// if cA == I or cV == I or B_v == I: return false
	if isSmallOrderPoint(A) {
		return false, nil
	}
	if isSmallOrderPoint(V) {
		return false, nil
	}
	if Bv.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return false, nil
	}

	// R = sB - hA
	negH := new(edwards25519.Scalar).Negate(hScalar)
	R := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(negH, A, sScalar)
	rBytes := R.Bytes()

	// R_v = sB_v - hV
	sBv := new(edwards25519.Point).ScalarMult(sScalar, Bv)
	hV := new(edwards25519.Point).ScalarMult(hScalar, V)
	Rv := new(edwards25519.Point).Subtract(sBv, hV)
	rvBytes := Rv.Bytes()

	// h_check = hash_4(A || V || R || R_v || M) mod q
	// Note: spec order is R (basepoint) before R_v
	var hCheckDigest [64]byte
	hash := sha512.New()
	hash.Write(diversifier4[:])
	hash.Write(aEdBytes[:])
	hash.Write(vBytes[:])
	hash.Write(rBytes)
	hash.Write(rvBytes)
	hash.Write(message)
	hash.Sum(hCheckDigest[:0])
	hCheckScalar, _ := new(edwards25519.Scalar).SetUniformBytes(hCheckDigest[:])

	// Compare h == h_check in constant time
	if subtle.ConstantTimeCompare(hScalar.Bytes(), hCheckScalar.Bytes()) != 1 {
		return false, nil
	}

	// VRF output = hash_5(cV) where c=8 is the cofactor
	vrf := vrfOutput(V)
	return true, vrf
}
