package ecc

// VXEdDSA (signal.org xeddsa spec): XEdDSA with a VRF output; hash_i prefixes 0xFE nonce, 0xFD hash_to_point, 0xFC r, 0xFB h, 0xFA v.

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

// VRFOutputSize is 32: v = hash_5(cV) truncated to the first 32 bytes of the SHA-512 digest.
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

// elligator2 maps r to a Montgomery u: u1 = -A/(1+2r^2); u = u1 if u1(u1^2+A u1+1) is square, else -A-u1.
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

// hashToPoint maps input to the prime-order subgroup with hash_2 and Elligator 2 (spec §2.6).
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

// calculateEdwardsKeyPair derives the Edwards key with sign 0 and scalar a (spec §2.3); edwardsKeyPairResult also keeps the original sign bit.
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

// vrfOutput returns the first 32 bytes of hash_5(cV), cofactor c=8.
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

// vxeddsaSign signs message with a 32-byte private key and 64 random bytes, returning (V || h || s) and v (spec §4).
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

// vxeddsaVerify verifies a 96-byte (V || h || s) signature and returns the VRF output (spec §4).
func vxeddsaVerify(publicKey [32]byte, message []byte, signature *[96]byte) (bool, []byte) {
	// Mask bit 255 before the canonical check, as curve25519-dalek does; XEdDSA verify rejects instead.
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
