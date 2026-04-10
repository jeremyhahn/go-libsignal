// Package elligator implements the inverse of the ristretto-flavored Elligator
// map, allowing recovery of field elements from ristretto255 points.
//
// This is a port of the curve25519-dalek-signal Lizard implementation, which
// provides bidirectional encoding between small data payloads and ristretto255
// points via the Elligator map and its inverse.
//
// The inverse is used by Signal's zkgroup to decode encrypted UUIDs and profile
// keys back to their original byte representations.
package elligator

import (
	"filippo.io/edwards25519/field"
)

// Precomputed constants for the Elligator inverse on curve25519.
//
// These are derived from the Edwards curve parameter d and related values.
// They match the Rust curve25519-dalek-signal lizard_constants module.
var (
	feZero = new(field.Element)
	feOne  = new(field.Element).One()

	// d is the Edwards curve parameter for curve25519.
	feD, _ = new(field.Element).SetBytes([]byte{
		0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75,
		0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
		0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c,
		0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
	})

	// sqrt(-1)
	sqrtM1, _ = new(field.Element).SetBytes([]byte{
		0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4,
		0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
		0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b,
		0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b,
	})

	// INVSQRT_A_MINUS_D = 1/sqrt(a-d) where a=-1
	invSqrtAMinusD, _ = new(field.Element).SetBytes([]byte{
		0xea, 0x40, 0x5d, 0x80, 0xaa, 0xfd, 0xc8, 0x99,
		0xbe, 0x72, 0x41, 0x5a, 0x17, 0x16, 0x2f, 0x9d,
		0x40, 0xd8, 0x01, 0xfe, 0x91, 0x7b, 0xc2, 0x16,
		0xa2, 0xfc, 0xaf, 0xcf, 0x05, 0x89, 0x6c, 0x78,
	})
)

// Derived constants, computed at init time.
var (
	// sqrt(i*d) where i = sqrt(-1)
	sqrtID *field.Element

	// (d+1)/(d-1)
	dp1OverDm1 *field.Element

	// -2/sqrt(a-d) = -2 * INVSQRT_A_MINUS_D
	mDoubleInvSqrtAMinusD *field.Element

	// -2i/sqrt(a-d) = -2i * INVSQRT_A_MINUS_D
	miDoubleInvSqrtAMinusD *field.Element

	// -1/sqrt(1+d)
	mInvSqrtOnePlusD *field.Element
)

func init() {
	// sqrt(i*d): compute sqrt_ratio_i(sqrt(-1) * d, 1)
	id := new(field.Element).Multiply(sqrtM1, feD)
	sqrtID = new(field.Element)
	sqrtID.SqrtRatio(id, feOne)

	// (d+1)/(d-1)
	dp1 := new(field.Element).Add(feD, feOne)
	dm1 := new(field.Element).Subtract(feD, feOne)
	dm1Inv := new(field.Element).Invert(dm1)
	dp1OverDm1 = new(field.Element).Multiply(dp1, dm1Inv)

	// -2 * INVSQRT_A_MINUS_D
	doubled := new(field.Element).Add(invSqrtAMinusD, invSqrtAMinusD)
	mDoubleInvSqrtAMinusD = new(field.Element).Negate(doubled)

	// -2i/sqrt(a-d) = mDoubleInvSqrtAMinusD * sqrt(-1)
	miDoubleInvSqrtAMinusD = new(field.Element).Multiply(mDoubleInvSqrtAMinusD, sqrtM1)

	// -1/sqrt(1+d)
	onePlusD := new(field.Element).Add(feOne, feD)
	invSqrt := new(field.Element)
	invSqrt.SqrtRatio(feOne, onePlusD)
	mInvSqrtOnePlusD = new(field.Element).Negate(invSqrt)
}

// jacobiPoint represents a point (S, T) on the Jacobi quartic associated
// to the Edwards curve.
type jacobiPoint struct {
	S *field.Element
	T *field.Element
}

// dual returns the dual point (-S, -T).
func (jp *jacobiPoint) dual() *jacobiPoint {
	return &jacobiPoint{
		S: new(field.Element).Negate(jp.S),
		T: new(field.Element).Negate(jp.T),
	}
}

// elligatorInv computes a field element that maps to this Jacobi quartic point
// under Elligator2, if one exists. Returns (wasFound, fieldElement).
//
// This implementation uses constant-time conditional selection to avoid
// branching on secret-dependent values, preventing timing side channels.
func (jp *jacobiPoint) elligatorInv() (bool, *field.Element) {
	// Special case: s = 0. If s is zero, either t = 1 or t = -1.
	// If t=1, then sqrt(i*d) is the preimage. Otherwise it's 0.
	sIsZero := jp.S.Equal(feZero)
	tEqualsOne := jp.T.Equal(feOne)

	// s==0 result: sqrtID if t==1, else zero
	s0Result := new(field.Element).Select(sqrtID, feZero, int(tEqualsOne))

	// Compute the general case regardless (constant-time: always execute).
	// a := (t+1) * (d+1)/(d-1)
	tPlusOne := new(field.Element).Add(jp.T, feOne)
	a := new(field.Element).Multiply(tPlusOne, dp1OverDm1)
	a2 := new(field.Element).Square(a)

	// y := 1/sqrt(i * (s^4 - a^2))
	s2 := new(field.Element).Square(jp.S)
	s4 := new(field.Element).Square(s2)
	s4MinusA2 := new(field.Element).Subtract(s4, a2)
	invSqY := new(field.Element).Multiply(s4MinusA2, sqrtM1)

	// Check if sqrt exists
	y := new(field.Element)
	_, wasSquare := y.SqrtRatio(feOne, invSqY)

	// x := (a + sign(s)*s^2) * y
	negS2 := new(field.Element).Negate(s2)
	pms2 := new(field.Element).Select(negS2, s2, int(jp.S.IsNegative()))
	x := new(field.Element).Add(a, pms2)
	x.Multiply(x, y)

	// Make x positive (constant-time absolute value)
	x.Absolute(x)

	// Select between s==0 result and general case result.
	// If s==0, use s0Result; otherwise use x (the general case).
	out := new(field.Element).Select(s0Result, x, int(sIsZero))

	// found = sIsZero || (wasSquare && !sIsZero)
	// If sIsZero, always found (it's a valid degenerate case).
	// If not sIsZero, found only if wasSquare.
	found := sIsZero == 1 || (wasSquare == 1 && sIsZero != 1)

	return found, out
}

// decodeToExtended decodes a 32-byte canonical ristretto encoding to extended
// Edwards coordinates (X, Y, Z, T). This reimplements the ristretto DECODE
// operation from RFC 9496, Section 4.3.1 using only field arithmetic.
func decodeToExtended(encoded []byte) (X, Y, Z, T *field.Element, ok bool) {
	if len(encoded) != 32 {
		return nil, nil, nil, nil, false
	}

	s, err := new(field.Element).SetBytes(encoded)
	if err != nil {
		return nil, nil, nil, nil, false
	}

	// Check that s is non-negative and canonical
	if s.IsNegative() == 1 {
		return nil, nil, nil, nil, false
	}
	reEncoded := s.Bytes()
	for i := range encoded {
		if encoded[i] != reEncoded[i] {
			return nil, nil, nil, nil, false
		}
	}

	// ss = s^2
	ss := new(field.Element).Square(s)

	// u1 = 1 - ss
	u1 := new(field.Element).Subtract(feOne, ss)
	// u2 = 1 + ss
	u2 := new(field.Element).Add(feOne, ss)
	// u2_sqr = u2^2
	u2Sqr := new(field.Element).Square(u2)

	// v = -(D * u1^2) - u2^2
	u1Sqr := new(field.Element).Square(u1)
	v := new(field.Element).Multiply(feD, u1Sqr)
	v.Negate(v)
	v.Subtract(v, u2Sqr)

	// (was_square, invsqrt) = SQRT_RATIO_M1(1, v * u2_sqr)
	vu2Sqr := new(field.Element).Multiply(v, u2Sqr)
	I := new(field.Element)
	_, wasSquare := I.SqrtRatio(feOne, vu2Sqr)
	if wasSquare != 1 {
		return nil, nil, nil, nil, false
	}

	// den_x = invsqrt * u2
	// den_y = invsqrt * den_x * v
	Dx := new(field.Element).Multiply(I, u2)
	Dy := new(field.Element).Multiply(I, Dx)
	Dy.Multiply(Dy, v)

	// x = CT_ABS(2 * s * den_x)
	x := new(field.Element).Add(s, s)
	x.Multiply(x, Dx)
	x.Absolute(x)

	// y = u1 * den_y
	y := new(field.Element).Multiply(u1, Dy)

	// t = x * y
	t := new(field.Element).Multiply(x, y)

	// Check IS_NEGATIVE(t) == FALSE
	if t.IsNegative() == 1 {
		return nil, nil, nil, nil, false
	}

	// Check y != 0
	if y.Equal(feZero) == 1 {
		return nil, nil, nil, nil, false
	}

	z := new(field.Element).One()

	return x, y, z, t, true
}

// toJacobiQuarticRistretto finds a point on the Jacobi quartic associated to
// each of the four points Ristretto-equivalent to the given Edwards point
// (X, Y, Z, T). This is a direct port of the Rust to_jacobi_quartic_ristretto.
func toJacobiQuarticRistretto(X, Y, Z, T *field.Element) [4]*jacobiPoint {
	x2 := new(field.Element).Square(X)
	y2 := new(field.Element).Square(Y)
	y4 := new(field.Element).Square(y2)
	z2 := new(field.Element).Square(Z)
	zMinY := new(field.Element).Subtract(Z, Y)
	zPlY := new(field.Element).Add(Z, Y)
	z2MinY2 := new(field.Element).Subtract(z2, y2)

	// gamma := 1/sqrt(Y^4 * X^2 * (Z^2 - Y^2))
	tmp := new(field.Element).Multiply(y4, x2)
	tmp.Multiply(tmp, z2MinY2)
	gamma := new(field.Element)
	gamma.SqrtRatio(feOne, tmp)

	den := new(field.Element).Multiply(gamma, y2)

	sOverX := new(field.Element).Multiply(den, zMinY)
	spOverXp := new(field.Element).Multiply(den, zPlY)

	s0 := new(field.Element).Multiply(sOverX, X)
	s1 := new(field.Element).Negate(new(field.Element).Multiply(spOverXp, X))

	// t_0 := -2/sqrt(-d-1) * Z * sOverX
	// t_1 := -2/sqrt(-d-1) * Z * spOverXp
	tmpZ := new(field.Element).Multiply(mDoubleInvSqrtAMinusD, Z)
	t0 := new(field.Element).Multiply(tmpZ, sOverX)
	t1 := new(field.Element).Multiply(tmpZ, spOverXp)

	// den := -1/sqrt(1+d) * (Y^2 - Z^2) * gamma
	negZ2MinY2 := new(field.Element).Negate(z2MinY2)
	den2 := new(field.Element).Multiply(negZ2MinY2, mInvSqrtOnePlusD)
	den2.Multiply(den2, gamma)

	// Same as before but with the substitution (X, Y, Z) = (Y, X, i*Z)
	iZ := new(field.Element).Multiply(sqrtM1, Z)
	iZMinX := new(field.Element).Subtract(iZ, X)
	iZPlX := new(field.Element).Add(iZ, X)

	sOverY := new(field.Element).Multiply(den2, iZMinX)
	spOverYp := new(field.Element).Multiply(den2, iZPlX)

	s2 := new(field.Element).Multiply(sOverY, Y)
	s3 := new(field.Element).Negate(new(field.Element).Multiply(spOverYp, Y))

	// t_2 := -2/sqrt(-d-1) * i*Z * sOverY
	// t_3 := -2/sqrt(-d-1) * i*Z * spOverYp
	tmpiZ := new(field.Element).Multiply(mDoubleInvSqrtAMinusD, iZ)
	t2 := new(field.Element).Multiply(tmpiZ, sOverY)
	t3 := new(field.Element).Multiply(tmpiZ, spOverYp)

	// Special case: X=0 or Y=0. Use constant-time Select to avoid branching on
	// secret-dependent field elements. When xOrYIsZero==1, the degenerate values
	// are selected; otherwise the computed values are kept unchanged.
	xOrYIsZero := X.Equal(feZero) | Y.Equal(feZero)
	t0.Select(feOne, t0, xOrYIsZero)
	t1.Select(feOne, t1, xOrYIsZero)
	t2.Select(miDoubleInvSqrtAMinusD, t2, xOrYIsZero)
	t3.Select(miDoubleInvSqrtAMinusD, t3, xOrYIsZero)
	s2.Select(feOne, s2, xOrYIsZero)
	negOne := new(field.Element).Negate(feOne)
	s3.Select(negOne, s3, xOrYIsZero)

	return [4]*jacobiPoint{
		{S: s0, T: t0},
		{S: s1, T: t1},
		{S: s2, T: t2},
		{S: s3, T: t3},
	}
}

// ElligatorRistrettoFlavorInverse computes the at most 8 positive field elements
// f such that MAP(f) equals the ristretto point encoded by the given 32 bytes.
//
// Returns a bitmask indicating which of the 8 returned field elements are valid
// preimages, and the 8 candidate field elements as 32-byte little-endian arrays.
//
// This is a direct port of the Rust elligator_ristretto_flavor_inverse method.
func ElligatorRistrettoFlavorInverse(encoded []byte) (mask uint8, candidates [8][32]byte, ok bool) {
	X, Y, Z, T, valid := decodeToExtended(encoded)
	if !valid {
		return 0, candidates, false
	}

	jcs := toJacobiQuarticRistretto(X, Y, Z, T)

	for i := 0; i < 4; i++ {
		found, fe := jcs[i].elligatorInv()
		if found {
			mask |= 1 << (2 * i)
		}
		copy(candidates[2*i][:], fe.Bytes())

		dualJC := jcs[i].dual()
		found2, fe2 := dualJC.elligatorInv()
		if found2 {
			mask |= 1 << (2*i + 1)
		}
		copy(candidates[2*i+1][:], fe2.Bytes())
	}

	return mask, candidates, true
}
