// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Package gf implements arithmetic in GF(2^16) with primitive polynomial
// POLY = 0x1100b (x^16 + x^12 + x^3 + x + 1).
//
// This is an internal implementation detail of pkg/mlkembraid; the algorithm
// is a direct port of the Rust sparsepostquantumratchet crate (commit f2589fef).
// Byte-level parity with the Rust reference is a hard requirement.
package gf

// Poly is the primitive polynomial for GF(2^16): x^16 + x^12 + x^3 + x + 1.
// Matches Rust's POLY = 0x1100b.
//
// Reference: https://web.eecs.utk.edu/~jplank/plank/papers/CS-07-593/primitive-polynomial-table.txt
const Poly uint32 = 0x1100b

// ErrInvalidInverse is returned when computing the multiplicative inverse of
// zero, which is undefined in GF(2^16).
type ErrInvalidInverse struct{}

// Error implements the error interface.
func (ErrInvalidInverse) Error() string {
	return "gf: zero has no multiplicative inverse"
}

// GF16 is an element of GF(2^16) with primitive polynomial 0x1100b.
// Representation is a uint16 where bit i corresponds to the coefficient of x^i.
// The zero representation is GF16{Value: 0} and the multiplicative identity
// is GF16{Value: 1}.
type GF16 struct {
	// Value is the underlying field element in polynomial representation.
	Value uint16
}

// Zero is the additive identity in GF(2^16). Matches Rust's GF16::ZERO.
var Zero = GF16{Value: 0}

// One is the multiplicative identity in GF(2^16). Matches Rust's GF16::ONE.
var One = GF16{Value: 1}

// reduceBytes is the precomputed lookup table for polynomial reduction.
// reduceBytes[b] encodes the u16 XOR contribution when byte b appears
// in bit positions [24..32] or [16..24] of an unreduced u32 product.
// Matches Rust's REDUCE_BYTES.
var reduceBytes [256]uint16

func init() {
	for i := range 256 {
		reduceBytes[i] = uint16(reduceFromByte(uint8(i)))
	}
}

// reduceFromByte computes the u16 reduction for a single byte a in the high
// position. Matches Rust's reduce_from_byte.
func reduceFromByte(a uint8) uint32 {
	var out uint32
	for i := 7; i >= 0; i-- {
		if (1<<uint(i))&a != 0 {
			out ^= Poly << uint(i)
			a ^= uint8((Poly << uint(i)) >> 16)
		}
	}
	return out
}

// polyReduce reduces an unreduced 32-bit polynomial product modulo Poly,
// returning the 16-bit field element. Matches Rust's reduce::poly_reduce.
func polyReduce(v uint32) uint16 {
	i1 := v >> 24
	v ^= uint32(reduceBytes[i1]) << 8
	i2 := (v >> 16) & 0xFF
	v ^= uint32(reduceBytes[i2])
	return uint16(v)
}

// polyMul computes the unreduced carryless (polynomial) product of two u16
// values, returning a u32. Matches Rust's unaccelerated::poly_mul.
func polyMul(a, b uint16) uint32 {
	var acc uint32
	me := uint32(a)
	for shift := uint32(0); shift < 16; shift++ {
		if uint32(b)&(1<<shift) != 0 {
			acc ^= me << shift
		}
	}
	return acc
}

// rawMul multiplies two u16 field elements, returning a u16 result reduced
// modulo Poly. Matches Rust's unaccelerated::mul.
func rawMul(a, b uint16) uint16 {
	return polyReduce(polyMul(a, b))
}

// New constructs a GF16 element from a uint16 value.
// Mirrors Rust's GF16::new(v).
func New(v uint16) GF16 {
	return GF16{Value: v}
}

// Add returns the sum of g and other in GF(2^16).
// In GF(2), addition is bitwise XOR. Matches Rust's Add impl.
func (g GF16) Add(other GF16) GF16 {
	return GF16{Value: g.Value ^ other.Value}
}

// AddAssign sets g to the sum of g and other in place.
// Matches Rust's AddAssign impl.
func (g *GF16) AddAssign(other GF16) {
	g.Value ^= other.Value
}

// Sub returns the difference of g and other in GF(2^16).
// In GF(2), subtraction is identical to addition (XOR). Matches Rust's Sub impl.
func (g GF16) Sub(other GF16) GF16 {
	return GF16{Value: g.Value ^ other.Value}
}

// SubAssign sets g to the difference of g and other in place.
// Matches Rust's SubAssign impl.
func (g *GF16) SubAssign(other GF16) {
	g.Value ^= other.Value
}

// Mul returns the product of g and other in GF(2^16).
// Uses polynomial long multiplication followed by reduction modulo Poly.
// Matches Rust's Mul impl (via unaccelerated::mul).
func (g GF16) Mul(other GF16) GF16 {
	return GF16{Value: rawMul(g.Value, other.Value)}
}

// MulAssign sets g to the product of g and other in place.
// Matches Rust's MulAssign impl.
func (g *GF16) MulAssign(other GF16) {
	g.Value = rawMul(g.Value, other.Value)
}

// Inv returns the multiplicative inverse of g in GF(2^16).
// Uses Fermat's little theorem: inv(a) = a^(2^16 - 2).
// Returns ErrInvalidInverse if g is zero (which has no inverse).
//
// Note: Rust's div_impl computes self / other = self * inv(other). The Go Inv
// method implements the same exponentiation using the same squaring schedule,
// but applied to a single element.
func (g GF16) Inv() (GF16, error) {
	if g.Value == 0 {
		return Zero, ErrInvalidInverse{}
	}
	return GF16{Value: divImpl(One.Value, g.Value)}, nil
}

// divImpl computes num * denom^(2^16-2) = num / denom using Fermat's little
// theorem in GF(2^16). denom must be non-zero.
//
// This is a direct port of Rust's div_impl / const_div:
//
//	square = denom * denom    // denom^2
//	out = num
//	for i in 1..16:
//	  square, out = square*square, out*square
//	  // after i=k: square=denom^(2^(k+1)*2), out=num*denom^(2^(k+1)-2)
//	  // after i=15: out = num * denom^(2^16-2) = num / denom
func divImpl(num, denom uint16) uint16 {
	square := rawMul(denom, denom) // denom^2
	out := num
	for range 15 { // i in 1..16 (15 iterations)
		square, out = rawMul(square, square), rawMul(out, square)
	}
	return out
}

// Div returns g divided by other in GF(2^16).
// Returns ErrInvalidInverse if other is zero.
// Matches Rust's Div impl (via div_impl).
func (g GF16) Div(other GF16) (GF16, error) {
	if other.Value == 0 {
		return Zero, ErrInvalidInverse{}
	}
	return GF16{Value: divImpl(g.Value, other.Value)}, nil
}

// DivAssign sets g to g / other in place.
// Returns ErrInvalidInverse if other is zero.
// Matches Rust's DivAssign impl.
func (g *GF16) DivAssign(other GF16) error {
	if other.Value == 0 {
		return ErrInvalidInverse{}
	}
	g.Value = divImpl(g.Value, other.Value)
	return nil
}

// mul2 computes rawMul(a, b1) and rawMul(a, b2) together.
// Matches Rust's mul2_u16 (unaccelerated path).
func mul2(a, b1, b2 uint16) (uint16, uint16) {
	return rawMul(a, b1), rawMul(a, b2)
}

// ParallelMult multiplies each element of coeffs by m in place.
// Processes elements in pairs for efficiency (mirrors Rust's parallel_mult
// which uses mul2_u16 to process two elements at a time).
//
// Matches Rust's parallel_mult signature:
//
//	pub fn parallel_mult(a: GF16, into: &mut [GF16])
func ParallelMult(m GF16, coeffs []GF16) {
	i := 0
	for i+2 <= len(coeffs) {
		coeffs[i].Value, coeffs[i+1].Value = mul2(m.Value, coeffs[i].Value, coeffs[i+1].Value)
		i += 2
	}
	if i < len(coeffs) {
		coeffs[i].MulAssign(m)
	}
}

// ToBytes serializes g as a big-endian 2-byte array.
// Matches the serialization used in Rust's Pt::serialize and Poly::serialize
// (polynomial.rs), which write GF16 values as big-endian u16.
func (g GF16) ToBytes() [2]byte {
	return [2]byte{byte(g.Value >> 8), byte(g.Value)}
}

// FromBytes deserializes a GF16 element from a big-endian 2-byte array.
// This is the inverse of ToBytes.
func FromBytes(b [2]byte) GF16 {
	return GF16{Value: uint16(b[0])<<8 | uint16(b[1])}
}
