// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Package gf implements GF(2^16) arithmetic with POLY 0x1100b, byte-identical to the Rust sparsepostquantumratchet crate.
package gf

// Poly is the primitive polynomial x^16 + x^12 + x^3 + x + 1 (Rust POLY = 0x1100b).
const Poly uint32 = 0x1100b

// ErrInvalidInverse is returned when computing the multiplicative inverse of
// zero, which is undefined in GF(2^16).
type ErrInvalidInverse struct{}

// Error implements the error interface.
func (ErrInvalidInverse) Error() string {
	return "gf: zero has no multiplicative inverse"
}

// GF16 is a GF(2^16) element; bit i of Value is the coefficient of x^i.
type GF16 struct {
	// Value is the underlying field element in polynomial representation.
	Value uint16
}

// Zero is the additive identity in GF(2^16). Matches Rust's GF16::ZERO.
var Zero = GF16{Value: 0}

// One is the multiplicative identity in GF(2^16). Matches Rust's GF16::ONE.
var One = GF16{Value: 1}

// reduceBytes[b] is the XOR contribution of byte b in the high bits of an unreduced product (Rust REDUCE_BYTES).
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

// Inv returns g^(2^16-2), the inverse of g, or ErrInvalidInverse for zero.
func (g GF16) Inv() (GF16, error) {
	if g.Value == 0 {
		return Zero, ErrInvalidInverse{}
	}
	return GF16{Value: divImpl(One.Value, g.Value)}, nil
}

// divImpl returns num * denom^(2^16-2) = num/denom for non-zero denom, a port of Rust div_impl.
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

// ParallelMult multiplies each element of coeffs by m in place, two at a time (Rust parallel_mult).
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
