package ecc

import (
	"crypto/subtle"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
)

// cofactorInvBytes is 8^(-1) mod l in little-endian, where l is the prime order
// of the edwards25519 subgroup. Used to check whether a point is torsion-free.
var cofactorInvBytes = [32]byte{
	0x79, 0x2f, 0xdc, 0xe2, 0x29, 0xe5, 0x06, 0x61,
	0xd0, 0xda, 0x1c, 0x7d, 0xb3, 0x9d, 0xd3, 0x07,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
}

// NewDjbECPublicKey creates a new Curve25519 public key with the given bytes.
func NewDjbECPublicKey(publicKey [32]byte) *DjbECPublicKey {
	key := DjbECPublicKey{
		publicKey: publicKey,
	}
	return &key
}

// DjbECPublicKey implements the ECPublicKey interface and uses Curve25519.
type DjbECPublicKey struct {
	publicKey [32]byte
}

// PublicKey returns the EC public key as a byte array.
func (d *DjbECPublicKey) PublicKey() [32]byte {
	return d.publicKey
}

// Serialize returns the public key prepended by the DjbType value.
func (d *DjbECPublicKey) Serialize() []byte {
	return append([]byte{DjbType}, d.publicKey[:]...)
}

// Type returns the DjbType value.
func (d *DjbECPublicKey) Type() int {
	return DjbType
}

// Equal reports whether this public key equals other using a constant-time
// byte comparison.  Mirrors the subtle::ConstantTimeEq / PartialEq
// implementation on Rust libsignal's PublicKey (rust/core/src/curve.rs:201-218).
// The type byte is not compared separately; only the 32 key bytes are compared
// because two DjbECPublicKey values with the same 32-byte payload are identical.
func (d *DjbECPublicKey) Equal(other *DjbECPublicKey) bool {
	if other == nil {
		return false
	}
	return subtle.ConstantTimeCompare(d.publicKey[:], other.publicKey[:]) == 1
}

// IsCanonical returns true if the Curve25519 public key is canonical:
// the Montgomery point can be converted to an Edwards point that is torsion-free,
// and the scalar encoding is in the reduced range [0, p) where p = 2^255 - 19.
// This matches the Rust libsignal PublicKey::is_canonical() implementation.
func (d *DjbECPublicKey) IsCanonical() bool {
	return d.isTorsionFree() && d.scalarIsInRange()
}

// isTorsionFree checks that the Montgomery point, when converted to Edwards form
// using sign=0 (positive square root), is in the prime-order subgroup.
//
// This matches the Rust libsignal implementation which calls
// mont_point.to_edwards(0).is_some_and(|ed| ed.is_torsion_free()).
// Only sign=0 is checked; keys requiring sign=1 are rejected.
//
// Algorithm: convert Montgomery u-coordinate to Edwards y-coordinate via
// y = (u-1)/(u+1), reconstruct the Edwards point with sign bit 0, then
// verify prime order using the cofactor inverse trick:
// P has prime order iff [8]([8^{-1} mod l] * P) == P.
func (d *DjbECPublicKey) isTorsionFree() bool {
	u, err := new(field.Element).SetBytes(d.publicKey[:])
	if err != nil {
		return false
	}

	one := new(field.Element).One()
	num := new(field.Element).Subtract(u, one)
	den := new(field.Element).Add(u, one)

	// u + 1 == 0 mod p means no valid Edwards point exists.
	if den.Equal(new(field.Element)) == 1 {
		return false
	}

	inv := new(field.Element).Invert(den)
	y := new(field.Element).Multiply(num, inv)
	yBytes := y.Bytes()

	// Use sign=0 only (positive square root), matching Rust's to_edwards(0).
	// The high bit of yBytes encodes the sign; ensure it is cleared for sign=0.
	candidate := make([]byte, 32)
	copy(candidate, yBytes)
	candidate[31] &= 0x7F

	pt, err := new(edwards25519.Point).SetBytes(candidate)
	if err != nil {
		return false
	}

	// The identity point is not a valid public key.
	if pt.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return false
	}

	return hasPrimeOrder(pt)
}

// hasPrimeOrder checks whether the Edwards25519 point is in the prime-order
// subgroup by verifying [8]([8^{-1} mod l] * P) == P.
// This works because if P is in the prime-order-l subgroup, then
// [8^{-1} mod l] * P is also in that subgroup, and [8] is an isomorphism
// on the subgroup. If P has a torsion component, the torsion is destroyed
// by the scalar multiplication and [8] cannot recover it.
func hasPrimeOrder(pt *edwards25519.Point) bool {
	cofInv, err := edwards25519.NewScalar().SetCanonicalBytes(cofactorInvBytes[:])
	if err != nil {
		return false
	}

	q := new(edwards25519.Point).ScalarMult(cofInv, pt)
	eightQ := new(edwards25519.Point).MultByCofactor(q)
	return eightQ.Equal(pt) == 1
}

// ScalarIsInRange reports whether the Curve25519 public key encoding is
// in the reduced range [0, 2^255 - 19). Mirrors Rust libsignal_core's
// PublicKey::scalar_is_in_range at rust/core/src/curve.rs.
func (d *DjbECPublicKey) ScalarIsInRange() bool {
	return d.scalarIsInRange()
}

// scalarIsInRange checks that the Curve25519 public key encoding is in the
// reduced range [0, 2^255 - 19). Matches the Rust scalar_is_in_range() check:
//
//	!(k[31] & 0x80 != 0 || (k[0] >= 237 && k[1..31] == [0xFF; 30] && k[31] == 0x7F))
func (d *DjbECPublicKey) scalarIsInRange() bool {
	k := d.publicKey

	// High bit set means value >= 2^255, which is >= p.
	if k[31]&0x80 != 0 {
		return false
	}

	// Check the range [p, 2^255-1] where p = 2^255 - 19.
	// In little-endian: p = {0xed, 0xff...0xff, 0x7f}.
	// Values >= p have k[0] >= 237, k[1..30] all 0xFF, k[31] == 0x7F.
	if k[0] >= 237 {
		allFF := true
		for i := 1; i < 31; i++ {
			if k[i] != 0xFF {
				allFF = false
				break
			}
		}
		if allFF && k[31] == 0x7F {
			return false
		}
	}

	return true
}
