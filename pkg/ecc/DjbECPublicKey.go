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

// Equal compares the 32 key bytes in constant time, as Rust libsignal PublicKey (rust/core/src/curve.rs).
func (d *DjbECPublicKey) Equal(other *DjbECPublicKey) bool {
	if other == nil {
		return false
	}
	return subtle.ConstantTimeCompare(d.publicKey[:], other.publicKey[:]) == 1
}

// IsCanonical reports whether the key is torsion-free with sign 0 and encoded below 2^255 - 19, as Rust PublicKey::is_canonical.
func (d *DjbECPublicKey) IsCanonical() bool {
	return d.isTorsionFree() && d.scalarIsInRange()
}

// isTorsionFree converts the Montgomery point to Edwards with sign 0 and checks it has prime order, as Rust to_edwards(0).is_torsion_free().
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

// hasPrimeOrder reports whether [8]([8^-1 mod l] * P) == P, which holds only for points in the prime-order subgroup.
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

// scalarIsInRange reports whether the encoding is below 2^255 - 19, as Rust scalar_is_in_range.
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
