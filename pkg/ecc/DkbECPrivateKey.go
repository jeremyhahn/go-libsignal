package ecc

import "runtime"

// clampCurve25519 applies the Curve25519 clamping operation in-place.
// Mirrors Rust libsignal's scalar::clamp_integer (curve25519.rs:172 / curve.rs:247).
// Clamping ensures the scalar is a valid Curve25519 secret key:
//
//	key[0]  &= 248   — clear the three low bits
//	key[31] &= 127   — clear the high bit (cofactor)
//	key[31] |= 64    — set the second-highest bit (canonicalization)
func clampCurve25519(key *[32]byte) {
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
}

// NewDjbECPrivateKey returns a new EC private key with the given bytes after
// applying Curve25519 clamping.  Rust PrivateKey::From<[u8;32]> and
// PrivateKey::deserialize both call scalar::clamp_integer before storing the
// key; this constructor matches that behaviour so that serialize→deserialize
// round-trips are byte-for-byte identical to the Rust reference.
//
// Rust source: rust/core/src/curve/curve25519.rs:170-175; rust/core/src/curve.rs:246-247.
//
// WARNING: This constructor creates an unprotected DjbECPrivateKey and exists
// only for test vector construction. Production code MUST use
// NewGuardedECPrivateKey instead.
func NewDjbECPrivateKey(key [32]byte) *DjbECPrivateKey {
	clampCurve25519(&key)
	private := DjbECPrivateKey{
		privateKey: key,
	}
	return &private
}

// DjbECPrivateKey stores a private key in unprotected memory.
// WARNING: This type exists only for test vector construction.
// Production code MUST use GuardedECPrivateKey instead.
type DjbECPrivateKey struct {
	privateKey [32]byte
}

// PrivateKey returns the private key as a byte-array.
func (d *DjbECPrivateKey) PrivateKey() [32]byte {
	return d.privateKey
}

// Serialize returns the private key as a byte-array.
func (d *DjbECPrivateKey) Serialize() [32]byte {
	return d.privateKey
}

// Zeroize overwrites the private key material with zeros.
// runtime.KeepAlive prevents the compiler from eliminating the stores as dead writes.
func (d *DjbECPrivateKey) Zeroize() {
	for i := range d.privateKey {
		d.privateKey[i] = 0
	}
	runtime.KeepAlive(&d.privateKey)
}

// Type returns the EC type value.
func (d *DjbECPrivateKey) Type() int {
	return DjbType
}
