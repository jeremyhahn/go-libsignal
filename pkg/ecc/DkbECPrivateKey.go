package ecc

import "runtime"

// clampCurve25519 clamps in place: key[0] &= 248, key[31] &= 127, key[31] |= 64.
func clampCurve25519(key *[32]byte) {
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
}

// NewDjbECPrivateKey returns an unprotected clamped key for test vectors only; production code uses NewGuardedECPrivateKey.
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
