package ecc

import "runtime"

// NewDjbECPrivateKey returns a new EC private key with the given bytes.
// WARNING: This constructor creates an unprotected DjbECPrivateKey and exists
// only for test vector construction. Production code MUST use
// NewGuardedECPrivateKey instead.
func NewDjbECPrivateKey(key [32]byte) *DjbECPrivateKey {
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
