package ecc

// KeySize is the size of EC keys (32) with the EC type byte prepended to it.
const KeySize int = 33

// ECPublicKeyable is an interface for all elliptic curve public keys.
type ECPublicKeyable interface {
	Serialize() []byte
	Type() int
	PublicKey() [32]byte
	// IsCanonical returns true if the public key encoding is canonical:
	// the point is torsion-free and the scalar is in the reduced range [0, p).
	// This matches the Rust libsignal PublicKey::is_canonical() check.
	IsCanonical() bool
}
