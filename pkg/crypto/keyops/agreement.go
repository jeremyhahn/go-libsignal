package keyops

import "github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"

// KeyAgreement abstracts ECDH key agreement operations.
// Software implementations perform X25519 Diffie-Hellman using
// locked-memory-protected private keys. Hardware implementations delegate to the secure
// element without exposing raw key material.
type KeyAgreement interface {
	// Agreement performs X25519 Diffie-Hellman with the peer's public key.
	// Returns the 32-byte shared secret in a guarded Secret32.
	// The caller is responsible for destroying the returned secret when
	// it is no longer needed.
	Agreement(peerPublic [32]byte) (*secret.Secret32, error)

	// PublicKey returns the corresponding public key (32 bytes for Curve25519).
	PublicKey() [32]byte

	// Destroy zeroizes the private key material. This method is idempotent
	// and safe to call multiple times. For hardware-backed keys, this is a
	// no-op since the hardware manages key lifecycle.
	Destroy()
}

// PrivateKey combines signing and key agreement for EC private keys.
// This is the primary interface for Curve25519 private keys in the Signal
// protocol, where the same key is used for both XEdDSA signatures and
// X25519 key agreement.
type PrivateKey interface {
	Signer
	KeyAgreement
}
