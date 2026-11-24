package keyops

import "github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"

// KeyAgreement abstracts X25519 key agreement over software or hardware-held private keys.
type KeyAgreement interface {
	// Agreement returns the X25519 shared secret with the peer's public key; the caller destroys it.
	Agreement(peerPublic [32]byte) (*secret.Secret32, error)

	// PublicKey returns the corresponding public key (32 bytes for Curve25519).
	PublicKey() [32]byte

	// Destroy zeroizes the private key material. This method is idempotent
	// and safe to call multiple times. For hardware-backed keys, this is a
	// no-op since the hardware manages key lifecycle.
	Destroy()
}

// PrivateKey combines XEdDSA signing and X25519 agreement for a Curve25519 private key.
type PrivateKey interface {
	Signer
	KeyAgreement
}
