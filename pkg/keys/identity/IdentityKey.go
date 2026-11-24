// Package identity provides identity keys used for verifying the identity
// of a signal user.
package identity

import (
	"encoding/hex"
	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
)

// NewKey wraps an ECPublicKey in an IdentityKey.
// This is the Go equivalent of Rust's IdentityKey::new at
// rust/protocol/src/identity_key.rs:40.
func NewKey(publicKey ecc.ECPublicKeyable) *Key {
	identityKey := Key{
		publicKey: publicKey,
	}

	return &identityKey
}

// NewKeyFromBytes wraps a raw 32-byte Curve25519 key without validation (offset is unused); use ecc.DecodePoint for fail-fast checks.
func NewKeyFromBytes(publicKey [32]byte, offset int) Key {
	identityKey := Key{
		publicKey: ecc.NewDjbECPublicKey(publicKey),
	}

	return identityKey
}

// Decode parses a 0x05-prefixed Curve25519 public key, checking type and length; point validation waits for first use, as in Rust.
func Decode(value []byte) (*Key, error) {
	pub, err := ecc.DecodePoint(value, 0)
	if err != nil {
		return nil, err
	}
	return NewKey(pub), nil
}

// Key is a structure for representing an identity key. This same structure can
// be used for verifying recipient's identity key or storing our own identity key.
type Key struct {
	publicKey ecc.ECPublicKeyable
}

// Fingerprint gets the string fingerprint representation of the public key.
func (k *Key) Fingerprint() string {
	return hex.EncodeToString(k.publicKey.Serialize())
}

// PublicKey returns the EC Public key of the identity key
func (k *Key) PublicKey() ecc.ECPublicKeyable {
	return k.publicKey
}

// Serialize returns the serialized version of the key
func (k *Key) Serialize() []byte {
	return k.publicKey.Serialize()
}
