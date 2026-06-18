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

// NewKeyFromBytes generates a new IdentityKey from a raw 32-byte Curve25519
// public key. The offset parameter is unused and retained for API compatibility.
//
// NOTE: this constructor is infallible and performs no curve-point validation.
// A caller can construct a Key from 32 arbitrary bytes; any invalid-point
// failure will surface at first use (e.g. key agreement or signature verify).
// Rust's IdentityKey::decode returns Result<Self> via PublicKey::try_from which
// validates the point immediately (rust/protocol/src/identity_key.rs:50-54).
// If you need fail-fast validation, parse via ecc.DecodePoint and wrap the
// result with NewKey instead.
func NewKeyFromBytes(publicKey [32]byte, offset int) Key {
	identityKey := Key{
		publicKey: ecc.NewDjbECPublicKey(publicKey),
	}

	return identityKey
}

// Decode parses and validates a DjbType-prefixed (0x05) Curve25519 public key
// from a byte slice, returning a Key or an error on malformed input.
//
// This is the Go equivalent of Rust's IdentityKey::decode at
// rust/protocol/src/identity_key.rs:50, which calls PublicKey::try_from and
// validates the curve point immediately. Unlike NewKeyFromBytes, this function
// is fallible and performs immediate point validation via ecc.DecodePoint.
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
