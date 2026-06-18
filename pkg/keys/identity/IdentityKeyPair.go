package identity

import (
	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/proto/storagepb"
	"google.golang.org/protobuf/proto"
)

// GenerateKeyPair generates a fresh Curve25519 identity key pair using the
// OS CSPRNG. It is the Go equivalent of Rust's IdentityKeyPair::generate at
// rust/protocol/src/identity_key.rs:99.
//
// Callers that need only construction from existing key material should use
// NewKeyPair instead. util/keyhelper.GenerateIdentityKeyPair delegates to this
// function and remains for backwards compatibility.
func GenerateKeyPair() (*KeyPair, error) {
	kp, err := ecc.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	return NewKeyPair(NewKey(kp.PublicKey()), kp.PrivateKey()), nil
}

// NewKeyPair returns a new identity key with the given public and private keys.
func NewKeyPair(publicKey *Key, privateKey ecc.ECPrivateKeyable) *KeyPair {
	keyPair := KeyPair{
		publicKey:  publicKey,
		privateKey: privateKey,
	}

	return &keyPair
}

// NewKeyPairFromBytes deserializes an IdentityKeyPairStructure protobuf and
// returns the corresponding KeyPair.
//
// Wire format: proto.Marshal of storage.IdentityKeyPairStructure where
//   - public_key  = 33-byte DjbType-prefixed (0x05) Curve25519 public key
//   - private_key = 32-byte raw Curve25519 scalar
//
// Rust source: rust/protocol/src/identity_key.rs — TryFrom<&[u8]> for IdentityKeyPair (line 154)
func NewKeyPairFromBytes(b []byte) (*KeyPair, error) {
	var structure storagepb.IdentityKeyPairStructure
	if err := proto.Unmarshal(b, &structure); err != nil {
		return nil, ErrInvalidIdentityKeyPairProto
	}

	pub, err := ecc.DecodePoint(structure.GetPublicKey(), 0)
	if err != nil {
		return nil, &ErrInvalidIdentityKeyPairPublicKeyType{Err: err}
	}

	privBytes := structure.GetPrivateKey()
	if len(privBytes) != 32 {
		return nil, &ErrInvalidIdentityKeyPairPrivateKeyType{Got: len(privBytes)}
	}

	var privArray [32]byte
	copy(privArray[:], privBytes)
	priv := ecc.NewDjbECPrivateKey(privArray)

	return NewKeyPair(NewKey(pub), priv), nil
}

// KeyPair is a holder for public and private identity key pair.
type KeyPair struct {
	publicKey  *Key
	privateKey ecc.ECPrivateKeyable
}

// PublicKey returns the identity key's public key.
func (k *KeyPair) PublicKey() *Key {
	return k.publicKey
}

// PrivateKey returns the identity key's private key.
func (k *KeyPair) PrivateKey() ecc.ECPrivateKeyable {
	return k.privateKey
}

// Serialize encodes the KeyPair as an IdentityKeyPairStructure protobuf.
//
// Wire format: proto.Marshal of storage.IdentityKeyPairStructure where
//   - public_key  = 33-byte DjbType-prefixed (0x05) Curve25519 public key
//   - private_key = 32-byte raw Curve25519 scalar
//
// Rust source: rust/protocol/src/identity_key.rs — IdentityKeyPair::serialize (line 127)
func (k *KeyPair) Serialize() ([]byte, error) {
	privBytes := k.privateKey.Serialize()
	structure := &storagepb.IdentityKeyPairStructure{
		PublicKey:  k.publicKey.Serialize(),
		PrivateKey: privBytes[:],
	}
	return proto.Marshal(structure)
}
