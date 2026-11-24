package identity

import (
	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/proto/storagepb"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"google.golang.org/protobuf/proto"
)

// GenerateKeyPair generates a Curve25519 identity key pair from the OS CSPRNG (Rust IdentityKeyPair::generate).
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

// NewKeyPairFromBytes parses an IdentityKeyPairStructure: a 33-byte 0x05-prefixed public key and a 32-byte private scalar.
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

// Serialize encodes the KeyPair as an IdentityKeyPairStructure (Rust IdentityKeyPair::serialize).
func (k *KeyPair) Serialize() ([]byte, error) {
	privBytes := k.privateKey.Serialize()
	// Serialize returns an owned copy; the marshaled output is the caller's.
	defer crypto.ZeroizeArray32(&privBytes)
	structure := &storagepb.IdentityKeyPairStructure{
		PublicKey:  k.publicKey.Serialize(),
		PrivateKey: privBytes[:],
	}
	return proto.Marshal(structure)
}
