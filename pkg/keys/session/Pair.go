// Package session provides a simple structure for session keys, which is
// a pair of root and chain keys for a session.
package session

import (
	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/chain"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/message"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// RootKeyable is an interface for all root key implementations that are part of
// a session keypair.
type RootKeyable interface {
	Bytes() []byte
	CreateChain(theirRatchetKey ecc.ECPublicKeyable, ourRatchetKey *ecc.ECKeyPair) (*KeyPair, error)
}

// ChainKeyable is an interface for all chain key implementations that are part of
// a session keypair.
type ChainKeyable interface {
	Key() []byte
	Index() uint32
	NextKey() *chain.Key
	MessageKeys() (*message.Keys, error)
	MessageKeysWithSalt(pqrSalt []byte) (*message.Keys, error)
	MessageKeysWithSeed() (*message.Keys, error)
	Current() *chain.Key
}

// NewKeyPair returns a new session key pair that holds a root and chain key.
func NewKeyPair(rootKey RootKeyable, chainKey ChainKeyable) *KeyPair {
	keyPair := KeyPair{
		RootKey:  rootKey,
		ChainKey: chainKey,
	}

	return &keyPair
}

// NewKeyPairWithPQR returns a session key pair with an initial PQR key in locked memory; nil means a v3 session.
func NewKeyPairWithPQR(rootKey RootKeyable, chainKey ChainKeyable, pqrKey []byte) (*KeyPair, error) {
	if pqrKey == nil {
		return &KeyPair{
			RootKey:       rootKey,
			ChainKey:      chainKey,
			InitialPQRKey: nil,
		}, nil
	}
	guarded, err := secret.New(pqrKey)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		RootKey:       rootKey,
		ChainKey:      chainKey,
		InitialPQRKey: guarded,
	}, nil
}

// KeyPair holds a session's root and chain keys and, except for v3 sessions, the initial PQR key; call Zeroize after use.
type KeyPair struct {
	RootKey       RootKeyable
	ChainKey      ChainKeyable
	InitialPQRKey *secret.Secret
}

// Zeroize destroys the PQR key; it is idempotent.
func (kp *KeyPair) Zeroize() {
	if kp.InitialPQRKey != nil {
		kp.InitialPQRKey.Destroy()
	}
}
