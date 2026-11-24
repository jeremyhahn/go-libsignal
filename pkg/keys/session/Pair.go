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

// NewKeyPairWithPQR returns a new session key pair that holds a root key, chain key,
// and an initial PQR (post-quantum ratchet) key for SPQR initialization.
// The pqrKey bytes are moved into locked memory; the source slice is
// zeroized by secret.New. Pass nil to indicate no PQR key (legacy v3 sessions).
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

// KeyPair is a session key pair that holds a single root and chain key pair. These
// keys are ratcheted after every message sent and every message round trip.
// InitialPQRKey holds the third derived key for SPQR initialization in
// locked memory. It is nil for legacy v3 sessions.
// Callers must invoke Zeroize() after consuming the PQR key.
type KeyPair struct {
	RootKey       RootKeyable
	ChainKey      ChainKeyable
	InitialPQRKey *secret.Secret
}

// Zeroize destroys the guarded PQR key material. This is idempotent and
// safe to call when InitialPQRKey is nil. Call this after the PQR key has
// been consumed by SPQR initialization.
func (kp *KeyPair) Zeroize() {
	if kp.InitialPQRKey != nil {
		kp.InitialPQRKey.Destroy()
	}
}
