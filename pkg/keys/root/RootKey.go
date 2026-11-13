// Package root provides root keys which are used to derive new chain and
// root keys in a ratcheting session.
package root

import (
	"errors"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/kdf"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/chain"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/session"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// DerivedSecretsSize is the size of the initial session key derivation.
// Produces 96 bytes (3x32): RootKey + ChainKey + InitialPQRKey, matching
// the Rust derive_keys which returns (RootKey, ChainKey, InitialPQRKey).
const DerivedSecretsSize = 96

// ChainDerivedSecretsSize is the size of the chain ratchet step derivation.
// Produces 64 bytes (2x32): RootKey + ChainKey. The ratchet step
// (Rust RootKey::create_chain) only derives two keys, not three.
const ChainDerivedSecretsSize = 64

// KdfInfo is used as the info for message keys to derive secrets using a Key Derivation Function
const KdfInfo string = "WhisperRatchet"

// KdfInfoPQXDH is used as the HKDF info label when PQXDH (post-quantum extended Diffie-Hellman)
// key agreement is used, incorporating CRYSTALS-KYBER-1024 alongside X25519.
const KdfInfoPQXDH string = "WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024"

// NewKey returns a new RootKey given the key derivation function and bytes.
// The key material is moved into locked memory and the source
// slice is zeroized by go-enclave. Panics if the locked-memory allocation fails
// (fatal condition).
func NewKey(kdf kdf.HKDF, key []byte) *Key {
	guardedKey, err := secret.New(key)
	if err != nil {
		panic("root: failed to allocate guarded memory for root key: " + err.Error())
	}
	return &Key{
		kdf: kdf,
		key: guardedKey,
	}
}

// Key is a structure for RootKeys, which are used to derive a new set of chain and root
// keys for every round trip of messages. The key material is stored in locked memory.
type Key struct {
	kdf kdf.HKDF
	key *secret.Secret
}

// Bytes returns a copy of the RootKey bytes, made inside a WithBytes borrow
// of the guarded memory. A destroyed, missing or wrong-length key is an
// error, never a nil copy, so it cannot be persisted as an absent root key.
// The caller should wipe the copy after use.
func (k *Key) Bytes() ([]byte, error) {
	var out []byte
	if err := k.key.WithBytes(func(b []byte) error {
		if len(b) != rootKeyLength {
			return &session.KeyLengthError{Field: "root key", Got: len(b), Want: rootKeyLength}
		}
		out = append(make([]byte, 0, rootKeyLength), b...)
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// ErrEmptyRootKey is returned when a root key has no key material.
// Using it as the HKDF salt would derive the next root and chain keys
// from the DH output alone.
var ErrEmptyRootKey = errors.New("root: root key is empty")

// rootKeyLength is the length of a root key.
const rootKeyLength = 32

// CreateChain creates a new RootKey and ChainKey from the recipient's ratchet key and our private key.
func (k *Key) CreateChain(theirRatchetKey ecc.ECPublicKeyable, ourRatchetKey *ecc.ECKeyPair) (*session.KeyPair, error) {
	keyMaterial := make([]byte, 32)
	theirPublicKey := theirRatchetKey.PublicKey()
	ourPrivateKey := ourRatchetKey.PrivateKey().Serialize()

	// Use our key derivation function to calculate a shared secret.
	sharedSecret, dhErr := kdf.CalculateSharedSecret(theirPublicKey, ourPrivateKey)
	if dhErr != nil {
		return nil, dhErr
	}
	defer crypto.ZeroizeArray32(&sharedSecret)
	defer crypto.ZeroizeArray32(&ourPrivateKey)
	copy(keyMaterial, sharedSecret[:])
	var derivedSecretBytes []byte
	err := k.key.WithBytes(func(rootKey []byte) error {
		// WithBytes borrows a nil or zero Secret as nil; refuse it.
		if len(rootKey) == 0 {
			return ErrEmptyRootKey
		}
		var dErr error
		derivedSecretBytes, dErr = kdf.DeriveSecrets(keyMaterial, rootKey, []byte(KdfInfo), ChainDerivedSecretsSize)
		return dErr
	})
	crypto.Zeroize(keyMaterial)
	if err != nil {
		return nil, err
	}

	// Split the derived secret bytes in half, using one half for the root key and the second for the chain key.
	derivedSecrets := session.NewDerivedSecrets(derivedSecretBytes)

	// Copy bytes out of guarded memory before passing to constructors,
	// since NewKey/chain.NewKey will move data into new guarded memory
	// and zeroize the source (which cannot be done on locked-memory views).
	// The accessors return owned 32-byte copies; a failed copy is an error,
	// never a zero key.
	rootKeyBytes, err := derivedSecrets.RootKey()
	if err != nil {
		derivedSecrets.Zeroize()
		return nil, err
	}
	chainKeyBytes, err := derivedSecrets.ChainKey()
	derivedSecrets.Zeroize()
	if err != nil {
		crypto.Zeroize(rootKeyBytes)
		return nil, err
	}

	// Create new root and chain key structures from the derived secrets.
	rootKey := NewKey(k.kdf, rootKeyBytes)
	chainKey := chain.NewKey(k.kdf, chainKeyBytes, 0)

	// Create a session keypair with the generated root and chain keys.
	keyPair := session.NewKeyPair(
		rootKey,
		chainKey,
	)

	return keyPair, nil
}

// Zeroize destroys the guarded memory holding the root key material.
// This method is idempotent and safe to call multiple times.
func (k *Key) Zeroize() {
	if k.key != nil {
		k.key.Destroy()
	}
}
