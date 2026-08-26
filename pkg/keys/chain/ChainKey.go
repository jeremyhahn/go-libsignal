// Package chain provides chain keys used in double ratchet sessions.
package chain

import (
	"crypto/hmac"
	"crypto/sha256"

	"github.com/jeremyhahn/go-libsignal/pkg/kdf"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/message"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

var messageKeySeed = []byte{0x01}
var chainKeySeed = []byte{0x02}

// NewKey returns a new chain key with the given kdf, key, and index.
// The key material is moved into locked memory and the source
// slice is zeroized by go-enclave. Panics if the locked-memory allocation fails
// (fatal condition).
func NewKey(kdf kdf.HKDF, key []byte, index uint32) *Key {
	guardedKey, err := secret.New(key)
	if err != nil {
		panic("chain: failed to allocate guarded memory for chain key: " + err.Error())
	}
	return &Key{
		kdf:   kdf,
		key:   guardedKey,
		index: index,
	}
}

// NewKeyFromStruct will return a chain key built from the given structure.
// The key is cloned from the structure's guarded memory straight into the
// returned key's own guarded memory, so the material never lands on the Go
// heap and the source structure is left intact for its owner to Zeroize.
//
// Returns *MissingKeyError if the structure carries no key material — a chain
// key is mandatory, and decoding one that is absent or already destroyed must
// fail rather than yield a Key nothing can ratchet.
func NewKeyFromStruct(structure *KeyStructure, kdf kdf.HKDF) (*Key, error) {
	if structure == nil || structure.Key.IsZero() {
		return nil, &MissingKeyError{}
	}
	guardedKey, err := structure.Key.Clone()
	if err != nil {
		return nil, err
	}
	return &Key{
		kdf:   kdf,
		key:   guardedKey,
		index: structure.Index,
	}, nil
}

// NewStructFromKey will return a chain key structure for serialization.
// The key is cloned guarded-to-guarded, so serialization no longer stages the
// chain key on the heap. Callers must call Zeroize() on the returned structure
// once the serializer has consumed it.
func NewStructFromKey(key *Key) (*KeyStructure, error) {
	cloned, err := key.key.Clone()
	if err != nil {
		return nil, err
	}
	return &KeyStructure{
		Key:   secret.FromSecret(cloned),
		Index: key.index,
	}, nil
}

// KeyStructure is a serializeable structure for chain keys. The key is held in
// guarded memory: it crosses the storage boundary, and a chain key on the
// plain heap can be swapped out or captured in a core dump, which zeroizing it
// afterwards does not undo.
type KeyStructure struct {
	Key   secret.Secret
	Index uint32
}

// Zeroize releases the guarded chain key. Call this (via defer) after the
// structure has been serialized. It is idempotent.
func (k *KeyStructure) Zeroize() {
	k.Key.Destroy()
}

// Key is used for generating message keys. This key "ratchets" every time a
// message key is generated. Every time the chain key ratchets forward, its index
// increases by one. The key material is stored in locked memory.
type Key struct {
	kdf   kdf.HKDF
	key   *secret.Secret
	index uint32 // Index's maximum size: 4,294,967,295
}

// Current returns the current ChainKey struct.
func (c *Key) Current() *Key {
	return c
}

// Key returns the ChainKey's key material as a view into guarded memory.
// The returned slice must not be retained beyond the lifetime of this Key.
func (c *Key) Key() []byte {
	return c.key.Bytes()
}

// SetKey replaces the ChainKey's key material. The old key is destroyed and the
// new key is moved into guarded memory. The source slice is zeroized by go-enclave.
func (c *Key) SetKey(key []byte) {
	if c.key != nil {
		c.key.Destroy()
	}
	guardedKey, err := secret.New(key)
	if err != nil {
		panic("chain: failed to allocate guarded memory for chain key: " + err.Error())
	}
	c.key = guardedKey
}

// Index returns how many times the ChainKey has been "ratcheted" forward.
func (c *Key) Index() uint32 {
	return c.index
}

// SetIndex sets how many times the ChainKey has been "ratcheted" forward.
func (c *Key) SetIndex(index uint32) {
	c.index = index
}

// NextKey uses the key derivation function to generate a new ChainKey.
// The old chain key material is destroyed via go-enclave per Signal spec
// Section 8.1 to ensure deleted keys are not recoverable.
func (c *Key) NextKey() *Key {
	nextKey := c.BaseMaterial(chainKeySeed)
	// nextKey is consumed by NewKey (moved into guarded memory), but we
	// defer-zeroize the backing array in case NewKey panics before consuming it.
	defer crypto.Zeroize(nextKey)
	c.key.Destroy()
	return NewKey(c.kdf, nextKey, c.index+1)
}

// MessageKeys returns message keys, which includes the cipherkey, mac, iv, and index.
// Intermediate key material is protected in guarded memory and zeroized after use
// to limit exposure of sensitive data.
func (c *Key) MessageKeys() (*message.Keys, error) {
	return c.MessageKeysWithSalt(nil)
}

// MessageKeysWithSalt derives message keys using an optional HKDF salt (PQR key).
// When pqrSalt is nil, this produces identical output to MessageKeys().
func (c *Key) MessageKeysWithSalt(pqrSalt []byte) (*message.Keys, error) {
	inputKeyMaterial := c.BaseMaterial(messageKeySeed)
	defer crypto.Zeroize(inputKeyMaterial)
	return deriveMessageKeysFromSeed(c.kdf, inputKeyMaterial, pqrSalt, c.Index())
}

// MessageKeysWithSeed derives message keys and attaches the seed material to the
// result, enabling later re-derivation with a different HKDF salt (e.g., SPQR).
// This is used for skipped message keys in SPQR sessions.
func (c *Key) MessageKeysWithSeed() (*message.Keys, error) {
	inputKeyMaterial := c.BaseMaterial(messageKeySeed)
	defer crypto.Zeroize(inputKeyMaterial)
	// Save a copy of the seed before it gets consumed by deriveMessageKeysFromSeed.
	seedCopy := make([]byte, len(inputKeyMaterial))
	copy(seedCopy, inputKeyMaterial)

	keys, err := deriveMessageKeysFromSeed(c.kdf, inputKeyMaterial, nil, c.Index())
	if err != nil {
		crypto.Zeroize(seedCopy)
		return nil, err
	}
	keys.SetSeedMaterial(seedCopy)
	return keys, nil
}

// DeriveMessageKeysFromSeed performs the HKDF derivation from raw seed material
// with an optional PQR salt. This is used to re-derive skipped message keys when
// the original message arrives with SPQR post-quantum ratchet data.
// The inputKeyMaterial slice is consumed (moved into guarded memory).
func DeriveMessageKeysFromSeed(kdfFunc kdf.HKDF, inputKeyMaterial []byte, pqrSalt []byte, index uint32) (*message.Keys, error) {
	return deriveMessageKeysFromSeed(kdfFunc, inputKeyMaterial, pqrSalt, index)
}

// deriveMessageKeysFromSeed performs the HKDF derivation from raw seed material.
// The inputKeyMaterial slice is consumed (moved into guarded memory).
func deriveMessageKeysFromSeed(kdfFunc kdf.HKDF, inputKeyMaterial []byte, pqrSalt []byte, index uint32) (*message.Keys, error) {
	inputKeySecret, err := secret.New(inputKeyMaterial)
	if err != nil {
		panic("chain: failed to allocate guarded memory for input key material: " + err.Error())
	}
	defer inputKeySecret.Destroy()

	keyMaterialBytes, err := kdfFunc(inputKeySecret.Bytes(), pqrSalt, []byte(message.KdfInfo), message.DerivedSecretsSize)
	if err != nil {
		return nil, err
	}
	keyMaterialSecret, secErr := secret.New(keyMaterialBytes)
	if secErr != nil {
		panic("chain: failed to allocate guarded memory for derived key material: " + secErr.Error())
	}
	defer keyMaterialSecret.Destroy()

	keyMaterial := newKeyMaterial(keyMaterialSecret.Bytes())

	// Use the key material returned from the key derivation function for our cipherkey, mac, and iv.
	messageKeys := message.NewKeys(
		keyMaterial.CipherKey, // Use the first 32 bytes of the key material for the CipherKey
		keyMaterial.MacKey,    // Use bytes 32-64 of the key material for the MacKey
		keyMaterial.IV,        // Use the last 16 bytes for the IV.
		index,                 // Attach the chain key's index to the message keys.
	)

	return messageKeys, nil
}

// Zeroize destroys the guarded memory holding the chain key material.
// This method is idempotent and safe to call multiple times.
func (c *Key) Zeroize() {
	if c.key != nil {
		c.key.Destroy()
	}
}

// BaseMaterial uses hmac to derive the base material used in the key derivation function for a new key.
func (c *Key) BaseMaterial(seed []byte) []byte {
	mac := hmac.New(sha256.New, c.key.Bytes())
	mac.Write(seed)

	return mac.Sum(nil)
}

// NewKeyMaterial takes an 80-byte slice derived from a key derivation function and splits
// it into the cipherkey, mac, and iv.
func newKeyMaterial(keyMaterialBytes []byte) *kdf.KeyMaterial {
	cipherKey := make([]byte, 32)
	macKey := make([]byte, 32)
	iv := make([]byte, 16)
	copy(cipherKey, keyMaterialBytes[:32])
	copy(macKey, keyMaterialBytes[32:64])
	copy(iv, keyMaterialBytes[64:80])

	keyMaterial := kdf.KeyMaterial{
		CipherKey: cipherKey,
		MacKey:    macKey,
		IV:        iv,
	}

	return &keyMaterial
}
