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
// The key material is moved into memguard-protected memory and the source
// slice is zeroized by memguard. Panics if the memguard allocation fails
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
// The key bytes are copied before being moved into guarded memory so that
// the source structure is not zeroized by memguard.
func NewKeyFromStruct(structure *KeyStructure, kdf kdf.HKDF) *Key {
	keyCopy := make([]byte, len(structure.Key))
	copy(keyCopy, structure.Key)
	return NewKey(
		kdf,
		keyCopy,
		structure.Index,
	)
}

// NewStructFromKey will return a chain key structure for serialization.
// The returned structure contains a copy of the key bytes for safe serialization.
// Callers must call Zeroize() on the returned structure after the serializer
// has consumed it to prevent key material lingering on the heap.
func NewStructFromKey(key *Key) *KeyStructure {
	keyBytes := key.key.Bytes()
	keyCopy := make([]byte, len(keyBytes))
	copy(keyCopy, keyBytes)
	return &KeyStructure{
		Key:   keyCopy,
		Index: key.index,
	}
}

// KeyStructure is a serializeable structure for chain keys.
type KeyStructure struct {
	Key   []byte
	Index uint32
}

// Zeroize overwrites all sensitive key material in the structure with zeros.
// Call this (via defer) after the structure has been serialized to prevent
// plaintext key bytes from lingering in heap memory.
func (k *KeyStructure) Zeroize() {
	for i := range k.Key {
		k.Key[i] = 0
	}
}

// Key is used for generating message keys. This key "ratchets" every time a
// message key is generated. Every time the chain key ratchets forward, its index
// increases by one. The key material is stored in memguard-protected memory.
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
// new key is moved into guarded memory. The source slice is zeroized by memguard.
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
// The old chain key material is destroyed via memguard per Signal spec
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
