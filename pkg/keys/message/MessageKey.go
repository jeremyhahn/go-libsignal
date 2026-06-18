// Package message provides a structure for message keys, which are symmetric
// keys used for the encryption/decryption of Signal messages.
package message

import (
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// DerivedSecretsSize is the size of the derived secrets for message keys.
const DerivedSecretsSize = 80

// CipherKeyLength is the length of the actual cipher key used for messages.
const CipherKeyLength = 32

// MacKeyLength is the length of the message authentication code in bytes.
const MacKeyLength = 32

// IVLength is the length of the initialization vector in bytes.
const IVLength = 16

// KdfInfo is the HKDF info parameter used when deriving message keys.
// Despite the historical name "WhisperMessageKeys", this string is passed
// as the HKDF info (context) parameter, not the salt.
const KdfInfo string = "WhisperMessageKeys"

// NewKeys returns a new message keys structure with the given cipherKey, mac, iv, and index.
// Each key component is moved into memguard-protected memory and the source slices
// are zeroized by memguard. Panics if memguard allocation fails (fatal condition).
func NewKeys(cipherKey, macKey, iv []byte, index uint32) *Keys {
	guardedCipher, err := secret.New(cipherKey)
	if err != nil {
		panic("message: failed to allocate guarded memory for cipher key: " + err.Error())
	}
	guardedMac, err := secret.New(macKey)
	if err != nil {
		guardedCipher.Destroy()
		panic("message: failed to allocate guarded memory for mac key: " + err.Error())
	}
	guardedIV, err := secret.New(iv)
	if err != nil {
		guardedCipher.Destroy()
		guardedMac.Destroy()
		panic("message: failed to allocate guarded memory for iv: " + err.Error())
	}
	return &Keys{
		cipherKey: guardedCipher,
		macKey:    guardedMac,
		iv:        guardedIV,
		index:     index,
	}
}

// NewSeedOnlyKeys creates a Keys containing only seed material and an index.
// The cipher/mac/iv fields are nil; the caller MUST re-derive the actual keys
// via chain.DeriveMessageKeysFromSeed before encryption/decryption.
// This matches Rust's MessageKeyGenerator::Seed variant, which defers full
// derivation until the PQR salt is known at rust/protocol/src/ratchet/keys.rs:29-43.
func NewSeedOnlyKeys(index uint32, seed []byte) *Keys {
	seedCopy := make([]byte, len(seed))
	copy(seedCopy, seed)
	guardedSeed, err := secret.New(seedCopy)
	if err != nil {
		panic("message: failed to allocate guarded memory for seed-only key: " + err.Error())
	}
	return &Keys{
		index:        index,
		seedMaterial: guardedSeed,
	}
}

// NewKeysFromStruct will return a new message keys object from the
// given serializeable structure.
//
// When SeedMaterial is non-empty (seed-only form, matching Rust
// MessageKeyGenerator::from_pb Seed branch at
// rust/protocol/src/ratchet/keys.rs:85-86), only the seed and index are
// loaded; cipher_key, mac_key, and iv are left nil. The caller must
// re-derive the keys via DeriveMessageKeysFromSeed before use.
//
// When SeedMaterial is empty (derived-keys form, matching Rust Keys branch),
// cipher_key, mac_key, and iv are loaded into guarded memory.
//
// Panics if memguard allocation fails (fatal condition).
func NewKeysFromStruct(structure *KeysStructure) *Keys {
	// Seed-only form: matches Rust MessageKeyGenerator::from_pb Seed branch.
	if len(structure.SeedMaterial) > 0 {
		seedCopy := make([]byte, len(structure.SeedMaterial))
		copy(seedCopy, structure.SeedMaterial)
		guardedSeed, err := secret.New(seedCopy)
		if err != nil {
			panic("message: failed to allocate guarded memory for seed material: " + err.Error())
		}
		return &Keys{
			index:        structure.Index,
			seedMaterial: guardedSeed,
		}
	}

	// Derived-keys form: matches Rust MessageKeyGenerator::from_pb Keys branch.
	cipherCopy := make([]byte, len(structure.CipherKey))
	copy(cipherCopy, structure.CipherKey)
	macCopy := make([]byte, len(structure.MacKey))
	copy(macCopy, structure.MacKey)
	ivCopy := make([]byte, len(structure.IV))
	copy(ivCopy, structure.IV)
	return NewKeys(cipherCopy, macCopy, ivCopy, structure.Index)
}

// NewStructFromKeys returns a serializeable structure of message keys.
//
// When seed material is present, the structure is written in seed-only form
// (cipher_key, mac_key, and iv are empty). This matches Rust's
// MessageKeyGenerator::into_pb for the Seed variant at
// rust/protocol/src/ratchet/keys.rs:54-60, which stores only the seed so
// that SPQR re-derivation with a different PQR salt remains possible at
// decrypt time. When no seed material is present, the fully-derived keys are
// stored (cipher_key, mac_key, iv populated; seed empty), matching the Keys
// variant of into_pb.
func NewStructFromKeys(keys *Keys) *KeysStructure {
	// Seed-only form: matches Rust MessageKeyGenerator::into_pb Seed variant.
	if keys.seedMaterial != nil && !keys.seedMaterial.IsDestroyed() {
		seedBytes := keys.seedMaterial.Bytes()
		seedCopy := make([]byte, len(seedBytes))
		copy(seedCopy, seedBytes)
		return &KeysStructure{
			Index:        keys.index,
			SeedMaterial: seedCopy,
		}
	}

	// Derived-keys form: matches Rust MessageKeyGenerator::into_pb Keys variant.
	cipherBytes := keys.cipherKey.Bytes()
	macBytes := keys.macKey.Bytes()
	ivBytes := keys.iv.Bytes()

	cipherCopy := make([]byte, len(cipherBytes))
	copy(cipherCopy, cipherBytes)
	macCopy := make([]byte, len(macBytes))
	copy(macCopy, macBytes)
	ivCopy := make([]byte, len(ivBytes))
	copy(ivCopy, ivBytes)

	return &KeysStructure{
		CipherKey: cipherCopy,
		MacKey:    macCopy,
		IV:        ivCopy,
		Index:     keys.index,
	}
}

// KeysStructure is a serializeable structure of message keys.
type KeysStructure struct {
	CipherKey    []byte
	MacKey       []byte
	IV           []byte
	Index        uint32
	SeedMaterial []byte `json:",omitempty"`
}

// Zeroize overwrites all sensitive key material in the structure with zeros.
// Call this (via defer) after the structure has been serialized to prevent
// plaintext key bytes from lingering in heap memory.
func (k *KeysStructure) Zeroize() {
	for i := range k.CipherKey {
		k.CipherKey[i] = 0
	}
	for i := range k.MacKey {
		k.MacKey[i] = 0
	}
	for i := range k.IV {
		k.IV[i] = 0
	}
	for i := range k.SeedMaterial {
		k.SeedMaterial[i] = 0
	}
}

// Keys is a structure to hold all the keys for a single MessageKey, including the
// cipherKey, mac, iv, and index of the chain key. MessageKeys are used to
// encrypt individual messages. All key material is stored in memguard-protected memory.
//
// SeedMaterial optionally holds the 32-byte HMAC output (BaseMaterial) from which
// the keys were derived. When present, it allows re-derivation with a different HKDF
// salt (e.g., for SPQR post-quantum ratchet). This is used for skipped message keys
// that may later need PQR-salted re-derivation. It is stored in memguard-protected
// memory alongside the other key components.
type Keys struct {
	cipherKey    *secret.Secret
	macKey       *secret.Secret
	iv           *secret.Secret
	index        uint32
	seedMaterial *secret.Secret
}

// CipherKey returns the key used to produce ciphertext as a view into guarded memory.
// The returned slice must not be retained beyond the lifetime of this Keys.
func (k *Keys) CipherKey() []byte {
	return k.cipherKey.Bytes()
}

// MacKey returns the message authentication code key as a view into guarded memory.
// The returned slice must not be retained beyond the lifetime of this Keys.
func (k *Keys) MacKey() []byte {
	return k.macKey.Bytes()
}

// Iv returns the initialization vector as a view into guarded memory.
// The returned slice must not be retained beyond the lifetime of this Keys.
func (k *Keys) Iv() []byte {
	return k.iv.Bytes()
}

// Index returns the number of times the chain key has been put through a key derivation
// function to generate this message key.
func (k *Keys) Index() uint32 {
	return k.index
}

// SeedMaterial returns a view into the guarded HMAC base material for re-derivation,
// or nil if no seed material is stored. The returned slice must not be retained
// beyond the lifetime of this Keys.
func (k *Keys) SeedMaterial() []byte {
	if k.seedMaterial == nil || k.seedMaterial.IsDestroyed() {
		return nil
	}
	return k.seedMaterial.Bytes()
}

// SetSeedMaterial stores the 32-byte HMAC base material for later re-derivation
// in memguard-protected memory. Any previously stored seed material is destroyed
// before the new value is stored. Panics if memguard allocation fails (fatal condition).
func (k *Keys) SetSeedMaterial(seed []byte) {
	if k.seedMaterial != nil {
		k.seedMaterial.Destroy()
		k.seedMaterial = nil
	}
	if seed == nil {
		return
	}
	seedCopy := make([]byte, len(seed))
	copy(seedCopy, seed)
	guardedSeed, err := secret.New(seedCopy)
	if err != nil {
		panic("message: failed to allocate guarded memory for seed material: " + err.Error())
	}
	k.seedMaterial = guardedSeed
}

// Zeroize destroys all guarded memory holding the message key material,
// including seedMaterial. This method is idempotent and safe to call multiple times.
func (k *Keys) Zeroize() {
	if k.cipherKey != nil {
		k.cipherKey.Destroy()
	}
	if k.macKey != nil {
		k.macKey.Destroy()
	}
	if k.iv != nil {
		k.iv.Destroy()
	}
	if k.seedMaterial != nil {
		k.seedMaterial.Destroy()
	}
}
