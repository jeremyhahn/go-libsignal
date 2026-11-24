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
// Each key component is moved into locked memory and the source slices
// are zeroized by go-enclave. Panics if locked-memory allocation fails (fatal condition).
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

// NewSeedOnlyKeys returns seed-only Keys; derive the keys with chain.DeriveMessageKeysFromSeed before use (Rust MessageKeyGenerator::Seed).
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

// NewKeysFromStruct loads seed-only or derived-keys form guarded-to-guarded; derived form missing a component returns *MissingKeyError.
func NewKeysFromStruct(structure *KeysStructure) (_ *Keys, err error) {
	if structure == nil {
		return nil, &MissingKeyError{Field: "structure"}
	}

	// Seed-only form: matches Rust MessageKeyGenerator::from_pb Seed branch.
	if !structure.SeedMaterial.IsZero() {
		guardedSeed, cloneErr := structure.SeedMaterial.Clone()
		if cloneErr != nil {
			return nil, cloneErr
		}
		return &Keys{
			index:        structure.Index,
			seedMaterial: guardedSeed,
		}, nil
	}

	// Derived-keys form: matches Rust MessageKeyGenerator::from_pb Keys branch.
	if structure.CipherKey.IsZero() {
		return nil, &MissingKeyError{Field: "cipher key"}
	}
	if structure.MacKey.IsZero() {
		return nil, &MissingKeyError{Field: "mac key"}
	}
	if structure.IV.IsZero() {
		return nil, &MissingKeyError{Field: "iv"}
	}

	// Populate as the clones are made, so that whichever step fails, everything
	// allocated so far is reachable by the cleanup below.
	keys := &Keys{index: structure.Index}
	defer func() {
		if err != nil {
			keys.Zeroize()
		}
	}()
	if keys.cipherKey, err = structure.CipherKey.Clone(); err != nil {
		return nil, err
	}
	if keys.macKey, err = structure.MacKey.Clone(); err != nil {
		return nil, err
	}
	if keys.iv, err = structure.IV.Clone(); err != nil {
		return nil, err
	}
	return keys, nil
}

// NewStructFromKeys returns seed-only form when a seed exists, else the derived keys, cloned guarded; the caller must Zeroize it.
func NewStructFromKeys(keys *Keys) (_ *KeysStructure, err error) {
	// Seed-only form: matches Rust MessageKeyGenerator::into_pb Seed variant.
	if !keys.seedMaterial.IsDestroyed() {
		clonedSeed, cloneErr := keys.seedMaterial.Clone()
		if cloneErr != nil {
			return nil, cloneErr
		}
		return &KeysStructure{
			Index:        keys.index,
			SeedMaterial: secret.FromSecret(clonedSeed),
		}, nil
	}

	// Derived-keys form: matches Rust MessageKeyGenerator::into_pb Keys variant.
	// Populate as the clones are made so the cleanup below can reach them.
	structure := &KeysStructure{Index: keys.index}
	defer func() {
		if err != nil {
			structure.Zeroize()
		}
	}()
	if structure.CipherKey, err = cloneInto(keys.cipherKey); err != nil {
		return nil, err
	}
	if structure.MacKey, err = cloneInto(keys.macKey); err != nil {
		return nil, err
	}
	if structure.IV, err = cloneInto(keys.iv); err != nil {
		return nil, err
	}
	return structure, nil
}

// cloneInto clones live guarded material into a Secret held by value, ready to
// be stored in a structure that crosses the storage boundary.
func cloneInto(live *secret.Secret) (secret.Secret, error) {
	cloned, err := live.Clone()
	if err != nil {
		return secret.Secret{}, err
	}
	return secret.FromSecret(cloned), nil
}

// KeysStructure is the serializable form of message keys, held in guarded memory.
type KeysStructure struct {
	CipherKey    secret.Secret
	MacKey       secret.Secret
	IV           secret.Secret
	Index        uint32
	SeedMaterial secret.Secret `json:",omitzero"`
}

// Zeroize releases all guarded key material in the structure. Call this (via
// defer) after the structure has been serialized. It is idempotent.
func (k *KeysStructure) Zeroize() {
	k.CipherKey.Destroy()
	k.MacKey.Destroy()
	k.IV.Destroy()
	k.SeedMaterial.Destroy()
}

// Keys holds a message's cipher key, MAC key, IV, index and optional seed for SPQR re-derivation, all in locked memory.
type Keys struct {
	cipherKey    *secret.Secret
	macKey       *secret.Secret
	iv           *secret.Secret
	index        uint32
	seedMaterial *secret.Secret
}

// CipherKey returns the key used to produce ciphertext as a copy made
// inside the enclave borrow. The caller owns the copy and should zeroize it.
func (k *Keys) CipherKey() []byte {
	return copySecret(k.cipherKey)
}

// MacKey returns the message authentication code key as a copy
// made inside the enclave borrow. The caller owns the copy and should zeroize it.
func (k *Keys) MacKey() []byte {
	return copySecret(k.macKey)
}

// Iv returns the initialization vector as a copy
// made inside the enclave borrow. The caller owns the copy and should zeroize it.
func (k *Keys) Iv() []byte {
	return copySecret(k.iv)
}

// copySecret copies s's bytes inside its enclave borrow, for the accessors
// whose value must leave the borrow. A nil or destroyed secret yields nil.
func copySecret(s *secret.Secret) []byte {
	var out []byte
	if err := s.WithBytes(func(b []byte) error {
		if b != nil {
			out = append([]byte(nil), b...)
		}
		return nil
	}); err != nil {
		return nil
	}
	return out
}

// Index returns the number of times the chain key has been put through a key derivation
// function to generate this message key.
func (k *Keys) Index() uint32 {
	return k.index
}

// SeedMaterial returns a copy of the guarded HMAC base material for re-derivation,
// made inside the enclave borrow, or nil if no seed material is stored. The
// caller owns the copy and should zeroize it.
func (k *Keys) SeedMaterial() []byte {
	if k.seedMaterial == nil || k.seedMaterial.IsDestroyed() {
		return nil
	}
	return copySecret(k.seedMaterial)
}

// SetSeedMaterial stores the 32-byte seed in locked memory, destroying any previous seed; it panics if allocation fails.
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
