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

// SeedMaterialLength is the length of the HMAC base material a message key
// is derived from.
const SeedMaterialLength = 32

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
// Every component is cloned from the structure's guarded memory straight into
// the returned Keys' own guarded memory, so the material never lands on the Go
// heap and the source structure is left intact for its owner to Zeroize. If a
// later clone fails, the ones already made are released before returning.
//
// Returns *MissingKeyError when the derived-keys form is missing one of its
// three components; that form is only meaningful with all three present.
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
//
// Every component is cloned guarded-to-guarded, so serialization no longer
// stages message key material on the heap. Callers must Zeroize the returned
// structure once the serializer has consumed it; on failure everything cloned
// so far is released before returning.
func NewStructFromKeys(keys *Keys) (_ *KeysStructure, err error) {
	// Seed-only form: matches Rust MessageKeyGenerator::into_pb Seed variant.
	// A destroyed seed is an error: storing the key without it would later
	// skip the PQR re-derivation.
	seedLen := 0
	if err := keys.seedMaterial.WithBytes(func(b []byte) error {
		seedLen = len(b)
		return nil
	}); err != nil {
		return nil, err
	}
	if seedLen > 0 {
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

// KeysStructure is a serializeable structure of message keys. Every key
// component is held in guarded memory: these structures cross the storage
// boundary, and a cipher key, MAC key, IV or PQR seed on the plain heap can be
// swapped out or captured in a core dump, which zeroizing it afterwards does
// not undo.
//
// SeedMaterial carries omitzero rather than omitempty because the field is now
// a struct; see secret.Secret.IsZero for why the two are equivalent here and
// why the distinction matters for the persisted layout.
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

// Keys is a structure to hold all the keys for a single MessageKey, including the
// cipherKey, mac, iv, and index of the chain key. MessageKeys are used to
// encrypt individual messages. All key material is stored in locked memory.
//
// SeedMaterial optionally holds the 32-byte HMAC output (BaseMaterial) from which
// the keys were derived. When present, it allows re-derivation with a different HKDF
// salt (e.g., for SPQR post-quantum ratchet). This is used for skipped message keys
// that may later need PQR-salted re-derivation. It is stored in locked
// memory alongside the other key components.
type Keys struct {
	cipherKey    *secret.Secret
	macKey       *secret.Secret
	iv           *secret.Secret
	index        uint32
	seedMaterial *secret.Secret
}

// CipherKey returns the key used to produce ciphertext as a copy made
// inside the enclave borrow. A missing, destroyed or wrong-length key is an
// error. The caller owns the copy and should zeroize it.
func (k *Keys) CipherKey() ([]byte, error) {
	return copySecret(k.cipherKey, "cipher key", CipherKeyLength)
}

// MacKey returns the message authentication code key as a copy made inside
// the enclave borrow. A missing, destroyed or wrong-length key is an error.
// The caller owns the copy and should zeroize it.
func (k *Keys) MacKey() ([]byte, error) {
	return copySecret(k.macKey, "mac key", MacKeyLength)
}

// Iv returns the initialization vector as a copy made inside the enclave
// borrow. A missing, destroyed or wrong-length IV is an error. The caller
// owns the copy and should zeroize it.
func (k *Keys) Iv() ([]byte, error) {
	return copySecret(k.iv, "iv", IVLength)
}

// copySecret copies s's bytes inside its enclave borrow, for the accessors
// whose value must leave the borrow. The material must be exactly want
// bytes. A nil, destroyed or wrong-length secret is an error, never a nil
// or short copy.
func copySecret(s *secret.Secret, field string, want int) ([]byte, error) {
	if s == nil {
		return nil, &MissingKeyError{Field: field}
	}
	var out []byte
	if err := s.WithBytes(func(b []byte) error {
		if len(b) != want {
			return &KeyLengthError{Field: field, Got: len(b), Want: want}
		}
		out = append(make([]byte, 0, want), b...)
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// Index returns the number of times the chain key has been put through a key derivation
// function to generate this message key.
func (k *Keys) Index() uint32 {
	return k.index
}

// SeedMaterial returns a copy of the guarded HMAC base material for re-derivation,
// made inside the enclave borrow, or nil, nil if no seed material is stored.
// A destroyed or wrong-length seed is an error, so it is never mistaken for
// a key without one. The caller owns the copy and should zeroize it.
func (k *Keys) SeedMaterial() ([]byte, error) {
	if k.seedMaterial == nil {
		return nil, nil
	}
	return copySecret(k.seedMaterial, "seed material", SeedMaterialLength)
}

// SetSeedMaterial stores the 32-byte HMAC base material for later re-derivation
// in locked memory. Any previously stored seed material is destroyed
// before the new value is stored. Panics if locked-memory allocation fails (fatal condition).
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
