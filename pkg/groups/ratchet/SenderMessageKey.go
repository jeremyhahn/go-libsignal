package ratchet

import (
	"github.com/jeremyhahn/go-libsignal/pkg/kdf"
	"github.com/jeremyhahn/go-libsignal/pkg/util/bytehelper"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// KdfInfo is optional bytes to include in deriving secrets with KDF.
const KdfInfo string = "WhisperGroup"

// NewSenderMessageKey will return a new sender message key using the given
// iteration and seed.
func NewSenderMessageKey(iteration uint32, seed []byte) (*SenderMessageKey, error) {
	derivative, err := kdf.DeriveSecrets(seed, nil, []byte(KdfInfo), 48)
	if err != nil {
		return nil, err
	}

	// Split our derived secrets into 2 parts
	parts, err := bytehelper.Split(derivative, 16, 32)
	if err != nil {
		return nil, err
	}

	// Copy sub-slices before wrapping in secrets (New zeroizes the source)
	ivCopy := make([]byte, len(parts[0]))
	copy(ivCopy, parts[0])

	cipherKeyCopy := make([]byte, len(parts[1]))
	copy(cipherKeyCopy, parts[1])

	seedCopy := make([]byte, len(seed))
	copy(seedCopy, seed)

	ivSecret, err := secret.New(ivCopy)
	if err != nil {
		// coverage-exempt: defensive OOM guard for the locked-memory allocation;
		// cannot be unit-tested without modifying the host (see CLAUDE.md).
		return nil, err
	}

	cipherKeySecret, err := secret.New(cipherKeyCopy)
	if err != nil {
		ivSecret.Destroy()
		// coverage-exempt: defensive OOM guard for the locked-memory allocation;
		// cannot be unit-tested without modifying the host (see CLAUDE.md).
		return nil, err
	}

	seedSecret, err := secret.New(seedCopy)
	if err != nil {
		ivSecret.Destroy()
		cipherKeySecret.Destroy()
		// coverage-exempt: defensive OOM guard for the locked-memory allocation;
		// cannot be unit-tested without modifying the host (see CLAUDE.md).
		return nil, err
	}

	// Zeroize the derivative buffer now that secrets are stored
	for i := range derivative {
		derivative[i] = 0
	}

	return &SenderMessageKey{
		iteration: iteration,
		seed:      seedSecret,
		iv:        ivSecret,
		cipherKey: cipherKeySecret,
	}, nil
}

// NewSenderMessageKeyFromStruct will return a new message key object from the
// given serializeable structure. Each field present is cloned from the
// structure's guarded memory straight into the key's own, so the material never
// lands on the Go heap and the source structure is left intact for its owner to
// Zeroize.
//
// All three fields are optional: a stored key may carry only its seed, with the
// IV and cipher key re-derived later. An absent field stays absent. If a later
// clone fails, the ones already made are released before returning.
func NewSenderMessageKeyFromStruct(structure *SenderMessageKeyStructure) (_ *SenderMessageKey, err error) {
	if structure == nil {
		return nil, &MissingKeyError{Field: "structure"}
	}

	// Populate as the clones are made, so whichever step fails, everything
	// allocated so far is reachable by the cleanup below.
	mk := &SenderMessageKey{iteration: structure.Iteration}
	defer func() {
		if err != nil {
			mk.Zeroize()
		}
	}()
	if mk.iv, err = cloneOptional(&structure.IV); err != nil {
		return nil, err
	}
	if mk.cipherKey, err = cloneOptional(&structure.CipherKey); err != nil {
		return nil, err
	}
	if mk.seed, err = cloneOptional(&structure.Seed); err != nil {
		return nil, err
	}
	return mk, nil
}

// cloneOptional clones a structure field that may legitimately hold no
// material, yielding a nil *secret.Secret in that case rather than an error.
func cloneOptional(field *secret.Secret) (*secret.Secret, error) {
	if field.IsZero() {
		return nil, nil
	}
	return field.Clone()
}

// NewStructFromSenderMessageKey returns a serializeable structure of message
// keys. Each field present is cloned guarded-to-guarded, so serialization no
// longer stages message key material on the heap. Callers must Zeroize the
// returned structure once the serializer has consumed it; on failure everything
// cloned so far is released before returning.
func NewStructFromSenderMessageKey(key *SenderMessageKey) (_ *SenderMessageKeyStructure, err error) {
	structure := &SenderMessageKeyStructure{Iteration: key.iteration}
	defer func() {
		if err != nil {
			structure.Zeroize()
		}
	}()
	if structure.IV, err = cloneLiveOptional(key.iv); err != nil {
		return nil, err
	}
	if structure.CipherKey, err = cloneLiveOptional(key.cipherKey); err != nil {
		return nil, err
	}
	if structure.Seed, err = cloneLiveOptional(key.seed); err != nil {
		return nil, err
	}
	return structure, nil
}

// cloneLiveOptional clones live guarded material into a Secret held by value,
// ready to cross the storage boundary. Absent (nil or empty) material yields
// the zero Secret; destroyed material is an error, so a wiped key is never
// persisted as one that was never there.
func cloneLiveOptional(live *secret.Secret) (secret.Secret, error) {
	n := 0
	if err := live.WithBytes(func(b []byte) error {
		n = len(b)
		return nil
	}); err != nil {
		return secret.Secret{}, err
	}
	if n == 0 {
		return secret.Secret{}, nil
	}
	cloned, err := live.Clone()
	if err != nil {
		return secret.Secret{}, err
	}
	return secret.FromSecret(cloned), nil
}

// SenderMessageKeyStructure is a serializeable structure of SenderMessageKeys.
// Every field is held in guarded memory: these structures cross the storage
// boundary, and an IV, cipher key or seed on the plain heap can be swapped out
// or captured in a core dump, which zeroizing it afterwards does not undo.
type SenderMessageKeyStructure struct {
	Iteration uint32
	IV        secret.Secret
	CipherKey secret.Secret
	Seed      secret.Secret
}

// Zeroize releases all guarded key material in the structure. Call this (via
// defer) after the structure has been serialized. It is idempotent.
func (s *SenderMessageKeyStructure) Zeroize() {
	s.IV.Destroy()
	s.CipherKey.Destroy()
	s.Seed.Destroy()
}

// SenderMessageKey is a structure for sender message keys used in group
// messaging. All sensitive fields are stored in guarded memory.
type SenderMessageKey struct {
	iteration uint32
	iv        *secret.Secret
	cipherKey *secret.Secret
	seed      *secret.Secret
}

// Iteration will return the sender message key's iteration.
func (k *SenderMessageKey) Iteration() uint32 {
	return k.iteration
}

// Sender key component lengths.
const (
	senderIVLength        = 16
	senderCipherKeyLength = 32
	senderSeedLength      = 32
)

// Iv will return a copy of the sender message key's initialization vector.
// A missing, destroyed or wrong-length IV is an error.
func (k *SenderMessageKey) Iv() ([]byte, error) {
	return copySecret(k.iv, "iv", senderIVLength)
}

// CipherKey will return a copy of the cipher key. A missing, destroyed or
// wrong-length key is an error.
func (k *SenderMessageKey) CipherKey() ([]byte, error) {
	return copySecret(k.cipherKey, "cipher key", senderCipherKeyLength)
}

// Seed will return a copy of the sender message key's seed. A missing,
// destroyed or wrong-length seed is an error.
func (k *SenderMessageKey) Seed() ([]byte, error) {
	return copySecret(k.seed, "seed", senderSeedLength)
}

// copySecret copies s's bytes inside its enclave borrow, for the accessors
// whose value must leave the borrow. The material must be exactly want
// bytes. A nil, destroyed or wrong-length secret is an error, never a nil
// or short copy. The caller owns the copy and should zeroize it.
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

// Zeroize destroys the guarded memory holding all sensitive key material.
// This method is idempotent and safe to call multiple times.
func (k *SenderMessageKey) Zeroize() {
	if k.iv != nil {
		k.iv.Destroy()
	}
	if k.cipherKey != nil {
		k.cipherKey.Destroy()
	}
	if k.seed != nil {
		k.seed.Destroy()
	}
}
