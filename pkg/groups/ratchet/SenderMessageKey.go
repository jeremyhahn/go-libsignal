package ratchet

import (
	"github.com/jeremyhahn/go-libsignal/pkg/kdf"
	"github.com/jeremyhahn/go-libsignal/pkg/util/bytehelper"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
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
		// coverage-exempt: defensive OOM panic-recovery for memguard.NewBufferFromBytes;
		// cannot be unit-tested without modifying the host (see CLAUDE.md).
		return nil, err
	}

	cipherKeySecret, err := secret.New(cipherKeyCopy)
	if err != nil {
		ivSecret.Destroy()
		// coverage-exempt: defensive OOM panic-recovery for memguard.NewBufferFromBytes;
		// cannot be unit-tested without modifying the host (see CLAUDE.md).
		return nil, err
	}

	seedSecret, err := secret.New(seedCopy)
	if err != nil {
		ivSecret.Destroy()
		cipherKeySecret.Destroy()
		// coverage-exempt: defensive OOM panic-recovery for memguard.NewBufferFromBytes;
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
// given serializeable structure.
func NewSenderMessageKeyFromStruct(structure *SenderMessageKeyStructure) *SenderMessageKey {
	mk := &SenderMessageKey{
		iteration: structure.Iteration,
	}

	if structure.IV != nil {
		cp := make([]byte, len(structure.IV))
		copy(cp, structure.IV)
		s, err := secret.New(cp)
		if err != nil {
			// coverage-exempt: defensive OOM panic-recovery for memguard.NewBufferFromBytes;
			// cannot be unit-tested without modifying the host (see CLAUDE.md).
			panic("ratchet: failed to allocate guarded memory for IV: " + err.Error())
		}
		mk.iv = s
	}

	if structure.CipherKey != nil {
		cp := make([]byte, len(structure.CipherKey))
		copy(cp, structure.CipherKey)
		s, err := secret.New(cp)
		if err != nil {
			mk.Zeroize()
			// coverage-exempt: defensive OOM panic-recovery for memguard.NewBufferFromBytes;
			// cannot be unit-tested without modifying the host (see CLAUDE.md).
			panic("ratchet: failed to allocate guarded memory for cipher key: " + err.Error())
		}
		mk.cipherKey = s
	}

	if structure.Seed != nil {
		cp := make([]byte, len(structure.Seed))
		copy(cp, structure.Seed)
		s, err := secret.New(cp)
		if err != nil {
			mk.Zeroize()
			// coverage-exempt: defensive OOM panic-recovery for memguard.NewBufferFromBytes;
			// cannot be unit-tested without modifying the host (see CLAUDE.md).
			panic("ratchet: failed to allocate guarded memory for seed: " + err.Error())
		}
		mk.seed = s
	}

	return mk
}

// NewStructFromSenderMessageKey returns a serializeable structure of message keys.
func NewStructFromSenderMessageKey(key *SenderMessageKey) *SenderMessageKeyStructure {
	s := &SenderMessageKeyStructure{
		Iteration: key.iteration,
	}

	if key.iv != nil {
		src := key.iv.Bytes()
		cp := make([]byte, len(src))
		copy(cp, src)
		s.IV = cp
	}

	if key.cipherKey != nil {
		src := key.cipherKey.Bytes()
		cp := make([]byte, len(src))
		copy(cp, src)
		s.CipherKey = cp
	}

	if key.seed != nil {
		src := key.seed.Bytes()
		cp := make([]byte, len(src))
		copy(cp, src)
		s.Seed = cp
	}

	return s
}

// SenderMessageKeyStructure is a serializeable structure of SenderMessageKeys.
type SenderMessageKeyStructure struct {
	Iteration uint32
	IV        []byte
	CipherKey []byte
	Seed      []byte
}

// Zeroize overwrites all sensitive byte fields in the structure with zeros.
// Call this (via defer) after the structure has been serialized.
func (s *SenderMessageKeyStructure) Zeroize() {
	crypto.Zeroize(s.IV)
	crypto.Zeroize(s.CipherKey)
	crypto.Zeroize(s.Seed)
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

// Iv will return the sender message key's initialization vector.
func (k *SenderMessageKey) Iv() []byte {
	if k.iv == nil {
		return nil
	}
	return k.iv.Bytes()
}

// CipherKey will return the key in bytes.
func (k *SenderMessageKey) CipherKey() []byte {
	if k.cipherKey == nil {
		return nil
	}
	return k.cipherKey.Bytes()
}

// Seed will return the sender message key's seed.
func (k *SenderMessageKey) Seed() []byte {
	if k.seed == nil {
		return nil
	}
	return k.seed.Bytes()
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
