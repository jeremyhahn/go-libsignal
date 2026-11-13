package ratchet

import (
	"crypto/hmac"
	"crypto/sha256"
	"math"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// ErrChainTooLong indicates the sender chain key iteration counter would
// overflow uint32. This matches the Rust reference checked_add in
// SenderChainKey::next().
type ErrChainTooLong struct{}

func (e *ErrChainTooLong) Error() string {
	return "ratchet: sender chain is too long"
}

// ErrEmptyChainKey is returned when a sender chain key has no key
// material. Deriving from it would key HMAC with an empty key and give a
// predictable message key and chain.
type ErrEmptyChainKey struct{}

func (e *ErrEmptyChainKey) Error() string {
	return "ratchet: sender chain key is empty"
}

var messageKeySeed = []byte{0x01}
var chainKeySeed = []byte{0x02}

// NewSenderChainKey will return a new SenderChainKey.
func NewSenderChainKey(iteration uint32, chainKey []byte) *SenderChainKey {
	cp := make([]byte, len(chainKey))
	copy(cp, chainKey)
	s, err := secret.New(cp)
	if err != nil {
		// coverage-exempt: defensive OOM guard for the locked-memory allocation;
		// cannot be unit-tested without modifying the host (see CLAUDE.md).
		panic("ratchet: failed to allocate guarded memory for chain key: " + err.Error())
	}
	return &SenderChainKey{
		iteration: iteration,
		chainKey:  s,
	}
}

// NewSenderChainKeyFromStruct will return a new chain key object from the
// given serializeable structure. The key is cloned from the structure's
// guarded memory straight into the returned key's own, so the material never
// lands on the Go heap and the source structure is left intact for its owner
// to Zeroize.
//
// Returns *MissingKeyError if the structure carries no chain key: a sender
// chain key is mandatory, and decoding one that is absent or already destroyed
// must fail rather than yield a key nothing can ratchet.
func NewSenderChainKeyFromStruct(structure *SenderChainKeyStructure) (*SenderChainKey, error) {
	if structure == nil || structure.ChainKey.IsZero() {
		return nil, &MissingKeyError{Field: "sender chain key"}
	}
	guarded, err := structure.ChainKey.Clone()
	if err != nil {
		return nil, err
	}
	return &SenderChainKey{
		iteration: structure.Iteration,
		chainKey:  guarded,
	}, nil
}

// NewStructFromSenderChainKey returns a serializable structure of a SenderChainKey,
// suitable for persistence and transmission. Mirrors NewSenderChainKeyFromStruct:
// the key is cloned guarded-to-guarded, so serialization no longer stages it on
// the heap. Callers must Zeroize the returned structure once the serializer has
// consumed it.
func NewStructFromSenderChainKey(key *SenderChainKey) (*SenderChainKeyStructure, error) {
	cloned, err := key.chainKey.Clone()
	if err != nil {
		return nil, err
	}
	return &SenderChainKeyStructure{
		Iteration: key.iteration,
		ChainKey:  secret.FromSecret(cloned),
	}, nil
}

// SenderChainKeyStructure is a serializeable structure of SenderChainKeys. The
// chain key is held in guarded memory: it crosses the storage boundary, and a
// chain key on the plain heap can be swapped out or captured in a core dump,
// which zeroizing it afterwards does not undo.
type SenderChainKeyStructure struct {
	Iteration uint32
	ChainKey  secret.Secret
}

// Zeroize releases the guarded chain key. Call this (via defer) after the
// structure has been serialized. It is idempotent.
func (s *SenderChainKeyStructure) Zeroize() {
	s.ChainKey.Destroy()
}

// SenderChainKey holds sender chain key material in guarded memory.
type SenderChainKey struct {
	iteration uint32
	chainKey  *secret.Secret
}

// Iteration returns the chain key iteration.
func (k *SenderChainKey) Iteration() uint32 {
	return k.iteration
}

// SenderMessageKey derives a new SenderMessageKey from this chain key.
func (k *SenderChainKey) SenderMessageKey() (*SenderMessageKey, error) {
	derived, err := k.getDerivative(messageKeySeed)
	if err != nil {
		return nil, err
	}
	return NewSenderMessageKey(k.iteration, derived)
}

// Next returns the next SenderChainKey in the chain. It returns
// ErrChainTooLong if the iteration counter would overflow uint32,
// matching the Rust reference checked_add behavior.
func (k *SenderChainKey) Next() (*SenderChainKey, error) {
	if k.iteration == math.MaxUint32 {
		return nil, &ErrChainTooLong{}
	}
	derived, err := k.getDerivative(chainKeySeed)
	if err != nil {
		return nil, err
	}
	// derived is freshly allocated by HMAC, safe to pass directly to secret.New
	// which will zeroize it (that's fine, it's a throwaway buffer).
	s, err := secret.New(derived)
	if err != nil {
		// coverage-exempt: defensive OOM guard for the locked-memory allocation;
		// cannot be unit-tested without modifying the host (see CLAUDE.md).
		panic("ratchet: failed to allocate guarded memory for next chain key: " + err.Error())
	}
	return &SenderChainKey{
		iteration: k.iteration + 1,
		chainKey:  s,
	}, nil
}

// Seed will return a copy of the chain key bytes, made inside the enclave
// borrow. The caller owns the copy and should zeroize it after use.
func (k *SenderChainKey) Seed() []byte {
	return copySecret(k.chainKey)
}

// SeedSecret returns an independent locked copy of the chain key seed,
// cloned region to region with no heap copy. The caller owns it and
// destroys it.
func (k *SenderChainKey) SeedSecret() (*secret.Secret, error) {
	if k == nil || k.chainKey == nil {
		return nil, &ErrEmptyChainKey{}
	}
	return k.chainKey.Clone()
}

// Zeroize destroys the guarded memory holding the chain key material.
// This method is idempotent and safe to call multiple times.
func (k *SenderChainKey) Zeroize() {
	if k.chainKey != nil {
		k.chainKey.Destroy()
	}
}

func (k *SenderChainKey) getDerivative(seed []byte) ([]byte, error) {
	if k == nil {
		return nil, &ErrEmptyChainKey{}
	}
	var derived []byte
	err := k.chainKey.WithBytes(func(key []byte) error {
		// WithBytes borrows a nil or zero Secret as nil; refuse it.
		if len(key) == 0 {
			return &ErrEmptyChainKey{}
		}
		mac := hmac.New(sha256.New, key)
		mac.Write(seed)
		derived = mac.Sum(nil)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return derived, nil
}
