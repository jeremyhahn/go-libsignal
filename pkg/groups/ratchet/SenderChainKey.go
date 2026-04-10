package ratchet

import (
	"crypto/hmac"
	"crypto/sha256"
	"math"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// ErrChainTooLong indicates the sender chain key iteration counter would
// overflow uint32. This matches the Rust reference checked_add in
// SenderChainKey::next().
type ErrChainTooLong struct{}

func (e *ErrChainTooLong) Error() string {
	return "ratchet: sender chain is too long"
}

var messageKeySeed = []byte{0x01}
var chainKeySeed = []byte{0x02}

// NewSenderChainKey will return a new SenderChainKey.
func NewSenderChainKey(iteration uint32, chainKey []byte) *SenderChainKey {
	cp := make([]byte, len(chainKey))
	copy(cp, chainKey)
	s, err := secret.New(cp)
	if err != nil {
		panic("ratchet: failed to allocate guarded memory for chain key: " + err.Error())
	}
	return &SenderChainKey{
		iteration: iteration,
		chainKey:  s,
	}
}

// NewSenderChainKeyFromStruct will return a new chain key object from the
// given serializeable structure.
func NewSenderChainKeyFromStruct(structure *SenderChainKeyStructure) *SenderChainKey {
	cp := make([]byte, len(structure.ChainKey))
	copy(cp, structure.ChainKey)
	return NewSenderChainKey(structure.Iteration, cp)
}

// NewStructFromSenderChainKeys returns a serializeable structure of chain keys.
func NewStructFromSenderChainKey(key *SenderChainKey) *SenderChainKeyStructure {
	src := key.chainKey.Bytes()
	cp := make([]byte, len(src))
	copy(cp, src)
	return &SenderChainKeyStructure{
		Iteration: key.iteration,
		ChainKey:  cp,
	}
}

// SenderChainKeyStructure is a serializeable structure of SenderChainKeys.
type SenderChainKeyStructure struct {
	Iteration uint32
	ChainKey  []byte
}

// Zeroize overwrites the chain key bytes in the structure with zeros.
// Call this (via defer) after the structure has been serialized.
func (s *SenderChainKeyStructure) Zeroize() {
	crypto.Zeroize(s.ChainKey)
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
	return NewSenderMessageKey(k.iteration, k.getDerivative(messageKeySeed, k.chainKey.Bytes()))
}

// Next returns the next SenderChainKey in the chain. It returns
// ErrChainTooLong if the iteration counter would overflow uint32,
// matching the Rust reference checked_add behavior.
func (k *SenderChainKey) Next() (*SenderChainKey, error) {
	if k.iteration == math.MaxUint32 {
		return nil, &ErrChainTooLong{}
	}
	derived := k.getDerivative(chainKeySeed, k.chainKey.Bytes())
	// derived is freshly allocated by HMAC, safe to pass directly to secret.New
	// which will zeroize it (that's fine, it's a throwaway buffer).
	s, err := secret.New(derived)
	if err != nil {
		panic("ratchet: failed to allocate guarded memory for next chain key: " + err.Error())
	}
	return &SenderChainKey{
		iteration: k.iteration + 1,
		chainKey:  s,
	}, nil
}

// Seed will return a copy of the chain key bytes.
func (k *SenderChainKey) Seed() []byte {
	return k.chainKey.Bytes()
}

// Zeroize destroys the guarded memory holding the chain key material.
// This method is idempotent and safe to call multiple times.
func (k *SenderChainKey) Zeroize() {
	if k.chainKey != nil {
		k.chainKey.Destroy()
	}
}

func (k *SenderChainKey) getDerivative(seed []byte, key []byte) []byte {
	mac := hmac.New(sha256.New, key[:])
	mac.Write(seed)

	return mac.Sum(nil)
}
