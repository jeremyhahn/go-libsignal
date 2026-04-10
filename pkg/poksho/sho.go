// Package poksho implements a Proof of Knowledge library using SHA-256 and
// HMAC-SHA-256. It provides the Stateful Hash Object (SHO) abstraction and
// Schnorr-style zero-knowledge proofs over Ed25519.
//
// The SHO is a sponge-like construction built on SHA-256 or HMAC-SHA-256 that
// can absorb data and squeeze out deterministic output. It forms the foundation
// for the zero-knowledge proof system used by Signal's zkcredential, zkgroup,
// and username modules.
//
// This implementation matches the Rust reference in libsignal/rust/poksho/src/.
package poksho

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"hash"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
)

const (
	hashLen  = 32
	blockLen = 64
)

// shoMode tracks whether the SHO is absorbing input or has been ratcheted.
type shoMode int

const (
	modeAbsorbing shoMode = iota
	modeRatcheted
)

// shoVariant defines the hash-function-specific operations for each SHO variant.
type shoVariant interface {
	// initHasher initializes a new streaming hasher keyed/seeded by the
	// current chaining value. Called at the start of absorbing.
	initHasher(cv [hashLen]byte) hash.Hash

	// ratchetFinalize completes the ratchet phase on the given hasher,
	// returning the new chaining value.
	// HMAC: appends 0x00, then cv = HMAC.finalize()
	// SHA256: cv = SHA256(SHA256(accumulated_data))
	ratchetFinalize(h hash.Hash) [hashLen]byte

	// squeezeBlock produces one output block for the given counter.
	// HMAC variant: HMAC(cv, counter_be64 || 0x01)
	// SHA256 variant: SHA256(pad63 || 0x01 || cv || counter_be64)
	squeezeBlock(cv [hashLen]byte, counter uint64) [hashLen]byte

	// squeezeStateUpdate computes the new cv after a squeeze.
	// HMAC variant: HMAC(cv, outlen_be64 || 0x02)
	// SHA256 variant: SHA256(pad63 || 0x02 || cv || outlen_be64)
	squeezeStateUpdate(cv [hashLen]byte, outLen uint64) [hashLen]byte

	// clone returns a deep copy of the variant-specific state.
	clone() shoVariant
}

// SHO is a Stateful Hash Object used as the basis for zero-knowledge proofs.
// It provides a sponge-like construction over SHA-256 or HMAC-SHA-256,
// matching the Rust ShoApi trait from libsignal.
//
// The absorbed field records all data written to the hasher during the current
// absorb phase. This enables Clone() to perform a true deep copy by replaying
// the absorbed data into a fresh hasher, matching Rust's #[derive(Clone)]
// semantics without requiring hash.Hash to implement encoding.BinaryMarshaler
// (which crypto/hmac does not).
type SHO struct {
	cv       [hashLen]byte
	hasher   hash.Hash
	mode     shoMode
	variant  shoVariant
	absorbed []byte // data accumulated in current absorb phase, nil when ratcheted
}

// --- HMAC-SHA-256 variant ---

type hmacVariant struct{}

func (hmacVariant) initHasher(cv [hashLen]byte) hash.Hash {
	return hmac.New(sha256.New, cv[:])
}

func (hmacVariant) ratchetFinalize(h hash.Hash) [hashLen]byte {
	// Rust: self.hasher.update(&[0x00]); cv = self.hasher.finalize()
	h.Write([]byte{0x00})
	var cv [hashLen]byte
	copy(cv[:], h.Sum(nil))
	return cv
}

func (hmacVariant) squeezeBlock(cv [hashLen]byte, counter uint64) [hashLen]byte {
	mac := hmac.New(sha256.New, cv[:])
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac.Write(buf[:])
	mac.Write([]byte{0x01})
	var out [hashLen]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func (hmacVariant) squeezeStateUpdate(cv [hashLen]byte, outLen uint64) [hashLen]byte {
	mac := hmac.New(sha256.New, cv[:])
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], outLen)
	mac.Write(buf[:])
	mac.Write([]byte{0x02})
	var out [hashLen]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func (hmacVariant) clone() shoVariant {
	return hmacVariant{}
}

// --- SHA-256 variant ---

type sha256Variant struct{}

func (sha256Variant) initHasher(cv [hashLen]byte) hash.Hash {
	h := sha256.New()
	// Pad with 64 zero bytes, then cv
	var zeros [blockLen]byte
	h.Write(zeros[:])
	h.Write(cv[:])
	return h
}

func (sha256Variant) ratchetFinalize(h hash.Hash) [hashLen]byte {
	// Rust: cv = SHA256(hasher.finalize_reset())
	// Double hash: cv = SHA256(SHA256(pad64 || cv || input))
	firstHash := h.Sum(nil)
	secondHash := sha256.Sum256(firstHash)
	return secondHash
}

func (sha256Variant) squeezeBlock(cv [hashLen]byte, counter uint64) [hashLen]byte {
	h := sha256.New()
	// pad63 || 0x01 || cv || counter_be64
	var pad [blockLen - 1]byte
	h.Write(pad[:])
	h.Write([]byte{0x01})
	h.Write(cv[:])
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	h.Write(buf[:])
	var out [hashLen]byte
	copy(out[:], h.Sum(nil))
	return out
}

func (sha256Variant) squeezeStateUpdate(cv [hashLen]byte, outLen uint64) [hashLen]byte {
	h := sha256.New()
	// pad63 || 0x02 || cv || outlen_be64
	var pad [blockLen - 1]byte
	h.Write(pad[:])
	h.Write([]byte{0x02})
	h.Write(cv[:])
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], outLen)
	h.Write(buf[:])
	var out [hashLen]byte
	copy(out[:], h.Sum(nil))
	return out
}

func (sha256Variant) clone() shoVariant {
	return sha256Variant{}
}

// NewShoHmacSha256 creates a new SHO using HMAC-SHA-256 with the given label.
// This matches the Rust ShoHmacSha256::new().
func NewShoHmacSha256(label string) *SHO {
	s := &SHO{
		variant: hmacVariant{},
		mode:    modeRatcheted,
	}
	s.AbsorbAndRatchet([]byte(label))
	return s
}

// NewShoSha256 creates a new SHO using SHA-256 with the given label.
// This matches the Rust ShoSha256::new().
func NewShoSha256(label string) *SHO {
	s := &SHO{
		variant: sha256Variant{},
		mode:    modeRatcheted,
	}
	s.AbsorbAndRatchet([]byte(label))
	return s
}

// Absorb feeds data into the SHO state. If the SHO is in RATCHETED mode,
// a new streaming hasher is initialized from the current chaining value.
// Multiple Absorb calls accumulate data into the same hasher until Ratchet
// is called.
func (s *SHO) Absorb(data []byte) {
	if s.mode == modeRatcheted {
		s.hasher = s.variant.initHasher(s.cv)
		// Zeroize the old capacity before reuse to prevent secret scalar
		// data from lingering in the backing array.
		for i := range s.absorbed {
			s.absorbed[i] = 0
		}
		s.absorbed = s.absorbed[:0]
		s.mode = modeAbsorbing
	}
	s.hasher.Write(data)
	s.absorbed = append(s.absorbed, data...)
}

// Ratchet finalizes the current absorb phase and updates the chaining value.
// If already in RATCHETED mode, this is a no-op (matching Rust behavior).
//
// For the HMAC variant: appends 0x00, then cv = HMAC.finalize()
// For the SHA256 variant: cv = SHA256(SHA256(accumulated_data))
func (s *SHO) Ratchet() {
	if s.mode == modeRatcheted {
		return
	}
	s.ratchetInternal()
}

func (s *SHO) ratchetInternal() {
	s.cv = s.variant.ratchetFinalize(s.hasher)
	s.hasher = nil
	crypto.Zeroize(s.absorbed)
	s.absorbed = nil
	s.mode = modeRatcheted
}

// Zeroize clears all sensitive state from the SHO: the chaining value,
// the in-progress absorbed buffer, and the hasher reference.
// After Zeroize the SHO must not be used.
func (s *SHO) Zeroize() {
	crypto.ZeroizeArray32(&s.cv)
	crypto.Zeroize(s.absorbed)
	s.absorbed = nil
	s.hasher = nil
}

// AbsorbAndRatchet absorbs data and then ratchets the state.
// This matches the Rust absorb_and_ratchet() method.
func (s *SHO) AbsorbAndRatchet(data []byte) {
	s.Absorb(data)
	s.Ratchet()
}

// SqueezeAndRatchet produces output bytes from the SHO state and updates
// the chaining value. The SHO must be in RATCHETED mode.
//
// This matches the Rust squeeze_and_ratchet() method exactly:
//   - For each 32-byte block i: output_i = hash(cv, i_as_be64 || 0x01)
//   - New cv = hash(cv, outlen_as_be64 || 0x02)
func (s *SHO) SqueezeAndRatchet(length int) []byte {
	if length <= 0 {
		// Even with zero length, update the state per Rust behavior.
		s.cv = s.variant.squeezeStateUpdate(s.cv, 0)
		return nil
	}

	result := make([]byte, 0, ((length+hashLen-1)/hashLen)*hashLen)
	numBlocks := (length + hashLen - 1) / hashLen

	for i := 0; i < numBlocks; i++ {
		block := s.variant.squeezeBlock(s.cv, uint64(i))
		numBytes := hashLen
		if remaining := length - i*hashLen; remaining < hashLen {
			numBytes = remaining
		}
		result = append(result, block[:numBytes]...)
	}

	// Update chaining value with output length.
	s.cv = s.variant.squeezeStateUpdate(s.cv, uint64(length))
	s.mode = modeRatcheted
	return result
}

// Squeeze produces output bytes and ratchets the state. This is an alias for
// SqueezeAndRatchet for backward compatibility with callers that previously
// used Squeeze followed by Ratchet.
//
// If the SHO is in ABSORBING mode, it will be ratcheted first before squeezing.
// This provides backward compatibility for callers that absorb then squeeze
// without an explicit ratchet step.
func (s *SHO) Squeeze(length int) []byte {
	if s.mode == modeAbsorbing {
		s.Ratchet()
	}
	return s.SqueezeAndRatchet(length)
}

// Clone returns a deep copy of the SHO state. The clone is in exactly the same
// state as the original, including mid-absorb hasher state. This matches the
// Rust #[derive(Clone)] behavior where Clone produces a true field-by-field
// deep copy without any side effects on the original.
//
// When the SHO is in ABSORBING mode, Clone recreates the hasher from the
// chaining value and replays the absorbed data. This is necessary because Go's
// hash.Hash interface (and crypto/hmac in particular) does not provide a
// general-purpose clone method. The replay produces an identical hasher state
// because hash functions are deterministic: initHasher(cv) + Write(absorbed)
// always yields the same internal state.
func (s *SHO) Clone() *SHO {
	clone := &SHO{
		cv:      s.cv,
		mode:    s.mode,
		variant: s.variant.clone(),
	}
	if s.mode == modeAbsorbing {
		// Replay absorbed data into a fresh hasher to produce an identical copy.
		clone.hasher = s.variant.initHasher(s.cv)
		if len(s.absorbed) > 0 {
			clone.hasher.Write(s.absorbed)
		}
		// Deep copy the absorbed buffer so mutations are independent.
		clone.absorbed = make([]byte, len(s.absorbed))
		copy(clone.absorbed, s.absorbed)
	}
	return clone
}

// ShoHash is a convenience function that creates a new SHO, absorbs input,
// and squeezes output in a single call. This matches the Rust ShoApi::shohash().
func ShoHash(newSho func(string) *SHO, label string, input []byte, outLen int) []byte {
	sho := newSho(label)
	sho.AbsorbAndRatchet(input)
	return sho.SqueezeAndRatchet(outLen)
}
