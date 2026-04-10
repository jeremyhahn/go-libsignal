package fingerprint

import (
	"bytes"
	"crypto/sha512"
	"sort"

	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
)

const (
	// DefaultIterations is the standard number of SHA-512 iterations used
	// by the Signal Protocol for fingerprint generation.
	DefaultIterations = 5200

	// minIterations is the minimum allowed iteration count (exclusive).
	minIterations = 1

	// maxIterations is the maximum allowed iteration count (inclusive).
	maxIterations = 1_000_000
)

// fingerprintVersion is the 2-byte big-endian version prefix used in the
// initial SHA-512 hash iteration. This is version 0 (0x0000).
var fingerprintVersion = [2]byte{0x00, 0x00}

// NumericFingerprintGenerator produces numeric fingerprints for identity
// key verification. It implements the iterative SHA-512 hashing algorithm
// from the Signal Protocol specification.
type NumericFingerprintGenerator struct {
	iterations uint32
}

// NewNumericFingerprintGenerator creates a generator with the given iteration
// count. Use DefaultIterations (5200) for standard Signal Protocol behavior.
func NewNumericFingerprintGenerator(iterations uint32) (*NumericFingerprintGenerator, error) {
	if iterations <= minIterations || iterations > maxIterations {
		return nil, &InvalidIterationCountError{Count: iterations}
	}
	return &NumericFingerprintGenerator{iterations: iterations}, nil
}

// CreateFor generates a Fingerprint containing both a displayable 60-digit
// numeric string and a scannable protobuf-encoded fingerprint.
//
// The version parameter is encoded in the scannable fingerprint and used for
// version matching during comparison. The display fingerprint is independent
// of the version parameter.
//
// Each identity key is hashed through an iterative SHA-512 computation:
//
//	iteration 0: SHA-512(version_bytes || key || stable_id || key)
//	iteration i: SHA-512(previous_hash || key)
//
// The full 64-byte hash is used for the displayable fingerprint encoding.
// The first 32 bytes are used for the scannable fingerprint.
func (g *NumericFingerprintGenerator) CreateFor(
	version uint32,
	localStableID []byte,
	localKey *identity.Key,
	remoteStableID []byte,
	remoteKey *identity.Key,
) (*Fingerprint, error) {
	localHash, err := computeFingerprint(g.iterations, localStableID, localKey)
	if err != nil {
		return nil, err
	}
	remoteHash, err := computeFingerprint(g.iterations, remoteStableID, remoteKey)
	if err != nil {
		return nil, err
	}

	display, err := NewDisplay(localHash, remoteHash)
	if err != nil {
		return nil, err
	}
	scannable := newScannable(version, localHash, remoteHash)

	return NewFingerprint(display, scannable), nil
}

// CreateForMultiple generates a Fingerprint for multiple identity keys per
// party. This is used when a party has multiple identity keys (e.g., across
// devices). The keys are concatenated before hashing.
func (g *NumericFingerprintGenerator) CreateForMultiple(
	version uint32,
	localStableID []byte,
	localKeys []*identity.Key,
	remoteStableID []byte,
	remoteKeys []*identity.Key,
) (*Fingerprint, error) {
	localHash, err := computeFingerprintMultiple(g.iterations, localStableID, localKeys)
	if err != nil {
		return nil, err
	}
	remoteHash, err := computeFingerprintMultiple(g.iterations, remoteStableID, remoteKeys)
	if err != nil {
		return nil, err
	}

	display, err := NewDisplay(localHash, remoteHash)
	if err != nil {
		return nil, err
	}
	scannable := newScannable(version, localHash, remoteHash)

	return NewFingerprint(display, scannable), nil
}

// computeFingerprint performs the iterative SHA-512 hash computation for a
// single identity key.
func computeFingerprint(iterations uint32, stableID []byte, key *identity.Key) ([]byte, error) {
	if iterations <= minIterations || iterations > maxIterations {
		return nil, &InvalidIterationCountError{Count: iterations}
	}

	keyBytes := key.Serialize()

	// Iteration 0: SHA-512(version_bytes || key_bytes || stable_id || key_bytes)
	h := sha512.New()
	h.Write(fingerprintVersion[:])
	h.Write(keyBytes)
	h.Write(stableID)
	h.Write(keyBytes)
	buf := h.Sum(nil)

	// Iterations 1..N-1: SHA-512(previous_hash || key_bytes)
	for i := uint32(1); i < iterations; i++ {
		h.Reset()
		h.Write(buf)
		h.Write(keyBytes)
		buf = h.Sum(buf[:0])
	}

	return buf, nil
}

// computeFingerprintMultiple performs the iterative SHA-512 hash computation
// for multiple identity keys. The key bytes are concatenated in order.
func computeFingerprintMultiple(iterations uint32, stableID []byte, keys []*identity.Key) ([]byte, error) {
	if iterations <= minIterations || iterations > maxIterations {
		return nil, &InvalidIterationCountError{Count: iterations}
	}
	if len(keys) == 0 {
		return nil, &ParsingError{Detail: "no identity keys provided"}
	}

	// Sort keys by their serialized byte representation for deterministic
	// fingerprint computation regardless of key ordering.
	sort.Slice(keys, func(i, j int) bool {
		return bytes.Compare(keys[i].Serialize(), keys[j].Serialize()) < 0
	})

	// Concatenate all key bytes.
	var allKeyBytes []byte
	for _, k := range keys {
		allKeyBytes = append(allKeyBytes, k.Serialize()...)
	}

	// Iteration 0: SHA-512(version_bytes || all_key_bytes || stable_id || all_key_bytes)
	h := sha512.New()
	h.Write(fingerprintVersion[:])
	h.Write(allKeyBytes)
	h.Write(stableID)
	h.Write(allKeyBytes)
	buf := h.Sum(nil)

	// Iterations 1..N-1: SHA-512(previous_hash || all_key_bytes)
	for i := uint32(1); i < iterations; i++ {
		h.Reset()
		h.Write(buf)
		h.Write(allKeyBytes)
		buf = h.Sum(buf[:0])
	}

	return buf, nil
}
