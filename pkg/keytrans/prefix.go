// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package keytrans

import (
	"crypto/sha256"
)

const prefixKeyLength = 32

// PrefixProof contains a proof step in the prefix tree.
type PrefixProof struct {
	Proof   [][]byte
	Counter uint32
}

// prefixLeafHash computes the leaf hash in the prefix tree.
func prefixLeafHash(key *[32]byte, ctr uint32, pos uint64) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(key[:])
	h.Write(uint32ToBeBytes(ctr))
	h.Write(uint64ToBeBytes(pos))
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// prefixParentHash computes the parent hash in the prefix tree.
func prefixParentHash(left, right *[32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left[:])
	h.Write(right[:])
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// evaluatePrefixProof evaluates a prefix proof.
func evaluatePrefixProof(key, value *[32]byte, proof [][]byte) ([32]byte, error) {
	if len(proof) != 8*prefixKeyLength {
		return [32]byte{}, ErrMalformedPrefixProof
	}

	val := *value
	for i := 0; i < len(proof); i++ {
		if len(proof[i]) != 32 {
			return [32]byte{}, ErrMalformedPrefixProof
		}
		var sibling [32]byte
		copy(sibling[:], proof[i])

		n := len(proof) - i - 1
		b := key[n/8] & (1 << (7 - n%8))

		if b == 0 {
			val = prefixParentHash(&val, &sibling)
		} else {
			val = prefixParentHash(&sibling, &val)
		}
	}
	return val, nil
}

// EvaluatePrefix takes a search result and returns the root that would make the
// proof valid.
func EvaluatePrefix(key *[32]byte, pos uint64, proof *PrefixProof) ([32]byte, error) {
	leaf := prefixLeafHash(key, proof.Counter, pos)
	return evaluatePrefixProof(key, &leaf, proof.Proof)
}

// Helper functions for byte conversion.

func uint32ToBeBytes(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func uint64ToBeBytes(v uint64) []byte {
	return []byte{
		byte(v >> 56), byte(v >> 48), byte(v >> 40), byte(v >> 32),
		byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v),
	}
}

func int64ToBeBytes(v int64) []byte {
	return uint64ToBeBytes(uint64(v))
}

func uint16ToBeBytes(v uint16) []byte {
	return []byte{byte(v >> 8), byte(v)}
}
