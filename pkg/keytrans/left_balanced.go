// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

// Package keytrans implements key transparency verification for the Signal protocol.
//
// It provides VRF (Verifiable Random Function) verification, Merkle tree proof
// evaluation, monitoring protocol support, and search/lookup operations for
// detecting misbehavior in key transparency logs.
package keytrans

import (
	"math/bits"
)

// log2 returns the floor of the base-2 logarithm of n, or 0 if n is 0.
func log2(n uint64) uint32 {
	if n == 0 {
		return 0
	}
	return uint32(bits.Len64(n) - 1)
}

// isLeaf returns true if x is the position of a leaf node.
func isLeaf(x uint64) bool {
	return (x & 1) == 0
}

// level returns the level of a node in the tree. Leaves are level 0.
func level(x uint64) int {
	return bits.TrailingZeros64(^x)
}

// leftStep returns the left child of an intermediate node.
// Returns ErrLeafNodeHasNoChildren if x is a leaf node.
func leftStep(x uint64) (uint64, error) {
	k := level(x)
	if k == 0 {
		return 0, ErrLeafNodeHasNoChildren
	}
	return x ^ (1 << (k - 1)), nil
}

// rightStep returns the right child of an intermediate node.
// Returns ErrLeafNodeHasNoChildren if x is a leaf node.
func rightStep(x uint64) (uint64, error) {
	k := level(x)
	if k == 0 {
		return 0, ErrLeafNodeHasNoChildren
	}
	return x ^ (3 << (k - 1)), nil
}

// parentStep returns the parent node of x.
func parentStep(x uint64) uint64 {
	k := level(x)
	b := (x >> (k + 1)) & 1
	return (x | (1 << k)) ^ (b << (k + 1))
}
