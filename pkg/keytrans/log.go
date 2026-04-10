// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package keytrans

import (
	"crypto/sha256"
	"fmt"
)

// Hash represents a 32-byte hash value.
type Hash = [32]byte

// LogError represents an error from log tree operations.
type LogError struct {
	msg string
}

func (e *LogError) Error() string { return e.msg }

func logInvalidInput(msg string) *LogError {
	return &LogError{msg: fmt.Sprintf("invalid input: %s", msg)}
}

func logMalformedProof() *LogError {
	return &LogError{msg: "malformed proof"}
}

func logProofMismatch(msg string) *LogError {
	return &LogError{msg: fmt.Sprintf("proof mismatch: %s", msg)}
}

func logUnexpected(msg string) *LogError {
	return &LogError{msg: fmt.Sprintf("unexpected error: %s", msg)}
}

// logNodeWidth returns the number of nodes needed to store a tree with n leaves.
func logNodeWidth(n uint64) uint64 {
	if n == 0 {
		return 0
	}
	return 2*(n-1) + 1
}

// logRoot returns the id of the root node of a tree with n leaves.
func logRoot(n uint64) uint64 {
	return (1 << log2(logNodeWidth(n))) - 1
}

// logLeft returns the left child of an intermediate node.
func logLeft(x uint64) (uint64, error) {
	return leftStep(x)
}

// logRight returns the right child of an intermediate node, constrained to fit in a tree with n leaves.
func logRight(x, n uint64) (uint64, error) {
	r, err := rightStep(x)
	if err != nil {
		return 0, err
	}
	w := logNodeWidth(n)
	for r >= w {
		r, err = logLeft(r)
		if err != nil {
			return 0, err
		}
	}
	return r, nil
}

// logParent returns the parent of x in a tree with n leaves.
func logParent(x, n uint64) (uint64, error) {
	if x == logRoot(n) {
		return 0, ErrRootHasNoParent
	}
	w := logNodeWidth(n)
	p := parentStep(x)
	for p >= w {
		p = parentStep(p)
	}
	return p, nil
}

// logSibling returns the other child of the node's parent.
func logSibling(x, n uint64) (uint64, error) {
	p, err := logParent(x, n)
	if err != nil {
		return 0, err
	}
	if x < p {
		return logRight(p, n)
	}
	return logLeft(p)
}

// isFullSubtree returns true if node x represents a full subtree.
func isFullSubtree(x, n uint64) bool {
	rightmost := 2 * (n - 1)
	expected := x + (1 << level(x)) - 1
	return expected <= rightmost
}

// logFullSubtrees returns the list of full subtrees that x consists of.
func logFullSubtrees(x, n uint64) ([]uint64, error) {
	var result []uint64
	for {
		if isFullSubtree(x, n) {
			result = append(result, x)
			break
		}
		l, err := logLeft(x)
		if err != nil {
			return nil, err
		}
		result = append(result, l)
		x, err = logRight(x, n)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

// logConsistencyProof returns the list of node ids for a consistency proof between m and n.
func logConsistencyProof(m, n uint64) ([]uint64, error) {
	var output []uint64
	if err := subProofImpl(m, n, true, &output); err != nil {
		return nil, err
	}
	return output, nil
}

func subProofImpl(m, n uint64, b bool, output *[]uint64) error {
	if m == n {
		if !b {
			*output = append(*output, logRoot(m))
		}
		return nil
	}
	k := uint64(1) << log2(n)
	if k == n {
		k /= 2
	}
	if m <= k {
		if err := subProofImpl(m, k, b, output); err != nil {
			return err
		}
		r, err := logRight(logRoot(n), n)
		if err != nil {
			return err
		}
		*output = append(*output, r)
	} else {
		l, err := logLeft(logRoot(n))
		if err != nil {
			return err
		}
		*output = append(*output, l)
		start := len(*output)
		if err := subProofImpl(m-k, n-k, false, output); err != nil {
			return err
		}
		for i := start; i < len(*output); i++ {
			(*output)[i] += 2 * k
		}
	}
	return nil
}

// logBatchCopath returns the copath nodes of a batch of leaves.
func logBatchCopath(leaves []uint64, n uint64) ([]uint64, error) {
	// Convert leaf indices to node indices and sort.
	currentLevel := make([]uint64, len(leaves))
	for i, l := range leaves {
		currentLevel[i] = 2 * l
	}
	sortUint64s(currentLevel)

	var out []uint64
	root := logRoot(n)

	nodes := currentLevel

	for len(nodes) != 1 || nodes[0] != root {
		var nextLevel []uint64

		for len(nodes) > 1 {
			p, err := logParent(nodes[0], n)
			if err != nil {
				return nil, err
			}
			r, err := logRight(p, n)
			if err != nil {
				return nil, err
			}
			if r == nodes[1] {
				nodes = nodes[2:]
			} else {
				sib, err := logSibling(nodes[0], n)
				if err != nil {
					return nil, err
				}
				out = append(out, sib)
				nodes = nodes[1:]
			}
			nextLevel = append(nextLevel, p)
		}
		if len(nodes) == 1 {
			p, err := logParent(nodes[0], n)
			if err != nil {
				return nil, err
			}
			if len(nextLevel) > 0 && level(p) > level(nextLevel[0]) {
				nextLevel = append(nextLevel, nodes[0])
			} else {
				sib, err := logSibling(nodes[0], n)
				if err != nil {
					return nil, err
				}
				out = append(out, sib)
				nextLevel = append(nextLevel, p)
			}
		}

		currentLevel = nextLevel
		nodes = currentLevel
	}

	sortUint64s(out)
	return out, nil
}

// sortUint64s sorts a slice of uint64 in ascending order.
func sortUint64s(s []uint64) {
	// Simple insertion sort for small slices.
	for i := 1; i < len(s); i++ {
		key := s[i]
		j := i - 1
		for j >= 0 && s[j] > key {
			s[j+1] = s[j]
			j--
		}
		s[j+1] = key
	}
}

// nodeData is the primary wrapper struct for representing a single node in the tree.
type nodeData struct {
	interior bool
	value    Hash
}

// marshal returns the 33-byte representation of a node.
func (nd *nodeData) marshal() []byte {
	buf := make([]byte, 33)
	if nd.interior {
		buf[0] = 1
	}
	copy(buf[1:], nd.value[:])
	return buf
}

// treeHash returns the intermediate hash of left and right.
func treeHash(left, right *nodeData) nodeData {
	h := sha256.New()
	h.Write(left.marshal())
	h.Write(right.marshal())
	var value Hash
	copy(value[:], h.Sum(nil))
	return nodeData{interior: true, value: value}
}

// simpleRootCalculator computes the root hash of a tree.
type simpleRootCalculator struct {
	chain []*nodeData
}

func newSimpleRootCalculator() *simpleRootCalculator {
	return &simpleRootCalculator{}
}

func (c *simpleRootCalculator) insert(lev int, value Hash) {
	needed := lev + 1 - len(c.chain)
	if needed > 0 {
		c.chain = append(c.chain, make([]*nodeData, needed)...)
	}

	acc := &nodeData{
		interior: lev != 0,
		value:    value,
	}

	i := lev
	for i < len(c.chain) && c.chain[i] != nil {
		combined := treeHash(c.chain[i], acc)
		acc = &combined
		c.chain[i] = nil
		i++
	}
	if i == len(c.chain) {
		c.chain = append(c.chain, acc)
	} else {
		c.chain[i] = acc
	}
}

func (c *simpleRootCalculator) root() (Hash, error) {
	if len(c.chain) == 0 {
		return Hash{}, ErrEmptyChain
	}

	// Find first non-nil element.
	var rootPos int
	var root *nodeData
	for i, nd := range c.chain {
		if nd != nil {
			rootPos = i
			root = nd
			break
		}
	}
	if root == nil {
		return Hash{}, ErrMalformedChain
	}

	// Fold the hashes above.
	acc := *root
	for _, nd := range c.chain[rootPos+1:] {
		if nd != nil {
			acc = treeHash(nd, &acc)
		}
	}
	return acc.value, nil
}

// EvaluateBatchProof returns the root that would result in the given proof being valid.
func EvaluateBatchProof(x []uint64, n uint64, values []Hash, proof []Hash) (Hash, error) {
	if len(x) != len(values) {
		return Hash{}, logInvalidInput("expected same number of indices and values")
	}
	sorted := true
	for i := 1; i < len(x); i++ {
		if x[i-1] >= x[i] {
			sorted = false
			break
		}
	}
	if !sorted {
		return Hash{}, logInvalidInput("input entries must be in sorted order")
	}
	if len(x) == 0 {
		return Hash{}, logInvalidInput("can not evaluate empty batch inclusion proof")
	}
	if x[len(x)-1] >= n {
		return Hash{}, logInvalidInput("leaf ids can not be larger than tree size")
	}

	copath, err := logBatchCopath(x, n)
	if err != nil {
		return Hash{}, err
	}
	if len(proof) != len(copath) {
		return Hash{}, logMalformedProof()
	}

	calc := newSimpleRootCalculator()
	i, j := 0, 0
	for i < len(x) && j < len(copath) {
		if 2*x[i] < copath[j] {
			calc.insert(0, values[i])
			i++
		} else {
			calc.insert(level(copath[j]), proof[j])
			j++
		}
	}
	for i < len(x) {
		calc.insert(0, values[i])
		i++
	}
	for j < len(copath) {
		calc.insert(level(copath[j]), proof[j])
		j++
	}

	return calc.root()
}

// VerifyConsistencyProof checks that proof is a valid consistency proof between
// m_root and n_root where m < n.
func VerifyConsistencyProof(m, n uint64, proof []Hash, mRoot, nRoot *Hash) error {
	if m == 0 || m >= n {
		return logInvalidInput("m must be within [0, n)")
	}
	ids, err := logConsistencyProof(m, n)
	if err != nil {
		return err
	}
	if len(proof) != len(ids) {
		return logMalformedProof()
	}

	calc := newSimpleRootCalculator()

	path, err2 := logFullSubtrees(logRoot(m), m)
	if err2 != nil {
		return err2
	}
	pathIsSingleElement := len(path) == 1

	var i int
	if pathIsSingleElement {
		calc.insert(level(logRoot(m)), *mRoot)
		i = 0
	} else {
		for idx, elem := range path {
			if ids[idx] != elem {
				return logUnexpected("id does not match path")
			}
			calc.insert(level(elem), proof[idx])
		}
		calcRoot, err := calc.root()
		if err != nil {
			return err
		}
		if *mRoot != calcRoot {
			return logProofMismatch("first root does not match proof")
		}
		i = len(path)
	}

	// Step 2: Verify that the consistency proof aligns with n_root.
	for j := i; j < len(ids); j++ {
		calc.insert(level(ids[j]), proof[j])
	}
	calcRoot, err := calc.root()
	if err != nil {
		return err
	}
	if *nRoot != calcRoot {
		return logProofMismatch("second root does not match proof")
	}
	return nil
}
