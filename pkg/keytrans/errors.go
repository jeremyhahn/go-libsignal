// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package keytrans

// ErrKeytransEmptyChain is returned when root() is called on an empty calculator.
type ErrKeytransEmptyChain struct{}

func (e *ErrKeytransEmptyChain) Error() string { return "empty chain" }

// ErrKeytransMalformedChain is returned when a chain has no non-nil elements.
type ErrKeytransMalformedChain struct{}

func (e *ErrKeytransMalformedChain) Error() string { return "malformed chain" }

// ErrKeytransRootHasNoParent is returned when logParent is called on the root node.
type ErrKeytransRootHasNoParent struct{}

func (e *ErrKeytransRootHasNoParent) Error() string { return "root node has no parent" }

// ErrKeytransMalformedPrefixProof is returned when a prefix proof is malformed.
type ErrKeytransMalformedPrefixProof struct{}

func (e *ErrKeytransMalformedPrefixProof) Error() string { return "malformed prefix proof" }

// ErrKeytransInvalidCurvePoint is returned when a point cannot be decoded from the curve.
type ErrKeytransInvalidCurvePoint struct{}

func (e *ErrKeytransInvalidCurvePoint) Error() string { return "invalid point on curve" }

// ErrKeytransInvalidVRFProof is returned when a VRF proof fails verification.
type ErrKeytransInvalidVRFProof struct{}

func (e *ErrKeytransInvalidVRFProof) Error() string { return "invalid VRF proof" }

// ErrKeytransTryAndIncrementFailed is returned when all 256 hash-to-curve attempts fail.
type ErrKeytransTryAndIncrementFailed struct{}

func (e *ErrKeytransTryAndIncrementFailed) Error() string {
	return "try and increment: all 256 attempts failed"
}

// ErrKeytransInvalidGuideState is returned when the set of counters is not monotonic.
type ErrKeytransInvalidGuideState struct{}

func (e *ErrKeytransInvalidGuideState) Error() string { return "set of counters is not monotonic" }

// ErrKeytransLeafNodeHasNoChildren is returned when leftStep or rightStep is called on a leaf node.
type ErrKeytransLeafNodeHasNoChildren struct{}

func (e *ErrKeytransLeafNodeHasNoChildren) Error() string { return "leaf node has no children" }

// Sentinel variables for backward-compatible direct equality and errors.Is matching.
var (
	// ErrEmptyChain is returned when root() is called on an empty calculator.
	ErrEmptyChain error = &ErrKeytransEmptyChain{}

	// ErrMalformedChain is returned when the chain has no non-nil elements.
	ErrMalformedChain error = &ErrKeytransMalformedChain{}

	// ErrRootHasNoParent is returned when logParent is called on the root node.
	ErrRootHasNoParent error = &ErrKeytransRootHasNoParent{}

	// ErrMalformedPrefixProof is returned when a prefix proof is malformed.
	ErrMalformedPrefixProof error = &ErrKeytransMalformedPrefixProof{}

	// ErrInvalidCurvePoint is returned when a point cannot be decoded from the curve.
	ErrInvalidCurvePoint error = &ErrKeytransInvalidCurvePoint{}

	// ErrInvalidVRFProof is returned when a VRF proof fails verification.
	ErrInvalidVRFProof error = &ErrKeytransInvalidVRFProof{}

	// ErrTryAndIncrementFailed is returned when all 256 hash-to-curve attempts fail.
	ErrTryAndIncrementFailed error = &ErrKeytransTryAndIncrementFailed{}

	// ErrInvalidGuideState is returned when the set of counters is not monotonic.
	ErrInvalidGuideState error = &ErrKeytransInvalidGuideState{}

	// ErrLeafNodeHasNoChildren is returned when leftStep or rightStep is called on a leaf node.
	ErrLeafNodeHasNoChildren error = &ErrKeytransLeafNodeHasNoChildren{}
)
