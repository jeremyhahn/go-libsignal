// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package keytrans

// This file contains protocol buffer-like types used in key transparency.
// These are plain Go structs matching the protobuf message definitions.

// TreeHead contains the key transparency service operator's signature on the
// most recent version of the log.
type TreeHead struct {
	TreeSize   uint64
	Timestamp  int64
	Signatures []Signature
}

// Signature is a per-auditor signature on a tree head.
type Signature struct {
	AuditorPublicKey []byte
	SignatureBytes   []byte
}

// AuditorTreeHead contains an auditor's signature on its most recent view of the log.
type AuditorTreeHead struct {
	TreeSize  uint64
	Timestamp int64
	Signature []byte
}

// FullAuditorTreeHead is provided to end-users when third-party auditing is used.
type FullAuditorTreeHead struct {
	TreeHead    *AuditorTreeHead
	RootValue   []byte
	Consistency [][]byte
	PublicKey   []byte
}

// FullTreeHead wraps a basic TreeHead with additional information needed for validation.
type FullTreeHead struct {
	TreeHead             *TreeHead
	Last                 [][]byte
	Distinguished        [][]byte
	FullAuditorTreeHeads []FullAuditorTreeHead
}

// ProofStep is the output of one step of a binary search through the log.
type ProofStep struct {
	Prefix     *PrefixProof
	Commitment []byte
}

// SearchProof contains the output of a binary search through the log.
type SearchProof struct {
	Pos       uint64
	Steps     []ProofStep
	Inclusion [][]byte
}

// UpdateValue wraps the new value for a key.
type UpdateValue struct {
	Value []byte
}

// Consistency specifies the parameters of consistency proofs.
type Consistency struct {
	Last          *uint64
	Distinguished *uint64
}

// CondensedTreeSearchResponse is a condensed search response.
type CondensedTreeSearchResponse struct {
	VRFProof []byte
	Search   *SearchProof
	Opening  []byte
	Value    *UpdateValue
}

// UpdateRequest comes from a user that wishes to update a key.
type UpdateRequest struct {
	SearchKey   []byte
	Value       []byte
	Consistency *Consistency
}

// UpdateResponse is the output of executing an update on the tree.
type UpdateResponse struct {
	TreeHead *FullTreeHead
	VRFProof []byte
	Search   *SearchProof
	Opening  []byte
}

// MonitorKey is a single key that the user would like to monitor.
type MonitorKey struct {
	SearchKey       []byte
	EntryPosition   uint64
	CommitmentIndex []byte
}

// MonitorRequest comes from a user that wishes to monitor a set of keys.
type MonitorRequest struct {
	Keys        []MonitorKey
	Consistency *Consistency
}

// MonitorProof proves that a single key has been correctly managed in the log.
type MonitorProof struct {
	Steps []ProofStep
}

// MonitorResponse is the output of a monitoring operation.
type MonitorResponse struct {
	TreeHead  *FullTreeHead
	Proofs    []MonitorProof
	Inclusion [][]byte
}

// ChatSearchResponse contains search proofs for each of the requested identifiers.
type ChatSearchResponse struct {
	TreeHead     *FullTreeHead
	ACI          *CondensedTreeSearchResponse
	E164         *CondensedTreeSearchResponse
	UsernameHash *CondensedTreeSearchResponse
}

// ChatDistinguishedResponse contains the tree head and search proof for the
// most recent "distinguished" key in the log.
type ChatDistinguishedResponse struct {
	TreeHead      *FullTreeHead
	Distinguished *CondensedTreeSearchResponse
}

// ChatMonitorResponse contains monitoring proofs.
type ChatMonitorResponse struct {
	TreeHead     *FullTreeHead
	ACI          *MonitorProof
	UsernameHash *MonitorProof
	E164         *MonitorProof
	Inclusion    [][]byte
}

// StoredTreeHead is an encoded tree head stored on-disk.
type StoredTreeHead struct {
	TreeHead   *TreeHead
	Root       []byte
	StoredAtMs uint64
}

// StoredMonitoringData is encoded monitoring data stored on-disk.
type StoredMonitoringData struct {
	Index     []byte
	Pos       uint64
	Ptrs      map[uint64]uint32
	Owned     bool
	SearchKey []byte
}

// StoredAccountData wraps stored monitoring data for an account.
type StoredAccountData struct {
	ACI          *StoredMonitoringData
	E164         *StoredMonitoringData
	UsernameHash *StoredMonitoringData
	LastTreeHead *StoredTreeHead
}
