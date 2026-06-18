// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package keytrans

import (
	"crypto/ed25519"
	"sort"
	"time"
)

// TreeRoot is a 32-byte root hash of the transparency tree.
type TreeRoot = [32]byte

// DeploymentMode specifies the way that a transparency log is deployed.
type DeploymentMode struct {
	kind deploymentKind
	keys []ed25519.PublicKey
}

type deploymentKind int

const (
	deploymentContactMonitoring deploymentKind = iota
	deploymentThirdPartyManagement
	deploymentThirdPartyAuditing
)

// ContactMonitoring creates a DeploymentMode for contact monitoring.
func ContactMonitoring() DeploymentMode {
	return DeploymentMode{kind: deploymentContactMonitoring}
}

// ThirdPartyManagement creates a DeploymentMode for third-party management.
func ThirdPartyManagement(keys []ed25519.PublicKey) DeploymentMode {
	return DeploymentMode{kind: deploymentThirdPartyManagement, keys: keys}
}

// ThirdPartyAuditing creates a DeploymentMode for third-party auditing.
func ThirdPartyAuditing(keys []ed25519.PublicKey) DeploymentMode {
	return DeploymentMode{kind: deploymentThirdPartyAuditing, keys: keys}
}

func (dm DeploymentMode) byte() byte {
	switch dm.kind {
	case deploymentContactMonitoring:
		return 1
	case deploymentThirdPartyManagement:
		return 2
	case deploymentThirdPartyAuditing:
		return 3
	default:
		return 0
	}
}

func (dm DeploymentMode) hasAssociatedKeys() bool {
	return dm.kind != deploymentContactMonitoring
}

func (dm DeploymentMode) getAssociatedKeys() []ed25519.PublicKey {
	return dm.keys
}

// LastTreeHead stores a verified tree head and its root.
type LastTreeHead struct {
	Head TreeHead
	Root TreeRoot
}

// IntoStored converts a LastTreeHead into a StoredTreeHead.
func (lth *LastTreeHead) IntoStored(storedAt time.Time) StoredTreeHead {
	storedAtMs := uint64(storedAt.UnixMilli())
	return StoredTreeHead{
		TreeHead:   &lth.Head,
		Root:       lth.Root[:],
		StoredAtMs: storedAtMs,
	}
}

// StoredTreeHeadToLastTreeHead converts a StoredTreeHead back into a LastTreeHead.
func StoredTreeHeadToLastTreeHead(sth *StoredTreeHead) *LastTreeHead {
	if sth == nil || sth.TreeHead == nil {
		return nil
	}
	if len(sth.Root) != 32 {
		return nil
	}
	var root TreeRoot
	copy(root[:], sth.Root)
	return &LastTreeHead{Head: *sth.TreeHead, Root: root}
}

// SearchContext provides context for a search verification.
type SearchContext struct {
	LastTreeHead              *LastTreeHead
	LastDistinguishedTreeHead *LastTreeHead
	Data                      *MonitoringData
}

// MonitorContext provides context for a monitor verification.
type MonitorContext struct {
	LastTreeHead              *LastTreeHead
	LastDistinguishedTreeHead *LastTreeHead
	Data                      map[string]*MonitoringData
}

// MonitoringData is the structure retained for each key in the KT server being monitored.
type MonitoringData struct {
	// Index is the VRF output on the search key.
	Index [32]byte
	// Pos is the initial position of the key in the log.
	Pos uint64
	// Ptrs is a map from position in log to observed version.
	Ptrs map[uint64]uint32
	// Owned indicates whether this client owns the key.
	Owned bool
	// SearchKey is the raw search key associated with this monitoring entry,
	// preserved from StoredMonitoringData for round-trip fidelity.
	SearchKey []byte
}

// Clone creates a deep copy of MonitoringData.
func (md *MonitoringData) Clone() MonitoringData {
	ptrs := make(map[uint64]uint32, len(md.Ptrs))
	for k, v := range md.Ptrs {
		ptrs[k] = v
	}
	var searchKey []byte
	if len(md.SearchKey) > 0 {
		searchKey = make([]byte, len(md.SearchKey))
		copy(searchKey, md.SearchKey)
	}
	return MonitoringData{
		Index:     md.Index,
		Pos:       md.Pos,
		Ptrs:      ptrs,
		Owned:     md.Owned,
		SearchKey: searchKey,
	}
}

// NextMonitor returns the smallest tree size where monitoring would be valuable.
func (md *MonitoringData) NextMonitor() uint64 {
	return nextMonitor(md.Entries())
}

// Entries returns the sorted list of positions.
func (md *MonitoringData) Entries() []uint64 {
	out := make([]uint64, 0, len(md.Ptrs))
	for k := range md.Ptrs {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// LatestLogPosition returns the largest known log position.
func (md *MonitoringData) LatestLogPosition() uint64 {
	var maxPos uint64
	first := true
	for k := range md.Ptrs {
		if first || k > maxPos {
			maxPos = k
			first = false
		}
	}
	return maxPos
}

// GreatestVersion returns the greatest known version of the search key.
func (md *MonitoringData) GreatestVersion() uint32 {
	var maxVer uint32
	first := true
	for _, v := range md.Ptrs {
		if first || v > maxVer {
			maxVer = v
			first = false
		}
	}
	return maxVer
}

// IntoStored converts MonitoringData to StoredMonitoringData.
func (md *MonitoringData) IntoStored(searchKey []byte) StoredMonitoringData {
	return StoredMonitoringData{
		Index:     md.Index[:],
		Pos:       md.Pos,
		Ptrs:      md.Ptrs,
		Owned:     md.Owned,
		SearchKey: searchKey,
	}
}

// MonitoringDataFromStored creates MonitoringData from StoredMonitoringData.
func MonitoringDataFromStored(smd *StoredMonitoringData) *MonitoringData {
	if smd == nil {
		return nil
	}
	var index [32]byte
	copy(index[:], smd.Index)
	var searchKey []byte
	if len(smd.SearchKey) > 0 {
		searchKey = make([]byte, len(smd.SearchKey))
		copy(searchKey, smd.SearchKey)
	}
	return &MonitoringData{
		Index:     index,
		Pos:       smd.Pos,
		Ptrs:      smd.Ptrs,
		Owned:     smd.Owned,
		SearchKey: searchKey,
	}
}

// VerifiedSearchResult holds the result of a verified search operation.
type VerifiedSearchResult struct {
	Value       []byte
	StateUpdate SearchStateUpdate
}

// TreeRoot returns the tree root from the search result.
func (vsr *VerifiedSearchResult) TreeRoot() *TreeRoot {
	return &vsr.StateUpdate.TreeRoot
}

// AreAllRootsEqual checks whether all provided results share the same tree root.
func (vsr *VerifiedSearchResult) AreAllRootsEqual(others ...*VerifiedSearchResult) bool {
	for _, other := range others {
		if other != nil && *vsr.TreeRoot() != *other.TreeRoot() {
			return false
		}
	}
	return true
}

// LocalStateUpdate is a collection of updates needed after verifying a KT operation.
type LocalStateUpdate struct {
	TreeHead TreeHead
	TreeRoot TreeRoot
}

// SearchStateUpdate contains updates from a search verification.
type SearchStateUpdate struct {
	TreeHead       TreeHead
	TreeRoot       TreeRoot
	MonitoringData *MonitoringData
}

// MonitorStateUpdate contains updates from a monitor verification.
type MonitorStateUpdate struct {
	TreeHead       TreeHead
	TreeRoot       TreeRoot
	MonitoringData map[string]*MonitoringData
}

// PublicConfig wraps the cryptographic keys needed to interact with a transparency tree.
type PublicConfig struct {
	Mode         DeploymentMode
	SignatureKey ed25519.PublicKey
	VRFKey       *VRFPublicKey
}

// SlimSearchRequest is a search request trimmed to only the parts needed for verification.
type SlimSearchRequest struct {
	SearchKey []byte
	Version   *uint32
}

// NewSlimSearchRequest creates a new SlimSearchRequest.
func NewSlimSearchRequest(searchKey []byte) SlimSearchRequest {
	return SlimSearchRequest{SearchKey: searchKey}
}

// FullSearchResponse is a self-sufficient key transparency search response.
type FullSearchResponse struct {
	Condensed *CondensedTreeSearchResponse
	TreeHead  *FullTreeHead
}

// NewFullSearchResponse creates a new FullSearchResponse.
func NewFullSearchResponse(condensed *CondensedTreeSearchResponse, treeHead *FullTreeHead) FullSearchResponse {
	return FullSearchResponse{Condensed: condensed, TreeHead: treeHead}
}

// KeyTransparency is the main API entrypoint for key transparency operations.
type KeyTransparency struct {
	Config PublicConfig
}

// VerifySearch checks that the output of a Search operation is valid and updates
// the client's stored data.
func (kt *KeyTransparency) VerifySearch(
	request SlimSearchRequest,
	response FullSearchResponse,
	context SearchContext,
	forceMonitor bool,
	now time.Time,
) (*VerifiedSearchResult, error) {
	var unverifiedValue []byte
	if response.Condensed != nil && response.Condensed.Value != nil {
		unverifiedValue = make([]byte, len(response.Condensed.Value.Value))
		copy(unverifiedValue, response.Condensed.Value.Value)
	}

	stateUpdate, err := VerifySearch(&kt.Config, request, response, context, forceMonitor, now)
	if err != nil {
		return nil, err
	}

	if unverifiedValue == nil {
		return nil, errRequiredFieldMissing("update value")
	}

	return &VerifiedSearchResult{
		Value:       unverifiedValue,
		StateUpdate: *stateUpdate,
	}, nil
}

// VerifyDistinguished checks that the provided FullTreeHead has a valid consistency
// proof relative to the provided distinguished head.
func (kt *KeyTransparency) VerifyDistinguished(
	fullTreeHead *FullTreeHead,
	lastTreeHead *LastTreeHead,
	lastDistinguishedTreeHead *LastTreeHead,
) error {
	return VerifyDistinguished(fullTreeHead, lastTreeHead, lastDistinguishedTreeHead)
}

// VerifyMonitor checks that the output of a Monitor operation is valid and
// updates the client's stored data.
func (kt *KeyTransparency) VerifyMonitor(
	request *MonitorRequest,
	response *MonitorResponse,
	context MonitorContext,
	now time.Time,
) (*MonitorStateUpdate, error) {
	return VerifyMonitor(&kt.Config, request, response, context, now)
}

// AccountData is an in-memory representation of StoredAccountData.
type AccountData struct {
	ACI          MonitoringData
	E164         *MonitoringData
	UsernameHash *MonitoringData
	LastTreeHead LastTreeHead
}

// AccountDataFromStored converts StoredAccountData to AccountData.
func AccountDataFromStored(stored *StoredAccountData) (*AccountData, error) {
	if stored == nil {
		return nil, errRequiredFieldMissing("stored account data")
	}
	if stored.LastTreeHead == nil {
		return nil, errRequiredFieldMissing("last_tree_head")
	}
	lth := StoredTreeHeadToLastTreeHead(stored.LastTreeHead)
	if lth == nil {
		return nil, errBadData("invalid stored tree head")
	}
	if stored.ACI == nil {
		return nil, errRequiredFieldMissing("aci")
	}
	aci := MonitoringDataFromStored(stored.ACI)

	var e164 *MonitoringData
	if stored.E164 != nil {
		e164 = MonitoringDataFromStored(stored.E164)
	}
	var usernameHash *MonitoringData
	if stored.UsernameHash != nil {
		usernameHash = MonitoringDataFromStored(stored.UsernameHash)
	}

	return &AccountData{
		ACI:          *aci,
		E164:         e164,
		UsernameHash: usernameHash,
		LastTreeHead: *lth,
	}, nil
}

// IntoStored converts AccountData to StoredAccountData.
func (ad *AccountData) IntoStored(
	aciSearchKey []byte,
	e164SearchKey []byte,
	usernameHashSearchKey []byte,
	storedAt time.Time,
) StoredAccountData {
	aciStored := ad.ACI.IntoStored(aciSearchKey)
	var e164Stored *StoredMonitoringData
	if ad.E164 != nil && e164SearchKey != nil {
		s := ad.E164.IntoStored(e164SearchKey)
		e164Stored = &s
	}
	var usernameHashStored *StoredMonitoringData
	if ad.UsernameHash != nil && usernameHashSearchKey != nil {
		s := ad.UsernameHash.IntoStored(usernameHashSearchKey)
		usernameHashStored = &s
	}
	lthStored := ad.LastTreeHead.IntoStored(storedAt)

	return StoredAccountData{
		ACI:          &aciStored,
		E164:         e164Stored,
		UsernameHash: usernameHashStored,
		LastTreeHead: &lthStored,
	}
}
