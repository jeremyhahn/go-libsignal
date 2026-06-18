// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package keytrans

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"sort"
	"time"
)

// Verification constants.
const (
	// maxTimestampBehind is the maximum allowed time behind "now" for server timestamps.
	maxTimestampBehind = 24 * time.Hour
	// maxTimestampAhead is the maximum allowed time ahead of "now" for server timestamps.
	maxTimestampAhead = 60 * time.Second

	// maxAuditorTimestampBehind is the maximum allowed time behind for auditor timestamps.
	maxAuditorTimestampBehind = 7 * 24 * time.Hour
	// maxAuditorTimestampAhead is the maximum allowed time ahead for auditor timestamps.
	maxAuditorTimestampAhead = 60 * time.Second

	// entriesMaxBehind is the maximum distance an auditor can be behind the server.
	entriesMaxBehind uint64 = 10_000_000

	// maxTreeSize bounds tree_size to keep tree math within u64.
	maxTreeSize uint64 = 1 << 62
)

// Error represents a key transparency verification error.
type Error struct {
	kind    errorKind
	message string
}

type errorKind int

const (
	errorKindRequiredFieldMissing errorKind = iota
	errorKindBadData
	errorKindVerificationFailed
)

func (e *Error) Error() string {
	switch e.kind {
	case errorKindRequiredFieldMissing:
		return fmt.Sprintf("required field '%s' not found", e.message)
	case errorKindBadData:
		return fmt.Sprintf("bad data: %s", e.message)
	case errorKindVerificationFailed:
		return fmt.Sprintf("verification failed: %s", e.message)
	default:
		return e.message
	}
}

func errRequiredFieldMissing(name string) *Error {
	return &Error{kind: errorKindRequiredFieldMissing, message: name}
}

func errBadData(msg string) *Error {
	return &Error{kind: errorKindBadData, message: msg}
}

func errVerificationFailed(msg string) *Error {
	return &Error{kind: errorKindVerificationFailed, message: msg}
}

// timestampRange defines allowed timestamps relative to "now".
type timestampRange struct {
	maxBehind time.Duration
	maxAhead  time.Duration
}

type qualifier int

const (
	qualifierServer    qualifier = iota
	qualifierValidator qualifier = iota
)

func (q qualifier) String() string {
	switch q {
	case qualifierServer:
		return "Server"
	case qualifierValidator:
		return "Validator"
	default:
		return "Unknown"
	}
}

func getHashProof(proof [][]byte) ([][32]byte, error) {
	result := make([][32]byte, len(proof))
	for i, elem := range proof {
		if len(elem) != 32 {
			return nil, errBadData("proof element is wrong size")
		}
		copy(result[i][:], elem)
	}
	return result, nil
}

func marshalUpdateValue(value []byte) ([]byte, error) {
	if len(value) > int(^uint32(0)) {
		return nil, errBadData("value too long to be encoded")
	}
	length := uint32(len(value))
	buf := make([]byte, 4+len(value))
	copy(buf[0:4], uint32ToBeBytes(length))
	copy(buf[4:], value)
	return buf, nil
}

// verifyLeafHash returns the hash of the leaf of the transparency tree.
func verifyLeafHash(prefixRoot, commitment *[32]byte) [32]byte {
	return sha256Sum(prefixRoot[:], commitment[:])
}

// verifyTreeHeadSignature checks the signature on the provided transparency tree head.
func verifyTreeHeadSignature(
	config *PublicConfig,
	head verifiableTreeHead,
	root *[32]byte,
	verifyingKey ed25519.PublicKey,
	maybeAuditorKey ed25519.PublicKey,
) error {
	tbs := marshalTreeHeadTBS(head, root, config, maybeAuditorKey)
	sig := head.signatureBytes()
	if len(sig) != ed25519.SignatureSize {
		return errBadData("signature has wrong size")
	}
	if !ed25519.Verify(verifyingKey, tbs, sig) {
		return errVerificationFailed("failed to verify tree head signature")
	}
	return nil
}

// marshalTreeHeadTBS marshals a tree head for signing/verification.
func marshalTreeHeadTBS(
	head verifiableTreeHead,
	root *[32]byte,
	config *PublicConfig,
	maybeAuditorKey ed25519.PublicKey,
) []byte {
	var buf []byte

	buf = append(buf, 0, 0)               // Ciphersuite
	buf = append(buf, config.Mode.byte()) // Deployment mode

	serializeKey := func(keyMaterial []byte) {
		keyLen := uint16(len(keyMaterial))
		buf = append(buf, uint16ToBeBytes(keyLen)...)
		buf = append(buf, keyMaterial...)
	}

	serializeKey(config.SignatureKey)
	serializeKey(config.VRFKey.AsBytes()[:])

	if maybeAuditorKey != nil {
		serializeKey(maybeAuditorKey)
	}

	buf = append(buf, uint64ToBeBytes(head.treeSize())...)
	buf = append(buf, int64ToBeBytes(head.timestamp())...)
	buf = append(buf, root[:]...)

	return buf
}

// verifiableTreeHead is an interface for tree heads that can be verified.
type verifiableTreeHead interface {
	treeSize() uint64
	timestamp() int64
	signatureBytes() []byte
}

// singleSignatureTreeHead wraps a TreeHead guaranteeing one signature.
type singleSignatureTreeHead struct {
	inner *TreeHead
}

func (s *singleSignatureTreeHead) treeSize() uint64 { return s.inner.TreeSize }
func (s *singleSignatureTreeHead) timestamp() int64 { return s.inner.Timestamp }
func (s *singleSignatureTreeHead) signatureBytes() []byte {
	return s.inner.Signatures[0].SignatureBytes
}

// auditorTreeHeadWrapper wraps AuditorTreeHead as a verifiableTreeHead.
type auditorTreeHeadWrapper struct {
	inner *AuditorTreeHead
}

func (a *auditorTreeHeadWrapper) treeSize() uint64       { return a.inner.TreeSize }
func (a *auditorTreeHeadWrapper) timestamp() int64       { return a.inner.Timestamp }
func (a *auditorTreeHeadWrapper) signatureBytes() []byte { return a.inner.Signature }

// toSingleSignatureTreeHeads splits a multi-signature TreeHead into per-auditor heads.
func toSingleSignatureTreeHeads(th *TreeHead, config *PublicConfig) ([]struct {
	Key  ed25519.PublicKey
	Head *singleSignatureTreeHead
}, error) {
	keys := config.Mode.getAssociatedKeys()
	if len(keys) == 0 {
		return nil, nil
	}

	var result []struct {
		Key  ed25519.PublicKey
		Head *singleSignatureTreeHead
	}

	for _, key := range keys {
		found := false
		for _, sig := range th.Signatures {
			if bytes.Equal(key, sig.AuditorPublicKey) {
				head := &singleSignatureTreeHead{
					inner: &TreeHead{
						TreeSize:   th.TreeSize,
						Timestamp:  th.Timestamp,
						Signatures: []Signature{sig},
					},
				}
				result = append(result, struct {
					Key  ed25519.PublicKey
					Head *singleSignatureTreeHead
				}{Key: key, Head: head})
				found = true
				break
			}
		}
		if !found {
			return nil, errBadData("server signatures are either missing or not available for all auditors")
		}
	}
	return result, nil
}

// selectAuditorTreeHead finds an auditor tree head by public key.
func selectAuditorTreeHead(fth *FullTreeHead, publicKey ed25519.PublicKey) *FullAuditorTreeHead {
	for i := range fth.FullAuditorTreeHeads {
		if bytes.Equal(fth.FullAuditorTreeHeads[i].PublicKey, publicKey) {
			return &fth.FullAuditorTreeHeads[i]
		}
	}
	return nil
}

// auditorTreeHeads finds matching auditor tree heads for the given keys.
func auditorTreeHeads(fth *FullTreeHead, keys []ed25519.PublicKey) ([]struct {
	Key  ed25519.PublicKey
	Head *FullAuditorTreeHead
}, error) {
	var result []struct {
		Key  ed25519.PublicKey
		Head *FullAuditorTreeHead
	}
	for _, key := range keys {
		head := selectAuditorTreeHead(fth, key)
		if head == nil {
			return nil, errBadData("auditor tree heads are either missing or not available for all auditors")
		}
		result = append(result, struct {
			Key  ed25519.PublicKey
			Head *FullAuditorTreeHead
		}{Key: key, Head: head})
	}
	return result, nil
}

// verifyFullTreeHead validates a FullTreeHead structure.
func verifyFullTreeHead(
	config *PublicConfig,
	fth *FullTreeHead,
	root [32]byte,
	lastTreeHead *LastTreeHead,
	lastDistinguishedTreeHead *LastTreeHead,
	now time.Time,
) (*LastTreeHead, error) {
	if fth.TreeHead == nil {
		return nil, errRequiredFieldMissing("tree_head")
	}
	treeHead := fth.TreeHead

	// Check consistency with last tree head.
	lastProof, err := getHashProof(fth.Last)
	if err != nil {
		return nil, err
	}
	if err := checkAndVerifyConsistency(treeHead, &root, lastProof, lastTreeHead); err != nil {
		return nil, err
	}

	// Check consistency with last distinguished tree head.
	distinguishedProof, err := getHashProof(fth.Distinguished)
	if err != nil {
		return nil, err
	}
	if err := checkAndVerifyConsistency(treeHead, &root, distinguishedProof, lastDistinguishedTreeHead); err != nil {
		return nil, err
	}

	// Verify the signatures in TreeHead.
	singleHeads, err := toSingleSignatureTreeHeads(treeHead, config)
	if err != nil {
		return nil, err
	}
	for _, kh := range singleHeads {
		if err := verifyTreeHeadSignature(config, kh.Head, &root, config.SignatureKey, kh.Key); err != nil {
			return nil, err
		}
	}

	// Verify that the timestamp is sufficiently recent.
	if err := verifyTimestamp(qualifierServer, treeHead.Timestamp, &timestampRange{
		maxBehind: maxTimestampBehind,
		maxAhead:  maxTimestampAhead,
	}, now); err != nil {
		return nil, err
	}

	// If third-party auditing is used, verify every auditor_tree_head.
	if config.Mode.kind == deploymentThirdPartyAuditing {
		auditorKeys := config.Mode.getAssociatedKeys()
		keyHeadPairs, err := auditorTreeHeads(fth, auditorKeys)
		if err != nil {
			return nil, err
		}
		for _, pair := range keyHeadPairs {
			auditorHead := pair.Head.TreeHead
			if auditorHead == nil {
				return nil, errRequiredFieldMissing("tree_head")
			}
			if err := verifyTimestamp(qualifierValidator, auditorHead.Timestamp, &timestampRange{
				maxBehind: maxAuditorTimestampBehind,
				maxAhead:  maxAuditorTimestampAhead,
			}, now); err != nil {
				return nil, err
			}
			if uint64(auditorHead.TreeSize) > treeHead.TreeSize {
				return nil, errBadData("auditor tree head may not be further along than service tree head")
			}
			if treeHead.TreeSize-uint64(auditorHead.TreeSize) > entriesMaxBehind {
				return nil, errBadData("auditor tree head is too far behind service tree head")
			}
			wrapper := &auditorTreeHeadWrapper{inner: auditorHead}
			if treeHead.TreeSize > uint64(auditorHead.TreeSize) {
				if pair.Head.RootValue == nil || len(pair.Head.RootValue) != 32 {
					return nil, errBadData("auditor tree head is malformed")
				}
				var auditorRoot [32]byte
				copy(auditorRoot[:], pair.Head.RootValue)
				proof, err := getHashProof(pair.Head.Consistency)
				if err != nil {
					return nil, err
				}
				if err := VerifyConsistencyProof(
					uint64(auditorHead.TreeSize),
					treeHead.TreeSize,
					hashesToSlice(proof),
					&auditorRoot,
					&root,
				); err != nil {
					return nil, wrapLogError(err)
				}
				if err := verifyTreeHeadSignature(config, wrapper, &auditorRoot, pair.Key, pair.Key); err != nil {
					return nil, err
				}
			} else {
				if len(pair.Head.Consistency) > 0 {
					return nil, errBadData("consistency proof provided when not expected")
				}
				if pair.Head.RootValue != nil {
					return nil, errBadData("explicit root value provided when not expected")
				}
				if err := verifyTreeHeadSignature(config, wrapper, &root, pair.Key, pair.Key); err != nil {
					return nil, err
				}
			}
		}
	}

	return &LastTreeHead{Head: *treeHead, Root: root}, nil
}

// checkAndVerifyConsistency checks consistency between a current tree head and a baseline.
func checkAndVerifyConsistency(
	current *TreeHead,
	currentRoot *[32]byte,
	proof [][32]byte,
	baseline *LastTreeHead,
) error {
	if baseline == nil {
		if len(proof) > 0 {
			return errBadData("consistency proof provided when not expected")
		}
		return nil
	}

	if baseline.Head.TreeSize == current.TreeSize {
		if *currentRoot != baseline.Root {
			return errBadData("root is different but tree size is same")
		}
		if current.Timestamp != baseline.Head.Timestamp {
			return errBadData("tree size is the same but timestamps differ")
		}
		if len(proof) > 0 {
			return errBadData("consistency proof provided when not expected")
		}
		return nil
	}

	if current.TreeSize < baseline.Head.TreeSize {
		return errBadData("current tree size is less than previous tree size")
	}
	if current.Timestamp < baseline.Head.Timestamp {
		return errBadData("current timestamp is less than previous timestamp")
	}

	return wrapLogError(VerifyConsistencyProof(
		baseline.Head.TreeSize,
		current.TreeSize,
		hashesToSlice(proof),
		&baseline.Root,
		currentRoot,
	))
}

// verifyTimestamp checks that a timestamp is within the allowed range.
// A bounds check prevents int64 overflow on malicious timestamp values.
func verifyTimestamp(qual qualifier, timestamp int64, allowed *timestampRange, now time.Time) error {
	// Guard against int64 overflow: reject timestamps that would cause
	// nowMs - timestamp to overflow. math.MaxInt64/2 gives generous room
	// for both positive and negative values.
	const maxSafeTimestamp = 1<<62 - 1
	if timestamp < -maxSafeTimestamp || timestamp > maxSafeTimestamp {
		return errBadData(fmt.Sprintf("%s timestamp is out of representable range", qual))
	}
	nowMs := now.UnixMilli()
	delta := nowMs - timestamp
	if delta > allowed.maxBehind.Milliseconds() {
		return errBadData(fmt.Sprintf("%s timestamp is too far behind current time (delta: %d ms)", qual, delta))
	}
	if -delta > allowed.maxAhead.Milliseconds() {
		return errBadData(fmt.Sprintf("%s timestamp is too far ahead of current time (delta: %d ms)", qual, delta))
	}
	return nil
}

// VerifyDistinguished checks that the provided FullTreeHead has a valid
// consistency proof relative to the provided distinguished head.
func VerifyDistinguished(
	fth *FullTreeHead,
	lastTreeHead *LastTreeHead,
	lastDistinguishedTreeHead *LastTreeHead,
) error {
	if fth.TreeHead == nil {
		return errRequiredFieldMissing("tree_head")
	}
	treeSize := fth.TreeHead.TreeSize

	if lastTreeHead == nil {
		return nil
	}

	var root *[32]byte
	if lastTreeHead.Head.TreeSize == treeSize {
		root = &lastTreeHead.Root
	} else {
		return errBadData("expected tree head not found in storage")
	}

	distinguishedSize := lastDistinguishedTreeHead.Head.TreeSize
	distinguishedRoot := &lastDistinguishedTreeHead.Root

	if treeSize == distinguishedSize {
		if *root == *distinguishedRoot {
			return nil
		}
		return errBadData("root hash does not match expected value")
	}

	proof, err := getHashProof(fth.Distinguished)
	if err != nil {
		return err
	}
	return wrapLogError(VerifyConsistencyProof(
		distinguishedSize,
		treeSize,
		hashesToSlice(proof),
		distinguishedRoot,
		root,
	))
}

func evaluateVRFProof(proof []byte, vrfKey *VRFPublicKey, searchKey []byte) ([32]byte, error) {
	if len(proof) != 80 {
		return [32]byte{}, ErrMalformedPrefixProof
	}
	var proofArr [80]byte
	copy(proofArr[:], proof)
	return vrfKey.ProofToHash(searchKey, &proofArr)
}

// verifySearchInternal is the shared implementation of VerifySearch and VerifyUpdate.
func verifySearchInternal(
	config *PublicConfig,
	req SlimSearchRequest,
	res FullSearchResponse,
	context SearchContext,
	monitor bool,
	now time.Time,
) (*SearchStateUpdate, error) {
	index, err := evaluateVRFProof(res.Condensed.VRFProof, config.VRFKey, req.SearchKey)
	if err != nil {
		return nil, err
	}

	if res.TreeHead.TreeHead == nil {
		return nil, errRequiredFieldMissing("tree_head")
	}
	treeSize := res.TreeHead.TreeHead.TreeSize
	searchProof := res.Condensed.Search
	if searchProof == nil {
		return nil, errRequiredFieldMissing("search")
	}

	// Validate tree parameters.
	if treeSize == 0 || treeSize > maxTreeSize {
		return nil, errVerificationFailed("tree_size out of range")
	}
	if searchProof.Pos >= treeSize {
		return nil, errVerificationFailed("search proof pos must be less than tree_size")
	}

	guide, err := NewProofGuide(req.Version, searchProof.Pos, treeSize)
	if err != nil {
		return nil, err
	}

	i := 0
	leaves := make(map[uint64][32]byte)
	steps := make(map[uint64]ProofStep)

	resultIdx, resultID, resultOk, err := guide.Consume(func(g *ProofGuide, nextID uint64) error {
		if i >= len(searchProof.Steps) {
			return errVerificationFailed("unexpected number of steps in search proof")
		}
		step := &searchProof.Steps[i]
		if step.Prefix == nil {
			return errRequiredFieldMissing("prefix")
		}
		g.Insert(nextID, step.Prefix.Counter)

		prefixRoot, err := EvaluatePrefix(&index, searchProof.Pos, step.Prefix)
		if err != nil {
			return wrapPrefixError(err)
		}
		if len(step.Commitment) != 32 {
			return errVerificationFailed("malformed commitment")
		}
		var commitment [32]byte
		copy(commitment[:], step.Commitment)
		leaves[nextID] = verifyLeafHash(&prefixRoot, &commitment)
		steps[nextID] = *step
		i++
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Verify step count.
	if i != len(searchProof.Steps) {
		return nil, errVerificationFailed("unexpected number of steps in search proof")
	}

	// Evaluate inclusion proof.
	inclusionProof, err := getHashProof(searchProof.Inclusion)
	if err != nil {
		return nil, err
	}
	ids, values := intoSortedPairsHash(leaves)
	root, err := EvaluateBatchProof(ids, treeSize, values, hashesToSlice(inclusionProof))
	if err != nil {
		return nil, wrapLogError(err)
	}

	// Verify commitment opening.
	if !resultOk {
		return nil, errVerificationFailed("failed to find expected version of key")
	}
	resultStep := &searchProof.Steps[resultIdx]

	if res.Condensed.Value == nil {
		return nil, errRequiredFieldMissing("value")
	}
	value, err := marshalUpdateValue(res.Condensed.Value.Value)
	if err != nil {
		return nil, err
	}
	if len(res.Condensed.Opening) != 16 {
		return nil, errVerificationFailed("malformed opening")
	}
	var opening [16]byte
	copy(opening[:], res.Condensed.Opening)

	if !VerifyCommitment(req.SearchKey, resultStep.Commitment, value, &opening) {
		return nil, errVerificationFailed("failed to verify commitment opening")
	}

	// Verify the tree head.
	updatedTreeHead, err := verifyFullTreeHead(
		config,
		res.TreeHead,
		root,
		context.LastTreeHead,
		context.LastDistinguishedTreeHead,
		now,
	)
	if err != nil {
		return nil, err
	}

	// Update stored monitoring data.
	size := treeSize
	if bytes.Equal(req.SearchKey, []byte("distinguished")) {
		size = resultID + 1
	}
	if resultStep.Prefix == nil {
		return nil, errRequiredFieldMissing("prefix")
	}
	ver := resultStep.Prefix.Counter

	mdw := newMonitoringDataWrapper(context.Data)
	if monitor || config.Mode.kind == deploymentContactMonitoring {
		mdw.startMonitoring(&index, searchProof.Pos, resultID, ver, monitor)
	}
	if err := mdw.checkSearchConsistency(size, &index, searchProof.Pos, resultID, ver, monitor); err != nil {
		return nil, err
	}
	if err := mdw.update(size, steps); err != nil {
		return nil, err
	}

	return &SearchStateUpdate{
		TreeHead:       updatedTreeHead.Head,
		TreeRoot:       updatedTreeHead.Root,
		MonitoringData: mdw.intoDataUpdate(),
	}, nil
}

// VerifySearch checks that the output of a Search operation is valid.
func VerifySearch(
	config *PublicConfig,
	req SlimSearchRequest,
	res FullSearchResponse,
	context SearchContext,
	forceMonitor bool,
	now time.Time,
) (*SearchStateUpdate, error) {
	return verifySearchInternal(config, req, res, context, forceMonitor, now)
}

// VerifyMonitor checks that the output of a Monitor operation is valid.
func VerifyMonitor(
	config *PublicConfig,
	req *MonitorRequest,
	res *MonitorResponse,
	context MonitorContext,
	now time.Time,
) (*MonitorStateUpdate, error) {
	if len(req.Keys) != len(res.Proofs) {
		return nil, errBadData("monitoring response is malformed: wrong number of key proofs")
	}

	if res.TreeHead == nil {
		return nil, errRequiredFieldMissing("tree_head")
	}
	fullTreeHead := res.TreeHead
	if fullTreeHead.TreeHead == nil {
		return nil, errRequiredFieldMissing("tree_head")
	}
	treeSize := fullTreeHead.TreeHead.TreeSize

	if treeSize == 0 || treeSize > maxTreeSize {
		return nil, errVerificationFailed("tree_size out of range")
	}

	// Process all the individual MonitorProof structures.
	mpa := newMonitorProofAcc(treeSize)
	for i := range req.Keys {
		if err := mpa.process(context.Data, &req.Keys[i], &res.Proofs[i]); err != nil {
			return nil, err
		}
	}

	// Evaluate the inclusion proof to get a candidate root value.
	inclusionProof, err := getHashProof(res.Inclusion)
	if err != nil {
		return nil, err
	}

	var root [32]byte
	if len(mpa.leaves) == 0 {
		if len(inclusionProof) != 1 {
			return nil, errVerificationFailed("monitoring response is malformed: inclusion proof should be root")
		}
		root = inclusionProof[0]
	} else {
		ids, values := intoSortedPairsHash(mpa.leaves)
		root, err = EvaluateBatchProof(ids, treeSize, values, hashesToSlice(inclusionProof))
		if err != nil {
			return nil, wrapLogError(err)
		}
	}

	// Verify the tree head.
	updatedTreeHead, err := verifyFullTreeHead(
		config,
		fullTreeHead,
		root,
		context.LastTreeHead,
		&LastTreeHead{Head: context.LastDistinguishedTreeHead.Head, Root: context.LastDistinguishedTreeHead.Root},
		now,
	)
	if err != nil {
		return nil, err
	}

	dataUpdates := make(map[string]*MonitoringData, len(req.Keys))
	for i := range req.Keys {
		key := &req.Keys[i]
		size := treeSize
		if bytes.Equal(key.SearchKey, []byte("distinguished")) {
			if req.Consistency == nil || req.Consistency.Last == nil {
				return nil, errRequiredFieldMissing("consistency field when monitoring distinguished key")
			}
			size = *req.Consistency.Last
		}
		data := context.Data[string(key.SearchKey)]
		mdw := newMonitoringDataWrapper(data)
		if err := mdw.update(size, mpa.entries[i]); err != nil {
			return nil, err
		}
		if update := mdw.intoDataUpdate(); update != nil {
			dataUpdates[string(key.SearchKey)] = update
		}
	}

	return &MonitorStateUpdate{
		TreeHead:       updatedTreeHead.Head,
		TreeRoot:       updatedTreeHead.Root,
		MonitoringData: dataUpdates,
	}, nil
}

// monitorProofAcc accumulates monitoring proof data.
type monitorProofAcc struct {
	treeSize uint64
	leaves   map[uint64][32]byte
	entries  []map[uint64]ProofStep
}

func newMonitorProofAcc(treeSize uint64) *monitorProofAcc {
	return &monitorProofAcc{
		treeSize: treeSize,
		leaves:   make(map[uint64][32]byte),
	}
}

func (mpa *monitorProofAcc) process(
	monitoringData map[string]*MonitoringData,
	key *MonitorKey,
	proof *MonitorProof,
) error {
	data, ok := monitoringData[string(key.SearchKey)]
	if !ok {
		return errBadData("unable to process monitoring response for unknown search key")
	}

	entries, err := fullMonitoringPath(key.EntryPosition, data.Pos, mpa.treeSize)
	if err != nil {
		return err
	}
	if len(entries) != len(proof.Steps) {
		return errVerificationFailed("monitoring response is malformed: wrong number of proof steps")
	}

	steps := make(map[uint64]ProofStep)
	for i, entry := range entries {
		step := &proof.Steps[i]
		if step.Prefix == nil {
			return errRequiredFieldMissing("prefix")
		}
		prefixRoot, err := EvaluatePrefix(&data.Index, data.Pos, step.Prefix)
		if err != nil {
			return wrapPrefixError(err)
		}
		if len(step.Commitment) != 32 {
			return errVerificationFailed("malformed commitment")
		}
		var commitment [32]byte
		copy(commitment[:], step.Commitment)
		leaf := verifyLeafHash(&prefixRoot, &commitment)

		if other, exists := mpa.leaves[entry]; exists {
			if leaf != other {
				return errVerificationFailed("monitoring response is malformed: multiple values for same leaf")
			}
		} else {
			mpa.leaves[entry] = leaf
		}
		steps[entry] = *step
	}
	mpa.entries = append(mpa.entries, steps)
	return nil
}

// monitoringDataWrapper wraps monitoring data for updates.
type monitoringDataWrapper struct {
	inner *MonitoringData
}

func newMonitoringDataWrapper(data *MonitoringData) *monitoringDataWrapper {
	if data != nil {
		cloned := data.Clone()
		return &monitoringDataWrapper{inner: &cloned}
	}
	return &monitoringDataWrapper{}
}

func (mdw *monitoringDataWrapper) intoDataUpdate() *MonitoringData {
	return mdw.inner
}

// startMonitoring adds a key to the database of keys to monitor.
func (mdw *monitoringDataWrapper) startMonitoring(
	index *[32]byte,
	zeroPos, verPos uint64,
	version uint32,
	owned bool,
) {
	if mdw.inner == nil {
		mdw.inner = &MonitoringData{
			Index: *index,
			Pos:   zeroPos,
			Ptrs:  map[uint64]uint32{verPos: version},
			Owned: owned,
		}
	}
}

func (mdw *monitoringDataWrapper) checkSearchConsistency(
	treeSize uint64,
	index *[32]byte,
	zeroPos, verPos uint64,
	version uint32,
	owned bool,
) error {
	if mdw.inner == nil {
		return nil
	}
	data := mdw.inner

	if *index != data.Index {
		return errVerificationFailed("given search key index does not match database")
	}
	if zeroPos != data.Pos {
		return errVerificationFailed("given search start position does not match database")
	}

	if ver, ok := data.Ptrs[verPos]; ok {
		if ver != version {
			return errVerificationFailed("different versions of key recorded at same position")
		}
	} else {
		// Check monitoring path.
		path, pathErr := monitoringPath(verPos, zeroPos, treeSize)
		if pathErr != nil {
			return pathErr
		}
		found := false
		for _, x := range path {
			if ver, ok := data.Ptrs[x]; ok {
				if ver < version {
					return errVerificationFailed("prefix tree has unexpectedly low version counter")
				}
				found = true
				break
			}
		}
		if !found {
			data.Ptrs[verPos] = version
		}
	}

	if !data.Owned && owned {
		data.Owned = true
	}
	return nil
}

// update updates the internal monitoring data based on ProofStep structures.
func (mdw *monitoringDataWrapper) update(treeSize uint64, entries map[uint64]ProofStep) error {
	if mdw.inner == nil {
		return nil
	}
	data := mdw.inner
	firstPos := data.Pos

	newPtrs := make(map[uint64]uint32, len(data.Ptrs))
	for pos, ver := range data.Ptrs {
		updated, err := findUpdatedMapping(pos, ver, firstPos, treeSize, entries)
		if err != nil {
			return err
		}
		finalPos, finalVer := pos, ver
		if updated != nil {
			finalPos, finalVer = updated.pos, updated.ver
		}
		if existingVer, ok := newPtrs[finalPos]; ok {
			if finalVer != existingVer {
				return errVerificationFailed("inconsistent versions found")
			}
		} else {
			newPtrs[finalPos] = finalVer
		}
	}
	data.Ptrs = newPtrs
	return nil
}

type posVer struct {
	pos uint64
	ver uint32
}

func findUpdatedMapping(
	storedPos uint64,
	storedVer uint32,
	firstPos, treeSize uint64,
	entries map[uint64]ProofStep,
) (*posVer, error) {
	var updated *posVer
	path, err := monitoringPath(storedPos, firstPos, treeSize)
	if err != nil {
		return nil, err
	}
	for _, intermediatePos := range path {
		step, ok := entries[intermediatePos]
		if !ok {
			break
		}
		if step.Prefix == nil {
			return nil, errRequiredFieldMissing("prefix")
		}
		newVersion := step.Prefix.Counter
		if newVersion < storedVer {
			return nil, errVerificationFailed("prefix tree has unexpectedly low version counter")
		}
		updated = &posVer{pos: intermediatePos, ver: newVersion}
	}
	return updated, nil
}

// Helper functions.

func hashesToSlice(hashes [][32]byte) []Hash {
	return hashes
}

func intoSortedPairsHash(m map[uint64][32]byte) ([]uint64, [][32]byte) {
	keys := make([]uint64, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	values := make([][32]byte, len(keys))
	for i, k := range keys {
		values[i] = m[k]
	}
	return keys, values
}

func wrapLogError(err error) error {
	if err == nil {
		return nil
	}
	return errVerificationFailed(err.Error())
}

func wrapPrefixError(err error) error {
	if err == nil {
		return nil
	}
	return errVerificationFailed(err.Error())
}

// sha256Sum computes the SHA-256 hash of the concatenation of the data slices.
func sha256Sum(data ...[]byte) [32]byte {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}
