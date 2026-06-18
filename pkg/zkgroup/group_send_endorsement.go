package zkgroup

import (
	"bytes"
	"sort"

	"github.com/gtank/ristretto255"
	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
)

const secondsPerHour = 60 * 60

// GroupSendDerivedKeyPair is a key pair derived for a specific expiration time,
// used to sign endorsements.
type GroupSendDerivedKeyPair struct {
	KeyPair    *zkcredential.ServerDerivedKeyPair
	Expiration Timestamp
}

// GroupSendDerivedKeyPairTagInfo creates the SHO for the tag info, which encodes
// the public attributes of an endorsement.
func groupSendDerivedKeyPairTagInfo(expiration Timestamp) *zkcredential.ShoExt {
	sho := zkcredential.NewShoHmacSha256Ext("20240215_Signal_GroupSendEndorsement")
	b := expiration.ToBeBytes()
	sho.AbsorbAndRatchet(b[:])
	return sho
}

// ForExpiration derives the appropriate key pair for the given expiration.
func ForExpiration(
	expiration Timestamp,
	rootKeyPair *zkcredential.ServerRootKeyPair,
) (*GroupSendDerivedKeyPair, error) {
	tagInfo := groupSendDerivedKeyPairTagInfo(expiration)
	derived, err := rootKeyPair.DeriveKey(tagInfo)
	if err != nil {
		return nil, err
	}
	return &GroupSendDerivedKeyPair{
		KeyPair:    derived,
		Expiration: expiration,
	}, nil
}

// GroupSendEndorsementsResponse contains endorsements for all group members,
// issued by the group server.
type GroupSendEndorsementsResponse struct {
	Endorsements *zkcredential.EndorsementResponse
	Expiration   Timestamp
}

// DefaultExpiration returns the standard expiration for group send endorsements.
func DefaultExpiration(currentTime Timestamp) Timestamp {
	currentSeconds := currentTime.EpochSeconds()
	startOfDay := currentSeconds - (currentSeconds % SecondsPerDay)
	expiration := startOfDay + 2*SecondsPerDay
	if (expiration - currentSeconds) < SecondsPerDay+secondsPerHour {
		expiration += SecondsPerDay
	}
	return NewTimestamp(expiration)
}

// sortPoints computes a deterministic sort order for ristretto255 points.
// Each point is doubled and compressed to a canonical 32-byte encoding, and
// the resulting sort keys are compared lexicographically. Returns the
// permutation (sorted index -> original index) and the reordered points.
//
// This matches Rust GroupSendEndorsementsResponse::sort_points which uses
// double_and_compress_batch for deterministic ordering.
func sortPoints(points []*ristretto255.Element) (perm []int, sorted []*ristretto255.Element) {
	type indexedKey struct {
		index int
		key   [32]byte
	}
	indexed := make([]indexedKey, len(points))
	for i, p := range points {
		doubled := new(ristretto255.Element).Add(p, p)
		var key [32]byte
		copy(key[:], doubled.Bytes())
		indexed[i] = indexedKey{index: i, key: key}
	}
	sort.Slice(indexed, func(i, j int) bool {
		return bytes.Compare(indexed[i].key[:], indexed[j].key[:]) < 0
	})
	perm = make([]int, len(points))
	sorted = make([]*ristretto255.Element, len(points))
	for i, ik := range indexed {
		perm[i] = ik.index
		sorted[i] = points[ik.index]
	}
	return perm, sorted
}

// collectPermutation places values at their original indices according to
// the given permutation. perm[i] is the original index for sorted position i.
func collectPermutation[T any](values []T, perm []int) []T {
	result := make([]T, len(values))
	for i, v := range values {
		result[perm[i]] = v
	}
	return result
}

// IssueGroupSendEndorsements creates endorsements for a list of member
// ciphertexts. Points are sorted deterministically before issuance, matching
// the Rust implementation. The returned endorsements are in sorted order.
func IssueGroupSendEndorsements(
	memberCiphertexts []*UUIDCiphertext,
	keyPair *GroupSendDerivedKeyPair,
	randomness RandomnessBytes,
) (*GroupSendEndorsementsResponse, error) {
	points := make([]*ristretto255.Element, len(memberCiphertexts))
	for i, ct := range memberCiphertexts {
		points[i] = ct.Ciphertext.EA1
	}

	// Sort points deterministically before issuance (matching Rust).
	// The server returns endorsements in sorted order.
	_, sortedPoints := sortPoints(points)

	response, err := zkcredential.IssueEndorsements(sortedPoints, keyPair.KeyPair, randomness)
	if err != nil {
		return nil, err
	}

	return &GroupSendEndorsementsResponse{
		Endorsements: response,
		Expiration:   keyPair.Expiration,
	}, nil
}

// GroupSendEndorsement is a single endorsement for one or multiple group members.
type GroupSendEndorsement struct {
	Endorsement *zkcredential.Endorsement
}

// CompressedGroupSendEndorsement is an endorsement stored in compressed form.
type CompressedGroupSendEndorsement struct {
	Endorsement *zkcredential.CompressedEndorsement
}

// ReceivedEndorsement contains both compressed and decompressed forms of an
// endorsement extracted from a GroupSendEndorsementsResponse.
type ReceivedEndorsement struct {
	Compressed   *CompressedGroupSendEndorsement
	Decompressed *GroupSendEndorsement
}

// ReceiveWithCiphertexts validates and returns the endorsements issued by the
// server. Points are sorted in the same deterministic order used during
// issuance, and results are un-permuted back to the original order of
// memberCiphertexts.
func (r *GroupSendEndorsementsResponse) ReceiveWithCiphertexts(
	memberCiphertexts []*UUIDCiphertext,
	now Timestamp,
	rootPublicKey *zkcredential.ServerRootPublicKey,
) ([]*ReceivedEndorsement, error) {
	derivedKey, err := r.derivePublicSigningKey(now, rootPublicKey)
	if err != nil {
		return nil, err
	}

	points := make([]*ristretto255.Element, len(memberCiphertexts))
	for i, ct := range memberCiphertexts {
		points[i] = ct.Ciphertext.EA1
	}

	// Sort points in the same deterministic order used during issuance.
	perm, sortedPoints := sortPoints(points)

	received, err := r.Endorsements.Receive(sortedPoints, derivedKey)
	if err != nil {
		return nil, ErrVerificationFailure
	}

	// Build sorted results, then un-permute to original order.
	sortedResult := make([]*ReceivedEndorsement, len(received.Decompressed))
	for i := range received.Decompressed {
		sortedResult[i] = &ReceivedEndorsement{
			Compressed: &CompressedGroupSendEndorsement{
				Endorsement: received.Compressed[i],
			},
			Decompressed: &GroupSendEndorsement{
				Endorsement: received.Decompressed[i],
			},
		}
	}

	return collectPermutation(sortedResult, perm), nil
}

// ReceiveWithServiceIDs validates and returns the endorsements issued by the
// server. Unlike ReceiveWithCiphertexts, this method takes ServiceIDs directly
// and computes the first ciphertext point (a1 * M1) internally.
//
// Points are sorted in the same deterministic order used during issuance, and
// results are un-permuted back to the original order of serviceIDs.
//
// This matches Rust GroupSendEndorsementsResponse::receive_with_service_ids.
func (r *GroupSendEndorsementsResponse) ReceiveWithServiceIDs(
	serviceIDs []ServiceID,
	now Timestamp,
	rootPublicKey *zkcredential.ServerRootPublicKey,
	groupParams *GroupSecretParams,
) ([]*ReceivedEndorsement, error) {
	derivedKey, err := r.derivePublicSigningKey(now, rootPublicKey)
	if err != nil {
		return nil, err
	}

	// Compute a1 * M1(service_id) for each member.
	// This is the first point of the ciphertext (EA1 = a1 * M1).
	a1 := groupParams.UIDEncKeyPair.A1
	points := make([]*ristretto255.Element, len(serviceIDs))
	for i, sid := range serviceIDs {
		uidStruct := NewUIDStructFromServiceID(sid)
		points[i] = new(ristretto255.Element).ScalarMult(a1, uidStruct.M1)
	}

	// Sort points in the same deterministic order used during issuance.
	perm, sortedPoints := sortPoints(points)

	received, err := r.Endorsements.Receive(sortedPoints, derivedKey)
	if err != nil {
		return nil, ErrVerificationFailure
	}

	// Build sorted results, then un-permute to original order.
	sortedResult := make([]*ReceivedEndorsement, len(received.Decompressed))
	for i := range received.Decompressed {
		sortedResult[i] = &ReceivedEndorsement{
			Compressed: &CompressedGroupSendEndorsement{
				Endorsement: received.Compressed[i],
			},
			Decompressed: &GroupSendEndorsement{
				Endorsement: received.Decompressed[i],
			},
		}
	}

	return collectPermutation(sortedResult, perm), nil
}

func (r *GroupSendEndorsementsResponse) derivePublicSigningKey(
	now Timestamp,
	rootPublicKey *zkcredential.ServerRootPublicKey,
) (*zkcredential.ServerDerivedPublicKey, error) {
	if !r.Expiration.IsDayAligned() {
		return nil, ErrVerificationFailure
	}
	remaining := r.Expiration.SaturatingSecondsSince(now)
	if remaining < 2*secondsPerHour {
		return nil, ErrVerificationFailure
	}
	if remaining > 7*SecondsPerDay {
		return nil, ErrVerificationFailure
	}

	tagInfo := groupSendDerivedKeyPairTagInfo(r.Expiration)
	derived, err := rootPublicKey.DeriveKey(tagInfo)
	if err != nil {
		return nil, ErrVerificationFailure
	}
	return derived, nil
}

// CombineGroupSendEndorsements combines several endorsements into one.
// All endorsements must come from the same issuance.
func CombineGroupSendEndorsements(endorsements []*GroupSendEndorsement) *GroupSendEndorsement {
	inner := make([]*zkcredential.Endorsement, len(endorsements))
	for i, e := range endorsements {
		inner[i] = e.Endorsement
	}
	return &GroupSendEndorsement{
		Endorsement: zkcredential.CombineEndorsements(inner),
	}
}

// Remove removes endorsements from a previously-combined endorsement.
func (e *GroupSendEndorsement) Remove(other *GroupSendEndorsement) *GroupSendEndorsement {
	return &GroupSendEndorsement{
		Endorsement: e.Endorsement.Remove(other.Endorsement),
	}
}

// ToToken generates a bearer token from the endorsement.
func (e *GroupSendEndorsement) ToToken(keyPair *zkcredential.KeyPair) *GroupSendToken {
	clientKey := zkcredential.NewClientDecryptionKeyForFirstPoint(keyPair)
	rawToken := e.Endorsement.ToToken(clientKey)
	return &GroupSendToken{
		RawToken: rawToken,
	}
}

// Compress returns the compressed form of this endorsement.
func (e *GroupSendEndorsement) Compress() *CompressedGroupSendEndorsement {
	return &CompressedGroupSendEndorsement{
		Endorsement: e.Endorsement.Compress(),
	}
}

// Decompress attempts to decompress the endorsement.
func (e *CompressedGroupSendEndorsement) Decompress() (*GroupSendEndorsement, error) {
	decompressed, err := e.Endorsement.Decompress()
	if err != nil {
		return nil, &ZkGroupDeserializationFailure{TypeName: "GroupSendEndorsement"}
	}
	return &GroupSendEndorsement{Endorsement: decompressed}, nil
}

// GroupSendToken is a token representing an endorsement. It can be cached for
// sending to the same recipient.
type GroupSendToken struct {
	RawToken []byte
}

// IntoFullToken attaches the expiration to this token.
func (t *GroupSendToken) IntoFullToken(expiration Timestamp) *GroupSendFullToken {
	return &GroupSendFullToken{
		RawToken:   t.RawToken,
		Expiration: expiration,
	}
}

// GroupSendFullToken is a token with its expiration, ready to send to the chat
// server.
type GroupSendFullToken struct {
	RawToken   []byte
	Expiration Timestamp
}

// GetExpiration returns the token's expiration.
func (t *GroupSendFullToken) GetExpiration() Timestamp {
	return t.Expiration
}

// Verify checks whether the token is valid for sending to the given userIDs at
// the given time.
func (t *GroupSendFullToken) Verify(
	userIDs []ServiceID,
	now Timestamp,
	keyPair *GroupSendDerivedKeyPair,
) error {
	if now.EpochSeconds() > t.Expiration.EpochSeconds() {
		return ErrVerificationFailure
	}

	// Sum the M1 points for all user IDs.
	sum := ristretto255.NewIdentityElement()
	for _, uid := range userIDs {
		uidStruct := NewUIDStructFromServiceID(uid)
		sum = sum.Add(sum, uidStruct.M1)
	}

	return keyPair.KeyPair.Verify(sum, t.RawToken)
}
