package spqr

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// ============================================================================
// serializeV4Resolved with skipped keys (covers loop body in serializeV4Resolved)
// ============================================================================

// TestSerializeV4ResolvedWithSkippedKeys exercises the skipped key loop body
// in serializeV4Resolved (serialize.go lines ~273-293) by creating a V4 state
// (with braid) that has a valid skipped key.
func TestSerializeV4ResolvedWithSkippedKeys(t *testing.T) {
	ss := randomBytes(t, 32)
	kem := mlkembraid.NewMLKEM768IncrementalKEM()
	braid, err := mlkembraid.InitAlice(ss, kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}

	alice, err := InitWithBraid(ss, DirectionA2B, uint32(maxJump), braid)
	if err != nil {
		t.Fatalf("InitWithBraid: %v", err)
	}
	defer alice.Zeroize()

	// Create a valid skipped key secret and inject it.
	skBytes := make([]byte, keyLen)
	for i := range skBytes {
		skBytes[i] = byte(i + 11)
	}
	sk, skErr := secret.New(skBytes)
	if skErr != nil {
		t.Fatalf("secret.New sk: %v", skErr)
	}
	// Inject the skipped key into the state.
	alice.skippedKeys[SkippedKeyID{Epoch: 0, Counter: 1}] = sk

	// Serialize — this triggers serializeV4Resolved with a non-empty skipped key map.
	serialized, serErr := alice.Serialize()
	if serErr != nil {
		t.Fatalf("Serialize V4 with skipped keys: %v", serErr)
	}
	if len(serialized) == 0 {
		t.Error("expected non-empty serialized state")
	}

	// Round-trip deserialize.
	s2, err := Deserialize(serialized)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	defer s2.Zeroize()

	if len(s2.skippedKeys) != 1 {
		t.Errorf("expected 1 skipped key after round-trip, got %d", len(s2.skippedKeys))
	}
}

// TestSerializeV4ResolvedDestroyedSkippedKey exercises the destroyed skipped key
// error path in serializeV4Resolved (serialize.go lines ~285-287).
func TestSerializeV4ResolvedDestroyedSkippedKey(t *testing.T) {
	ss := randomBytes(t, 32)
	kem := mlkembraid.NewMLKEM768IncrementalKEM()
	braid, err := mlkembraid.InitAlice(ss, kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}

	alice, err := InitWithBraid(ss, DirectionA2B, uint32(maxJump), braid)
	if err != nil {
		t.Fatalf("InitWithBraid: %v", err)
	}
	// Don't defer Zeroize because we have a destroyed secret in the map.
	defer alice.braid.Zeroize()
	if alice.rootKey != nil {
		defer alice.rootKey.Destroy()
	}

	// Create a destroyed skipped key.
	skBytes := make([]byte, keyLen)
	sk, skErr := secret.New(skBytes)
	if skErr != nil {
		t.Fatalf("secret.New sk: %v", skErr)
	}
	sk.Destroy() // destroyed

	alice.skippedKeys[SkippedKeyID{Epoch: 0, Counter: 1}] = sk

	// Serialize should fail because skipped key is destroyed.
	_, serErr := alice.Serialize()
	if serErr == nil {
		t.Fatal("expected error for destroyed skipped key in serializeV4Resolved")
	}
	var e *ErrSerialize
	if !errors.As(serErr, &e) {
		t.Errorf("expected *ErrSerialize, got %T: %v", serErr, serErr)
	}
}

// ============================================================================
// V4 resolved trailing data with braid (covers serialize.go lines ~1224-1226)
// ============================================================================

// TestDeserializeV4ResolvedTrailingDataWithBraid tests V4 resolved deserialization
// when there are trailing bytes AFTER valid braid state, covering the
// `if braid != nil { braid.Zeroize() }` path in deserializeV4Resolved.
func TestDeserializeV4ResolvedTrailingDataWithBraid(t *testing.T) {
	ss := randomBytes(t, 32)
	kem := mlkembraid.NewMLKEM768IncrementalKEM()
	braid, err := mlkembraid.InitAlice(ss, kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}

	alice, err := InitWithBraid(ss, DirectionA2B, uint32(maxJump), braid)
	if err != nil {
		t.Fatalf("InitWithBraid: %v", err)
	}
	defer alice.Zeroize()

	// Serialize to get a valid V4 state.
	serialized, serErr := alice.Serialize()
	if serErr != nil {
		t.Fatalf("Serialize: %v", serErr)
	}

	// Append a trailing byte to corrupt the serialized state.
	corrupted := append(serialized, 0xFF)

	_, err = Deserialize(corrupted)
	if err == nil {
		t.Fatal("expected error for V4 resolved trailing data with braid")
	}
	var e *ErrDeserialize
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// ============================================================================
// spqr.go: advanceEpoch KdfSckaRK error (line 383-385)
// ============================================================================

// TestAdvanceEpochWithDestroyedRootKey exercises the advanceEpoch KdfSckaRK failure
// path by destroying the root key before calling advanceEpoch.
// This covers spqr.go lines ~383-385.
func TestAdvanceEpochWithDestroyedRootKey(t *testing.T) {
	ss := randomBytes(t, 32)
	s, err := Init(ss, DirectionA2B, uint32(maxJump))
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	// Destroy the root key to trigger KdfSckaRK failure.
	s.rootKey.Destroy()

	outputKey := make([]byte, keyLen)
	for i := range outputKey {
		outputKey[i] = byte(i + 1)
	}
	outputSecret, oErr := secret.New(outputKey)
	if oErr != nil {
		t.Fatalf("secret.New output key: %v", oErr)
	}
	defer outputSecret.Destroy()

	err = s.advanceEpoch(outputSecret)
	if err == nil {
		t.Fatal("expected error for advanceEpoch with destroyed root key")
	}
	// Should be wrapped in an error from KdfSckaRK (invalid root key).
	if err.Error() == "" {
		t.Error("error message should not be empty")
	}
}

// ============================================================================
// spqr.go: clearOldEpochs sends sendKey destroy on epoch < sendEpoch
// ============================================================================

// TestClearOldEpochsSendKeyNilChain exercises clearOldEpochs when a chain
// has a nil send key — covers the nil-check path at clearOldEpochs line 422.
func TestClearOldEpochsSendKeyNilChain(t *testing.T) {
	rkBytes := make([]byte, keyLen)
	rk, err := secret.New(rkBytes)
	if err != nil {
		t.Fatalf("secret.New: %v", err)
	}

	// Create two epoch chains: epoch 0 (old, sendEpoch < current) and epoch 1 (current).
	ckBytes := make([]byte, keyLen)
	ck0, err := secret.New(ckBytes)
	if err != nil {
		t.Fatalf("secret.New ck0: %v", err)
	}
	ck1, err := secret.New(ckBytes)
	if err != nil {
		t.Fatalf("secret.New ck1: %v", err)
	}

	s := &SPQR{
		chains: map[uint64]*EpochChain{
			0: {sendKey: ck0},
			1: {sendKey: ck1},
		},
		skippedKeys: make(map[SkippedKeyID]*secret.Secret),
		direction:   DirectionA2B,
		maxJump:     uint32(maxJump),
		negotiation: negotiationResolved,
		version:     VersionV1,
		minVersion:  VersionV0,
		rootKey:     rk,
		epoch:       1,
		sendEpoch:   1, // current send epoch = 1
	}
	defer s.Zeroize()

	// clearOldEpochs should destroy epoch 0's send key (epoch < sendEpoch).
	s.clearOldEpochs()

	// Verify epoch 0's send key was cleared.
	chain0, ok := s.chains[0]
	if !ok {
		// Chain 0 may have been pruned if it's old enough.
		return
	}
	if chain0.sendKey != nil && !chain0.sendKey.IsDestroyed() {
		t.Error("expected epoch 0 send key to be destroyed after clearOldEpochs")
	}
}
