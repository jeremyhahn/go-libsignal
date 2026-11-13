package spqr

import (
	"errors"
	"fmt"
	"math"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret/secrettest"
)

// ============================================================================
// serializeV4Resolved with skipped keys (covers loop body in serializeV4Resolved)
// ============================================================================

// TestSerializeWithSkippedKeysProtoRoundTrip exercises the Serialize path with
// skipped keys present. The proto codec encodes skipped keys in the recv.prev
// field as (be32 idx | 32 B key) records (Rust KeyHistory format). On round-trip,
// the skipped key must be present in the deserialized SPQR.skippedKeys map.
func TestSerializeWithSkippedKeysProtoRoundTrip(t *testing.T) {
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

	// Create a valid skipped key and inject it.
	skBytes := make([]byte, keyLen)
	for i := range skBytes {
		skBytes[i] = byte(i + 11)
	}
	// Save a copy of the bytes before secret.New zeroizes skBytes.
	skBytesCopy := make([]byte, keyLen)
	copy(skBytesCopy, skBytes)
	sk, skErr := secret.New(skBytes)
	if skErr != nil {
		t.Fatalf("secret.New sk: %v", skErr)
	}
	alice.skippedKeys[SkippedKeyID{Epoch: 0, Counter: 1}] = sk

	// Serialize — the proto codec encodes skipped keys in recv.prev.
	serialized, serErr := alice.Serialize()
	if serErr != nil {
		t.Fatalf("Serialize with skipped keys: %v", serErr)
	}
	if len(serialized) == 0 {
		t.Error("expected non-empty serialized state")
	}

	// Round-trip: skipped keys are preserved by the proto codec.
	s2, err := Deserialize(serialized)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	defer s2.Zeroize()

	// The proto codec encodes skipped keys — the entry must survive the round-trip.
	id := SkippedKeyID{Epoch: 0, Counter: 1}
	sk2, ok := s2.skippedKeys[id]
	if !ok {
		t.Errorf("skipped key counter=1 missing after round-trip; got %d total", len(s2.skippedKeys))
	} else if !secrettest.Matches(t, sk2, skBytesCopy) {
		t.Error("skipped key bytes mismatch after round-trip")
	}
}

// TestSerializeDestroyedSkippedKeyProto verifies that a destroyed skipped key in
// the map does not cause Serialize to fail. Destroyed entries are silently
// excluded from the recv.prev encoding (skippedRecvKeysForEpoch filters them).
func TestSerializeDestroyedSkippedKeyProto(t *testing.T) {
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

	// Create and destroy a skipped key — inject the destroyed entry.
	skBytes := make([]byte, keyLen)
	sk, skErr := secret.New(skBytes)
	if skErr != nil {
		t.Fatalf("secret.New sk: %v", skErr)
	}
	sk.Destroy()
	alice.skippedKeys[SkippedKeyID{Epoch: 0, Counter: 1}] = sk

	// Destroyed entries are excluded from recv.prev — Serialize must succeed.
	serialized, serErr := alice.Serialize()
	if serErr != nil {
		t.Fatalf("Serialize with destroyed skipped key: %v (destroyed entry should be silently excluded)", serErr)
	}
	if len(serialized) == 0 {
		t.Error("expected non-empty serialized state")
	}

	// On round-trip, the destroyed key must NOT appear in skippedKeys.
	s2, desErr := Deserialize(serialized)
	if desErr != nil {
		t.Fatalf("Deserialize: %v", desErr)
	}
	defer s2.Zeroize()
	if _, ok := s2.skippedKeys[SkippedKeyID{Epoch: 0, Counter: 1}]; ok {
		t.Error("destroyed key should not appear in deserialized skippedKeys")
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

// ============================================================================
// Proto recv.prev round-trip for skipped keys
// ============================================================================

// TestProtoRecvPrevSkippedKeysRoundTrip verifies that after a proto round-trip,
// skipped keys that were accumulated during out-of-order receives are preserved
// via the recv.prev encoding in the proto Chain message. This tests the proto
// codec's ability to persist and restore the skippedKeys map across
// serialize/deserialize cycles.
func TestProtoRecvPrevSkippedKeysRoundTrip(t *testing.T) {
	ss := randomBytes(t, 32)
	s, err := Init(ss, DirectionA2B, uint32(maxJump))
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	// Encrypt 3 messages so Alice's sendCounter reaches 3.
	var keys [3]*secret.Secret
	for i := 0; i < 3; i++ {
		mk, _, encErr := s.Encrypt(0)
		if encErr != nil {
			t.Fatalf("Encrypt %d: %v", i, encErr)
		}
		keys[i] = mk
	}
	// keys[0] = mk for counter=1, keys[1] = mk for counter=2, keys[2] = mk for counter=3.

	// Bob receives msg 3 first (skipping 1 and 2). This establishes prevRecvKey.
	bobSS := randomBytes(t, 32)
	bob, bErr := Init(bobSS, DirectionB2A, uint32(maxJump))
	if bErr != nil {
		t.Fatalf("Init bob: %v", bErr)
	}
	defer bob.Zeroize()

	// Manually set up bob's chain 0 recv key to match alice's send chain.
	// For a pure unit test of restoreSkippedKeysFromPrev, inject a known chain.
	rkBytes := make([]byte, keyLen)
	for i := range rkBytes {
		rkBytes[i] = byte(i + 0x42)
	}
	rk, rkErr := secret.New(rkBytes)
	if rkErr != nil {
		t.Fatalf("secret.New rk: %v", rkErr)
	}

	ckBytes := make([]byte, keyLen)
	for i := range ckBytes {
		ckBytes[i] = byte(i + 0x10)
	}
	ck, ckErr := secret.New(ckBytes)
	if ckErr != nil {
		t.Fatalf("secret.New ck: %v", ckErr)
	}

	receiver := &SPQR{
		chains: map[uint64]*EpochChain{
			0: {recvKey: ck},
		},
		skippedKeys: make(map[SkippedKeyID]*secret.Secret),
		direction:   DirectionB2A,
		maxJump:     uint32(maxJump),
		negotiation: negotiationResolved,
		version:     VersionV1,
		minVersion:  VersionV0,
		rootKey:     rk,
		epoch:       0,
	}
	defer receiver.Zeroize()

	// Derive 3 consecutive keys upfront (simulate what the sender has).
	var senderKeys [3]*secret.Secret
	tmpCK := ck
	for i := 0; i < 3; i++ {
		var mk *secret.Secret
		var nextCK *secret.Secret
		mk, nextCK, err = KdfSckaCK(tmpCK, uint32(i+1))
		if err != nil {
			t.Fatalf("KdfSckaCK %d: %v", i, err)
		}
		// We cloned ck above, so we do not destroy tmpCK on first iteration.
		if i > 0 {
			tmpCK.Destroy()
		}
		tmpCK = nextCK
		senderKeys[i] = mk
	}
	tmpCK.Destroy()

	// Receiver decrypts counter=3 first (skipping 1 and 2).
	mk3, decErr := receiver.Decrypt(0, 3)
	if decErr != nil {
		t.Fatalf("Decrypt counter=3: %v", decErr)
	}
	if !secrettest.Same(t, mk3, senderKeys[2]) {
		t.Error("mk3 mismatch")
	}
	mk3.Destroy()
	senderKeys[2].Destroy()

	// Serialize and deserialize. The proto codec now persists skipped keys in
	// recv.prev as (be32 idx | 32 B key) records — counters 1 and 2 survive.
	serialized, serErr := receiver.Serialize()
	if serErr != nil {
		t.Fatalf("Serialize: %v", serErr)
	}

	receiver2, desErr := Deserialize(serialized)
	if desErr != nil {
		t.Fatalf("Deserialize: %v", desErr)
	}
	defer receiver2.Zeroize()

	// Skipped keys are preserved across the proto round-trip.
	if len(receiver2.skippedKeys) != 2 {
		t.Errorf("expected 2 skipped keys after round-trip (counters 1 and 2), got %d", len(receiver2.skippedKeys))
	}

	// Decrypt counter=1 — found directly in skippedKeys (no re-derivation needed).
	mk1, decErr1 := receiver2.Decrypt(0, 1)
	if decErr1 != nil {
		t.Fatalf("Decrypt counter=1 after round-trip: %v", decErr1)
	}
	if !secrettest.Same(t, mk1, senderKeys[0]) {
		t.Error("mk1 mismatch after round-trip")
	}
	mk1.Destroy()
	senderKeys[0].Destroy()

	// Serialize again and round-trip once more.
	serialized2, serErr2 := receiver2.Serialize()
	if serErr2 != nil {
		t.Fatalf("second Serialize: %v", serErr2)
	}
	receiver3, desErr3 := Deserialize(serialized2)
	if desErr3 != nil {
		t.Fatalf("second Deserialize: %v", desErr3)
	}
	defer receiver3.Zeroize()

	// After counter=1 was consumed, only counter=2 remains. Decrypt counter=2.
	mk2, decErr2 := receiver3.Decrypt(0, 2)
	if decErr2 != nil {
		t.Fatalf("Decrypt counter=2 after second round-trip: %v", decErr2)
	}
	if !secrettest.Same(t, mk2, senderKeys[1]) {
		t.Error("mk2 mismatch after second round-trip")
	}
	mk2.Destroy()
	senderKeys[1].Destroy()

	// Clean up keys we allocated but didn't use.
	for _, k := range keys {
		if k != nil {
			k.Destroy()
		}
	}
}

// ============================================================================
// ErrEpochOverflow and ErrBraidTooLarge error string coverage
// ============================================================================

// TestErrEpochOverflowError verifies the ErrEpochOverflow.Error() string.
func TestErrEpochOverflowError(t *testing.T) {
	err := &ErrEpochOverflow{}
	want := "spqr: epoch counter overflow"
	if got := err.Error(); got != want {
		t.Errorf("ErrEpochOverflow.Error() = %q, want %q", got, want)
	}
}

// TestErrBraidTooLargeError verifies the ErrBraidTooLarge.Error() string.
func TestErrBraidTooLargeError(t *testing.T) {
	err := &ErrBraidTooLarge{Size: 1234, Max: 999}
	want := fmt.Sprintf("spqr: braid serialized length %d exceeds maximum %d", 1234, 999)
	if got := err.Error(); got != want {
		t.Errorf("ErrBraidTooLarge.Error() = %q, want %q", got, want)
	}
	// errors.As check.
	var target *ErrBraidTooLarge
	if !errors.As(err, &target) {
		t.Error("expected errors.As to match *ErrBraidTooLarge")
	}
}

// ============================================================================
// Serialize error path: braid.State() == nil triggers ErrSerialize
// ============================================================================

// TestSerializeWithNilBraidStateReturnsErrSerialize verifies that Serialize
// wraps proto-marshal failures in ErrSerialize. A SPQR with a braid whose
// state is nil triggers the guard in spqrToProto and causes MarshalStateProto
// to return an error, which Serialize must wrap in ErrSerialize.
func TestSerializeWithNilBraidStateReturnsErrSerialize(t *testing.T) {
	rkBytes := make([]byte, keyLen)
	rk, err := secret.New(rkBytes)
	if err != nil {
		t.Fatalf("secret.New: %v", err)
	}

	// Build a minimal SPQR with a braid whose State() returns nil.
	// mlkembraid.BraidFromState(nil, ...) creates such a braid.
	nilStateBraid := mlkembraid.BraidFromState(nil, mlkembraid.NewMLKEM768IncrementalKEM(), mlkembraid.DefaultChunkSize)
	s := &SPQR{
		chains:      make(map[uint64]*EpochChain),
		skippedKeys: make(map[SkippedKeyID]*secret.Secret),
		direction:   DirectionA2B,
		maxJump:     uint32(maxJump),
		negotiation: negotiationResolved,
		version:     VersionV1,
		minVersion:  VersionV0,
		rootKey:     rk,
		braid:       nilStateBraid,
	}
	// Nil out braid before Zeroize to avoid panic from nil braid.State.Zeroize().
	defer func() {
		s.braid = nil
		s.Zeroize()
	}()

	_, serErr := s.Serialize()
	if serErr == nil {
		t.Fatal("expected Serialize to fail when braid.State() is nil")
	}
	var se *ErrSerialize
	if !errors.As(serErr, &se) {
		t.Errorf("expected *ErrSerialize, got %T: %v", serErr, serErr)
	}
}

// ============================================================================
// spqr.go: Encrypt with nil sendKey (ErrSendKeyDestroyed path)
// ============================================================================

// TestEncryptSendKeyNil exercises the ErrSendKeyDestroyed path in Encrypt
// (spqr.go:189-191) when the chain exists but its sendKey is nil. This covers
// the defensive guard that prevents use of a cleared send key.
func TestEncryptSendKeyNil(t *testing.T) {
	rkBytes := make([]byte, keyLen)
	rk, err := secret.New(rkBytes)
	if err != nil {
		t.Fatalf("secret.New rk: %v", err)
	}

	s := &SPQR{
		chains: map[uint64]*EpochChain{
			// Chain with a nil sendKey — simulates a receive-only chain or a
			// chain whose send key was destroyed after epoch advancement.
			0: {sendKey: nil},
		},
		skippedKeys: make(map[SkippedKeyID]*secret.Secret),
		direction:   DirectionA2B,
		maxJump:     uint32(maxJump),
		negotiation: negotiationResolved,
		version:     VersionV1,
		minVersion:  VersionV1,
		rootKey:     rk,
		epoch:       0,
		sendEpoch:   0,
	}
	defer s.Zeroize()

	_, _, err = s.Encrypt(0)
	if err == nil {
		t.Fatal("expected ErrSendKeyDestroyed for nil sendKey")
	}
	var target *ErrSendKeyDestroyed
	if !errors.As(err, &target) {
		t.Errorf("expected *ErrSendKeyDestroyed, got %T: %v", err, err)
	}
	if target.Epoch != 0 {
		t.Errorf("ErrSendKeyDestroyed.Epoch = %d, want 0", target.Epoch)
	}
}

// ============================================================================
// spqr.go: Encrypt with counter at MaxUint32 (ErrCounterExhausted path)
// ============================================================================

// TestEncryptCounterExhausted exercises the ErrCounterExhausted path in
// Encrypt (spqr.go:201-203) when the send counter is at the maximum uint32
// value. This covers the overflow guard that prevents counter wraparound.
func TestEncryptCounterExhausted(t *testing.T) {
	rkBytes := make([]byte, keyLen)
	rk, err := secret.New(rkBytes)
	if err != nil {
		t.Fatalf("secret.New rk: %v", err)
	}

	ckBytes := make([]byte, keyLen)
	for i := range ckBytes {
		ckBytes[i] = byte(i + 1)
	}
	ck, err := secret.New(ckBytes)
	if err != nil {
		t.Fatalf("secret.New ck: %v", err)
	}

	s := &SPQR{
		chains: map[uint64]*EpochChain{
			// Chain with sendCounter at MaxUint32 — next increment would overflow.
			0: {sendKey: ck, sendCounter: math.MaxUint32},
		},
		skippedKeys: make(map[SkippedKeyID]*secret.Secret),
		direction:   DirectionA2B,
		maxJump:     uint32(maxJump),
		negotiation: negotiationResolved,
		version:     VersionV1,
		minVersion:  VersionV1,
		rootKey:     rk,
		epoch:       0,
		sendEpoch:   0,
	}
	defer s.Zeroize()

	_, _, err = s.Encrypt(0)
	if err == nil {
		t.Fatal("expected ErrCounterExhausted for MaxUint32 counter")
	}
	var target *ErrCounterExhausted
	if !errors.As(err, &target) {
		t.Errorf("expected *ErrCounterExhausted, got %T: %v", err, err)
	}
	if target.Epoch != 0 {
		t.Errorf("ErrCounterExhausted.Epoch = %d, want 0", target.Epoch)
	}
}

// ============================================================================
// direction.go: CurrentVersionOf with invalid serialized state
// ============================================================================

// TestCurrentVersionOf_DeserializeError exercises the err != nil path in
// CurrentVersionOf (direction.go:71-73) when Deserialize fails on invalid input.
// This covers the error return from a malformed serialized state.
func TestCurrentVersionOf_DeserializeError(t *testing.T) {
	// Provide bytes that are not a valid serialized SPQR state.
	invalid := []byte{0xFF, 0xFE, 0xFD}
	_, err := CurrentVersionOf(invalid)
	if err == nil {
		t.Fatal("expected error from CurrentVersionOf for invalid serialized state")
	}
}

// ============================================================================
// advanceEpoch: epoch overflow pre-check (Issue 1 fix)
// ============================================================================

// TestAdvanceEpochOverflowPreCheck verifies that advanceEpoch returns
// ErrEpochOverflow when the epoch counter is at math.MaxUint64, and that it
// does so WITHOUT mutating state (no new chain, no root key change).
// Before the fix, the overflow check came AFTER KdfSckaRK and root key
// destruction, leaking freshly derived chain keys on overflow.
func TestAdvanceEpochOverflowPreCheck(t *testing.T) {
	ss := randomBytes(t, 32)
	s, err := Init(ss, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	// Force the epoch to MaxUint64 to trigger overflow.
	s.epoch = math.MaxUint64

	// Capture the root key bytes BEFORE the call so we can verify it is
	// unchanged after the (correctly rejected) overflow attempt.
	rkBefore := secrettest.Digest(t, s.rootKey)

	chainCountBefore := len(s.chains)

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
		t.Fatal("expected ErrEpochOverflow, got nil")
	}
	var target *ErrEpochOverflow
	if !errors.As(err, &target) {
		t.Errorf("expected *ErrEpochOverflow, got %T: %v", err, err)
	}

	// State must be unchanged: epoch still MaxUint64, root key bytes identical,
	// chain count unchanged.
	if s.epoch != math.MaxUint64 {
		t.Errorf("epoch mutated: got %d, want MaxUint64", s.epoch)
	}
	if secrettest.Digest(t, s.rootKey) != rkBefore {
		t.Error("root key mutated after ErrEpochOverflow")
	}
	if len(s.chains) != chainCountBefore {
		t.Errorf("chain count mutated: got %d, want %d", len(s.chains), chainCountBefore)
	}
}
