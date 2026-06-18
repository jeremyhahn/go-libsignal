package spqr

import (
	"errors"
	"testing"

	pqratchetpb "github.com/jeremyhahn/go-libsignal/pkg/proto/pqratchetpb"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// ============================================================================
// Finding 2a: protoChainToSPQR underflow guard
// ============================================================================

// TestProtoChainUnderflow verifies that protoChainToSPQR returns
// ErrProtoChainUnderflow when len(links) > current_epoch+1, which would
// cause a uint64 underflow when computing startEpoch.
func TestProtoChainUnderflow(t *testing.T) {
	// current_epoch=0, 2 links → startEpoch = 0 - (2-1) = underflow.
	pb := &pqratchetpb.Chain{
		Direction:    pqratchetpb.Direction_A_2_B,
		CurrentEpoch: 0,
		SendEpoch:    0,
		Links: []*pqratchetpb.Chain_Epoch{
			{},
			{},
		},
	}

	s := &SPQR{
		chains:      make(map[uint64]*EpochChain),
		skippedKeys: make(map[SkippedKeyID]*secret.Secret),
		maxJump:     maxJump,
	}
	defer s.Zeroize()

	err := protoChainToSPQR(pb, s)
	if err == nil {
		t.Fatal("expected ErrProtoChainUnderflow for current_epoch=0 with 2 links")
	}
	var target *ErrProtoChainUnderflow
	if !errors.As(err, &target) {
		t.Errorf("expected *ErrProtoChainUnderflow, got %T: %v", err, err)
	}
	if target.CurrentEpoch != 0 {
		t.Errorf("CurrentEpoch = %d, want 0", target.CurrentEpoch)
	}
	if target.NumLinks != 2 {
		t.Errorf("NumLinks = %d, want 2", target.NumLinks)
	}
}

// TestProtoChainUnderflowErrorString verifies the ErrProtoChainUnderflow
// error message format.
func TestProtoChainUnderflowErrorString(t *testing.T) {
	err := &ErrProtoChainUnderflow{CurrentEpoch: 1, NumLinks: 5}
	got := err.Error()
	want := "spqr proto_codec: chain startEpoch underflow: current_epoch=1 num_links=5"
	if got != want {
		t.Errorf("ErrProtoChainUnderflow.Error() = %q, want %q", got, want)
	}
}

// TestProtoChainNoUnderflow verifies that a Chain with exactly one link at
// epoch 0 is accepted (boundary condition: 1 link, current_epoch=0,
// n-1=0, no underflow).
func TestProtoChainNoUnderflow(t *testing.T) {
	rkBytes := make([]byte, keyLen)
	for i := range rkBytes {
		rkBytes[i] = byte(i + 1)
	}
	sendBytes := make([]byte, keyLen)
	for i := range sendBytes {
		sendBytes[i] = byte(i + 2)
	}
	recvBytes := make([]byte, keyLen)
	for i := range recvBytes {
		recvBytes[i] = byte(i + 3)
	}

	pb := &pqratchetpb.Chain{
		Direction:    pqratchetpb.Direction_A_2_B,
		CurrentEpoch: 0,
		SendEpoch:    0,
		NextRoot:     rkBytes,
		Links: []*pqratchetpb.Chain_Epoch{
			{
				Send: &pqratchetpb.Chain_Epoch_EpochDirection{
					Ctr:  0,
					Next: sendBytes,
				},
				Recv: &pqratchetpb.Chain_Epoch_EpochDirection{
					Ctr:  0,
					Next: recvBytes,
				},
			},
		},
	}

	s := &SPQR{
		chains:      make(map[uint64]*EpochChain),
		skippedKeys: make(map[SkippedKeyID]*secret.Secret),
		maxJump:     maxJump,
	}
	defer s.Zeroize()

	if err := protoChainToSPQR(pb, s); err != nil {
		t.Fatalf("unexpected error for valid single-link chain: %v", err)
	}
	if _, ok := s.chains[0]; !ok {
		t.Error("expected epoch 0 chain to be populated")
	}
}

// ============================================================================
// Finding 7: FIFO eviction tests
// ============================================================================

// TestFIFOEvictOldestSkippedKey verifies that evictOldestSkippedKey removes
// the first key inserted into the FIFO, not an arbitrary map entry.
func TestFIFOEvictOldestSkippedKey(t *testing.T) {
	rkBytes := make([]byte, keyLen)
	rk, err := secret.New(rkBytes)
	if err != nil {
		t.Fatalf("secret.New rk: %v", err)
	}

	s := &SPQR{
		chains:      make(map[uint64]*EpochChain),
		skippedKeys: make(map[SkippedKeyID]*secret.Secret),
		direction:   DirectionA2B,
		maxJump:     maxJump,
		negotiation: negotiationResolved,
		version:     VersionV1,
		minVersion:  VersionV1,
		rootKey:     rk,
	}
	defer s.Zeroize()

	// Insert three keys in a specific order: counter 5, 3, 7.
	// After eviction the FIFO-oldest (counter=5) must be removed.
	for _, counter := range []uint32{5, 3, 7} {
		kb := make([]byte, keyLen)
		kb[0] = byte(counter)
		mk, mErr := secret.New(kb)
		if mErr != nil {
			t.Fatalf("secret.New: %v", mErr)
		}
		id := SkippedKeyID{Epoch: 0, Counter: counter}
		s.skippedKeys[id] = mk
		s.skippedKeysFIFO = append(s.skippedKeysFIFO, id)
	}

	if len(s.skippedKeys) != 3 {
		t.Fatalf("expected 3 skipped keys before eviction, got %d", len(s.skippedKeys))
	}

	s.evictOldestSkippedKey()

	if len(s.skippedKeys) != 2 {
		t.Fatalf("expected 2 skipped keys after eviction, got %d", len(s.skippedKeys))
	}
	// counter=5 was inserted first — it must be the one evicted.
	if _, ok := s.skippedKeys[SkippedKeyID{Epoch: 0, Counter: 5}]; ok {
		t.Error("expected counter=5 (FIFO-oldest) to be evicted, but it remains")
	}
	if _, ok := s.skippedKeys[SkippedKeyID{Epoch: 0, Counter: 3}]; !ok {
		t.Error("counter=3 should remain after eviction")
	}
	if _, ok := s.skippedKeys[SkippedKeyID{Epoch: 0, Counter: 7}]; !ok {
		t.Error("counter=7 should remain after eviction")
	}
}

// TestFIFOEvictSkipsStaleEntries verifies that when the first FIFO entry has
// already been removed from the map (stale), evictOldestSkippedKey advances
// past it and removes the next live entry.
func TestFIFOEvictSkipsStaleEntries(t *testing.T) {
	rkBytes := make([]byte, keyLen)
	rk, err := secret.New(rkBytes)
	if err != nil {
		t.Fatalf("secret.New rk: %v", err)
	}

	s := &SPQR{
		chains:      make(map[uint64]*EpochChain),
		skippedKeys: make(map[SkippedKeyID]*secret.Secret),
		direction:   DirectionA2B,
		maxJump:     maxJump,
		negotiation: negotiationResolved,
		version:     VersionV1,
		minVersion:  VersionV1,
		rootKey:     rk,
	}
	defer s.Zeroize()

	// Insert two keys in FIFO order.
	for _, counter := range []uint32{1, 2} {
		kb := make([]byte, keyLen)
		kb[0] = byte(counter)
		mk, mErr := secret.New(kb)
		if mErr != nil {
			t.Fatalf("secret.New: %v", mErr)
		}
		id := SkippedKeyID{Epoch: 0, Counter: counter}
		s.skippedKeys[id] = mk
		s.skippedKeysFIFO = append(s.skippedKeysFIFO, id)
	}

	// Simulate counter=1 being consumed externally (e.g., by gcSkippedKeys).
	// The FIFO still holds {1, 2} but the map has only {2}.
	s.skippedKeys[SkippedKeyID{Epoch: 0, Counter: 1}].Destroy()
	delete(s.skippedKeys, SkippedKeyID{Epoch: 0, Counter: 1})

	// evictOldestSkippedKey must skip the stale counter=1 entry and evict counter=2.
	s.evictOldestSkippedKey()

	if len(s.skippedKeys) != 0 {
		t.Errorf("expected 0 skipped keys after eviction, got %d", len(s.skippedKeys))
	}
	if _, ok := s.skippedKeys[SkippedKeyID{Epoch: 0, Counter: 2}]; ok {
		t.Error("expected counter=2 to be evicted")
	}
}

// TestFIFOCompactReducesSlice verifies that compactFIFOIfNeeded copies the
// live tail to the front when head exceeds half the slice length.
func TestFIFOCompactReducesSlice(t *testing.T) {
	rkBytes := make([]byte, keyLen)
	rk, err := secret.New(rkBytes)
	if err != nil {
		t.Fatalf("secret.New rk: %v", err)
	}

	s := &SPQR{
		chains:      make(map[uint64]*EpochChain),
		skippedKeys: make(map[SkippedKeyID]*secret.Secret),
		direction:   DirectionA2B,
		maxJump:     maxJump,
		negotiation: negotiationResolved,
		version:     VersionV1,
		minVersion:  VersionV1,
		rootKey:     rk,
	}
	defer s.Zeroize()

	// Pre-populate the FIFO with 4 IDs (no map entries needed for compaction test).
	s.skippedKeysFIFO = []SkippedKeyID{
		{0, 1}, {0, 2}, {0, 3}, {0, 4},
	}
	// Advance head past the first 3 entries (head=3, len=4 → head > len/2).
	s.skippedKeysFIFOHead = 3

	s.compactFIFOIfNeeded()

	// After compaction, head=0 and only {0, 4} remains.
	if s.skippedKeysFIFOHead != 0 {
		t.Errorf("expected head=0 after compaction, got %d", s.skippedKeysFIFOHead)
	}
	if len(s.skippedKeysFIFO) != 1 {
		t.Errorf("expected 1 element after compaction, got %d", len(s.skippedKeysFIFO))
	}
	if s.skippedKeysFIFO[0] != (SkippedKeyID{0, 4}) {
		t.Errorf("expected {0, 4} after compaction, got %v", s.skippedKeysFIFO[0])
	}
}

// TestRebuildSkippedKeysFIFOSortsCorrectly verifies that rebuildSkippedKeysFIFO
// produces a deterministic (Epoch, Counter) sorted order, ensuring the oldest
// key is evicted first after a deserialization rebuild.
func TestRebuildSkippedKeysFIFOSortsCorrectly(t *testing.T) {
	rkBytes := make([]byte, keyLen)
	rk, err := secret.New(rkBytes)
	if err != nil {
		t.Fatalf("secret.New rk: %v", err)
	}

	s := &SPQR{
		chains:      make(map[uint64]*EpochChain),
		skippedKeys: make(map[SkippedKeyID]*secret.Secret),
		direction:   DirectionA2B,
		maxJump:     maxJump,
		negotiation: negotiationResolved,
		version:     VersionV1,
		minVersion:  VersionV1,
		rootKey:     rk,
	}
	defer s.Zeroize()

	// Insert keys out of sorted order.
	ids := []SkippedKeyID{
		{Epoch: 1, Counter: 5},
		{Epoch: 0, Counter: 10},
		{Epoch: 1, Counter: 2},
		{Epoch: 0, Counter: 3},
	}
	for _, id := range ids {
		kb := make([]byte, keyLen)
		kb[0] = byte(id.Counter)
		mk, mErr := secret.New(kb)
		if mErr != nil {
			t.Fatalf("secret.New: %v", mErr)
		}
		s.skippedKeys[id] = mk
	}

	s.rebuildSkippedKeysFIFO()

	if s.skippedKeysFIFOHead != 0 {
		t.Errorf("expected head=0 after rebuild, got %d", s.skippedKeysFIFOHead)
	}
	if len(s.skippedKeysFIFO) != 4 {
		t.Fatalf("expected 4 entries in FIFO, got %d", len(s.skippedKeysFIFO))
	}
	// Expected sorted order: {0,3}, {0,10}, {1,2}, {1,5}.
	want := []SkippedKeyID{
		{Epoch: 0, Counter: 3},
		{Epoch: 0, Counter: 10},
		{Epoch: 1, Counter: 2},
		{Epoch: 1, Counter: 5},
	}
	for i, w := range want {
		if s.skippedKeysFIFO[i] != w {
			t.Errorf("FIFO[%d] = %v, want %v", i, s.skippedKeysFIFO[i], w)
		}
	}
}

// TestFIFOExhaustedTriggersRebuild verifies that when the FIFO is empty but
// the skippedKeys map has entries, evictOldestSkippedKey rebuilds the FIFO
// and correctly evicts an entry.
func TestFIFOExhaustedTriggersRebuild(t *testing.T) {
	rkBytes := make([]byte, keyLen)
	rk, err := secret.New(rkBytes)
	if err != nil {
		t.Fatalf("secret.New rk: %v", err)
	}

	s := &SPQR{
		chains:      make(map[uint64]*EpochChain),
		skippedKeys: make(map[SkippedKeyID]*secret.Secret),
		direction:   DirectionA2B,
		maxJump:     maxJump,
		negotiation: negotiationResolved,
		version:     VersionV1,
		minVersion:  VersionV1,
		rootKey:     rk,
		// Leave skippedKeysFIFO nil — simulates post-deserialization without rebuild.
	}
	defer s.Zeroize()

	// Insert a key into the map without updating the FIFO (deserialization path).
	kb := make([]byte, keyLen)
	kb[0] = 0x42
	mk, mErr := secret.New(kb)
	if mErr != nil {
		t.Fatalf("secret.New: %v", mErr)
	}
	id := SkippedKeyID{Epoch: 0, Counter: 100}
	s.skippedKeys[id] = mk

	// FIFO is empty (nil). evictOldestSkippedKey must rebuild and evict.
	s.evictOldestSkippedKey()

	if len(s.skippedKeys) != 0 {
		t.Errorf("expected 0 skipped keys after rebuild-eviction, got %d", len(s.skippedKeys))
	}
}

// TestDecryptSkipForwardPopulatesFIFO verifies that the FIFO is populated
// during normal Decrypt with a forward jump, so that subsequent evictions
// use FIFO order correctly.
func TestDecryptSkipForwardPopulatesFIFO(t *testing.T) {
	ss := randomBytes(t, 32)
	s, err := Init(ss, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	// Skip forward to counter=5, which stores counters 1-4 as skipped keys.
	mk, decErr := s.Decrypt(0, 5)
	if decErr != nil {
		t.Fatalf("Decrypt(0, 5): %v", decErr)
	}
	mk.Destroy()

	// skippedKeys must have 4 entries (counters 1-4).
	if len(s.skippedKeys) != 4 {
		t.Fatalf("expected 4 skipped keys, got %d", len(s.skippedKeys))
	}
	// FIFO must also have 4 entries in insertion order.
	if len(s.skippedKeysFIFO)-s.skippedKeysFIFOHead != 4 {
		t.Errorf("expected 4 live FIFO entries, got %d (head=%d, len=%d)",
			len(s.skippedKeysFIFO)-s.skippedKeysFIFOHead, s.skippedKeysFIFOHead, len(s.skippedKeysFIFO))
	}
	// FIFO entries must match the counters 1-4 in insertion order.
	liveEntries := s.skippedKeysFIFO[s.skippedKeysFIFOHead:]
	for i, id := range liveEntries {
		wantCounter := uint32(i + 1)
		if id.Counter != wantCounter {
			t.Errorf("FIFO[%d].Counter = %d, want %d", i, id.Counter, wantCounter)
		}
	}
}

// TestProtoDeserializeRebuildsFIFO verifies that after UnmarshalStateProto,
// the FIFO is rebuilt from the skippedKeys map so that eviction works
// immediately without a prior Decrypt call.
func TestProtoDeserializeRebuildsFIFO(t *testing.T) {
	ss := randomBytes(t, 32)
	s, err := Init(ss, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	// Skip forward to counter=4, storing counters 1-3 as skipped keys.
	mk, decErr := s.Decrypt(0, 4)
	if decErr != nil {
		t.Fatalf("Decrypt(0, 4): %v", decErr)
	}
	mk.Destroy()

	// Serialize and deserialize — FIFO should be rebuilt by protoChainToSPQR.
	serialized, serErr := s.Serialize()
	if serErr != nil {
		t.Fatalf("Serialize: %v", serErr)
	}
	s2, desErr := Deserialize(serialized)
	if desErr != nil {
		t.Fatalf("Deserialize: %v", desErr)
	}
	defer s2.Zeroize()

	// The deserialized SPQR must have the FIFO populated (3 live entries for counters 1-3).
	liveCount := len(s2.skippedKeysFIFO) - s2.skippedKeysFIFOHead
	if liveCount != 3 {
		t.Errorf("expected 3 live FIFO entries after deserialization, got %d (head=%d, len=%d)",
			liveCount, s2.skippedKeysFIFOHead, len(s2.skippedKeysFIFO))
	}

	// Eviction must work correctly after deserialization.
	s2.evictOldestSkippedKey()
	if len(s2.skippedKeys) != 2 {
		t.Errorf("expected 2 skipped keys after eviction, got %d", len(s2.skippedKeys))
	}
}

// TestFIFOSubCapacityConsumeCyclesDoNotGrowUnboundedly verifies that the FIFO
// backing slice does not grow proportional to the total number of skipped keys
// ever created when a session repeatedly inserts and consumes skipped keys while
// staying below the eviction capacity (maxSkippedKeys). Without the fix the
// stale FIFO entries were never reclaimed on the consume path, causing unbounded
// slice growth at 16 bytes per skipped key ever created.
func TestFIFOSubCapacityConsumeCyclesDoNotGrowUnboundedly(t *testing.T) {
	ss := randomBytes(t, 32)
	// Use math.MaxUint32 as the jump limit so the forward jumps in the test
	// never hit the DoS guard, keeping the focus on FIFO memory behaviour.
	s, err := Init(ss, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	const (
		cycleJump = 5   // each cycle skips 4 keys ahead and then consumes them
		numCycles = 200 // well above any reasonable bounded FIFO waste threshold
	)

	for i := 0; i < numCycles; i++ {
		chain := s.chains[s.epoch]
		base := chain.recvCounter

		// Decrypt at base+cycleJump stores keys base+1 .. base+cycleJump-1 in
		// skippedKeys and advances recvCounter to base+cycleJump.
		mk, decErr := s.Decrypt(s.epoch, base+cycleJump)
		if decErr != nil {
			t.Fatalf("cycle %d Decrypt forward: %v", i, decErr)
		}
		mk.Destroy()

		// Consume the skipped keys so the map returns to zero.
		for j := uint32(1); j < cycleJump; j++ {
			consumed, cErr := s.Decrypt(s.epoch, base+j)
			if cErr != nil {
				t.Fatalf("cycle %d consume key %d: %v", i, base+j, cErr)
			}
			consumed.Destroy()
		}
	}

	// After numCycles, the skippedKeys map should be empty.
	if len(s.skippedKeys) != 0 {
		t.Errorf("expected empty skippedKeys after all consumed, got %d", len(s.skippedKeys))
	}

	// The live FIFO length must be bounded: it must not grow proportional to the
	// total keys ever created (which would be numCycles*(cycleJump-1) = 800 stale
	// entries without the fix). With trimFIFOIfNeeded the live FIFO length is
	// bounded to 2*len(skippedKeys)+64 = 64 when the map is empty.
	liveFIFO := len(s.skippedKeysFIFO) - s.skippedKeysFIFOHead
	totalCreated := numCycles * (cycleJump - 1)
	if liveFIFO >= totalCreated {
		t.Errorf("FIFO grew proportional to total created keys (%d >= %d): unbounded growth detected",
			liveFIFO, totalCreated)
	}
	// Hard upper bound: must be much smaller than total created.
	const maxAllowedFIFO = 128
	if liveFIFO > maxAllowedFIFO {
		t.Errorf("FIFO backing slice too large: %d entries (limit %d)", liveFIFO, maxAllowedFIFO)
	}
}
