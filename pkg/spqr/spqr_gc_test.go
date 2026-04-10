package spqr

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// TestSkippedKeyGC verifies that after deriving a key at a high counter,
// skipped keys with counters below (currentCounter - maxSkippedKeys) are
// garbage collected.
func TestSkippedKeyGC(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	s, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	// Manually insert skipped keys at counters 1-9 to simulate out-of-order
	// messages without hitting the maxSkippedKeys limit.
	for counter := uint32(1); counter <= 9; counter++ {
		keyData := make([]byte, 32)
		keyData[0] = byte(counter)
		mk, sErr := secret.New(keyData)
		if sErr != nil {
			t.Fatalf("secret.New: %v", sErr)
		}
		s.skippedKeys[SkippedKeyID{Epoch: 0, Counter: counter}] = mk
	}

	if s.SkippedKeyCount() != 9 {
		t.Fatalf("expected 9 skipped keys, got %d", s.SkippedKeyCount())
	}

	// Set the chain's recvCounter to simulate having advanced past these keys,
	// then run GC with a counter high enough to trigger trimming.
	// trimBelow = 2010 - 2000 = 10, so keys at counters 1-9 should be removed.
	s.gcSkippedKeys(0, 2010)

	// Verify keys 1-9 have been garbage collected.
	for counter := uint32(1); counter <= 9; counter++ {
		id := SkippedKeyID{Epoch: 0, Counter: counter}
		if _, exists := s.skippedKeys[id]; exists {
			t.Errorf("skipped key at counter %d should have been GC'd", counter)
		}
	}

	if s.SkippedKeyCount() != 0 {
		t.Errorf("expected 0 skipped keys after GC, got %d", s.SkippedKeyCount())
	}
}

// TestSkippedKeyGCPreservesRecentKeys verifies that GC retains keys within
// the maxSkippedKeys window while trimming older ones.
func TestSkippedKeyGCPreservesRecentKeys(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	s, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	// Insert keys at counters 5, 15, and 25.
	for _, counter := range []uint32{5, 15, 25} {
		keyData := make([]byte, 32)
		keyData[0] = byte(counter)
		mk, sErr := secret.New(keyData)
		if sErr != nil {
			t.Fatalf("secret.New: %v", sErr)
		}
		s.skippedKeys[SkippedKeyID{Epoch: 0, Counter: counter}] = mk
	}

	// GC with currentCounter=2015: trimBelow = 2015 - 2000 = 15.
	// Keys at counter 5 should be trimmed, 15 and 25 should survive.
	s.gcSkippedKeys(0, 2015)

	if _, exists := s.skippedKeys[SkippedKeyID{Epoch: 0, Counter: 5}]; exists {
		t.Error("key at counter 5 should have been trimmed (5 < 15)")
	}
	if _, exists := s.skippedKeys[SkippedKeyID{Epoch: 0, Counter: 15}]; !exists {
		t.Error("key at counter 15 should be retained (15 >= 15)")
	}
	if _, exists := s.skippedKeys[SkippedKeyID{Epoch: 0, Counter: 25}]; !exists {
		t.Error("key at counter 25 should be retained (25 >= 15)")
	}
}

// TestSkippedKeyGCLowCounter verifies that no garbage collection occurs when
// the current counter is at or below maxSkippedKeys, since there are no keys
// old enough to trim.
func TestSkippedKeyGCLowCounter(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	s, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	// Skip forward to counter 100, creating 99 skipped keys (1-99).
	mk, err := s.Decrypt(0, 100)
	if err != nil {
		t.Fatalf("Decrypt(0, 100): %v", err)
	}
	mk.Destroy()

	if s.SkippedKeyCount() != 99 {
		t.Fatalf("expected 99 skipped keys, got %d", s.SkippedKeyCount())
	}

	// All keys should still be present since counter (100) <= maxSkippedKeys (2000).
	for counter := uint32(1); counter <= 99; counter++ {
		id := SkippedKeyID{Epoch: 0, Counter: counter}
		if _, exists := s.skippedKeys[id]; !exists {
			t.Errorf("skipped key at counter %d should still exist", counter)
		}
	}
}

// TestSkippedKeyGCOnlyAffectsTargetEpoch verifies that GC only removes keys
// from the specified epoch, leaving keys in other epochs untouched.
func TestSkippedKeyGCOnlyAffectsTargetEpoch(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	s, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	// Manually insert a skipped key in epoch 1 at a low counter to verify
	// it is not affected by GC running on epoch 0.
	fakeKeyData := make([]byte, 32)
	fakeKeyData[0] = 0xAB
	fakeKey, err := secret.New(fakeKeyData)
	if err != nil {
		t.Fatalf("secret.New: %v", err)
	}
	s.skippedKeys[SkippedKeyID{Epoch: 1, Counter: 1}] = fakeKey

	// Run GC for epoch 0 with a high counter.
	s.gcSkippedKeys(0, 3000)

	// The epoch 1 key should still exist.
	id := SkippedKeyID{Epoch: 1, Counter: 1}
	if _, exists := s.skippedKeys[id]; !exists {
		t.Error("skipped key in epoch 1 should not be affected by GC of epoch 0")
	}
}

// TestClearOldEpochsRelativeToSendEpoch verifies that when the receive epoch
// advances far ahead of sendEpoch, epochs between (sendEpoch-1) and the
// current epoch are all retained. This matches Rust's behavior of keeping
// EPOCHS_TO_KEEP_PRIOR_TO_SEND_EPOCH (1) epochs before sendEpoch.
func TestClearOldEpochsRelativeToSendEpoch(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	s, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	// Simulate recv advancing to epoch 5 while sendEpoch stays at 2.
	// Install chains for epochs 1-5 via ReceiveKey.
	for e := uint64(1); e <= 5; e++ {
		sckaOutput := randomBytes(t, 32)
		if err := s.ReceiveKey(sckaOutput, e); err != nil {
			t.Fatalf("ReceiveKey(%d): %v", e, err)
		}
	}

	// Advance sendEpoch to 2 by encrypting at epoch 2.
	_, _, err = s.Encrypt(2)
	if err != nil {
		t.Fatalf("Encrypt(2): %v", err)
	}

	// s.epoch=5, s.sendEpoch=2 => keepFrom = min(2, 5) - 1 = 1
	// Re-run clearOldEpochs to apply the new sendEpoch logic.
	s.clearOldEpochs()

	// Epochs 1-5 should all be retained (keepFrom=1).
	for e := uint64(1); e <= 5; e++ {
		if _, ok := s.chains[e]; !ok {
			t.Errorf("epoch %d should be retained (sendEpoch=2, recv epoch=5, keepFrom=1)", e)
		}
	}

	// Epoch 0 should have been removed (0 < keepFrom=1).
	if _, ok := s.chains[0]; ok {
		t.Error("epoch 0 should have been removed (below keepFrom=1)")
	}
}

// TestClearOldEpochsBothAdvanced verifies that when both sendEpoch and recv
// epoch advance to the same value, only the current and previous epoch are
// retained.
func TestClearOldEpochsBothAdvanced(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	s, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	// Advance through epochs 1-5 via ReceiveKey.
	for e := uint64(1); e <= 5; e++ {
		sckaOutput := randomBytes(t, 32)
		if err := s.ReceiveKey(sckaOutput, e); err != nil {
			t.Fatalf("ReceiveKey(%d): %v", e, err)
		}
	}

	// Advance sendEpoch to 5 by encrypting at epoch 5.
	_, _, err = s.Encrypt(5)
	if err != nil {
		t.Fatalf("Encrypt(5): %v", err)
	}

	// s.epoch=5, s.sendEpoch=5 => keepFrom = min(5, 5) - 1 = 4
	s.clearOldEpochs()

	// Only epochs 4 and 5 should be retained.
	for e := uint64(4); e <= 5; e++ {
		if _, ok := s.chains[e]; !ok {
			t.Errorf("epoch %d should be retained", e)
		}
	}

	// Epochs 0-3 should be removed.
	for e := uint64(0); e <= 3; e++ {
		if _, ok := s.chains[e]; ok {
			t.Errorf("epoch %d should have been removed (below keepFrom=4)", e)
		}
	}
}

// TestClearOldEpochsSkippedKeysRemoved verifies that skipped message keys
// in pruned epochs are also destroyed.
func TestClearOldEpochsSkippedKeysRemoved(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	s, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	// Create a skipped key in epoch 0.
	mk, err := s.Decrypt(0, 5)
	if err != nil {
		t.Fatalf("Decrypt(0, 5): %v", err)
	}
	mk.Destroy()

	// Should have 4 skipped keys (counters 1-4) in epoch 0.
	if s.SkippedKeyCount() != 4 {
		t.Fatalf("expected 4 skipped keys, got %d", s.SkippedKeyCount())
	}

	// Advance both epochs to 5.
	for e := uint64(1); e <= 5; e++ {
		sckaOutput := randomBytes(t, 32)
		if err := s.ReceiveKey(sckaOutput, e); err != nil {
			t.Fatalf("ReceiveKey(%d): %v", e, err)
		}
	}
	_, _, err = s.Encrypt(5)
	if err != nil {
		t.Fatalf("Encrypt(5): %v", err)
	}
	s.clearOldEpochs()

	// All epoch 0 skipped keys should have been removed.
	for counter := uint32(1); counter <= 4; counter++ {
		id := SkippedKeyID{Epoch: 0, Counter: counter}
		if _, exists := s.skippedKeys[id]; exists {
			t.Errorf("skipped key at epoch 0, counter %d should have been pruned", counter)
		}
	}
}
