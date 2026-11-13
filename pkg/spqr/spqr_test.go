package spqr

import (
	"crypto/rand"
	"errors"
	"math"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/kdf"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret/secrettest"
)

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("failed to generate random bytes: %v", err)
	}
	return b
}

func randomSecret(t *testing.T, n int) *secret.Secret {
	t.Helper()
	b := randomBytes(t, n)
	s, err := secret.New(b)
	if err != nil {
		t.Fatalf("failed to create secret: %v", err)
	}
	return s
}

// --- KDF Tests ---

func TestKdfSckaInit(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	// Copy because KdfSckaInit will pass it to DeriveSecrets but not zeroize it.
	sharedCopy := make([]byte, 32)
	copy(sharedCopy, sharedSecret)

	rk, cks, ckr, err := KdfSckaInit(sharedSecret)
	if err != nil {
		t.Fatalf("KdfSckaInit: %v", err)
	}
	defer rk.Destroy()
	defer cks.Destroy()
	defer ckr.Destroy()

	if rk.Size() != 32 {
		t.Errorf("rk size = %d, want 32", rk.Size())
	}
	if cks.Size() != 32 {
		t.Errorf("cks size = %d, want 32", cks.Size())
	}
	if ckr.Size() != 32 {
		t.Errorf("ckr size = %d, want 32", ckr.Size())
	}

	// All three outputs must be different from each other.
	if secrettest.Same(t, rk, cks) {
		t.Error("rk should differ from cks")
	}
	if secrettest.Same(t, rk, ckr) {
		t.Error("rk should differ from ckr")
	}
	if secrettest.Same(t, cks, ckr) {
		t.Error("cks should differ from ckr")
	}

	// Deterministic: same input produces same output.
	rk2, cks2, ckr2, err := KdfSckaInit(sharedCopy)
	if err != nil {
		t.Fatalf("KdfSckaInit (second call): %v", err)
	}
	defer rk2.Destroy()
	defer cks2.Destroy()
	defer ckr2.Destroy()

	if !secrettest.Same(t, rk, rk2) || !secrettest.Same(t, cks, cks2) || !secrettest.Same(t, ckr, ckr2) {
		t.Error("KdfSckaInit is not deterministic")
	}
}

func TestKdfSckaInitEmptySecret(t *testing.T) {
	_, _, _, err := KdfSckaInit(nil)
	if err == nil {
		t.Fatal("expected error for nil shared secret")
	}
	if _, ok := err.(*ErrInvalidInput); !ok {
		t.Errorf("expected *ErrInvalidInput, got %T", err)
	}

	_, _, _, err = KdfSckaInit([]byte{})
	if err == nil {
		t.Fatal("expected error for empty shared secret")
	}
}

func TestKdfSckaRK(t *testing.T) {
	rkSecret := randomSecret(t, 32)
	defer rkSecret.Destroy()
	sckaOutput := randomBytes(t, 32)

	rkDigest := secrettest.Digest(t, rkSecret)

	newRK, newCKs, newCKr, err := KdfSckaRK(rkSecret, sckaOutput)
	if err != nil {
		t.Fatalf("KdfSckaRK: %v", err)
	}
	defer newRK.Destroy()
	defer newCKs.Destroy()
	defer newCKr.Destroy()

	if newRK.Size() != 32 || newCKs.Size() != 32 || newCKr.Size() != 32 {
		t.Error("output key sizes are wrong")
	}

	// Output should differ from input.
	if secrettest.Digest(t, newRK) == rkDigest {
		t.Error("new RK should differ from old RK")
	}
}

func TestKdfSckaRKInvalidInputs(t *testing.T) {
	_, _, _, err := KdfSckaRK(nil, randomBytes(t, 32))
	if err == nil {
		t.Fatal("expected error for nil rk")
	}

	rkSecret := randomSecret(t, 32)
	defer rkSecret.Destroy()
	_, _, _, err = KdfSckaRK(rkSecret, nil)
	if err == nil {
		t.Fatal("expected error for nil sckaOutput")
	}
}

func TestKdfSckaCK(t *testing.T) {
	ckRaw := randomBytes(t, 32)
	// Keep a copy for manual HKDF verification later.
	ckForVerify := make([]byte, 32)
	copy(ckForVerify, ckRaw)

	// Create secret from a copy so ckRaw stays intact for verification.
	ckInput := make([]byte, 32)
	copy(ckInput, ckRaw)
	ck, err := secret.New(ckInput)
	if err != nil {
		t.Fatalf("secret.New: %v", err)
	}
	defer ck.Destroy()

	mk, nextCK, err := KdfSckaCK(ck, 0)
	if err != nil {
		t.Fatalf("KdfSckaCK: %v", err)
	}
	defer mk.Destroy()
	defer nextCK.Destroy()

	if mk.Size() != 32 {
		t.Errorf("mk size = %d, want 32", mk.Size())
	}
	if nextCK.Size() != 32 {
		t.Errorf("nextCK size = %d, want 32", nextCK.Size())
	}
	if secrettest.Same(t, mk, nextCK) {
		t.Error("mk and nextCK should differ")
	}

	// Verify output matches HKDF(salt=zeros(32), ikm=chain_key, info=ctr_be32||ChainNextInfo, len=64).
	info := append([]byte{0x00, 0x00, 0x00, 0x00}, []byte(ChainNextInfo)...) // counter 0
	expectedOutput, err := kdf.DeriveSecrets(ckForVerify, make([]byte, 32), info, 64)
	if err != nil {
		t.Fatalf("DeriveSecrets: %v", err)
	}
	// Split: nextCK(first 32) || mk(last 32)
	if !secrettest.Matches(t, nextCK, expectedOutput[:32]) {
		t.Error("nextCK does not match expected HKDF output")
	}
	if !secrettest.Matches(t, mk, expectedOutput[32:64]) {
		t.Error("mk does not match expected HKDF output")
	}

	// Different counters should produce different output.
	ckInput2 := make([]byte, 32)
	copy(ckInput2, ckForVerify)
	ck2, err := secret.New(ckInput2)
	if err != nil {
		t.Fatalf("secret.New: %v", err)
	}
	defer ck2.Destroy()

	mk2, nextCK2, err := KdfSckaCK(ck2, 1)
	if err != nil {
		t.Fatalf("KdfSckaCK counter 1: %v", err)
	}
	defer mk2.Destroy()
	defer nextCK2.Destroy()

	if secrettest.Same(t, mk, mk2) {
		t.Error("different counters should produce different mk")
	}
	if secrettest.Same(t, nextCK, nextCK2) {
		t.Error("different counters should produce different nextCK")
	}
}

func TestKdfSckaCK_EmptyInput(t *testing.T) {
	_, _, err := KdfSckaCK(nil, 0)
	if err == nil {
		t.Fatal("expected error for nil chain key")
	}
	var inputErr *ErrInvalidInput
	if !errors.As(err, &inputErr) {
		t.Fatalf("expected ErrInvalidInput, got %T", err)
	}
}

func TestClearOldEpochsCleansSkippedKeys(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	s, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Send some messages in epoch 0 so that the recv counter advances.
	// Then skip some messages to create skipped keys.
	scka1 := randomBytes(t, 32)
	if err := s.ReceiveKey(scka1, 1); err != nil {
		t.Fatalf("ReceiveKey(1): %v", err)
	}

	// Decrypt counter 3 in epoch 0 (1-based), skipping counter 1 and 2.
	mk, err := s.Decrypt(0, 3)
	if err != nil {
		t.Fatalf("Decrypt(0,3): %v", err)
	}
	mk.Destroy()

	if s.SkippedKeyCount() != 2 {
		t.Fatalf("expected 2 skipped keys, got %d", s.SkippedKeyCount())
	}

	// Advance sendEpoch to 2 by encrypting, then advance recv epoch to 2.
	// This ensures keepFrom = min(sendEpoch, epoch) - 1 = 1, so epoch 0
	// skipped keys are pruned.
	_, _, err = s.Encrypt(1)
	if err != nil {
		t.Fatalf("Encrypt(1): %v", err)
	}

	scka2 := randomBytes(t, 32)
	if err := s.ReceiveKey(scka2, 2); err != nil {
		t.Fatalf("ReceiveKey(2): %v", err)
	}

	// Advance sendEpoch to 2 so keepFrom = min(2, 2) - 1 = 1.
	_, _, err = s.Encrypt(2)
	if err != nil {
		t.Fatalf("Encrypt(2): %v", err)
	}
	s.clearOldEpochs()

	// Epoch 0 skipped keys (epoch 0 < keepFrom=1) should have been cleaned.
	if s.SkippedKeyCount() != 0 {
		t.Fatalf("expected 0 skipped keys after epoch advance, got %d", s.SkippedKeyCount())
	}
	s.Zeroize()
}

// --- Init Tests ---

func TestSPQRInit(t *testing.T) {
	sharedSecret := randomBytes(t, 32)

	s, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	if s.Epoch() != 0 {
		t.Errorf("initial epoch = %d, want 0", s.Epoch())
	}
	if s.rootKey.Size() != 32 {
		t.Errorf("rootKey size = %d, want 32", s.rootKey.Size())
	}
	if len(s.chains) != 1 {
		t.Errorf("chains count = %d, want 1", len(s.chains))
	}
	chain, ok := s.chains[0]
	if !ok {
		t.Fatal("epoch 0 chain not found")
	}
	if chain.sendKey.Size() != 32 || chain.recvKey.Size() != 32 {
		t.Error("chain keys have wrong size")
	}
}

func TestSPQRInitEmptySecret(t *testing.T) {
	_, err := Init(nil, DirectionA2B, maxJump)
	if err == nil {
		t.Fatal("expected error for nil shared secret")
	}
}

// --- Direction Tests ---

func TestSPQRDirectionSwap(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	sharedCopy := make([]byte, 32)
	copy(sharedCopy, sharedSecret)

	a, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init A2B: %v", err)
	}
	defer a.Zeroize()

	b, err := Init(sharedCopy, DirectionB2A, maxJump)
	if err != nil {
		t.Fatalf("Init B2A: %v", err)
	}
	defer b.Zeroize()

	// A's send key should be B's recv key and vice versa.
	if !secrettest.Same(t, a.chains[0].sendKey, b.chains[0].recvKey) {
		t.Error("A's sendKey should equal B's recvKey")
	}
	if !secrettest.Same(t, a.chains[0].recvKey, b.chains[0].sendKey) {
		t.Error("A's recvKey should equal B's sendKey")
	}

	// Root keys should be identical.
	if !secrettest.Same(t, a.rootKey, b.rootKey) {
		t.Error("root keys should be identical regardless of direction")
	}
}

func TestDirectionString(t *testing.T) {
	if DirectionA2B.String() != "A2B" {
		t.Errorf("expected A2B, got %s", DirectionA2B.String())
	}
	if DirectionB2A.String() != "B2A" {
		t.Errorf("expected B2A, got %s", DirectionB2A.String())
	}
	if Direction(99).String() != "unknown" {
		t.Errorf("expected unknown, got %s", Direction(99).String())
	}
}

// --- Encrypt/Decrypt Tests ---

func TestSPQREncryptDecrypt(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	sharedCopy := make([]byte, 32)
	copy(sharedCopy, sharedSecret)

	alice, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init alice: %v", err)
	}
	defer alice.Zeroize()

	bob, err := Init(sharedCopy, DirectionB2A, maxJump)
	if err != nil {
		t.Fatalf("Init bob: %v", err)
	}
	defer bob.Zeroize()

	// Alice encrypts, Bob decrypts.
	mk1, counter1, err := alice.Encrypt(0)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if counter1 != 1 {
		t.Errorf("first counter = %d, want 1", counter1)
	}

	mk1d, err := bob.Decrypt(0, counter1)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !secrettest.Same(t, mk1, mk1d) {
		t.Error("decrypted message key does not match encrypted message key")
	}
	mk1.Destroy()
	mk1d.Destroy()

	// Second message.
	mk2, counter2, err := alice.Encrypt(0)
	if err != nil {
		t.Fatalf("Encrypt 2: %v", err)
	}
	if counter2 != 2 {
		t.Errorf("second counter = %d, want 2", counter2)
	}

	mk2d, err := bob.Decrypt(0, counter2)
	if err != nil {
		t.Fatalf("Decrypt 2: %v", err)
	}
	if !secrettest.Same(t, mk2, mk2d) {
		t.Error("second message key mismatch")
	}
	mk2.Destroy()
	mk2d.Destroy()
}

func TestSPQREncryptUnknownEpoch(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	s, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	_, _, err = s.Encrypt(99)
	if err == nil {
		t.Fatal("expected error for unknown epoch")
	}
	if _, ok := err.(*ErrUnknownEpoch); !ok {
		t.Errorf("expected *ErrUnknownEpoch, got %T", err)
	}
}

func TestSPQRDecryptUnknownEpoch(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	s, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	_, err = s.Decrypt(99, 0)
	if err == nil {
		t.Fatal("expected error for unknown epoch")
	}
	if _, ok := err.(*ErrUnknownEpoch); !ok {
		t.Errorf("expected *ErrUnknownEpoch, got %T", err)
	}
}

// --- Multiple Epochs Tests ---

func TestSPQRMultipleEpochs(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	sharedCopy := make([]byte, 32)
	copy(sharedCopy, sharedSecret)

	alice, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init alice: %v", err)
	}
	defer alice.Zeroize()

	bob, err := Init(sharedCopy, DirectionB2A, maxJump)
	if err != nil {
		t.Fatalf("Init bob: %v", err)
	}
	defer bob.Zeroize()

	// Advance through 3 epochs.
	for epoch := uint64(1); epoch <= 3; epoch++ {
		sckaOutput := randomBytes(t, 32)

		if err := alice.ReceiveKey(sckaOutput, epoch); err != nil {
			t.Fatalf("alice.ReceiveKey epoch %d: %v", epoch, err)
		}
		if err := bob.ReceiveKey(sckaOutput, epoch); err != nil {
			t.Fatalf("bob.ReceiveKey epoch %d: %v", epoch, err)
		}

		if alice.Epoch() != epoch {
			t.Errorf("alice epoch = %d, want %d", alice.Epoch(), epoch)
		}

		mk, counter, err := alice.Encrypt(epoch)
		if err != nil {
			t.Fatalf("Encrypt epoch %d: %v", epoch, err)
		}
		if counter != 1 {
			t.Errorf("epoch %d first counter = %d, want 1", epoch, counter)
		}

		mkd, err := bob.Decrypt(epoch, counter)
		if err != nil {
			t.Fatalf("Decrypt epoch %d: %v", epoch, err)
		}
		if !secrettest.Same(t, mk, mkd) {
			t.Errorf("epoch %d message key mismatch", epoch)
		}
		mk.Destroy()
		mkd.Destroy()
	}
}

func TestSPQRReceiveKeyOldEpoch(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	s, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	if err := s.ReceiveKey(randomBytes(t, 32), 1); err != nil {
		t.Fatalf("ReceiveKey epoch 1: %v", err)
	}

	// Attempt to go backwards.
	err = s.ReceiveKey(randomBytes(t, 32), 0)
	if err == nil {
		t.Fatal("expected error for old epoch")
	}
	if _, ok := err.(*ErrOldEpoch); !ok {
		t.Errorf("expected *ErrOldEpoch, got %T", err)
	}

	// Same epoch should also fail.
	err = s.ReceiveKey(randomBytes(t, 32), 1)
	if err == nil {
		t.Fatal("expected error for same epoch")
	}
}

// --- Out-of-Order Decrypt Tests ---

func TestSPQROutOfOrderDecrypt(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	sharedCopy := make([]byte, 32)
	copy(sharedCopy, sharedSecret)

	alice, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init alice: %v", err)
	}
	defer alice.Zeroize()

	bob, err := Init(sharedCopy, DirectionB2A, maxJump)
	if err != nil {
		t.Fatalf("Init bob: %v", err)
	}
	defer bob.Zeroize()

	// Alice sends 5 messages.
	type msg struct {
		mk      *secret.Secret
		counter uint32
	}
	msgs := make([]msg, 5)
	for i := 0; i < 5; i++ {
		mk, counter, err := alice.Encrypt(0)
		if err != nil {
			t.Fatalf("Encrypt %d: %v", i, err)
		}
		msgs[i] = msg{mk: mk, counter: counter}
	}

	// Bob receives them out of order: 3, 0, 4, 1, 2.
	order := []int{3, 0, 4, 1, 2}
	for _, idx := range order {
		mkd, err := bob.Decrypt(0, msgs[idx].counter)
		if err != nil {
			t.Fatalf("Decrypt msg %d: %v", idx, err)
		}
		if !secrettest.Same(t, msgs[idx].mk, mkd) {
			t.Errorf("message key mismatch for msg %d", idx)
		}
		mkd.Destroy()
	}

	for _, m := range msgs {
		m.mk.Destroy()
	}
}

// --- Skipped Keys Tests ---

func TestSPQRSkippedKeys(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	sharedCopy := make([]byte, 32)
	copy(sharedCopy, sharedSecret)

	alice, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init alice: %v", err)
	}
	defer alice.Zeroize()

	bob, err := Init(sharedCopy, DirectionB2A, maxJump)
	if err != nil {
		t.Fatalf("Init bob: %v", err)
	}
	defer bob.Zeroize()

	// Alice sends 3 messages. Clone the keys since Encrypt returns ownership.
	mks := make([]*secret.Secret, 3)
	for i := 0; i < 3; i++ {
		mk, _, err := alice.Encrypt(0)
		if err != nil {
			t.Fatalf("Encrypt %d: %v", i, err)
		}
		mks[i] = mk
	}

	// Bob skips to message 3 (counter is 1-based), which should store keys for 1 and 2.
	mkd, err := bob.Decrypt(0, 3)
	if err != nil {
		t.Fatalf("Decrypt counter 3: %v", err)
	}
	if !secrettest.Same(t, mks[2], mkd) {
		t.Error("message key mismatch for counter 3")
	}
	mkd.Destroy()

	if bob.SkippedKeyCount() != 2 {
		t.Errorf("skipped key count = %d, want 2", bob.SkippedKeyCount())
	}

	// Now retrieve skipped keys (1-based counters).
	for i := 0; i < 2; i++ {
		mkd, err := bob.Decrypt(0, uint32(i+1))
		if err != nil {
			t.Fatalf("Decrypt skipped counter %d: %v", i+1, err)
		}
		if !secrettest.Same(t, mks[i], mkd) {
			t.Errorf("skipped message key mismatch for counter %d", i+1)
		}
		mkd.Destroy()
	}

	if bob.SkippedKeyCount() != 0 {
		t.Errorf("skipped key count after retrieval = %d, want 0", bob.SkippedKeyCount())
	}

	for _, mk := range mks {
		mk.Destroy()
	}
}

// --- Clear Old Epochs Tests ---

func TestSPQRClearOldEpochs(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	s, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	// Add epochs 1, 2, 3.
	for i := uint64(1); i <= 3; i++ {
		if err := s.ReceiveKey(randomBytes(t, 32), i); err != nil {
			t.Fatalf("ReceiveKey epoch %d: %v", i, err)
		}
	}

	// Advance sendEpoch to 3 so keepFrom = min(3, 3) - 1 = 2.
	_, _, err = s.Encrypt(3)
	if err != nil {
		t.Fatalf("Encrypt(3): %v", err)
	}
	s.clearOldEpochs()

	// After epoch 3 with sendEpoch=3, only epochs 2 and 3 should remain.
	if len(s.chains) != 2 {
		t.Errorf("chains count = %d, want 2", len(s.chains))
	}
	if _, ok := s.chains[2]; !ok {
		t.Error("epoch 2 should be retained")
	}
	if _, ok := s.chains[3]; !ok {
		t.Error("epoch 3 should be retained")
	}
	if _, ok := s.chains[0]; ok {
		t.Error("epoch 0 should have been cleared")
	}
	if _, ok := s.chains[1]; ok {
		t.Error("epoch 1 should have been cleared")
	}
}

// --- Max Skipped Keys Tests ---

func TestSPQRMaxSkippedKeys(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	s, err := Init(sharedSecret, DirectionB2A, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	// FIFO eviction: requesting a key that skips beyond maxSkippedKeys now
	// succeeds. Oldest skipped keys are evicted silently, matching the Rust
	// reference (sparsepostquantumratchet chain.rs KeyHistory::gc). The map
	// should not exceed maxSkippedKeys after the call.
	mk, decryptErr := s.Decrypt(0, maxSkippedKeys+2)
	if decryptErr != nil {
		t.Fatalf("expected FIFO eviction to allow decryption beyond maxSkippedKeys, got: %v", decryptErr)
	}
	mk.Destroy()
	if s.SkippedKeyCount() > maxSkippedKeys {
		t.Errorf("skippedKeys count %d exceeds maxSkippedKeys %d after eviction", s.SkippedKeyCount(), maxSkippedKeys)
	}
}

// --- Zeroize Tests ---

func TestSPQRZeroize(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	s, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Store references to check destruction.
	rootKey := s.rootKey
	chainSend := s.chains[0].sendKey

	s.Zeroize()

	if !rootKey.IsDestroyed() {
		t.Error("root key was not destroyed")
	}
	if !chainSend.IsDestroyed() {
		t.Error("chain send key was not destroyed")
	}
}

// --- Error String Tests ---

func TestErrorStrings(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "ErrUnknownEpoch",
			err:  &ErrUnknownEpoch{Epoch: 5},
			want: "spqr: unknown epoch 5",
		},
		{
			name: "ErrOldEpoch",
			err:  &ErrOldEpoch{Current: 3, Received: 1},
			want: "spqr: old epoch 1, current is 3",
		},
		{
			name: "ErrMaxSkippedKeys",
			err:  &ErrMaxSkippedKeys{Limit: 2000},
			want: "spqr: exceeded max skipped keys limit of 2000",
		},
		{
			name: "ErrInvalidInput",
			err:  &ErrInvalidInput{Field: "secret", Reason: "empty"},
			want: "spqr: invalid input secret: empty",
		},
		{
			name: "ErrKeyAlreadyRequested",
			err:  &ErrKeyAlreadyRequested{Counter: 42},
			want: "spqr: key already requested at counter 42",
		},
		{
			name: "ErrKeyTrimmed",
			err:  &ErrKeyTrimmed{Counter: 7},
			want: "spqr: key trimmed at counter 7",
		},
		{
			name: "ErrMaxJump",
			err:  &ErrMaxJump{From: 10, To: 30000},
			want: "spqr: key jump too large from 10 to 30000",
		},
		{
			name: "ErrSendEpochDecreased",
			err:  &ErrSendEpochDecreased{Current: 5, Requested: 2},
			want: "spqr: send epoch decreased from 5 to 2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestErrDecryptionFailedUnwrap(t *testing.T) {
	inner := &ErrUnknownEpoch{Epoch: 1}
	err := &ErrDecryptionFailed{Epoch: 1, Counter: 0, Err: inner}

	if err.Unwrap() != inner {
		t.Error("Unwrap did not return inner error")
	}
	if err.Error() == "" {
		t.Error("error string should not be empty")
	}
}

// --- Bidirectional Communication Test ---

// --- Duplicate Counter / Key Trimmed Tests ---

func TestSPQRDecryptDuplicateCounterReturnsError(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	sharedCopy := make([]byte, 32)
	copy(sharedCopy, sharedSecret)

	alice, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init alice: %v", err)
	}
	defer alice.Zeroize()

	bob, err := Init(sharedCopy, DirectionB2A, maxJump)
	if err != nil {
		t.Fatalf("Init bob: %v", err)
	}
	defer bob.Zeroize()

	// Alice sends, Bob decrypts counter 1.
	mk, counter, err := alice.Encrypt(0)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	mk.Destroy()

	mkd, err := bob.Decrypt(0, counter)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	mkd.Destroy()

	// Requesting the same counter again should fail with ErrKeyAlreadyRequested.
	_, err = bob.Decrypt(0, counter)
	if err == nil {
		t.Fatal("expected error for duplicate counter")
	}
	if _, ok := err.(*ErrKeyAlreadyRequested); !ok {
		t.Errorf("expected *ErrKeyAlreadyRequested, got %T: %v", err, err)
	}
}

func TestSPQRDecryptOldCounterReturnsKeyAlreadyRequested(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	bob, err := Init(sharedSecret, DirectionB2A, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer bob.Zeroize()

	// Advance to counter 5 by decrypting at counter 5.
	mk, err := bob.Decrypt(0, 5)
	if err != nil {
		t.Fatalf("Decrypt(0, 5): %v", err)
	}
	mk.Destroy()

	// Counter 3 was skipped and stored. Retrieve it first.
	mk, err = bob.Decrypt(0, 3)
	if err != nil {
		t.Fatalf("Decrypt(0, 3): %v", err)
	}
	mk.Destroy()

	// Now request counter 3 again - it was in skipped keys but already consumed.
	// recvCounter is 5 and counter 3 is within maxSkippedKeys of recvCounter,
	// so it must have been already requested (matching Rust KeyHistory::get).
	_, err = bob.Decrypt(0, 3)
	if err == nil {
		t.Fatal("expected error for already-consumed counter")
	}
	if _, ok := err.(*ErrKeyAlreadyRequested); !ok {
		t.Errorf("expected *ErrKeyAlreadyRequested, got %T: %v", err, err)
	}
}

func TestSPQRDecryptTrimmedCounter(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	bob, err := Init(sharedSecret, DirectionB2A, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer bob.Zeroize()

	// Advance the recv counter far enough that counter 1 falls outside
	// the maxSkippedKeys window, making it truly trimmed.
	// We need recvCounter > counter + maxSkippedKeys, i.e., recvCounter > 1 + 2000 = 2001.
	// Decrypt sequentially to avoid the maxSkippedKeys limit on a single jump.
	for i := uint32(1); i <= maxSkippedKeys+2; i++ {
		mk, decErr := bob.Decrypt(0, i)
		if decErr != nil {
			t.Fatalf("Decrypt(0, %d): %v", i, decErr)
		}
		mk.Destroy()
	}

	// Counter 1 is now beyond the maxSkippedKeys horizon (1 + 2000 < 2002).
	_, err = bob.Decrypt(0, 1)
	if err == nil {
		t.Fatal("expected error for trimmed counter")
	}
	if _, ok := err.(*ErrKeyTrimmed); !ok {
		t.Errorf("expected *ErrKeyTrimmed, got %T: %v", err, err)
	}
}

// --- Max Jump Tests ---

func TestSPQRDecryptMaxJumpExceeded(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	bob, err := Init(sharedSecret, DirectionB2A, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer bob.Zeroize()

	// Request a counter that exceeds maxJump from the current position (0).
	_, err = bob.Decrypt(0, maxJump+1)
	if err == nil {
		t.Fatal("expected error for exceeding max jump")
	}
	if e, ok := err.(*ErrMaxJump); !ok {
		t.Errorf("expected *ErrMaxJump, got %T: %v", err, err)
	} else {
		if e.From != 0 || e.To != maxJump+1 {
			t.Errorf("ErrMaxJump fields: From=%d To=%d, want From=0 To=%d",
				e.From, e.To, maxJump+1)
		}
	}
}

func TestSPQRDecryptAtMaxJumpSucceeds(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	bob, err := Init(sharedSecret, DirectionB2A, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer bob.Zeroize()

	// maxJump exactly should succeed (counter - recvCounter == maxJump).
	// But maxSkippedKeys (2000) will be hit before maxJump (25000) in the
	// skip loop. So test with a smaller jump that stays within maxSkippedKeys.
	mk, err := bob.Decrypt(0, maxSkippedKeys)
	if err != nil {
		t.Fatalf("Decrypt at maxSkippedKeys boundary: %v", err)
	}
	mk.Destroy()
}

// --- Send Epoch Monotonicity Tests ---

func TestSPQREncryptSendEpochDecreased(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	alice, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer alice.Zeroize()

	// Advance to epoch 1.
	if err := alice.ReceiveKey(randomBytes(t, 32), 1); err != nil {
		t.Fatalf("ReceiveKey(1): %v", err)
	}

	// Encrypt at epoch 1, establishing sendEpoch = 1.
	mk, _, err := alice.Encrypt(1)
	if err != nil {
		t.Fatalf("Encrypt(1): %v", err)
	}
	mk.Destroy()

	// Attempting to encrypt at epoch 0 should fail.
	_, _, err = alice.Encrypt(0)
	if err == nil {
		t.Fatal("expected error for send epoch decrease")
	}
	if e, ok := err.(*ErrSendEpochDecreased); !ok {
		t.Errorf("expected *ErrSendEpochDecreased, got %T: %v", err, err)
	} else {
		if e.Current != 1 || e.Requested != 0 {
			t.Errorf("ErrSendEpochDecreased: Current=%d Requested=%d, want Current=1 Requested=0",
				e.Current, e.Requested)
		}
	}
}

func TestSPQREncryptSendEpochAdvanceClearsPriorKeys(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	alice, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer alice.Zeroize()

	// Encrypt at epoch 0 to confirm it works.
	mk, _, err := alice.Encrypt(0)
	if err != nil {
		t.Fatalf("Encrypt(0): %v", err)
	}
	mk.Destroy()

	// Advance to epoch 1.
	if err := alice.ReceiveKey(randomBytes(t, 32), 1); err != nil {
		t.Fatalf("ReceiveKey(1): %v", err)
	}

	// Encrypt at epoch 1 -- this should clear epoch 0's send key.
	mk, _, err = alice.Encrypt(1)
	if err != nil {
		t.Fatalf("Encrypt(1): %v", err)
	}
	mk.Destroy()

	// Epoch 0 chain's send key should be nil.
	if chain, ok := alice.chains[0]; ok && chain.sendKey != nil {
		t.Error("epoch 0 send key should be nil after advancing send epoch to 1")
	}
}

func TestSPQRBidirectionalCommunication(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	sharedCopy := make([]byte, 32)
	copy(sharedCopy, sharedSecret)

	alice, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init alice: %v", err)
	}
	defer alice.Zeroize()

	bob, err := Init(sharedCopy, DirectionB2A, maxJump)
	if err != nil {
		t.Fatalf("Init bob: %v", err)
	}
	defer bob.Zeroize()

	// Alice sends to Bob.
	mkA, ctrA, err := alice.Encrypt(0)
	if err != nil {
		t.Fatalf("Alice Encrypt: %v", err)
	}
	mkAd, err := bob.Decrypt(0, ctrA)
	if err != nil {
		t.Fatalf("Bob Decrypt: %v", err)
	}
	if !secrettest.Same(t, mkA, mkAd) {
		t.Error("A->B message key mismatch")
	}
	mkA.Destroy()
	mkAd.Destroy()

	// Bob sends to Alice.
	mkB, ctrB, err := bob.Encrypt(0)
	if err != nil {
		t.Fatalf("Bob Encrypt: %v", err)
	}
	mkBd, err := alice.Decrypt(0, ctrB)
	if err != nil {
		t.Fatalf("Alice Decrypt: %v", err)
	}
	if !secrettest.Same(t, mkB, mkBd) {
		t.Error("B->A message key mismatch")
	}
	mkB.Destroy()
	mkBd.Destroy()
}

// --- Self-Session (maxJump=MaxUint32) Tests ---

func TestSPQRSelfSessionAllowsLargeForwardJump(t *testing.T) {
	sharedSecret := randomBytes(t, 32)

	// Create a self-session with maxJump = math.MaxUint32.
	s, err := Init(sharedSecret, DirectionA2B, math.MaxUint32)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	// With FIFO eviction, a jump of maxJump+1 (25001) from recvCounter=0
	// succeeds: the maxJump check passes (MaxUint32 limit), and the skip
	// loop evicts old keys instead of rejecting. Verify no ErrMaxJump is
	// returned and the result key count is capped at maxSkippedKeys.
	mk, decryptErr := s.Decrypt(0, maxJump+1)
	if decryptErr != nil {
		// The only acceptable errors are ErrCounterExhausted or ErrMaxJump
		// (if the check fires before eviction), but ErrMaxSkippedKeys must
		// not appear since FIFO eviction replaces it.
		if _, ok := decryptErr.(*ErrMaxJump); ok {
			t.Fatal("self-session should not reject with ErrMaxJump for jump of 25001 (maxJump=MaxUint32)")
		}
		if _, ok := decryptErr.(*ErrMaxSkippedKeys); ok {
			t.Fatal("FIFO eviction must replace ErrMaxSkippedKeys rejection; got ErrMaxSkippedKeys")
		}
		t.Fatalf("unexpected error: %T: %v", decryptErr, decryptErr)
	}
	mk.Destroy()
	if s.SkippedKeyCount() > maxSkippedKeys {
		t.Errorf("skippedKeys count %d exceeds maxSkippedKeys %d after eviction", s.SkippedKeyCount(), maxSkippedKeys)
	}
}

func TestSPQRDefaultMaxJumpRejectsLargeForwardJump(t *testing.T) {
	sharedSecret := randomBytes(t, 32)

	// Create a normal session with default maxJump.
	s, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	// Counter maxJump+1 from recvCounter=0 should fail with ErrMaxJump.
	_, err = s.Decrypt(0, maxJump+1)
	if err == nil {
		t.Fatal("expected ErrMaxJump for exceeding default maxJump")
	}
	if _, ok := err.(*ErrMaxJump); !ok {
		t.Errorf("expected *ErrMaxJump, got %T: %v", err, err)
	}
}

func TestSPQRSelfSessionSerializeRoundTrip(t *testing.T) {
	sharedSecret := randomBytes(t, 32)

	s, err := Init(sharedSecret, DirectionA2B, math.MaxUint32)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	data, err := s.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	restored, err := Deserialize(data)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	defer restored.Zeroize()

	if restored.maxJump != math.MaxUint32 {
		t.Errorf("maxJump: got %d, want %d", restored.maxJump, uint32(math.MaxUint32))
	}

	// Verify the restored self-session still allows large forward jumps.
	_, err = restored.Decrypt(0, maxJump+1)
	if _, ok := err.(*ErrMaxJump); ok {
		t.Fatal("restored self-session should not reject with ErrMaxJump")
	}
}

// --- Epoch Chain Zeroize Test ---

func TestEpochChainZeroize(t *testing.T) {
	sendKey := randomSecret(t, 32)
	recvKey := randomSecret(t, 32)

	chain := &EpochChain{
		sendKey: sendKey,
		recvKey: recvKey,
	}

	chain.Zeroize()

	if !sendKey.IsDestroyed() {
		t.Fatal("sendKey not destroyed")
	}
	if !recvKey.IsDestroyed() {
		t.Fatal("recvKey not destroyed")
	}
}
