package spqr

import (
	"bytes"
	"math"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret/secrettest"
)

// TestSPQRZeroizeWithSkippedKeys exercises the Zeroize path that clears
// skipped message keys.
func TestSPQRZeroizeWithSkippedKeys(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	sharedCopy := make([]byte, 32)
	copy(sharedCopy, sharedSecret)

	alice, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init alice: %v", err)
	}
	bob, err := Init(sharedCopy, DirectionB2A, maxJump)
	if err != nil {
		t.Fatalf("Init bob: %v", err)
	}

	// Alice sends 3 messages.
	for i := 0; i < 3; i++ {
		mk, _, encErr := alice.Encrypt(0)
		if encErr != nil {
			t.Fatalf("Encrypt %d: %v", i, encErr)
		}
		mk.Destroy()
	}

	// Bob skips to message 3 (1-based counter), creating skipped keys for 1 and 2.
	mk, err := bob.Decrypt(0, 3)
	if err != nil {
		t.Fatalf("Decrypt(0, 3): %v", err)
	}
	mk.Destroy()

	if bob.SkippedKeyCount() != 2 {
		t.Fatalf("expected 2 skipped keys, got %d", bob.SkippedKeyCount())
	}

	// Capture references to skipped key secrets before zeroization.
	var skippedSecrets []*secret.Secret
	for _, sk := range bob.skippedKeys {
		skippedSecrets = append(skippedSecrets, sk)
	}

	bob.Zeroize()

	// Verify skipped keys were destroyed and removed.
	if bob.SkippedKeyCount() != 0 {
		t.Errorf("expected 0 skipped keys after Zeroize, got %d", bob.SkippedKeyCount())
	}
	for i, sk := range skippedSecrets {
		if !sk.IsDestroyed() {
			t.Errorf("skipped key %d was not destroyed", i)
		}
	}

	alice.Zeroize()
}

// TestSPQRReceiveKeyB2ADirection exercises the B2A direction swap branch
// in ReceiveKey.
func TestSPQRReceiveKeyB2ADirection(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	sharedCopy := make([]byte, 32)
	copy(sharedCopy, sharedSecret)
	sckaOutput := randomBytes(t, 32)

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

	if err := a.ReceiveKey(sckaOutput, 1); err != nil {
		t.Fatalf("A ReceiveKey: %v", err)
	}
	if err := b.ReceiveKey(sckaOutput, 1); err != nil {
		t.Fatalf("B ReceiveKey: %v", err)
	}

	// Verify A's send key in epoch 1 equals B's recv key.
	if !bytes.Equal(secrettest.Bytes(a.chains[1].sendKey), secrettest.Bytes(b.chains[1].recvKey)) {
		t.Error("A's sendKey should equal B's recvKey after ReceiveKey")
	}
	if !bytes.Equal(secrettest.Bytes(a.chains[1].recvKey), secrettest.Bytes(b.chains[1].sendKey)) {
		t.Error("A's recvKey should equal B's sendKey after ReceiveKey")
	}

	// Verify encrypt/decrypt works across direction after epoch advance.
	mk, counter, err := a.Encrypt(1)
	if err != nil {
		t.Fatalf("A Encrypt epoch 1: %v", err)
	}
	mkd, err := b.Decrypt(1, counter)
	if err != nil {
		t.Fatalf("B Decrypt epoch 1: %v", err)
	}
	if !bytes.Equal(secrettest.Bytes(mk), secrettest.Bytes(mkd)) {
		t.Error("message key mismatch after ReceiveKey in both directions")
	}
	mk.Destroy()
	mkd.Destroy()
}

// TestSPQRDecryptSkippedKeyRetrieval exercises the skipped key retrieval
// path to ensure the transfer-ownership logic works correctly.
func TestSPQRDecryptSkippedKeyRetrieval(t *testing.T) {
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

	// Alice sends 3 messages.
	mks := make([]*secret.Secret, 3)
	for i := 0; i < 3; i++ {
		mk, _, encErr := alice.Encrypt(0)
		if encErr != nil {
			t.Fatalf("Encrypt %d: %v", i, encErr)
		}
		mks[i] = mk
	}

	// Bob decrypts message 3 first (1-based counter), skipping 1 and 2.
	mkd2, err := bob.Decrypt(0, 3)
	if err != nil {
		t.Fatalf("Decrypt counter 3: %v", err)
	}
	if !bytes.Equal(secrettest.Bytes(mks[2]), secrettest.Bytes(mkd2)) {
		t.Error("message 3 key mismatch")
	}
	mkd2.Destroy()

	// Retrieve skipped key for counter 2.
	mkd1, err := bob.Decrypt(0, 2)
	if err != nil {
		t.Fatalf("Decrypt skipped counter 2: %v", err)
	}
	if !bytes.Equal(secrettest.Bytes(mks[1]), secrettest.Bytes(mkd1)) {
		t.Error("skipped message 2 key mismatch")
	}
	mkd1.Destroy()

	// The skipped key should be removed after retrieval.
	if bob.SkippedKeyCount() != 1 {
		t.Errorf("expected 1 skipped key remaining, got %d", bob.SkippedKeyCount())
	}

	// Retrieve skipped key for counter 1.
	mkd0, err := bob.Decrypt(0, 1)
	if err != nil {
		t.Fatalf("Decrypt skipped counter 1: %v", err)
	}
	if !bytes.Equal(secrettest.Bytes(mks[0]), secrettest.Bytes(mkd0)) {
		t.Error("skipped message 1 key mismatch")
	}
	mkd0.Destroy()

	if bob.SkippedKeyCount() != 0 {
		t.Errorf("expected 0 skipped keys, got %d", bob.SkippedKeyCount())
	}

	for _, mk := range mks {
		mk.Destroy()
	}
}

// TestSPQRClearOldEpochsRetainsCurrentAndPrevious verifies that clearOldEpochs
// correctly retains only current and immediately previous epoch chains.
func TestSPQRClearOldEpochsRetainsCurrentAndPrevious(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	s, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	// Advance epochs 1 through 5.
	for i := uint64(1); i <= 5; i++ {
		if err := s.ReceiveKey(randomBytes(t, 32), i); err != nil {
			t.Fatalf("ReceiveKey epoch %d: %v", i, err)
		}
	}

	// Advance sendEpoch to 5 so keepFrom = min(5, 5) - 1 = 4.
	_, _, err = s.Encrypt(5)
	if err != nil {
		t.Fatalf("Encrypt(5): %v", err)
	}
	s.clearOldEpochs()

	// Only epochs 4 and 5 should remain.
	if len(s.chains) != 2 {
		t.Errorf("chains count = %d, want 2", len(s.chains))
	}
	if _, ok := s.chains[4]; !ok {
		t.Error("epoch 4 should be retained")
	}
	if _, ok := s.chains[5]; !ok {
		t.Error("epoch 5 should be retained")
	}
}

// TestSPQREncryptDecryptMultipleInSameEpoch verifies the counter increments
// correctly within a single epoch.
func TestSPQREncryptDecryptMultipleInSameEpoch(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	alice, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init alice: %v", err)
	}
	defer alice.Zeroize()

	for i := uint32(1); i <= 10; i++ {
		mk, counter, encErr := alice.Encrypt(0)
		if encErr != nil {
			t.Fatalf("Encrypt %d: %v", i, encErr)
		}
		if counter != i {
			t.Errorf("counter = %d, want %d", counter, i)
		}
		mk.Destroy()
	}
}

// TestKdfSckaRKEmptySckaOutput exercises the empty sckaOutput validation in KdfSckaRK.
func TestKdfSckaRKEmptySckaOutput(t *testing.T) {
	rk := randomSecret(t, 32)
	defer rk.Destroy()

	_, _, _, err := KdfSckaRK(rk, []byte{})
	if err == nil {
		t.Fatal("expected error for empty sckaOutput")
	}
	if e, ok := err.(*ErrInvalidInput); !ok || e.Field != "sckaOutput" {
		t.Errorf("expected ErrInvalidInput for sckaOutput, got %v", err)
	}
}

// TestKdfSckaRKEmptyRK exercises the nil/destroyed rk validation in KdfSckaRK.
func TestKdfSckaRKEmptyRK(t *testing.T) {
	_, _, _, err := KdfSckaRK(nil, randomBytes(t, 32))
	if err == nil {
		t.Fatal("expected error for nil rk")
	}
	if e, ok := err.(*ErrInvalidInput); !ok || e.Field != "rk" {
		t.Errorf("expected ErrInvalidInput for rk, got %v", err)
	}

	// Also test with a destroyed secret.
	rk := randomSecret(t, 32)
	rk.Destroy()
	_, _, _, err = KdfSckaRK(rk, randomBytes(t, 32))
	if err == nil {
		t.Fatal("expected error for destroyed rk")
	}
	if e, ok := err.(*ErrInvalidInput); !ok || e.Field != "rk" {
		t.Errorf("expected ErrInvalidInput for rk, got %v", err)
	}
}

// TestKdfSckaCKEmptyCK exercises the nil/destroyed ck validation in KdfSckaCK.
func TestKdfSckaCKEmptyCK(t *testing.T) {
	_, _, err := KdfSckaCK(nil, 0)
	if err == nil {
		t.Fatal("expected error for nil ck")
	}
	if e, ok := err.(*ErrInvalidInput); !ok || e.Field != "ck" {
		t.Errorf("expected ErrInvalidInput for ck, got %v", err)
	}

	ck := randomSecret(t, 32)
	ck.Destroy()
	_, _, err = KdfSckaCK(ck, 0)
	if err == nil {
		t.Fatal("expected error for destroyed ck")
	}
}

// TestKdfSckaInitEmptySharedSecret exercises the empty sharedSecret validation.
func TestKdfSckaInitEmptySharedSecret(t *testing.T) {
	_, _, _, err := KdfSckaInit([]byte{})
	if err == nil {
		t.Fatal("expected error for empty sharedSecret")
	}
	if e, ok := err.(*ErrInvalidInput); !ok || e.Field != "sharedSecret" {
		t.Errorf("expected ErrInvalidInput for sharedSecret, got %v", err)
	}
}

// TestKdfSckaRKSuccessfulDerivation verifies successful 3-key derivation.
func TestKdfSckaRKSuccessfulDerivation(t *testing.T) {
	rk := randomSecret(t, 32)
	defer rk.Destroy()
	sckaOutput := randomBytes(t, 32)

	newRK, newCKs, newCKr, err := KdfSckaRK(rk, sckaOutput)
	if err != nil {
		t.Fatalf("KdfSckaRK: %v", err)
	}
	defer newRK.Destroy()
	defer newCKs.Destroy()
	defer newCKr.Destroy()

	if newRK.Size() != 32 {
		t.Errorf("newRK size = %d, want 32", newRK.Size())
	}
	if newCKs.Size() != 32 {
		t.Errorf("newCKs size = %d, want 32", newCKs.Size())
	}
	if newCKr.Size() != 32 {
		t.Errorf("newCKr size = %d, want 32", newCKr.Size())
	}

	// All three derived keys should be distinct.
	if bytes.Equal(secrettest.Bytes(newRK), secrettest.Bytes(newCKs)) {
		t.Error("newRK and newCKs should differ")
	}
	if bytes.Equal(secrettest.Bytes(newRK), secrettest.Bytes(newCKr)) {
		t.Error("newRK and newCKr should differ")
	}
}

// TestKdfSckaCKSuccessfulDerivation verifies successful MK/CK derivation.
func TestKdfSckaCKSuccessfulDerivation(t *testing.T) {
	ck := randomSecret(t, 32)
	defer ck.Destroy()

	mk, nextCK, err := KdfSckaCK(ck, 42)
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
	if bytes.Equal(secrettest.Bytes(mk), secrettest.Bytes(nextCK)) {
		t.Error("mk and nextCK should differ")
	}
}

// TestKdfSckaCKDifferentCounters produces different keys for different counters.
func TestKdfSckaCKDifferentCounters(t *testing.T) {
	ckBytes := randomBytes(t, 32)

	ck1, err := secret.New(append([]byte(nil), ckBytes...))
	if err != nil {
		t.Fatalf("secret.New: %v", err)
	}
	defer ck1.Destroy()

	ck2, err := secret.New(append([]byte(nil), ckBytes...))
	if err != nil {
		t.Fatalf("secret.New: %v", err)
	}
	defer ck2.Destroy()

	mk1, next1, err := KdfSckaCK(ck1, 0)
	if err != nil {
		t.Fatalf("KdfSckaCK(0): %v", err)
	}
	defer mk1.Destroy()
	defer next1.Destroy()

	mk2, next2, err := KdfSckaCK(ck2, 1)
	if err != nil {
		t.Fatalf("KdfSckaCK(1): %v", err)
	}
	defer mk2.Destroy()
	defer next2.Destroy()

	if bytes.Equal(secrettest.Bytes(mk1), secrettest.Bytes(mk2)) {
		t.Error("different counters should produce different message keys")
	}
}

// TestDecryptAtMaxCounter verifies that Decrypt with recvCounter = MaxUint32
// and a lower counter request returns ErrKeyTrimmed (the counter is too old).
// This also validates the boundary behavior of the trim check.
func TestDecryptAtMaxCounter(t *testing.T) {
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

	// With recvCounter = MaxUint32 and counter = 1, counter < recvCounter, and
	// counter+maxSkippedKeys < recvCounter (1+2000 << MaxUint32), so ErrKeyTrimmed.
	s := &SPQR{
		chains: map[uint64]*EpochChain{
			0: {recvKey: ck, recvCounter: math.MaxUint32},
		},
		skippedKeys: make(map[SkippedKeyID]*secret.Secret),
		direction:   DirectionA2B,
		maxJump:     math.MaxUint32, // allow large jump
		negotiation: negotiationResolved,
		version:     VersionV1,
		minVersion:  VersionV0,
		rootKey:     rk,
	}
	defer s.Zeroize()

	_, err = s.Decrypt(0, 1)
	if err == nil {
		t.Fatal("expected error for counter far behind recvCounter=MaxUint32")
	}
	if _, ok := err.(*ErrKeyTrimmed); !ok {
		t.Errorf("expected *ErrKeyTrimmed, got %T: %v", err, err)
	}
}
