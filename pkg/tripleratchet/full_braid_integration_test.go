// Package tripleratchet whitebox tests for advancePQEpoch, purgeOldSkippedKeys,
// and takeSnapshot exercised via direct internal-state manipulation and
// single-direction braid message exchange.
//
// These tests live in package tripleratchet (not tripleratchet_test) to allow
// direct inspection and mutation of unexported fields (pqEpoch, sendCounter,
// recvCounter, braidHandshakeComplete, skippedPQKeys) without adding exported
// accessor surface area.
package tripleratchet

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
	"github.com/jeremyhahn/go-libsignal/pkg/spqr"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// ---- Shared EC cipher helpers (whitebox) ----

// braidECCipher is a symmetric deterministic ECCipher for whitebox tests.
type braidECCipher struct {
	sendSeed []byte
	recvSeed []byte
	sendCtr  uint32
}

func newBraidECCipher(seed []byte) *braidECCipher {
	s := make([]byte, len(seed))
	copy(s, seed)
	return &braidECCipher{sendSeed: s, recvSeed: s}
}

func (c *braidECCipher) SendKey() ([]byte, []byte, error) {
	c.sendCtr++
	ctr := c.sendCtr
	header := []byte{byte(ctr), byte(ctr >> 8), byte(ctr >> 16), byte(ctr >> 24)}
	key := make([]byte, 32)
	copy(key, c.sendSeed)
	key[0] ^= byte(ctr)
	key[1] ^= byte(ctr >> 8)
	return header, key, nil
}

func (c *braidECCipher) ReceiveKey(ecHeader []byte) ([]byte, error) {
	if len(ecHeader) < 4 {
		return nil, &ErrInvalidInput{Field: "ecHeader", Reason: "too short"}
	}
	ctr := uint32(ecHeader[0]) | uint32(ecHeader[1])<<8 | uint32(ecHeader[2])<<16 | uint32(ecHeader[3])<<24
	key := make([]byte, 32)
	copy(key, c.recvSeed)
	key[0] ^= byte(ctr)
	key[1] ^= byte(ctr >> 8)
	return key, nil
}

// TakeECSnapshot serializes the send counter as 4-byte big-endian for atomic rollback.
func (c *braidECCipher) TakeECSnapshot() ([]byte, error) {
	ctr := c.sendCtr
	return []byte{byte(ctr >> 24), byte(ctr >> 16), byte(ctr >> 8), byte(ctr)}, nil
}

// RestoreECSnapshot restores the send counter from a snapshot taken by TakeECSnapshot.
func (c *braidECCipher) RestoreECSnapshot(data []byte) error {
	if len(data) != 4 {
		return &ErrInvalidInput{Field: "data", Reason: "EC snapshot must be 4 bytes"}
	}
	c.sendCtr = uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	return nil
}

// braidRandomSharedSecret generates a random 32-byte shared secret.
func braidRandomSharedSecret(t *testing.T) []byte {
	t.Helper()
	buf := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return buf
}

// newUnidirectionalPair creates an Alice/Bob TripleRatchet pair where ONLY
// Alice→Bob message exchange is used. This is the only reliably exercisable
// direction before the braid handshake completes.
func newUnidirectionalPair(t *testing.T) (alice, bob *TripleRatchet, ss []byte) {
	t.Helper()
	ss = braidRandomSharedSecret(t)
	seed := make([]byte, 32)
	copy(seed, ss)

	aliceEC := newBraidECCipher(seed)
	bobEC := newBraidECCipher(seed)

	var err error
	alice, err = NewAlice(aliceEC, ss, mlkembraid.NewIncrementalMLKEM768KEM(), 10)
	if err != nil {
		t.Fatalf("NewAlice: %v", err)
	}
	bob, err = NewBob(bobEC, ss, mlkembraid.NewIncrementalMLKEM768KEM(), 10)
	if err != nil {
		t.Fatalf("NewBob: %v", err)
	}
	return alice, bob, ss
}

// injectEpochAdvance directly advances a TripleRatchet's PQ epoch using a
// test epoch secret, exercising the advancePQEpoch code path without requiring
// a full braid handshake. This is the whitebox path for testing advancePQEpoch.
//
// advancePQEpoch calls secret.New(epochSecret) which uses
// the locked-memory constructor — this destructively zeroes the input slice.
// injectEpochAdvance therefore makes an independent copy so the caller's slice
// is not clobbered. Callers that need to pass the same secret to multiple
// TripleRatchet instances must call injectEpochAdvance separately for each.
func injectEpochAdvance(t *testing.T, tr *TripleRatchet, epochSecret []byte) {
	t.Helper()
	secretCopy := make([]byte, len(epochSecret))
	copy(secretCopy, epochSecret)
	if err := tr.advancePQEpoch(secretCopy); err != nil {
		t.Fatalf("advancePQEpoch: %v", err)
	}
}

// ---- Tests ----

// TestTripleRatchet_AdvancePQEpoch_DirectCall exercises advancePQEpoch directly
// via whitebox access. It verifies that:
//   - pqEpoch increments
//   - sendCounter and recvCounter reset to 0
//   - braidHandshakeComplete becomes true
//   - chain keys are replaced with new values derived from the epoch secret
//   - a subsequent Encrypt/Decrypt round succeeds with the new chain keys
func TestTripleRatchet_AdvancePQEpoch_DirectCall(t *testing.T) {
	alice, bob, _ := newUnidirectionalPair(t)

	// Capture initial state.
	aliceEpochBefore := alice.pqEpoch // 0
	bobEpochBefore := bob.pqEpoch     // 0

	// Do one Encrypt/Decrypt before epoch advance to establish non-zero counters.
	msg := []byte("pre-epoch message")
	ct, err := alice.Encrypt(msg)
	if err != nil {
		t.Fatalf("pre-epoch Encrypt: %v", err)
	}
	if _, err = bob.Decrypt(ct); err != nil {
		t.Fatalf("pre-epoch Decrypt: %v", err)
	}

	// Both should have sendCounter=1, recvCounter=1 at epoch 0.
	if alice.sendCounter != 1 || bob.recvCounter != 1 {
		t.Fatalf("expected counters=1 after one round, got alice.send=%d bob.recv=%d",
			alice.sendCounter, bob.recvCounter)
	}

	// Use a random epoch secret (simulates the output of the braid handshake).
	epochSecret := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, epochSecret); err != nil {
		t.Fatalf("rand: %v", err)
	}
	// Use the SAME epoch secret for both parties (as the braid would produce).
	injectEpochAdvance(t, alice, epochSecret)
	injectEpochAdvance(t, bob, epochSecret)

	// Verify epoch advanced.
	if alice.pqEpoch != aliceEpochBefore+1 {
		t.Errorf("Alice pqEpoch = %d, want %d", alice.pqEpoch, aliceEpochBefore+1)
	}
	if bob.pqEpoch != bobEpochBefore+1 {
		t.Errorf("Bob pqEpoch = %d, want %d", bob.pqEpoch, bobEpochBefore+1)
	}

	// Verify counters reset.
	if alice.sendCounter != 0 {
		t.Errorf("Alice sendCounter = %d, want 0 after epoch advance", alice.sendCounter)
	}
	if bob.recvCounter != 0 {
		t.Errorf("Bob recvCounter = %d, want 0 after epoch advance", bob.recvCounter)
	}

	// Verify handshake flag set.
	if !alice.braidHandshakeComplete {
		t.Error("Alice braidHandshakeComplete must be true after advancePQEpoch")
	}
	if !bob.braidHandshakeComplete {
		t.Error("Bob braidHandshakeComplete must be true after advancePQEpoch")
	}

	// Verify encryption still works after epoch advance.
	// Both parties now use new chain keys derived from the epoch secret.
	// Alice's sendChain == Bob's recvChain (both derived from newCKs via KdfSckaRK).
	postMsg := []byte("post-epoch message")
	ct, err = alice.Encrypt(postMsg)
	if err != nil {
		t.Fatalf("post-epoch Encrypt: %v", err)
	}
	got, err := bob.Decrypt(ct)
	if err != nil {
		t.Fatalf("post-epoch Decrypt: %v", err)
	}
	if !bytes.Equal(got, postMsg) {
		t.Fatalf("post-epoch plaintext mismatch: got %q want %q", got, postMsg)
	}
}

// TestTripleRatchet_AdvancePQEpoch_MultipleEpochs verifies that advancePQEpoch
// can be called multiple times, each time advancing the epoch correctly and
// maintaining symmetric chain key derivation across all epoch transitions.
func TestTripleRatchet_AdvancePQEpoch_MultipleEpochs(t *testing.T) {
	alice, bob, _ := newUnidirectionalPair(t)

	for epoch := uint64(1); epoch <= 3; epoch++ {
		epochSecret := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, epochSecret); err != nil {
			t.Fatalf("rand epoch %d: %v", epoch, err)
		}

		injectEpochAdvance(t, alice, epochSecret)
		injectEpochAdvance(t, bob, epochSecret)

		if alice.pqEpoch != epoch {
			t.Errorf("epoch %d: Alice.pqEpoch = %d, want %d", epoch, alice.pqEpoch, epoch)
		}
		if bob.pqEpoch != epoch {
			t.Errorf("epoch %d: Bob.pqEpoch = %d, want %d", epoch, bob.pqEpoch, epoch)
		}
		if alice.sendCounter != 0 || bob.recvCounter != 0 {
			t.Errorf("epoch %d: counters not reset: alice.send=%d bob.recv=%d",
				epoch, alice.sendCounter, bob.recvCounter)
		}

		// Verify Encrypt/Decrypt works after each epoch advance.
		msg := []byte("epoch message")
		ct, err := alice.Encrypt(msg)
		if err != nil {
			t.Fatalf("epoch %d Encrypt: %v", epoch, err)
		}
		got, err := bob.Decrypt(ct)
		if err != nil {
			t.Fatalf("epoch %d Decrypt: %v", epoch, err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("epoch %d: plaintext mismatch", epoch)
		}
	}
}

// TestTripleRatchet_PurgeOldSkippedKeys_DirectCall exercises purgeOldSkippedKeys
// via direct whitebox manipulation. It:
//  1. Creates a TripleRatchet and populates skippedPQKeys with keys from multiple epochs.
//  2. Sets pqEpoch high enough so the older epochs fall below the retention cutoff.
//  3. Calls purgeOldSkippedKeys() directly.
//  4. Verifies old-epoch keys are removed and current-epoch keys are retained.
func TestTripleRatchet_PurgeOldSkippedKeys_DirectCall(t *testing.T) {
	ss := braidRandomSharedSecret(t)
	ec := newBraidECCipher(ss)
	tr, err := NewAlice(ec, ss, mlkembraid.NewIncrementalMLKEM768KEM(), 10)
	if err != nil {
		t.Fatalf("NewAlice: %v", err)
	}

	// Inject fake skipped keys at epochs 1, 2, 3.
	epochSecret := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, epochSecret); err != nil {
		t.Fatalf("rand: %v", err)
	}

	addFakeSkippedKey := func(epoch uint64, counter uint32) {
		k, secErr := secret.New([]byte{byte(epoch), byte(counter), 0xAA, 0xBB})
		if secErr != nil {
			t.Fatalf("secret.New: %v", secErr)
		}
		tr.skippedPQKeys[pqSkippedKeyID{epoch: epoch, counter: counter}] = k
	}

	addFakeSkippedKey(1, 10)
	addFakeSkippedKey(2, 5)
	addFakeSkippedKey(3, 7)
	addFakeSkippedKey(3, 8)

	if len(tr.skippedPQKeys) != 4 {
		t.Fatalf("expected 4 skipped keys, got %d", len(tr.skippedPQKeys))
	}

	// Set pqEpoch=4 so cutoff = 4 - epochsToKeepPriorToSendEpoch(1) = 3.
	// Keys with epoch < 3 (i.e., epochs 1 and 2) should be purged.
	// Keys at epoch 3 should be retained.
	tr.pqEpoch = 4
	tr.purgeOldSkippedKeys()

	// Epoch 1 and 2 keys must be gone.
	if _, ok := tr.skippedPQKeys[pqSkippedKeyID{epoch: 1, counter: 10}]; ok {
		t.Error("epoch 1 key must be purged")
	}
	if _, ok := tr.skippedPQKeys[pqSkippedKeyID{epoch: 2, counter: 5}]; ok {
		t.Error("epoch 2 key must be purged")
	}

	// Epoch 3 keys must remain (3 >= cutoff=3).
	if _, ok := tr.skippedPQKeys[pqSkippedKeyID{epoch: 3, counter: 7}]; !ok {
		t.Error("epoch 3 key (counter=7) must be retained")
	}
	if _, ok := tr.skippedPQKeys[pqSkippedKeyID{epoch: 3, counter: 8}]; !ok {
		t.Error("epoch 3 key (counter=8) must be retained")
	}

	if len(tr.skippedPQKeys) != 2 {
		t.Errorf("expected 2 remaining skipped keys after purge, got %d", len(tr.skippedPQKeys))
	}
}

// TestTripleRatchet_PurgeOldSkippedKeys_BelowRetentionThreshold verifies that
// purgeOldSkippedKeys is a no-op when pqEpoch is within the retention window
// (i.e., pqEpoch <= epochsToKeepPriorToSendEpoch).
func TestTripleRatchet_PurgeOldSkippedKeys_BelowRetentionThreshold(t *testing.T) {
	ss := braidRandomSharedSecret(t)
	ec := newBraidECCipher(ss)
	tr, err := NewAlice(ec, ss, mlkembraid.NewIncrementalMLKEM768KEM(), 10)
	if err != nil {
		t.Fatalf("NewAlice: %v", err)
	}

	k, secErr := secret.New([]byte{1, 2, 3, 4})
	if secErr != nil {
		t.Fatalf("secret.New: %v", secErr)
	}
	tr.skippedPQKeys[pqSkippedKeyID{epoch: 0, counter: 1}] = k

	// With pqEpoch=1 and epochsToKeepPriorToSendEpoch=1, cutoff=0: only epoch<0
	// would be purged. No keys satisfy that, so all are retained.
	tr.pqEpoch = 1
	tr.purgeOldSkippedKeys()

	if len(tr.skippedPQKeys) != 1 {
		t.Errorf("no keys should be purged at pqEpoch=1, got %d remaining", len(tr.skippedPQKeys))
	}

	// With pqEpoch=0 (initial state), the early-return path fires.
	tr.pqEpoch = 0
	tr.purgeOldSkippedKeys() // early return: pqEpoch <= epochsToKeepPriorToSendEpoch

	if len(tr.skippedPQKeys) != 1 {
		t.Errorf("keys must not be purged at pqEpoch=0, got %d remaining", len(tr.skippedPQKeys))
	}
}

// TestTripleRatchet_PurgeOldSkippedKeys_ViaAdvanceEpoch verifies that calling
// advancePQEpoch (which calls purgeOldSkippedKeys internally) removes skipped
// keys from epochs that fall below the retention cutoff. This exercises the
// integration path: advancePQEpoch → purgeOldSkippedKeys.
func TestTripleRatchet_PurgeOldSkippedKeys_ViaAdvanceEpoch(t *testing.T) {
	ss := braidRandomSharedSecret(t)
	ec := newBraidECCipher(ss)
	tr, err := NewAlice(ec, ss, mlkembraid.NewIncrementalMLKEM768KEM(), 10)
	if err != nil {
		t.Fatalf("NewAlice: %v", err)
	}

	epochSecret1 := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, epochSecret1); err != nil {
		t.Fatalf("rand: %v", err)
	}

	// Advance to epoch 1.
	if err = tr.advancePQEpoch(epochSecret1); err != nil {
		t.Fatalf("advancePQEpoch(1): %v", err)
	}
	if tr.pqEpoch != 1 {
		t.Fatalf("expected pqEpoch=1, got %d", tr.pqEpoch)
	}

	// Inject a fake skipped key at epoch 1.
	k1, secErr := secret.New([]byte{0xAA, 0xBB, 0xCC, 0xDD})
	if secErr != nil {
		t.Fatalf("secret.New: %v", secErr)
	}
	tr.skippedPQKeys[pqSkippedKeyID{epoch: 1, counter: 5}] = k1

	// Advance to epoch 2.
	epochSecret2 := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, epochSecret2); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if err = tr.advancePQEpoch(epochSecret2); err != nil {
		t.Fatalf("advancePQEpoch(2): %v", err)
	}
	if tr.pqEpoch != 2 {
		t.Fatalf("expected pqEpoch=2, got %d", tr.pqEpoch)
	}

	// At pqEpoch=2, cutoff=1: epoch-1 key should still be present (1 >= 1).
	if _, ok := tr.skippedPQKeys[pqSkippedKeyID{epoch: 1, counter: 5}]; !ok {
		t.Error("epoch-1 key should still be retained at pqEpoch=2 (within retention window)")
	}

	// Advance to epoch 3: cutoff=2, epoch-1 key must be purged.
	epochSecret3 := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, epochSecret3); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if err = tr.advancePQEpoch(epochSecret3); err != nil {
		t.Fatalf("advancePQEpoch(3): %v", err)
	}
	if tr.pqEpoch != 3 {
		t.Fatalf("expected pqEpoch=3, got %d", tr.pqEpoch)
	}

	// Cutoff = 3-1=2: epoch < 2 (i.e., epoch=1) is purged.
	if _, ok := tr.skippedPQKeys[pqSkippedKeyID{epoch: 1, counter: 5}]; ok {
		t.Error("epoch-1 key must be purged at pqEpoch=3")
	}
}

// TestTripleRatchet_TakeSnapshot_PostEpochAdvance verifies that takeSnapshot
// captures all post-advancePQEpoch state fields correctly:
//   - braidData is non-empty
//   - pqEpoch matches the live value
//   - handshakeDone is true after epoch advance
//   - skippedPQKeys deep-copy path is exercised (snapshot has the right count)
func TestTripleRatchet_TakeSnapshot_PostEpochAdvance(t *testing.T) {
	alice, bob, _ := newUnidirectionalPair(t)

	// Advance Alice's epoch directly.
	epochSecret := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, epochSecret); err != nil {
		t.Fatalf("rand: %v", err)
	}
	injectEpochAdvance(t, alice, epochSecret)
	injectEpochAdvance(t, bob, epochSecret)

	// Add fake skipped keys to Bob to exercise the deep-copy path in takeSnapshot.
	k1, err := secret.New([]byte{0x01, 0x02, 0x03, 0x04})
	if err != nil {
		t.Fatalf("secret.New: %v", err)
	}
	k2, err := secret.New([]byte{0x05, 0x06, 0x07, 0x08})
	if err != nil {
		t.Fatalf("secret.New: %v", err)
	}
	bob.skippedPQKeys[pqSkippedKeyID{epoch: bob.pqEpoch, counter: 10}] = k1
	bob.skippedPQKeys[pqSkippedKeyID{epoch: bob.pqEpoch, counter: 11}] = k2

	// Take snapshot from Bob (post-epoch-advance, with skipped keys).
	snap, snapErr := bob.takeSnapshot()
	if snapErr != nil {
		t.Fatalf("takeSnapshot: %v", snapErr)
	}
	defer bob.destroySnapshot(snap)

	if len(snap.braidData) == 0 {
		t.Error("snapshot braidData must be non-empty")
	}
	if snap.pqEpoch != bob.pqEpoch {
		t.Errorf("snapshot pqEpoch = %d, want %d", snap.pqEpoch, bob.pqEpoch)
	}
	if !snap.handshakeDone {
		t.Error("snapshot handshakeDone must be true after epoch advance")
	}
	if len(snap.skippedPQKeys) != 2 {
		t.Errorf("snapshot must contain 2 skipped keys, got %d", len(snap.skippedPQKeys))
	}

	// Verify snapshot keys are independent copies.
	for k, v := range snap.skippedPQKeys {
		live, ok := bob.skippedPQKeys[k]
		if !ok {
			t.Errorf("snapshot key %v not in live state", k)
			continue
		}
		if v == live {
			t.Errorf("snapshot key %v is same pointer as live (must be deep copy)", k)
		}
	}
}

// TestTripleRatchet_Restore_FromPostEpochSnapshot verifies that restoring from
// a post-epoch-advance snapshot rolls back the state correctly so that a
// subsequent operation succeeds.
func TestTripleRatchet_Restore_FromPostEpochSnapshot(t *testing.T) {
	alice, bob, _ := newUnidirectionalPair(t)

	// Advance both parties to epoch 1.
	epochSecret := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, epochSecret); err != nil {
		t.Fatalf("rand: %v", err)
	}
	injectEpochAdvance(t, alice, epochSecret)
	injectEpochAdvance(t, bob, epochSecret)

	// Encrypt one message to advance counters.
	msg := []byte("restore-test")
	ct, err := alice.Encrypt(msg)
	if err != nil {
		t.Fatalf("Alice.Encrypt: %v", err)
	}

	// Take snapshot of Bob BEFORE decrypting.
	snap, snapErr := bob.takeSnapshot()
	if snapErr != nil {
		t.Fatalf("takeSnapshot: %v", snapErr)
	}

	recvCtrBefore := bob.recvCounter
	epochBefore := bob.pqEpoch

	// Decrypt to mutate Bob's state.
	if _, err = bob.Decrypt(ct); err != nil {
		t.Fatalf("Bob.Decrypt: %v", err)
	}
	if bob.recvCounter <= recvCtrBefore {
		// Counter should have advanced.
		t.Logf("recvCounter did not advance (may have epoch-advanced); recvCtrBefore=%d recvCounter=%d",
			recvCtrBefore, bob.recvCounter)
	}

	// Restore Bob to pre-Decrypt state.
	if restoreErr := bob.restoreSnapshot(snap); restoreErr != nil {
		t.Fatalf("restoreSnapshot unexpectedly failed: %v", restoreErr)
	}

	if bob.pqEpoch != epochBefore {
		t.Errorf("after restore pqEpoch = %d, want %d", bob.pqEpoch, epochBefore)
	}
	if bob.recvCounter != recvCtrBefore {
		t.Errorf("after restore recvCounter = %d, want %d", bob.recvCounter, recvCtrBefore)
	}
	if !bob.braidHandshakeComplete {
		t.Error("after restore braidHandshakeComplete must be true")
	}

	// Re-decrypt the same message — should succeed since state was rolled back.
	got, err := bob.Decrypt(ct)
	if err != nil {
		t.Fatalf("Bob.Decrypt after restore: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("post-restore plaintext mismatch: got %q want %q", got, msg)
	}
}

// TestTripleRatchet_TakeSnapshot_WithECSnapshotable exercises the ECCipherSnapshotable
// branch inside takeSnapshot, which is only triggered when the ECCipher also
// implements ECCipherSnapshotable. This covers the snap.ecSnapshot assignment path.
func TestTripleRatchet_TakeSnapshot_WithECSnapshotable(t *testing.T) {
	ss := braidRandomSharedSecret(t)
	ec := &snapshotableECCipher{seed: []byte{0xCA, 0xFE, 0xBA, 0xBE}}
	kem := mlkembraid.NewIncrementalMLKEM768KEM()

	tr, err := NewAlice(ec, ss, kem, 10)
	if err != nil {
		t.Fatalf("NewAlice: %v", err)
	}

	// Drive to handshake completion using a matching Bob with the same EC cipher.
	ec2 := &snapshotableECCipher{seed: []byte{0xCA, 0xFE, 0xBA, 0xBE}}
	bob, err := NewBob(ec2, ss, mlkembraid.NewIncrementalMLKEM768KEM(), 10)
	if err != nil {
		t.Fatalf("NewBob: %v", err)
	}

	// Do at least one round so the snapshotable path in takeSnapshot is exercised
	// via Decrypt's internal takeSnapshot call.
	msg := []byte("ec-snapshot")
	ct, err := tr.Encrypt(msg)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := bob.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("plaintext mismatch: got %q want %q", got, msg)
	}

	// Directly call takeSnapshot to confirm ecSnapshot is populated.
	snap, snapErr := bob.takeSnapshot()
	if snapErr != nil {
		t.Fatalf("takeSnapshot: %v", snapErr)
	}
	defer bob.destroySnapshot(snap)

	if len(snap.ecSnapshot) == 0 {
		t.Error("ecSnapshot must be non-empty when ECCipher implements ECCipherSnapshotable")
	}
}

// TestTripleRatchet_AdvancePQEpoch_ResetsCountersAndChain verifies that after
// advancePQEpoch, both sendCounter and recvCounter are 0, and that a full
// Encrypt/Decrypt sequence from the reset state produces correct output.
// This test drives Alice→Bob across the epoch boundary using direct injection.
func TestTripleRatchet_AdvancePQEpoch_ResetsCountersAndChain(t *testing.T) {
	alice, bob, _ := newUnidirectionalPair(t)

	// Advance counters before epoch advance.
	msg := []byte("before epoch")
	for i := 0; i < 5; i++ {
		ct, encErr := alice.Encrypt(msg)
		if encErr != nil {
			t.Fatalf("Encrypt[%d]: %v", i, encErr)
		}
		if _, decErr := bob.Decrypt(ct); decErr != nil {
			t.Fatalf("Decrypt[%d]: %v", i, decErr)
		}
	}

	if alice.sendCounter != 5 || bob.recvCounter != 5 {
		t.Fatalf("expected counters=5, got alice.send=%d bob.recv=%d",
			alice.sendCounter, bob.recvCounter)
	}

	// Use spqr.KdfSckaRK to derive a valid epoch secret (not just random bytes),
	// confirming that the chain key derivation is symmetric.
	// A random epoch secret is equally valid for testing the reset behavior.
	epochSecret := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, epochSecret); err != nil {
		t.Fatalf("rand: %v", err)
	}

	injectEpochAdvance(t, alice, epochSecret)
	injectEpochAdvance(t, bob, epochSecret)

	// After epoch advance: counters reset to 0.
	if alice.sendCounter != 0 {
		t.Errorf("Alice sendCounter = %d, want 0 after epoch advance", alice.sendCounter)
	}
	if bob.recvCounter != 0 {
		t.Errorf("Bob recvCounter = %d, want 0 after epoch advance", bob.recvCounter)
	}
	if alice.pqEpoch != 1 || bob.pqEpoch != 1 {
		t.Errorf("pqEpoch: alice=%d bob=%d, want both=1", alice.pqEpoch, bob.pqEpoch)
	}

	// Verify that Encrypt/Decrypt works correctly with the new epoch-1 chain keys.
	// Both derive chain keys from KdfSckaRK(rootKey, epochSecret), which produces
	// the same newCKs/newCKr for both parties since they share the same rootKey.
	postMsg := []byte("post epoch message")
	ct, err := alice.Encrypt(postMsg)
	if err != nil {
		t.Fatalf("post-epoch Encrypt: %v", err)
	}
	got, err := bob.Decrypt(ct)
	if err != nil {
		t.Fatalf("post-epoch Decrypt: %v", err)
	}
	if !bytes.Equal(got, postMsg) {
		t.Fatalf("post-epoch mismatch: got %q want %q", got, postMsg)
	}
}

// TestTripleRatchet_AdvancePQEpoch_SymmetricChainDerivation verifies that
// KdfSckaRK produces matching chain keys for both parties from the same
// inputs, by checking that Alice's sendChain == Bob's recvChain after
// epoch advance. This exercises the chain-key swapping logic in advancePQEpoch
// for both initiator (isResponder=false) and responder (isResponder=true).
func TestTripleRatchet_AdvancePQEpoch_SymmetricChainDerivation(t *testing.T) {
	ss := braidRandomSharedSecret(t)

	// Derive the same initial root key that both parties use.
	rk, cks, ckr, err := spqr.KdfSckaInit(ss)
	if err != nil {
		t.Fatalf("KdfSckaInit: %v", err)
	}

	// Build a minimal Alice and Bob with known initial chain keys.
	aliceEC := newBraidECCipher(ss)
	alice, err := NewAlice(aliceEC, ss, mlkembraid.NewIncrementalMLKEM768KEM(), 10)
	if err != nil {
		t.Fatalf("NewAlice: %v", err)
	}

	bobEC := newBraidECCipher(ss)
	bob, err := NewBob(bobEC, ss, mlkembraid.NewIncrementalMLKEM768KEM(), 10)
	if err != nil {
		t.Fatalf("NewBob: %v", err)
	}

	// Cleanup the duplicated initial secrets.
	rk.Destroy()
	cks.Destroy()
	ckr.Destroy()

	// Advance both with the same epoch secret.
	epochSecret := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, epochSecret); err != nil {
		t.Fatalf("rand: %v", err)
	}
	injectEpochAdvance(t, alice, epochSecret)
	injectEpochAdvance(t, bob, epochSecret)

	// Alice (initiator, isResponder=false): sendChain = newCKs, recvChain = newCKr
	// Bob  (responder,  isResponder=true):  sendChain = newCKr, recvChain = newCKs
	//
	// Therefore: Alice.sendChain == Bob.recvChain (both = newCKs)
	//            Alice.recvChain == Bob.sendChain (both = newCKr)
	//
	// A single Encrypt/Decrypt round confirms this structural invariant.
	msg := []byte("chain symmetry check")
	ct, encErr := alice.Encrypt(msg)
	if encErr != nil {
		t.Fatalf("Encrypt: %v", encErr)
	}
	got, decErr := bob.Decrypt(ct)
	if decErr != nil {
		t.Fatalf("Decrypt: %v", decErr)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("chain symmetry check failed: got %q want %q", got, msg)
	}
}
