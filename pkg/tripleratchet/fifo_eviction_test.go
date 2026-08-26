package tripleratchet

// White-box tests for the FIFO eviction fix in receivePQKey.
// These tests live in package tripleratchet (not tripleratchet_test) so they
// can access unexported fields (skippedPQKeysFIFO, skippedPQKeysFIFOHead,
// skippedPQKeys, pqEpoch, recvCounter) and call unexported methods
// (purgeOldSkippedKeys).

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// TestFIFOEviction_StaleTailBehindLiveHead exercises the case the round-3
// review flagged: an old skipped key stays live at the FIFO head while many
// newer keys are inserted and consumed. Head-only compaction cannot advance
// past the live head, so without the trim-and-rebuild guard the backing slice
// grows without bound even though the live map stays tiny. This is a white-box
// test: it populates skippedPQKeys and the FIFO directly and drives the
// consume-path trim helper.
func TestFIFOEviction_StaleTailBehindLiveHead(t *testing.T) {
	tr := &TripleRatchet{
		skippedPQKeys: make(map[pqSkippedKeyID]*secret.Secret),
	}

	mkSecret := func() *secret.Secret {
		s, err := secret.NewRandom(32)
		if err != nil {
			t.Fatalf("secret.NewRandom: %v", err)
		}
		return s
	}

	// Pin one live key permanently at the head of the FIFO.
	headID := pqSkippedKeyID{epoch: 1, counter: 0}
	tr.skippedPQKeys[headID] = mkSecret()
	tr.skippedPQKeysFIFO = append(tr.skippedPQKeysFIFO, headID)

	// Repeatedly insert a newer skipped key, then immediately consume it. The
	// head never advances (headID stays live), so only the rebuild guard can
	// reclaim the stale tail entries.
	const iterations = 5000
	for i := 1; i <= iterations; i++ {
		id := pqSkippedKeyID{epoch: 1, counter: uint32(i)}
		mk := mkSecret()
		tr.skippedPQKeys[id] = mk
		tr.skippedPQKeysFIFO = append(tr.skippedPQKeysFIFO, id)

		// Consume it (mirrors the receivePQKey skipped-key-hit path).
		delete(tr.skippedPQKeys, id)
		mk.Destroy()
		tr.trimPQFIFOIfNeeded()
	}

	// The live map holds exactly the pinned head key.
	if got := len(tr.skippedPQKeys); got != 1 {
		t.Fatalf("skippedPQKeys = %d, want 1 (the pinned head)", got)
	}
	// The backing slice must stay bounded by the rebuild guard
	// (live > 2*len(map)+64), not grow proportional to iterations.
	if got := len(tr.skippedPQKeysFIFO); got > 2*len(tr.skippedPQKeys)+64 {
		t.Fatalf("FIFO backing slice = %d entries after %d iterations; rebuild guard failed to bound stale-tail growth",
			got, iterations)
	}
	// The pinned head key must still be live and evictable.
	if _, ok := tr.skippedPQKeys[headID]; !ok {
		t.Fatal("pinned head key was lost")
	}
	tr.skippedPQKeys[headID].Destroy()
}

// fifoTestECCipher is a symmetric deterministic EC cipher for internal FIFO
// tests. Both sides are initialised from the same seed; the send counter is
// encoded in the 4-byte header so ReceiveKey can reproduce the exact same key.
type fifoTestECCipher struct {
	seed    []byte
	sendCtr uint32
}

func (c *fifoTestECCipher) SendKey() ([]byte, []byte, error) {
	c.sendCtr++
	ctr := c.sendCtr
	header := []byte{byte(ctr), byte(ctr >> 8), byte(ctr >> 16), byte(ctr >> 24)}
	key := make([]byte, 32)
	copy(key, c.seed)
	key[0] ^= byte(ctr)
	key[1] ^= byte(ctr >> 8)
	key[2] ^= byte(ctr >> 16)
	key[3] ^= byte(ctr >> 24)
	return header, key, nil
}

func (c *fifoTestECCipher) ReceiveKey(ecHeader []byte) ([]byte, error) {
	if len(ecHeader) < 4 {
		return nil, &ErrInvalidInput{Field: "ecHeader", Reason: "too short"}
	}
	ctr := uint32(ecHeader[0]) | uint32(ecHeader[1])<<8 | uint32(ecHeader[2])<<16 | uint32(ecHeader[3])<<24
	key := make([]byte, 32)
	copy(key, c.seed)
	key[0] ^= byte(ctr)
	key[1] ^= byte(ctr >> 8)
	key[2] ^= byte(ctr >> 16)
	key[3] ^= byte(ctr >> 24)
	return key, nil
}

// TakeECSnapshot serializes the send counter for atomic rollback.
func (c *fifoTestECCipher) TakeECSnapshot() ([]byte, error) {
	ctr := c.sendCtr
	return []byte{byte(ctr >> 24), byte(ctr >> 16), byte(ctr >> 8), byte(ctr)}, nil
}

// RestoreECSnapshot restores the send counter from a snapshot.
func (c *fifoTestECCipher) RestoreECSnapshot(data []byte) error {
	if len(data) != 4 {
		return &ErrInvalidInput{Field: "data", Reason: "EC snapshot must be 4 bytes"}
	}
	c.sendCtr = uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	return nil
}

// newFIFOTestPair creates a matched Alice/Bob TripleRatchet pair for FIFO tests.
func newFIFOTestPair(t *testing.T, ss []byte) (*TripleRatchet, *TripleRatchet) {
	t.Helper()
	seed := make([]byte, 32)
	copy(seed, ss)

	aliceEC := &fifoTestECCipher{seed: seed}
	bobEC := &fifoTestECCipher{seed: seed}

	alice, err := NewAlice(aliceEC, ss, mlkembraid.NewIncrementalMLKEM768KEM(), 10)
	if err != nil {
		t.Fatalf("NewAlice: %v", err)
	}
	bob, err := NewBob(bobEC, ss, mlkembraid.NewIncrementalMLKEM768KEM(), 10)
	if err != nil {
		t.Fatalf("NewBob: %v", err)
	}
	return alice, bob
}

func fifoRandomSS(t *testing.T) []byte {
	t.Helper()
	buf := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return buf
}

// pqFIFOLiveLen returns the number of FIFO entries that have NOT yet been
// consumed by the head pointer (includes both live and mid-slice stale entries).
// It is used to verify that the FIFO does not grow unboundedly.
func pqFIFOLiveLen(tr *TripleRatchet) int {
	return len(tr.skippedPQKeysFIFO) - tr.skippedPQKeysFIFOHead
}

// TestFIFOEviction_OldestEvictedAtCapacity verifies the FIFO eviction fix:
//
//  1. After a forward jump large enough to fill skippedPQKeys to exactly
//     maxSkippedPQKeys and then add one more entry, the OLDEST skipped counter
//     (counter 1) must be evicted.
//  2. The NEWEST skipped counter (maxSkippedPQKeys+1) must still be decryptable
//     — before the fix it was silently dropped.
//  3. The evicted counter returns ErrPQKeyConsumed (it is no longer in the map
//     and recvCounter has advanced past it).
//
// Rust reference: KeyHistory::gc / evict_oldest in chain.rs.
func TestFIFOEviction_OldestEvictedAtCapacity(t *testing.T) {
	const jumpTarget = maxSkippedPQKeys + 2 // counters 1..jumpTarget; skipped 1..jumpTarget-1

	ss := fifoRandomSS(t)
	alice, bob := newFIFOTestPair(t, ss)

	// Alice encrypts jumpTarget messages (counters 1..jumpTarget).
	ciphertexts := make([][]byte, jumpTarget)
	plaintexts := make([][]byte, jumpTarget)
	for i := 0; i < jumpTarget; i++ {
		msg := []byte{byte(i), byte(i >> 8)}
		ct, encErr := alice.Encrypt(msg)
		if encErr != nil {
			t.Fatalf("Encrypt[%d]: %v", i, encErr)
		}
		ciphertexts[i] = ct
		plaintexts[i] = msg
	}

	// Bob receives the LAST message first (counter jumpTarget).
	// This triggers a forward jump of jumpTarget-1 skipped entries:
	//   counters 1..maxSkippedPQKeys fill the map,
	//   counter maxSkippedPQKeys+1 evicts counter 1 and is inserted.
	// After this call: skippedPQKeys = {2..maxSkippedPQKeys+1}.
	lastIdx := jumpTarget - 1
	_, err := bob.Decrypt(ciphertexts[lastIdx])
	if err != nil {
		t.Fatalf("Decrypt(last, counter=%d): %v", lastIdx+1, err)
	}

	// Map must be exactly at capacity.
	if got := len(bob.skippedPQKeys); got != maxSkippedPQKeys {
		t.Fatalf("skippedPQKeys size = %d, want %d", got, maxSkippedPQKeys)
	}

	// The NEWEST skipped counter (maxSkippedPQKeys+1 = index maxSkippedPQKeys)
	// must still be decryptable — this was dropped by the old code.
	newestIdx := maxSkippedPQKeys // 0-based index → counter = maxSkippedPQKeys+1
	got, decErr := bob.Decrypt(ciphertexts[newestIdx])
	if decErr != nil {
		t.Fatalf("Decrypt(newest skipped, counter=%d): %v (should be decryptable after fix)", newestIdx+1, decErr)
	}
	if !bytes.Equal(got, plaintexts[newestIdx]) {
		t.Fatalf("newest skipped plaintext mismatch: got %v want %v", got, plaintexts[newestIdx])
	}

	// The OLDEST skipped counter (counter 1 = index 0) must be evicted.
	// recvCounter > 1 and the key is not in the map → ErrPQKeyConsumed.
	_, decErrOldest := bob.Decrypt(ciphertexts[0])
	if decErrOldest == nil {
		t.Fatal("expected ErrPQKeyConsumed for evicted oldest counter, got nil")
	}
	var consumed *ErrPQKeyConsumed
	if !errors.As(decErrOldest, &consumed) {
		t.Fatalf("expected *ErrPQKeyConsumed for oldest counter, got %T: %v", decErrOldest, decErrOldest)
	}
}

// TestFIFOEviction_NoDoubleFreOnConsumeAndPurge verifies that no secret key is
// Destroy()d more than once when skipped keys are consumed (via normal decryption)
// and then purged (via epoch advancement calling purgeOldSkippedKeys directly).
//
// go-enclave panics on a double-free of a protected allocation, so the absence of
// a panic is the correctness proof.
func TestFIFOEviction_NoDoubleFreOnConsumeAndPurge(t *testing.T) {
	ss := fifoRandomSS(t)
	alice, bob := newFIFOTestPair(t, ss)

	// Alice encrypts 6 messages (counters 1..6).
	const n = 6
	ciphertexts := make([][]byte, n)
	plaintexts := make([][]byte, n)
	for i := 0; i < n; i++ {
		msg := []byte("msg " + string(rune('A'+i)))
		ct, encErr := alice.Encrypt(msg)
		if encErr != nil {
			t.Fatalf("Encrypt[%d]: %v", i, encErr)
		}
		ciphertexts[i] = ct
		plaintexts[i] = msg
	}

	// Bob receives message 5 (counter 6) first — creates skipped keys for
	// counters 1..5 in the map.
	if _, err := bob.Decrypt(ciphertexts[n-1]); err != nil {
		t.Fatalf("Decrypt(last): %v", err)
	}

	// Bob consumes skipped keys for counters 2, 3, 4 (out of order).
	// Counter 1 and 5 remain in the map as live skipped keys.
	for _, idx := range []int{1, 2, 3} {
		got, decErr := bob.Decrypt(ciphertexts[idx])
		if decErr != nil {
			t.Fatalf("Decrypt[%d]: %v", idx, decErr)
		}
		if !bytes.Equal(got, plaintexts[idx]) {
			t.Fatalf("plaintext[%d] mismatch", idx)
		}
	}

	// FIFO has stale entries for counters 2, 3, 4 (consumed) and live entries
	// for counters 1 and 5. Call purgeOldSkippedKeys as if a new epoch has
	// advanced past the retention window (set pqEpoch to force cutoff).
	// We do this by directly manipulating internal state to simulate an epoch
	// advance without requiring a real braid handshake.
	const purgeEpoch = epochsToKeepPriorToSendEpoch + 2
	bob.pqEpoch = purgeEpoch
	// purgeOldSkippedKeys removes keys with epoch < pqEpoch - epochsToKeepPriorToSendEpoch.
	// Since the skipped keys were stored at epoch 0 and cutoff = purgeEpoch - 1 = 2,
	// epoch 0 < 2, so all skipped keys at epoch 0 are purged.
	bob.purgeOldSkippedKeys() // must not panic (no double-free)

	// All skipped keys at epoch 0 must now be gone from the map.
	if got := len(bob.skippedPQKeys); got != 0 {
		t.Fatalf("skippedPQKeys size = %d after purge, want 0", got)
	}

	// FIFO live length must be zero (all entries trimmed from the head).
	if live := pqFIFOLiveLen(bob); live != 0 {
		t.Fatalf("FIFO live length = %d after purge, want 0", live)
	}
}

// TestFIFOEviction_FIFOBoundedBelowCapacity verifies that the FIFO does not
// grow unbounded during repeated cycles of small forward-jumps (below capacity)
// followed by consumption of the skipped keys.
//
// Without the compactPQFIFOIfNeeded fix on the consume and purge paths, each
// insert-consume cycle would leave a stale FIFO entry that accumulates without
// bound because eviction (which was the only compaction trigger) is never
// invoked when the map stays below capacity.
func TestFIFOEviction_FIFOBoundedBelowCapacity(t *testing.T) {
	ss := fifoRandomSS(t)
	alice, bob := newFIFOTestPair(t, ss)

	// Each cycle: Alice sends jumpSize+1 messages; Bob receives the last one
	// first (creating jumpSize skipped entries), then delivers the rest in order.
	// jumpSize must stay below maxSkippedPQKeys so eviction is never triggered.
	const jumpSize = 10
	const cycles = 50

	var prevFIFOLen int
	for cycle := 0; cycle < cycles; cycle++ {
		// Encrypt jumpSize+1 messages.
		ciphertexts := make([][]byte, jumpSize+1)
		for i := 0; i <= jumpSize; i++ {
			ct, encErr := alice.Encrypt([]byte{byte(cycle), byte(i)})
			if encErr != nil {
				t.Fatalf("cycle %d Encrypt[%d]: %v", cycle, i, encErr)
			}
			ciphertexts[i] = ct
		}

		// Deliver last message first → creates jumpSize skipped keys.
		if _, err := bob.Decrypt(ciphertexts[jumpSize]); err != nil {
			t.Fatalf("cycle %d Decrypt(last): %v", cycle, err)
		}

		// Deliver remaining messages in order (consume skipped keys 0..jumpSize-1).
		for i := 0; i < jumpSize; i++ {
			if _, err := bob.Decrypt(ciphertexts[i]); err != nil {
				t.Fatalf("cycle %d Decrypt[%d]: %v", cycle, i, err)
			}
		}

		// After all skipped keys have been consumed, the map must be empty.
		if got := len(bob.skippedPQKeys); got != 0 {
			t.Fatalf("cycle %d: skippedPQKeys = %d, want 0", cycle, got)
		}

		// FIFO live length must not grow cycle-over-cycle. After all skipped
		// keys are consumed, compactPQFIFOIfNeeded should have trimmed all
		// stale head entries so the effective FIFO length stays bounded (zero
		// or very small, not unboundedly growing).
		currentFIFOLen := pqFIFOLiveLen(bob)
		if cycle > 0 && currentFIFOLen > prevFIFOLen+jumpSize {
			t.Fatalf("cycle %d: FIFO live length grew from %d to %d (expected bounded growth, max +%d per cycle)",
				cycle, prevFIFOLen, currentFIFOLen, jumpSize)
		}
		prevFIFOLen = currentFIFOLen
	}

	// After all cycles, the FIFO live length must be zero: the map is empty and
	// compaction trims all stale entries from the head.
	if live := pqFIFOLiveLen(bob); live != 0 {
		t.Fatalf("after all cycles: FIFO live length = %d, want 0", live)
	}
}
