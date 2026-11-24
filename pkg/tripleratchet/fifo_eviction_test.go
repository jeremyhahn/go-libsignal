package tripleratchet

// White-box tests for FIFO eviction in receivePQKey.

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// TestFIFOEviction_StaleTailBehindLiveHead checks the FIFO stays bounded while an old key stays live at its head.
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

// fifoTestECCipher is a deterministic EC cipher whose header carries the send counter.
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

// pqFIFOLiveLen returns the FIFO entries past the head pointer, live or stale.
func pqFIFOLiveLen(tr *TripleRatchet) int {
	return len(tr.skippedPQKeysFIFO) - tr.skippedPQKeysFIFOHead
}

// TestFIFOEviction_OldestEvictedAtCapacity checks overflow evicts the oldest counter (ErrPQKeyConsumed) and keeps the newest (Rust KeyHistory::gc).
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

	// Receiving the last message first skips counters 1..maxSkippedPQKeys+1, evicting counter 1.
	lastIdx := jumpTarget - 1
	_, err := bob.Decrypt(ciphertexts[lastIdx])
	if err != nil {
		t.Fatalf("Decrypt(last, counter=%d): %v", lastIdx+1, err)
	}

	// Map must be exactly at capacity.
	if got := len(bob.skippedPQKeys); got != maxSkippedPQKeys {
		t.Fatalf("skippedPQKeys size = %d, want %d", got, maxSkippedPQKeys)
	}

	// The newest skipped counter must still decrypt.
	newestIdx := maxSkippedPQKeys // 0-based index → counter = maxSkippedPQKeys+1
	got, decErr := bob.Decrypt(ciphertexts[newestIdx])
	if decErr != nil {
		t.Fatalf("Decrypt(newest skipped, counter=%d): %v (should be decryptable after fix)", newestIdx+1, decErr)
	}
	if !bytes.Equal(got, plaintexts[newestIdx]) {
		t.Fatalf("newest skipped plaintext mismatch: got %v want %v", got, plaintexts[newestIdx])
	}

	// Counter 1 was evicted, so it returns ErrPQKeyConsumed.
	_, decErrOldest := bob.Decrypt(ciphertexts[0])
	if decErrOldest == nil {
		t.Fatal("expected ErrPQKeyConsumed for evicted oldest counter, got nil")
	}
	var consumed *ErrPQKeyConsumed
	if !errors.As(decErrOldest, &consumed) {
		t.Fatalf("expected *ErrPQKeyConsumed for oldest counter, got %T: %v", decErrOldest, decErrOldest)
	}
}

// TestFIFOEviction_NoDoubleFreOnConsumeAndPurge checks consumed then purged keys are destroyed once; go-enclave panics on a double free.
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

	// Counters 2-4 are consumed and 1 and 5 live; force an epoch cutoff and purge.
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

// TestFIFOEviction_FIFOBoundedBelowCapacity checks insert-and-consume cycles below capacity keep the FIFO bounded.
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

		// compactPQFIFOIfNeeded keeps the live FIFO length from growing between cycles.
		currentFIFOLen := pqFIFOLiveLen(bob)
		if cycle > 0 && currentFIFOLen > prevFIFOLen+jumpSize {
			t.Fatalf("cycle %d: FIFO live length grew from %d to %d (expected bounded growth, max +%d per cycle)",
				cycle, prevFIFOLen, currentFIFOLen, jumpSize)
		}
		prevFIFOLen = currentFIFOLen
	}

	// With the map empty, the live FIFO length must be zero.
	if live := pqFIFOLiveLen(bob); live != 0 {
		t.Fatalf("after all cycles: FIFO live length = %d, want 0", live)
	}
}
