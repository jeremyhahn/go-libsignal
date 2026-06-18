package tripleratchet

// Whitebox tests for snapshot rollback failure paths (Finding 1) and for
// bidirectional message exchange and epoch transition (Finding 4).

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"math"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// ─── Helpers ─────────────────────────────────────────────────────────────────

// failingRestoreECCipher succeeds on TakeECSnapshot but fails on
// RestoreECSnapshot, letting us exercise the EC-restore failure path.
type failingRestoreECCipher struct {
	delegate *braidECCipher
}

func (c *failingRestoreECCipher) SendKey() ([]byte, []byte, error) {
	return c.delegate.SendKey()
}

func (c *failingRestoreECCipher) ReceiveKey(ecHeader []byte) ([]byte, error) {
	return c.delegate.ReceiveKey(ecHeader)
}

func (c *failingRestoreECCipher) TakeECSnapshot() ([]byte, error) {
	return []byte{0xEC, 0x42}, nil // succeeds
}

func (c *failingRestoreECCipher) RestoreECSnapshot(_ []byte) error {
	return &ErrInvalidInput{Field: "test", Reason: "injected RestoreECSnapshot failure"}
}

// ─── Finding 1: rollback path tests ──────────────────────────────────────────

// TestRollback_MACFailureRestoresState verifies the success rollback path:
// a tampered MAC causes decryption failure, snapshot restore succeeds, and the
// session can then decrypt the original (unmodified) ciphertext.
func TestRollback_MACFailureRestoresState(t *testing.T) {
	alice, bob, _ := newUnidirectionalPair(t)

	plaintext := []byte("rollback success test")
	ct, err := alice.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[len(tampered)-1] ^= 0xFF

	_, decErr := bob.Decrypt(tampered)
	if decErr == nil {
		t.Fatal("expected MAC verification failure")
	}
	var macErr *ErrMACVerificationFailed
	if !errors.As(decErr, &macErr) {
		t.Errorf("expected ErrMACVerificationFailed, got %T: %v", decErr, decErr)
	}

	// Session must be usable after rollback: original ciphertext decrypts.
	got, err := bob.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt after rollback: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch after rollback: got %q want %q", got, plaintext)
	}
}

// TestRollback_ECRestoreFailure_ReturnsErrStateCorrupted verifies that when a
// MAC failure triggers rollback and RestoreECSnapshot returns an error, Decrypt
// returns ErrStateCorrupted wrapping both the original error and the restore error.
func TestRollback_ECRestoreFailure_ReturnsErrStateCorrupted(t *testing.T) {
	ss := braidRandomSharedSecret(t)

	aliceEC := newBraidECCipher(ss)
	alice, err := NewAlice(aliceEC, ss, mlkembraid.NewIncrementalMLKEM768KEM(), 10)
	if err != nil {
		t.Fatalf("NewAlice: %v", err)
	}

	bobDelegate := newBraidECCipher(ss)
	bobEC := &failingRestoreECCipher{delegate: bobDelegate}
	bob, err := NewBob(bobEC, ss, mlkembraid.NewIncrementalMLKEM768KEM(), 10)
	if err != nil {
		t.Fatalf("NewBob: %v", err)
	}

	ct, err := alice.Encrypt([]byte("trigger"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[len(tampered)-1] ^= 0xFF

	_, decErr := bob.Decrypt(tampered)
	if decErr == nil {
		t.Fatal("expected error from Decrypt with tampered MAC")
	}

	// Must be ErrStateCorrupted because restore also failed.
	var corruptedErr *ErrStateCorrupted
	if !errors.As(decErr, &corruptedErr) {
		t.Fatalf("expected ErrStateCorrupted, got %T: %v", decErr, decErr)
	}

	// DecryptErr must be the MAC failure.
	var macErr *ErrMACVerificationFailed
	if !errors.As(corruptedErr.DecryptErr, &macErr) {
		t.Errorf("ErrStateCorrupted.DecryptErr expected ErrMACVerificationFailed, got %T: %v",
			corruptedErr.DecryptErr, corruptedErr.DecryptErr)
	}

	// RestoreErr must be the EC restore failure.
	var ecErr *ErrECRatchetFailed
	if !errors.As(corruptedErr.RestoreErr, &ecErr) {
		t.Errorf("ErrStateCorrupted.RestoreErr expected ErrECRatchetFailed, got %T: %v",
			corruptedErr.RestoreErr, corruptedErr.RestoreErr)
	}
}

// TestRollback_BraidRestoreFailure_ReturnsErr verifies that when braid data in
// a snapshot is corrupted and restoreSnapshot is called directly, it returns an
// ErrBraidFailed. The Decrypt integration path wrapping into ErrStateCorrupted
// is separately tested in TestRollback_ECRestoreFailure_ReturnsErrStateCorrupted.
func TestRollback_BraidRestoreFailure_ReturnsErr(t *testing.T) {
	alice, _, _ := newUnidirectionalPair(t)

	// Take a snapshot and corrupt the braid data.
	snap, snapErr := alice.takeSnapshot()
	if snapErr != nil {
		t.Fatalf("takeSnapshot: %v", snapErr)
	}
	if len(snap.braidData) > 0 {
		snap.braidData[0] ^= 0xFF
	}

	// Partially restore key material (inject a minimal set so restore doesn't
	// crash on nil dereference when we already consumed snap.rootKey etc.).
	// We must provide live values for rootKey / chain keys since restore destroys them.
	// The simplest approach: skip the full restore and call restoreSnapshot directly
	// with the corrupt snapshot so we observe the error return.
	restoreErr := alice.restoreSnapshot(snap)
	if restoreErr == nil {
		t.Fatal("expected restoreSnapshot to fail with corrupted braidData")
	}
	var braidErr *ErrBraidFailed
	if !errors.As(restoreErr, &braidErr) {
		t.Errorf("expected ErrBraidFailed from restoreSnapshot, got %T: %v", restoreErr, restoreErr)
	}
	// snap secrets were consumed by restoreSnapshot; no need to destroySnapshot.
}

// TestRollback_ErrStateCorrupted_UnwrapsErrors verifies that errors.As can reach
// both wrapped errors inside ErrStateCorrupted.
func TestRollback_ErrStateCorrupted_UnwrapsErrors(t *testing.T) {
	inner1 := &ErrMACVerificationFailed{}
	inner2 := &ErrBraidFailed{Op: "test", Cause: &ErrInvalidInput{Field: "x", Reason: "y"}}

	corrupt := &ErrStateCorrupted{
		DecryptErr: inner1,
		RestoreErr: inner2,
	}

	if corrupt.Error() == "" {
		t.Error("expected non-empty error message")
	}

	var mac *ErrMACVerificationFailed
	if !errors.As(corrupt, &mac) {
		t.Error("errors.As should find ErrMACVerificationFailed inside ErrStateCorrupted")
	}

	var braid *ErrBraidFailed
	if !errors.As(corrupt, &braid) {
		t.Error("errors.As should find ErrBraidFailed inside ErrStateCorrupted")
	}
}

// ─── Finding 4: bidirectional and epoch-transition tests ─────────────────────

// TestEncryptDecrypt_Bidirectional verifies true bidirectional message exchange:
// both Alice→Bob and Bob→Alice messages are encrypted and decrypted correctly,
// delivered in interleaved order.
//
// All messages from both sides are pre-encrypted before any delivery. This is
// required because the ML-KEM Braid SCKA handshake has intermediate states where
// braid.Send() fails once the braid has partially advanced. Pre-encrypting
// ensures Bob's Encrypt calls happen while his braid is still in its initial
// NoHeaderReceived state, which can always Send (returns probe chunks).
func TestEncryptDecrypt_Bidirectional(t *testing.T) {
	alice, bob, _ := newUnidirectionalPair(t)

	alicePlaintexts := [][]byte{
		[]byte("alice→bob #1"),
		[]byte("alice→bob #2"),
		[]byte("alice→bob #3"),
	}
	bobPlaintexts := [][]byte{
		[]byte("bob→alice #1"),
		[]byte("bob→alice #2"),
		[]byte("bob→alice #3"),
	}

	aliceCTs := make([][]byte, len(alicePlaintexts))
	bobCTs := make([][]byte, len(bobPlaintexts))

	for i, msg := range alicePlaintexts {
		ct, err := alice.Encrypt(msg)
		if err != nil {
			t.Fatalf("alice Encrypt[%d]: %v", i, err)
		}
		aliceCTs[i] = ct
	}
	for i, msg := range bobPlaintexts {
		ct, err := bob.Encrypt(msg)
		if err != nil {
			t.Fatalf("bob Encrypt[%d]: %v", i, err)
		}
		bobCTs[i] = ct
	}

	// Deliver interleaved: alice[i] then bob[i] for each index.
	for i := range alicePlaintexts {
		got, err := bob.Decrypt(aliceCTs[i])
		if err != nil {
			t.Fatalf("bob Decrypt alice[%d]: %v", i, err)
		}
		if !bytes.Equal(got, alicePlaintexts[i]) {
			t.Fatalf("alice[%d] mismatch: got %q want %q", i, got, alicePlaintexts[i])
		}

		got, err = alice.Decrypt(bobCTs[i])
		if err != nil {
			t.Fatalf("alice Decrypt bob[%d]: %v", i, err)
		}
		if !bytes.Equal(got, bobPlaintexts[i]) {
			t.Fatalf("bob[%d] mismatch: got %q want %q", i, got, bobPlaintexts[i])
		}
	}
}

// TestEncryptDecrypt_Bidirectional_OutOfOrder exercises bidirectional exchange
// where messages in both directions are delivered out of order.
func TestEncryptDecrypt_Bidirectional_OutOfOrder(t *testing.T) {
	alice, bob, _ := newUnidirectionalPair(t)

	aliceMsgs := [][]byte{
		[]byte("alice-1"), []byte("alice-2"), []byte("alice-3"),
	}
	bobMsgs := [][]byte{
		[]byte("bob-1"), []byte("bob-2"),
	}

	aliceCTs := make([][]byte, len(aliceMsgs))
	bobCTs := make([][]byte, len(bobMsgs))

	for i, msg := range aliceMsgs {
		ct, err := alice.Encrypt(msg)
		if err != nil {
			t.Fatalf("alice Encrypt[%d]: %v", i, err)
		}
		aliceCTs[i] = ct
	}
	for i, msg := range bobMsgs {
		ct, err := bob.Encrypt(msg)
		if err != nil {
			t.Fatalf("bob Encrypt[%d]: %v", i, err)
		}
		bobCTs[i] = ct
	}

	// Deliver alice's messages out of order to Bob: 2, 0, 1.
	for _, idx := range []int{2, 0, 1} {
		got, err := bob.Decrypt(aliceCTs[idx])
		if err != nil {
			t.Fatalf("bob Decrypt alice[%d]: %v", idx, err)
		}
		if !bytes.Equal(got, aliceMsgs[idx]) {
			t.Fatalf("bob alice[%d] mismatch", idx)
		}
	}

	// Deliver bob's messages in order to Alice.
	for i, ct := range bobCTs {
		got, err := alice.Decrypt(ct)
		if err != nil {
			t.Fatalf("alice Decrypt bob[%d]: %v", i, err)
		}
		if !bytes.Equal(got, bobMsgs[i]) {
			t.Fatalf("alice bob[%d] mismatch", i)
		}
	}
}

// TestEpochTransition_ViaInjection exercises the epoch-transition path by
// injecting a PQ epoch advance. After the advance, Encrypt and Decrypt must
// succeed and rollback across the epoch boundary must also work.
//
// Why injection and not completing the braid handshake in-process: the ML-KEM
// Braid SCKA produces an OutputKey only after a complete Alice→Bob→Alice→Bob
// ciphertext exchange including Braid chunks. Completing this requires the
// session layer to carry braid chunks — infrastructure not present in the unit
// test ECCipher. Injection via advancePQEpoch exercises every code path that
// the real epoch advance triggers: advancePQEpoch, chain-key replacement,
// counter reset, and snapshot restore across the epoch boundary.
func TestEpochTransition_ViaInjection(t *testing.T) {
	alice, bob, _ := newUnidirectionalPair(t)

	// Exchange one message at epoch 0 to confirm baseline works.
	msg0 := []byte("epoch-0 message")
	ct0, err := alice.Encrypt(msg0)
	if err != nil {
		t.Fatalf("epoch-0 Encrypt: %v", err)
	}
	got, err := bob.Decrypt(ct0)
	if err != nil {
		t.Fatalf("epoch-0 Decrypt: %v", err)
	}
	if !bytes.Equal(got, msg0) {
		t.Fatalf("epoch-0 mismatch")
	}

	// Inject epoch advance on both sides.
	epochSecret := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, epochSecret); err != nil {
		t.Fatalf("rand: %v", err)
	}
	injectEpochAdvance(t, alice, epochSecret)
	injectEpochAdvance(t, bob, epochSecret)

	if alice.pqEpoch != 1 || bob.pqEpoch != 1 {
		t.Fatalf("expected pqEpoch=1, got alice=%d bob=%d", alice.pqEpoch, bob.pqEpoch)
	}
	if alice.sendCounter != 0 || bob.recvCounter != 0 {
		t.Fatalf("counters not reset: alice.send=%d bob.recv=%d", alice.sendCounter, bob.recvCounter)
	}
	if !alice.braidHandshakeComplete || !bob.braidHandshakeComplete {
		t.Error("braidHandshakeComplete must be true after epoch advance")
	}

	// Exchange multiple messages at epoch 1.
	for i := 0; i < 5; i++ {
		msg := []byte("epoch-1 message")
		ct, err := alice.Encrypt(msg)
		if err != nil {
			t.Fatalf("epoch-1 Encrypt[%d]: %v", i, err)
		}
		got, err := bob.Decrypt(ct)
		if err != nil {
			t.Fatalf("epoch-1 Decrypt[%d]: %v", i, err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("epoch-1 [%d] mismatch", i)
		}
	}

	// Verify rollback at epoch 1 works.
	validMsg := []byte("epoch-1 rollback test")
	validCT, err := alice.Encrypt(validMsg)
	if err != nil {
		t.Fatalf("epoch-1 rollback Encrypt: %v", err)
	}

	tampered := make([]byte, len(validCT))
	copy(tampered, validCT)
	tampered[len(tampered)-1] ^= 0xFF

	if _, decErr := bob.Decrypt(tampered); decErr == nil {
		t.Fatal("expected error for tampered MAC at epoch 1")
	}

	got, err = bob.Decrypt(validCT)
	if err != nil {
		t.Fatalf("epoch-1 rollback re-decrypt: %v", err)
	}
	if !bytes.Equal(got, validMsg) {
		t.Fatalf("epoch-1 rollback plaintext mismatch")
	}
}

// TestEncryptDecrypt_SkippedKeyRollback verifies that when out-of-order messages
// are buffered as skipped keys, a MAC failure on a later message rolls back
// without disturbing the buffered keys.
func TestEncryptDecrypt_SkippedKeyRollback(t *testing.T) {
	alice, bob, _ := newUnidirectionalPair(t)

	msgs := make([][]byte, 4)
	cts := make([][]byte, 4)
	for i := range msgs {
		msgs[i] = []byte("msg " + string(rune('A'+i)))
		ct, err := alice.Encrypt(msgs[i])
		if err != nil {
			t.Fatalf("Encrypt[%d]: %v", i, err)
		}
		cts[i] = ct
	}

	// Bob receives message 3 first (skips 0, 1, 2).
	got, err := bob.Decrypt(cts[3])
	if err != nil {
		t.Fatalf("Decrypt[3]: %v", err)
	}
	if !bytes.Equal(got, msgs[3]) {
		t.Fatalf("msg[3] mismatch")
	}

	// Verify skipped keys are buffered.
	if len(bob.skippedPQKeys) == 0 {
		t.Fatal("expected skipped keys after out-of-order delivery")
	}

	// Tamper message 1 — rollback should not destroy skipped keys for 0 and 2.
	tampered := make([]byte, len(cts[1]))
	copy(tampered, cts[1])
	tampered[len(tampered)-1] ^= 0xFF
	if _, decErr := bob.Decrypt(tampered); decErr == nil {
		t.Fatal("expected error for tampered msg[1]")
	}

	// Deliver the skipped messages 0, 1, 2 in order.
	for i := 0; i < 3; i++ {
		got, err := bob.Decrypt(cts[i])
		if err != nil {
			t.Fatalf("Decrypt skipped[%d]: %v", i, err)
		}
		if !bytes.Equal(got, msgs[i]) {
			t.Fatalf("skipped msg[%d] mismatch", i)
		}
	}
}

// TestTakeSnapshot_SkippedKeys_AreIndependentClones verifies that the skipped
// key deep-copy in takeSnapshot produces independent secret.Secret values —
// destroying a snapshot key must not destroy the live key.
func TestTakeSnapshot_SkippedKeys_AreIndependentClones(t *testing.T) {
	ss := braidRandomSharedSecret(t)
	ec := newBraidECCipher(ss)
	tr, err := NewAlice(ec, ss, mlkembraid.NewIncrementalMLKEM768KEM(), 10)
	if err != nil {
		t.Fatalf("NewAlice: %v", err)
	}

	k, secErr := secret.New([]byte{0xAA, 0xBB, 0xCC, 0xDD})
	if secErr != nil {
		t.Fatalf("secret.New: %v", secErr)
	}
	id := pqSkippedKeyID{epoch: 1, counter: 7}
	tr.skippedPQKeys[id] = k

	snap, snapErr := tr.takeSnapshot()
	if snapErr != nil {
		t.Fatalf("takeSnapshot: %v", snapErr)
	}

	// Destroy the snapshot copy.
	if snapKey, ok := snap.skippedPQKeys[id]; ok {
		snapKey.Destroy()
	}

	// The live key must not be destroyed.
	if k.IsDestroyed() {
		t.Error("live skipped key was destroyed when snapshot key was destroyed")
	}

	tr.destroySnapshot(snap)
}

// TestEncrypt_SendCounterNotMutatedOnOverflow verifies the Finding-5 fix:
// when sendCounter == MaxUint32, Encrypt returns an error without incrementing
// the counter (no state mutation on error path).
func TestEncrypt_SendCounterNotMutatedOnOverflow(t *testing.T) {
	ss := braidRandomSharedSecret(t)
	ec := newBraidECCipher(ss)

	tr, err := NewAlice(ec, ss, mlkembraid.NewIncrementalMLKEM768KEM(), 10)
	if err != nil {
		t.Fatalf("NewAlice: %v", err)
	}

	tr.sendCounter = math.MaxUint32
	before := tr.sendCounter

	_, encErr := tr.Encrypt([]byte("overflow check"))
	if encErr == nil {
		t.Fatal("expected overflow error")
	}
	if tr.sendCounter != before {
		t.Errorf("sendCounter was mutated on error path: before=%d after=%d", before, tr.sendCounter)
	}
}
