package tripleratchet_test

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
	"github.com/jeremyhahn/go-libsignal/pkg/tripleratchet"
)

// TestEncryptDecrypt_OutOfOrderPQKeys verifies that the out-of-order PQ key
// handling works: encrypt multiple messages, then deliver them out of order.
// This exercises the receivePQKey skip-and-store path.
func TestEncryptDecrypt_OutOfOrderPQKeys(t *testing.T) {
	ss := randomSharedSecret(t)
	seed := make([]byte, 32)
	copy(seed, ss)

	aliceEC := &testECCipher{sendState: newTestECState(seed), recvState: newTestECState(seed)}
	bobEC := &testECCipher{sendState: newTestECState(seed), recvState: newTestECState(seed)}

	alice, err := tripleratchet.NewAlice(aliceEC, ss, mlkembraid.NewIncrementalMLKEM768KEM(), 10)
	if err != nil {
		t.Fatalf("NewAlice: %v", err)
	}
	bob, err := tripleratchet.NewBob(bobEC, ss, mlkembraid.NewIncrementalMLKEM768KEM(), 10)
	if err != nil {
		t.Fatalf("NewBob: %v", err)
	}

	// Encrypt 3 messages: m1, m2, m3 (in order).
	msgs := [][]byte{
		[]byte("first message"),
		[]byte("second message"),
		[]byte("third message"),
	}

	ciphertexts := make([][]byte, len(msgs))
	for i, msg := range msgs {
		ct, encErr := alice.Encrypt(msg)
		if encErr != nil {
			t.Fatalf("Encrypt[%d]: %v", i, encErr)
		}
		ciphertexts[i] = ct
	}

	// Deliver out of order: m2, m3, m1 (skipping m1 first forces skip storage).
	// Note: Bob's EC cipher is symmetric and deterministic, so ReceiveKey(header)
	// works for any ordering as long as the header encodes the counter.
	order := []int{1, 2, 0}
	for _, idx := range order {
		got, decErr := bob.Decrypt(ciphertexts[idx])
		if decErr != nil {
			t.Fatalf("Decrypt[%d] (out of order): %v", idx, decErr)
		}
		if !bytes.Equal(got, msgs[idx]) {
			t.Fatalf("message[%d] mismatch: got %q want %q", idx, got, msgs[idx])
		}
	}
}

// TestEncryptDecrypt_ReplayAfterConsume verifies that re-decrypting a message
// after its PQ key has been consumed returns an appropriate error.
func TestEncryptDecrypt_ReplayAfterConsume(t *testing.T) {
	ss := randomSharedSecret(t)
	seed := make([]byte, 32)
	copy(seed, ss)

	aliceEC := &testECCipher{sendState: newTestECState(seed), recvState: newTestECState(seed)}
	bobEC := &testECCipher{sendState: newTestECState(seed), recvState: newTestECState(seed)}

	alice, err := tripleratchet.NewAlice(aliceEC, ss, mlkembraid.NewIncrementalMLKEM768KEM(), 10)
	if err != nil {
		t.Fatalf("NewAlice: %v", err)
	}
	bob, err := tripleratchet.NewBob(bobEC, ss, mlkembraid.NewIncrementalMLKEM768KEM(), 10)
	if err != nil {
		t.Fatalf("NewBob: %v", err)
	}

	ct, encErr := alice.Encrypt([]byte("replay test"))
	if encErr != nil {
		t.Fatalf("Encrypt: %v", encErr)
	}

	// First decrypt should succeed.
	if _, err = bob.Decrypt(ct); err != nil {
		t.Fatalf("First Decrypt: %v", err)
	}

	// Second decrypt of the same message should fail because the PQ counter
	// has already advanced past this position.
	_, err = bob.Decrypt(ct)
	if err == nil {
		t.Fatal("expected error on replay decrypt, got nil")
	}
}

// TestEncrypt_StateUnchangedOnBraidError verifies that if braid.Send() fails
// during Encrypt (which can happen in certain braid states), the error is
// properly surfaced. This is a best-effort test since the braid error depends
// on state machine progression.
func TestNewAlice_ZeroSharedSecret(t *testing.T) {
	// A zero-length shared secret should be rejected.
	kem := mlkembraid.NewIncrementalMLKEM768KEM()
	ec := &testECCipher{
		sendState: newTestECState(make([]byte, 32)),
		recvState: newTestECState(make([]byte, 32)),
	}
	_, err := tripleratchet.NewAlice(ec, []byte{}, kem, 10)
	if err == nil {
		t.Fatal("expected error for zero-length shared secret")
	}
}
