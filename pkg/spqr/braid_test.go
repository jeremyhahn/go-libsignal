package spqr

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

func TestInitWithBraid_Alice(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	kem := mlkembraid.NewMLKEM768IncrementalKEM()
	braid, err := mlkembraid.InitAlice(sharedSecret, kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice failed: %v", err)
	}

	s, err := InitWithBraid(sharedSecret, DirectionA2B, maxJump, braid)
	if err != nil {
		t.Fatalf("InitWithBraid failed: %v", err)
	}
	defer s.Zeroize()

	if s.braid == nil {
		t.Fatal("braid should not be nil")
	}
	if s.Braid() == nil {
		t.Fatal("Braid() should return non-nil")
	}
}

func TestInitWithBraid_Bob(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	kem := mlkembraid.NewMLKEM768IncrementalKEM()
	braid, err := mlkembraid.InitBob(sharedSecret, kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitBob failed: %v", err)
	}

	s, err := InitWithBraid(sharedSecret, DirectionB2A, maxJump, braid)
	if err != nil {
		t.Fatalf("InitWithBraid failed: %v", err)
	}
	defer s.Zeroize()

	if s.braid == nil {
		t.Fatal("braid should not be nil")
	}
}

func TestSendBraid_NoBraid(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	s, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer s.Zeroize()

	_, _, sendErr := s.SendBraid()
	if sendErr == nil {
		t.Fatal("expected ErrNoBraid")
	}
	if _, ok := sendErr.(*ErrNoBraid); !ok {
		t.Errorf("expected *ErrNoBraid, got %T: %v", sendErr, sendErr)
	}
}

func TestRecvBraid_NoBraid(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	s, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer s.Zeroize()

	_, recvErr := s.RecvBraid([]byte{0x01, 0x01, 0x01, 0x00})
	if recvErr == nil {
		t.Fatal("expected ErrNoBraid")
	}
	if _, ok := recvErr.(*ErrNoBraid); !ok {
		t.Errorf("expected *ErrNoBraid, got %T: %v", recvErr, recvErr)
	}
}

func TestSendBraid_ProducesWireMessage(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	kem := mlkembraid.NewMLKEM768IncrementalKEM()
	braid, err := mlkembraid.InitAlice(sharedSecret, kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice failed: %v", err)
	}

	s, err := InitWithBraid(sharedSecret, DirectionA2B, maxJump, braid)
	if err != nil {
		t.Fatalf("InitWithBraid failed: %v", err)
	}
	defer s.Zeroize()

	pqrMsg, messageKey, sendErr := s.SendBraid()
	if sendErr != nil {
		t.Fatalf("SendBraid failed: %v", sendErr)
	}

	if len(pqrMsg) == 0 {
		t.Fatal("expected non-empty wire message")
	}
	if len(messageKey) == 0 {
		t.Fatal("expected non-nil message key")
	}

	// Parse the wire message using DeserializeSCKA to verify structure.
	braidMsg, chainCounter, decErr := mlkembraid.DeserializeSCKA(pqrMsg)
	if decErr != nil {
		t.Fatalf("DeserializeSCKA failed: %v", decErr)
	}

	// Chain counter should be 1 (first message).
	if chainCounter != 1 {
		t.Errorf("chainCounter: got %d, want 1", chainCounter)
	}

	// Braid epoch should be 1 (initialized at epoch 1).
	if braidMsg.Epoch != 1 {
		t.Errorf("braid epoch: got %d, want 1", braidMsg.Epoch)
	}

	// Alice's first Send should produce a Header message (keys unsampled -> sampled).
	if braidMsg.Type != mlkembraid.MessageTypeHdr {
		t.Errorf("msgType: got %s, want Hdr", braidMsg.Type)
	}
	if braidMsg.Data == nil {
		t.Error("expected chunk data for Hdr message")
	}
}

func TestSendRecvBraid_RoundTrip(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	kemAlice := mlkembraid.NewMLKEM768IncrementalKEM()
	kemBob := mlkembraid.NewMLKEM768IncrementalKEM()

	braidAlice, err := mlkembraid.InitAlice(sharedSecret, kemAlice, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice failed: %v", err)
	}
	braidBob, err := mlkembraid.InitBob(sharedSecret, kemBob, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitBob failed: %v", err)
	}

	alice, err := InitWithBraid(sharedSecret, DirectionA2B, maxJump, braidAlice)
	if err != nil {
		t.Fatalf("InitWithBraid(Alice) failed: %v", err)
	}
	defer alice.Zeroize()

	bob, err := InitWithBraid(sharedSecret, DirectionB2A, maxJump, braidBob)
	if err != nil {
		t.Fatalf("InitWithBraid(Bob) failed: %v", err)
	}
	defer bob.Zeroize()

	// Alice sends a message.
	pqrMsg, aliceMK, err := alice.SendBraid()
	if err != nil {
		t.Fatalf("Alice SendBraid failed: %v", err)
	}

	// Bob receives Alice's message.
	bobMK, err := bob.RecvBraid(pqrMsg)
	if err != nil {
		t.Fatalf("Bob RecvBraid failed: %v", err)
	}

	// Both should derive the same message key.
	if !bytes.Equal(aliceMK, bobMK) {
		t.Errorf("message keys do not match:\n  alice: %x\n  bob:   %x", aliceMK, bobMK)
	}
}

func TestSendRecvBraid_MultipleMessages(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	kemAlice := mlkembraid.NewMLKEM768IncrementalKEM()
	kemBob := mlkembraid.NewMLKEM768IncrementalKEM()

	braidAlice, err := mlkembraid.InitAlice(sharedSecret, kemAlice, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice failed: %v", err)
	}
	braidBob, err := mlkembraid.InitBob(sharedSecret, kemBob, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitBob failed: %v", err)
	}

	alice, err := InitWithBraid(sharedSecret, DirectionA2B, maxJump, braidAlice)
	if err != nil {
		t.Fatalf("InitWithBraid(Alice) failed: %v", err)
	}
	defer alice.Zeroize()

	bob, err := InitWithBraid(sharedSecret, DirectionB2A, maxJump, braidBob)
	if err != nil {
		t.Fatalf("InitWithBraid(Bob) failed: %v", err)
	}
	defer bob.Zeroize()

	// Exchange several messages and verify keys match.
	for i := 0; i < 10; i++ {
		// Alice -> Bob
		pqrMsg, aliceMK, sendErr := alice.SendBraid()
		if sendErr != nil {
			t.Fatalf("Alice SendBraid [%d] failed: %v", i, sendErr)
		}

		bobMK, recvErr := bob.RecvBraid(pqrMsg)
		if recvErr != nil {
			t.Fatalf("Bob RecvBraid [%d] failed: %v", i, recvErr)
		}

		if !bytes.Equal(aliceMK, bobMK) {
			t.Errorf("message [%d] A->B keys mismatch:\n  alice: %x\n  bob:   %x", i, aliceMK, bobMK)
		}

		// Bob -> Alice
		pqrMsg, bobMK, sendErr = bob.SendBraid()
		if sendErr != nil {
			t.Fatalf("Bob SendBraid [%d] failed: %v", i, sendErr)
		}

		aliceMK, recvErr = alice.RecvBraid(pqrMsg)
		if recvErr != nil {
			t.Fatalf("Alice RecvBraid [%d] failed: %v", i, recvErr)
		}

		if !bytes.Equal(aliceMK, bobMK) {
			t.Errorf("message [%d] B->A keys mismatch:\n  alice: %x\n  bob:   %x", i, aliceMK, bobMK)
		}
	}
}

func TestAdvanceEpoch(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	s, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer s.Zeroize()

	if s.Epoch() != 0 {
		t.Fatalf("initial epoch: got %d, want 0", s.Epoch())
	}

	// Create a fake output key for advancement.
	outputKeyBytes := make([]byte, 32)
	for i := range outputKeyBytes {
		outputKeyBytes[i] = byte(i + 100)
	}

	// Need to import secret.New - but we're in the package, so we can use it directly.
	outputKeyCopy := make([]byte, 32)
	copy(outputKeyCopy, outputKeyBytes)

	outputKey, secErr := newTestSecret(outputKeyCopy)
	if secErr != nil {
		t.Fatalf("secret.New failed: %v", secErr)
	}

	err = s.advanceEpoch(outputKey)
	if err != nil {
		t.Fatalf("advanceEpoch failed: %v", err)
	}

	if s.Epoch() != 1 {
		t.Errorf("epoch after advance: got %d, want 1", s.Epoch())
	}

	// The new epoch chain should exist.
	if _, ok := s.chains[1]; !ok {
		t.Error("epoch 1 chain not found")
	}
}

func TestAdvanceEpoch_NilKey(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	s, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer s.Zeroize()

	err = s.advanceEpoch(nil)
	if err == nil {
		t.Fatal("expected error for nil output key")
	}
	if _, ok := err.(*ErrInvalidInput); !ok {
		t.Errorf("expected *ErrInvalidInput, got %T: %v", err, err)
	}
}

func TestSetBraid(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	s, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer s.Zeroize()

	if s.Braid() != nil {
		t.Fatal("braid should be nil initially")
	}

	kem := mlkembraid.NewMLKEM768IncrementalKEM()
	braid, err := mlkembraid.InitAlice(sharedSecret, kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice failed: %v", err)
	}

	s.SetBraid(braid)
	if s.Braid() == nil {
		t.Fatal("braid should not be nil after SetBraid")
	}
}

// newTestSecret creates a secret from a byte slice for testing.
// Uses the real secret.New under the hood.
func newTestSecret(data []byte) (*secret.Secret, error) {
	return secret.New(data)
}
