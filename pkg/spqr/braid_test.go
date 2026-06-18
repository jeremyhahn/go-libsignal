package spqr

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// TestInitWithBraid_EmptySharedSecret verifies that InitWithBraid propagates
// the Init error when sharedSecret is empty.
func TestInitWithBraid_EmptySharedSecret(t *testing.T) {
	kem := mlkembraid.NewMLKEM768IncrementalKEM()
	braid, err := mlkembraid.InitAlice(make([]byte, 32), kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}
	_, err = InitWithBraid(nil, DirectionA2B, uint32(maxJump), braid)
	if err == nil {
		t.Fatal("expected error for nil sharedSecret")
	}
}

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

// TestSendBraid_PendingMinVersionV0ReturnsEmpty exercises the SendBraid path
// where negotiation is still pending and minVersion < V1. In this state,
// SendBraid returns empty bytes and nil key (deferred to later negotiation).
func TestSendBraid_PendingMinVersionV0ReturnsEmpty(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	kem := mlkembraid.NewMLKEM768IncrementalKEM()
	braid, err := mlkembraid.InitAlice(sharedSecret, kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}

	// Construct SPQR in negotiationPending state with minVersion=V0 (< V1).
	authKeyBytes := make([]byte, 32)
	for i := range authKeyBytes {
		authKeyBytes[i] = byte(i + 0xAA)
	}
	authKeyCopy := make([]byte, len(authKeyBytes))
	copy(authKeyCopy, authKeyBytes)

	s := &SPQR{
		chains:      make(map[uint64]*EpochChain),
		skippedKeys: make(map[SkippedKeyID]*secret.Secret),
		direction:   DirectionA2B,
		maxJump:     uint32(maxJump),
		negotiation: negotiationPending,
		version:     VersionV1,
		minVersion:  VersionV0, // < VersionV1 → triggers empty-return path
		authKey:     authKeyCopy,
		braid:       braid,
	}
	defer s.Zeroize()

	pqrMsg, messageKey, err := s.SendBraid()
	if err != nil {
		t.Fatalf("SendBraid: unexpected error: %v", err)
	}
	if len(pqrMsg) != 0 {
		t.Errorf("expected empty pqrMsg for pending V0 negotiation, got %d bytes", len(pqrMsg))
	}
	if messageKey != nil {
		t.Errorf("expected nil messageKey for pending V0 negotiation, got %d bytes", len(messageKey))
	}
}

// TestRecvBraid_PendingMinVersionV0ReturnsNil exercises the RecvBraid path
// where negotiation is pending and minVersion < V1. RecvBraid should resolve
// negotiation to V0-disabled and return nil message key.
func TestRecvBraid_PendingMinVersionV0ReturnsNil(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	kem := mlkembraid.NewMLKEM768IncrementalKEM()
	braid, err := mlkembraid.InitAlice(sharedSecret, kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}

	authKeyBytes := make([]byte, 32)
	for i := range authKeyBytes {
		authKeyBytes[i] = byte(i + 0xBB)
	}
	authKeyCopy := make([]byte, len(authKeyBytes))
	copy(authKeyCopy, authKeyBytes)

	s := &SPQR{
		chains:      make(map[uint64]*EpochChain),
		skippedKeys: make(map[SkippedKeyID]*secret.Secret),
		direction:   DirectionA2B,
		maxJump:     uint32(maxJump),
		negotiation: negotiationPending,
		version:     VersionV1,
		minVersion:  VersionV0,
		authKey:     authKeyCopy,
		braid:       braid,
	}
	defer s.Zeroize()

	// An empty pqrMsg signals V0 (peer does not support PQR). Since minVersion=V0,
	// negotiation resolves to disabled and RecvBraid returns nil without error.
	pqrMsg := []byte{}
	messageKey, err := s.RecvBraid(pqrMsg)
	if err != nil {
		t.Fatalf("RecvBraid: unexpected error: %v", err)
	}
	// V0-disabled: nil message key.
	if messageKey != nil {
		t.Errorf("expected nil messageKey for V0 negotiation, got %d bytes", len(messageKey))
	}
}
