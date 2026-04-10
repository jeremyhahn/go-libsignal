package spqr

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
)

// TestSendRecvBraidViaPackageLevelAPI tests that the package-level Send()/Recv()
// functions transparently handle braid state in V4 format.
func TestSendRecvBraidViaPackageLevelAPI(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	kemAlice := mlkembraid.NewMLKEM768IncrementalKEM()
	kemBob := mlkembraid.NewMLKEM768IncrementalKEM()

	braidAlice, err := mlkembraid.InitAlice(sharedSecret, kemAlice, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}
	braidBob, err := mlkembraid.InitBob(sharedSecret, kemBob, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitBob: %v", err)
	}

	// Create pre-resolved states with braid.
	aliceState, err := InitialStateWithBraidResolved(sharedSecret, DirectionA2B, false, braidAlice)
	if err != nil {
		t.Fatalf("InitialStateWithBraidResolved(Alice): %v", err)
	}
	bobState, err := InitialStateWithBraidResolved(sharedSecret, DirectionB2A, false, braidBob)
	if err != nil {
		t.Fatalf("InitialStateWithBraidResolved(Bob): %v", err)
	}

	// Alice sends via package-level Send().
	newAliceState, pqrMsg, aliceKey, sendErr := Send(aliceState)
	if sendErr != nil {
		t.Fatalf("Send(alice): %v", sendErr)
	}
	if len(pqrMsg) == 0 {
		t.Fatal("expected non-empty wire message from braid path")
	}
	if len(aliceKey) == 0 {
		t.Fatal("expected non-nil message key")
	}

	// Wire message should NOT be 12 bytes (braid uses variable-length format).
	if len(pqrMsg) == pqrMsgSize {
		t.Error("braid path should use variable-length wire format, not legacy 12-byte format")
	}

	// Bob receives via package-level Recv().
	newBobState, bobKey, recvErr := Recv(bobState, pqrMsg)
	if recvErr != nil {
		t.Fatalf("Recv(bob): %v", recvErr)
	}

	if !bytes.Equal(aliceKey, bobKey) {
		t.Errorf("message keys do not match:\n  alice: %x\n  bob:   %x", aliceKey, bobKey)
	}

	// Verify states were updated and are V4 format.
	if newAliceState[0] != serializeVersionV4 {
		t.Errorf("alice state version: got %d, want V4 (%d)", newAliceState[0], serializeVersionV4)
	}
	if newBobState[0] != serializeVersionV4 {
		t.Errorf("bob state version: got %d, want V4 (%d)", newBobState[0], serializeVersionV4)
	}
}

// TestSendRecvBraidMultipleRoundTrips tests multiple bidirectional exchanges
// through the package-level API with braid state.
func TestSendRecvBraidMultipleRoundTrips(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	kemAlice := mlkembraid.NewMLKEM768IncrementalKEM()
	kemBob := mlkembraid.NewMLKEM768IncrementalKEM()

	braidAlice, err := mlkembraid.InitAlice(sharedSecret, kemAlice, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}
	braidBob, err := mlkembraid.InitBob(sharedSecret, kemBob, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitBob: %v", err)
	}

	aliceState, err := InitialStateWithBraidResolved(sharedSecret, DirectionA2B, false, braidAlice)
	if err != nil {
		t.Fatalf("InitialStateWithBraidResolved(Alice): %v", err)
	}
	bobState, err := InitialStateWithBraidResolved(sharedSecret, DirectionB2A, false, braidBob)
	if err != nil {
		t.Fatalf("InitialStateWithBraidResolved(Bob): %v", err)
	}

	for i := 0; i < 10; i++ {
		// Alice -> Bob.
		var pqrMsg []byte
		var aliceKey, bobKey MessageKey
		aliceState, pqrMsg, aliceKey, err = Send(aliceState)
		if err != nil {
			t.Fatalf("Send(alice)[%d]: %v", i, err)
		}
		bobState, bobKey, err = Recv(bobState, pqrMsg)
		if err != nil {
			t.Fatalf("Recv(bob)[%d]: %v", i, err)
		}
		if !bytes.Equal(aliceKey, bobKey) {
			t.Errorf("A->B key mismatch at round %d", i)
		}

		// Bob -> Alice.
		bobState, pqrMsg, bobKey, err = Send(bobState)
		if err != nil {
			t.Fatalf("Send(bob)[%d]: %v", i, err)
		}
		aliceState, aliceKey, err = Recv(aliceState, pqrMsg)
		if err != nil {
			t.Fatalf("Recv(alice)[%d]: %v", i, err)
		}
		if !bytes.Equal(aliceKey, bobKey) {
			t.Errorf("B->A key mismatch at round %d", i)
		}
	}
}

// TestSendRecvNoBraidLegacyPath tests that the package-level Send()/Recv()
// still works correctly with V3 state (no braid) using 12-byte wire format.
func TestSendRecvNoBraidLegacyPath(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	sharedCopy := make([]byte, 32)
	copy(sharedCopy, sharedSecret)

	// Pre-resolve both sides without braid (V3 format).
	aliceSPQR, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init alice: %v", err)
	}
	aliceState, err := aliceSPQR.Serialize()
	if err != nil {
		t.Fatalf("Serialize alice: %v", err)
	}
	aliceSPQR.Zeroize()

	bobSPQR, err := Init(sharedCopy, DirectionB2A, maxJump)
	if err != nil {
		t.Fatalf("Init bob: %v", err)
	}
	bobState, err := bobSPQR.Serialize()
	if err != nil {
		t.Fatalf("Serialize bob: %v", err)
	}
	bobSPQR.Zeroize()

	// Verify V3 format.
	if aliceState[0] != serializeVersionV3 {
		t.Errorf("expected V3 format, got version %d", aliceState[0])
	}

	// Send/Recv should use legacy 12-byte wire format.
	var pqrMsg []byte
	var aliceKey, bobKey MessageKey
	aliceState, pqrMsg, aliceKey, err = Send(aliceState)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(pqrMsg) != pqrMsgSize {
		t.Errorf("legacy path should produce %d-byte message, got %d", pqrMsgSize, len(pqrMsg))
	}

	bobState, bobKey, err = Recv(bobState, pqrMsg)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if !bytes.Equal(aliceKey, bobKey) {
		t.Error("key mismatch on legacy path")
	}

	// States remain V3.
	if aliceState[0] != serializeVersionV3 {
		t.Errorf("alice state should remain V3, got version %d", aliceState[0])
	}
	if bobState[0] != serializeVersionV3 {
		t.Errorf("bob state should remain V3, got version %d", bobState[0])
	}
}

// TestV4SerializationRoundTrip tests that V4 serialization round-trips correctly,
// preserving braid state across serialize/deserialize cycles.
func TestV4SerializationRoundTrip(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	kemAlice := mlkembraid.NewMLKEM768IncrementalKEM()
	braidAlice, err := mlkembraid.InitAlice(sharedSecret, kemAlice, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}

	aliceState, err := InitialStateWithBraidResolved(sharedSecret, DirectionA2B, false, braidAlice)
	if err != nil {
		t.Fatalf("InitialStateWithBraidResolved: %v", err)
	}

	// Deserialize and verify braid is present.
	s, err := Deserialize(aliceState)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if s.braid == nil {
		t.Fatal("braid should not be nil after V4 deserialization")
	}
	if s.braid.Epoch() != 1 {
		t.Errorf("braid epoch: got %d, want 1", s.braid.Epoch())
	}

	// Re-serialize and verify round-trip.
	state2, err := s.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	s.Zeroize()

	if state2[0] != serializeVersionV4 {
		t.Errorf("re-serialized version: got %d, want V4 (%d)", state2[0], serializeVersionV4)
	}

	// Deserialize again and verify braid is still intact.
	s2, err := Deserialize(state2)
	if err != nil {
		t.Fatalf("Deserialize(2): %v", err)
	}
	defer s2.Zeroize()

	if s2.braid == nil {
		t.Fatal("braid should survive round-trip")
	}
	if s2.braid.Epoch() != 1 {
		t.Errorf("braid epoch after round-trip: got %d, want 1", s2.braid.Epoch())
	}
	if !s2.IsNegotiated() {
		t.Error("should be negotiated after round-trip")
	}
	if s2.NegotiatedVersion() != VersionV1 {
		t.Errorf("version after round-trip: got %v, want V1", s2.NegotiatedVersion())
	}
}

// TestV4PendingWithBraidRoundTrip tests V4 pending state serialization with braid.
func TestV4PendingWithBraidRoundTrip(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	kemAlice := mlkembraid.NewMLKEM768IncrementalKEM()
	braidAlice, err := mlkembraid.InitAlice(sharedSecret, kemAlice, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}

	// Create pending state with braid.
	state, err := InitialStateWithBraid(sharedSecret, DirectionA2B, false, braidAlice)
	if err != nil {
		t.Fatalf("InitialStateWithBraid: %v", err)
	}

	if state[0] != serializeVersionV4 {
		t.Errorf("expected V4 format, got version %d", state[0])
	}

	// Deserialize and verify.
	s, err := Deserialize(state)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	defer s.Zeroize()

	if s.negotiation != negotiationPending {
		t.Error("should be pending negotiation")
	}
	if s.braid == nil {
		t.Fatal("braid should not be nil in pending state")
	}
	if len(s.authKey) != keyLen {
		t.Errorf("authKey length: got %d, want %d", len(s.authKey), keyLen)
	}
}

// TestInitialStateWithBraidNilBraid tests error handling for nil braid.
func TestInitialStateWithBraidNilBraid(t *testing.T) {
	sharedSecret := make([]byte, 32)
	_, err := InitialStateWithBraid(sharedSecret, DirectionA2B, false, nil)
	if err == nil {
		t.Fatal("expected error for nil braid")
	}
	var inputErr *ErrInvalidInput
	if !errors.As(err, &inputErr) {
		t.Errorf("expected *ErrInvalidInput, got %T: %v", err, err)
	}
}

// TestInitialStateWithBraidEmptySecret tests error handling for empty shared secret.
func TestInitialStateWithBraidEmptySecret(t *testing.T) {
	kem := mlkembraid.NewMLKEM768IncrementalKEM()
	sharedSecret := make([]byte, 32)
	braid, err := mlkembraid.InitAlice(sharedSecret, kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}
	defer braid.Zeroize()

	_, err = InitialStateWithBraid(nil, DirectionA2B, false, braid)
	if err == nil {
		t.Fatal("expected error for empty shared secret")
	}
}

// TestInitialStateWithBraidResolvedNilBraid tests error handling for nil braid.
func TestInitialStateWithBraidResolvedNilBraid(t *testing.T) {
	sharedSecret := make([]byte, 32)
	_, err := InitialStateWithBraidResolved(sharedSecret, DirectionA2B, false, nil)
	if err == nil {
		t.Fatal("expected error for nil braid")
	}
	var inputErr *ErrInvalidInput
	if !errors.As(err, &inputErr) {
		t.Errorf("expected *ErrInvalidInput, got %T: %v", err, err)
	}
}

// TestInitialStateWithBraidSelfSession tests self-session maxJump.
func TestInitialStateWithBraidSelfSession(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	kem := mlkembraid.NewMLKEM768IncrementalKEM()
	braid, err := mlkembraid.InitAlice(sharedSecret, kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}

	state, err := InitialStateWithBraid(sharedSecret, DirectionA2B, true, braid)
	if err != nil {
		t.Fatalf("InitialStateWithBraid: %v", err)
	}

	s, err := Deserialize(state)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	defer s.Zeroize()

	if s.maxJump != ^uint32(0) {
		t.Errorf("maxJump: got %d, want MaxUint32", s.maxJump)
	}
}

// TestV3BackwardCompatibilityWithUpdatedSendRecv tests that existing V3 states
// continue to work correctly with the updated Send()/Recv() functions.
func TestV3BackwardCompatibilityWithUpdatedSendRecv(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	sharedCopy := make([]byte, 32)
	copy(sharedCopy, sharedSecret)

	// Create V3 pending states (no braid).
	aliceState, err := InitialState(sharedSecret, DirectionA2B, false)
	if err != nil {
		t.Fatalf("InitialState alice: %v", err)
	}
	bobState, err := InitialState(sharedCopy, DirectionB2A, false)
	if err != nil {
		t.Fatalf("InitialState bob: %v", err)
	}

	// Verify V3 format.
	if aliceState[0] != serializeVersionV3 {
		t.Fatalf("expected V3, got %d", aliceState[0])
	}

	// Alice sends (pending -> empty).
	_, pqrMsg, aliceKey, err := Send(aliceState)
	if err != nil {
		t.Fatalf("Alice Send: %v", err)
	}
	if len(pqrMsg) != 0 || aliceKey != nil {
		t.Error("pending Send should return empty msg and nil key")
	}

	// Bob receives empty msg -> V0.
	bobState, bobKey, err := Recv(bobState, pqrMsg)
	if err != nil {
		t.Fatalf("Bob Recv: %v", err)
	}
	if bobKey != nil {
		t.Error("V0 negotiation should return nil key")
	}

	// Subsequent Send on V0 returns empty.
	_, pqrMsg, bobKey, err = Send(bobState)
	if err != nil {
		t.Fatalf("Bob Send: %v", err)
	}
	if len(pqrMsg) != 0 || bobKey != nil {
		t.Error("V0 Send should return empty msg and nil key")
	}
}

// TestBraidStatePersistedAcrossMessages tests that braid state is correctly
// persisted and advanced through multiple serialize/deserialize cycles via Send/Recv.
func TestBraidStatePersistedAcrossMessages(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	kemAlice := mlkembraid.NewMLKEM768IncrementalKEM()
	kemBob := mlkembraid.NewMLKEM768IncrementalKEM()

	braidAlice, err := mlkembraid.InitAlice(sharedSecret, kemAlice, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}
	braidBob, err := mlkembraid.InitBob(sharedSecret, kemBob, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitBob: %v", err)
	}

	aliceState, err := InitialStateWithBraidResolved(sharedSecret, DirectionA2B, false, braidAlice)
	if err != nil {
		t.Fatalf("InitialStateWithBraidResolved(Alice): %v", err)
	}
	bobState, err := InitialStateWithBraidResolved(sharedSecret, DirectionB2A, false, braidBob)
	if err != nil {
		t.Fatalf("InitialStateWithBraidResolved(Bob): %v", err)
	}

	// Exchange 5 messages and verify braid state changes.
	for i := 0; i < 5; i++ {
		var pqrMsg []byte
		var aliceKey, bobKey MessageKey

		aliceState, pqrMsg, aliceKey, err = Send(aliceState)
		if err != nil {
			t.Fatalf("Send(alice)[%d]: %v", i, err)
		}

		// Verify braid exists in deserialized state.
		s, deserErr := Deserialize(aliceState)
		if deserErr != nil {
			t.Fatalf("Deserialize(alice)[%d]: %v", i, deserErr)
		}
		if s.braid == nil {
			t.Fatalf("braid lost after Send at round %d", i)
		}
		s.Zeroize()

		bobState, bobKey, err = Recv(bobState, pqrMsg)
		if err != nil {
			t.Fatalf("Recv(bob)[%d]: %v", i, err)
		}
		if !bytes.Equal(aliceKey, bobKey) {
			t.Errorf("key mismatch at round %d", i)
		}

		// Verify braid exists in Bob's deserialized state.
		s, deserErr = Deserialize(bobState)
		if deserErr != nil {
			t.Fatalf("Deserialize(bob)[%d]: %v", i, deserErr)
		}
		if s.braid == nil {
			t.Fatalf("braid lost after Recv at round %d", i)
		}
		s.Zeroize()
	}
}

// TestV4DeserializeInvalidData tests V4 deserialization error handling.
func TestV4DeserializeInvalidData(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"v4 too short", []byte{serializeVersionV4}},
		{"v4 invalid negotiation byte", []byte{serializeVersionV4, 0x05}},
		{"v4 resolved too short", []byte{serializeVersionV4, 0x01}},
		{"v4 resolved unsupported version", []byte{serializeVersionV4, 0x01, 0x05}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Deserialize(tt.data)
			if err == nil {
				t.Fatal("expected error for invalid V4 data")
			}
			var deserErr *ErrDeserialize
			if !errors.As(err, &deserErr) {
				t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
			}
		})
	}
}

// TestV4PendingTruncatedBraid tests that truncated braid data is rejected.
func TestV4PendingTruncatedBraid(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	kem := mlkembraid.NewMLKEM768IncrementalKEM()
	braid, err := mlkembraid.InitAlice(sharedSecret, kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}

	state, err := InitialStateWithBraid(sharedSecret, DirectionA2B, false, braid)
	if err != nil {
		t.Fatalf("InitialStateWithBraid: %v", err)
	}

	// Truncate after hasBraid byte.
	truncated := state[:len(state)-10]
	_, err = Deserialize(truncated)
	if err == nil {
		t.Fatal("expected error for truncated braid data")
	}
	var deserErr *ErrDeserialize
	if !errors.As(err, &deserErr) {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}
