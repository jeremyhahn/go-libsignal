package spqr

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"testing"
)

func TestInitialState(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	state, err := InitialState(sharedSecret, DirectionA2B, false)
	if err != nil {
		t.Fatalf("InitialState: %v", err)
	}
	if len(state) == 0 {
		t.Fatal("serialized state is empty")
	}

	// Verify we can deserialize it as a pending negotiation.
	s, err := Deserialize(state)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	defer s.Zeroize()

	if s.negotiation != negotiationPending {
		t.Errorf("negotiation: got %d, want pending", s.negotiation)
	}
	if s.direction != DirectionA2B {
		t.Errorf("direction: got %v, want A2B", s.direction)
	}
	if len(s.authKey) != keyLen {
		t.Errorf("authKey length: got %d, want %d", len(s.authKey), keyLen)
	}
}

func TestInitialStateInvalidInput(t *testing.T) {
	_, err := InitialState(nil, DirectionA2B, false)
	if err == nil {
		t.Fatal("expected error for nil shared secret")
	}
}

// TestSendRecvV1Negotiation tests the V1 version negotiation flow where both
// sides start pending, one resolves via Init (simulating pre-resolved state),
// and the other resolves via receiving PQR data.
func TestSendRecvV1Negotiation(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	sharedCopy := make([]byte, 32)
	copy(sharedCopy, sharedSecret)

	// Create Alice with pre-resolved V1 state (simulates the initiator side
	// that knows PQR is supported from X3DH setup).
	aliceSPQR, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init alice: %v", err)
	}
	aliceState, err := aliceSPQR.Serialize()
	if err != nil {
		t.Fatalf("Serialize alice: %v", err)
	}
	aliceSPQR.Zeroize()

	// Create Bob with pending negotiation.
	bobState, err := InitialState(sharedCopy, DirectionB2A, false)
	if err != nil {
		t.Fatalf("InitialState bob: %v", err)
	}

	// Alice sends (resolved V1 -> produces PQR data).
	newAliceState, pqrMsg, aliceKey, sendErr := Send(aliceState)
	if sendErr != nil {
		t.Fatalf("Send: %v", sendErr)
	}
	if len(pqrMsg) != pqrMsgSize {
		t.Fatalf("pqrMsg size: got %d, want %d", len(pqrMsg), pqrMsgSize)
	}
	if len(aliceKey) != keyLen {
		t.Fatalf("message key size: got %d, want %d", len(aliceKey), keyLen)
	}

	// Verify wire format: epoch=0, counter=1.
	wireEpoch := binary.BigEndian.Uint64(pqrMsg[0:8])
	wireCounter := binary.BigEndian.Uint32(pqrMsg[8:12])
	if wireEpoch != 0 {
		t.Errorf("wire epoch: got %d, want 0", wireEpoch)
	}
	if wireCounter != 1 {
		t.Errorf("wire counter: got %d, want 1", wireCounter)
	}

	// Bob receives (pending + non-empty PQR -> resolves to V1).
	newBobState, bobKey, recvErr := Recv(bobState, pqrMsg)
	if recvErr != nil {
		t.Fatalf("Recv: %v", recvErr)
	}

	// Keys must match.
	if !bytes.Equal(aliceKey, bobKey) {
		t.Error("alice and bob message keys do not match")
	}

	// Verify states were updated.
	if bytes.Equal(aliceState, newAliceState) {
		t.Error("alice state should have changed after Send")
	}
	if bytes.Equal(bobState, newBobState) {
		t.Error("bob state should have changed after Recv")
	}

	// Verify Bob is now resolved to V1.
	bobSPQR, err := Deserialize(newBobState)
	if err != nil {
		t.Fatalf("Deserialize bob: %v", err)
	}
	if !bobSPQR.IsNegotiated() {
		t.Error("bob should be negotiated after Recv")
	}
	if bobSPQR.NegotiatedVersion() != VersionV1 {
		t.Errorf("bob version: got %v, want V1", bobSPQR.NegotiatedVersion())
	}
	bobSPQR.Zeroize()
}

// TestSendPendingReturnsEmptyMsg verifies that Send on a pending state returns
// an empty PQR message and nil key.
func TestSendPendingReturnsEmptyMsg(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	state, err := InitialState(sharedSecret, DirectionA2B, false)
	if err != nil {
		t.Fatalf("InitialState: %v", err)
	}

	newState, pqrMsg, key, sendErr := Send(state)
	if sendErr != nil {
		t.Fatalf("Send: %v", sendErr)
	}
	if len(pqrMsg) != 0 {
		t.Errorf("pqrMsg should be empty during pending negotiation, got %d bytes", len(pqrMsg))
	}
	if key != nil {
		t.Error("message key should be nil during pending negotiation")
	}
	if len(newState) == 0 {
		t.Error("new state should not be empty")
	}
}

// TestRecvEmptyResolvesV0 tests that receiving an empty PQR message during
// pending negotiation resolves to V0 (disabled).
func TestRecvEmptyResolvesV0(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	state, err := InitialState(sharedSecret, DirectionA2B, false)
	if err != nil {
		t.Fatalf("InitialState: %v", err)
	}

	// Recv with empty msg -> resolves V0.
	newState, key, recvErr := Recv(state, []byte{})
	if recvErr != nil {
		t.Fatalf("Recv: %v", recvErr)
	}
	if key != nil {
		t.Error("message key should be nil for V0")
	}

	// Verify resolved to V0.
	s, err := Deserialize(newState)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	defer s.Zeroize()

	if !s.IsNegotiated() {
		t.Error("should be negotiated")
	}
	if !s.IsDisabled() {
		t.Error("should be disabled (V0)")
	}

	// Subsequent Send should return empty + nil.
	newState2, pqrMsg, key2, sendErr := Send(newState)
	if sendErr != nil {
		t.Fatalf("Send after V0: %v", sendErr)
	}
	if len(pqrMsg) != 0 {
		t.Errorf("pqrMsg should be empty for V0, got %d bytes", len(pqrMsg))
	}
	if key2 != nil {
		t.Error("message key should be nil for V0")
	}
	if len(newState2) == 0 {
		t.Error("state should not be empty")
	}
}

// TestRecvNilResolvesV0 tests that receiving a nil PQR message during
// pending negotiation resolves to V0.
func TestRecvNilResolvesV0(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	state, err := InitialState(sharedSecret, DirectionA2B, false)
	if err != nil {
		t.Fatalf("InitialState: %v", err)
	}

	newState, key, recvErr := Recv(state, nil)
	if recvErr != nil {
		t.Fatalf("Recv: %v", recvErr)
	}
	if key != nil {
		t.Error("message key should be nil for V0")
	}

	s, err := Deserialize(newState)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	defer s.Zeroize()

	if !s.IsDisabled() {
		t.Error("should be disabled (V0)")
	}
}

// TestMinVersionRejectsV0 tests that minVersion > V0 rejects empty PQR messages
// during negotiation.
func TestMinVersionRejectsV0(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	state, err := InitialStateWithParams(Params{
		AuthKey:    sharedSecret,
		Version:    VersionV1,
		Direction:  DirectionA2B,
		MinVersion: VersionV1, // Require V1 minimum.
		MaxJump:    maxJump,
		MaxOOOKeys: maxSkippedKeys,
	})
	if err != nil {
		t.Fatalf("InitialStateWithParams: %v", err)
	}

	// Recv with empty -> should fail because minVersion is V1.
	_, _, recvErr := Recv(state, []byte{})
	if recvErr == nil {
		t.Fatal("expected error for V0 fallback with minVersion=V1")
	}
	var negErr *ErrVersionNegotiationFailed
	if !errors.As(recvErr, &negErr) {
		t.Errorf("expected *ErrVersionNegotiationFailed, got %T: %v", recvErr, recvErr)
	}
}

// TestV0RoundTrip tests a full bidirectional exchange where both sides
// negotiate to V0 (PQR disabled).
func TestV0RoundTrip(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	sharedCopy := make([]byte, 32)
	copy(sharedCopy, sharedSecret)

	aliceState, err := InitialState(sharedSecret, DirectionA2B, false)
	if err != nil {
		t.Fatalf("InitialState alice: %v", err)
	}
	bobState, err := InitialState(sharedCopy, DirectionB2A, false)
	if err != nil {
		t.Fatalf("InitialState bob: %v", err)
	}

	// Alice sends (pending -> empty msg).
	aliceState, pqrMsg, aliceKey, err := Send(aliceState)
	if err != nil {
		t.Fatalf("Alice Send: %v", err)
	}
	if len(pqrMsg) != 0 {
		t.Errorf("expected empty pqrMsg, got %d bytes", len(pqrMsg))
	}
	if aliceKey != nil {
		t.Error("expected nil key from pending Send")
	}

	// Bob receives empty msg (pending -> V0).
	bobState, bobKey, err := Recv(bobState, pqrMsg)
	if err != nil {
		t.Fatalf("Bob Recv: %v", err)
	}
	if bobKey != nil {
		t.Error("expected nil key for V0 negotiation")
	}

	// Bob sends (V0 -> empty msg).
	_, pqrMsg, bobKey, err = Send(bobState)
	if err != nil {
		t.Fatalf("Bob Send: %v", err)
	}
	if len(pqrMsg) != 0 {
		t.Errorf("expected empty pqrMsg for V0, got %d bytes", len(pqrMsg))
	}
	if bobKey != nil {
		t.Error("expected nil key for V0 Send")
	}

	// Alice receives empty msg (pending -> V0).
	aliceState, aliceKey, err = Recv(aliceState, pqrMsg)
	if err != nil {
		t.Fatalf("Alice Recv: %v", err)
	}
	if aliceKey != nil {
		t.Error("expected nil key for V0 negotiation")
	}

	// Both V0 now: all subsequent sends return empty + nil.
	for i := 0; i < 3; i++ {
		aliceState, pqrMsg, aliceKey, err = Send(aliceState)
		if err != nil {
			t.Fatalf("Alice Send %d: %v", i, err)
		}
		if aliceKey != nil || len(pqrMsg) != 0 {
			t.Errorf("round %d: expected empty msg and nil key for V0", i)
		}
	}
}

// TestMultipleSendRecvV1 tests multiple message exchanges after V1 negotiation.
func TestMultipleSendRecvV1(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	sharedCopy := make([]byte, 32)
	copy(sharedCopy, sharedSecret)

	// Pre-resolve Alice to V1.
	aliceSPQR, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init alice: %v", err)
	}
	aliceState, err := aliceSPQR.Serialize()
	if err != nil {
		t.Fatalf("Serialize alice: %v", err)
	}
	aliceSPQR.Zeroize()

	// Bob starts with pending negotiation.
	bobState, err := InitialState(sharedCopy, DirectionB2A, false)
	if err != nil {
		t.Fatalf("InitialState bob: %v", err)
	}

	var prevKey MessageKey
	for i := 0; i < 5; i++ {
		var pqrMsg []byte
		var key MessageKey

		aliceState, pqrMsg, key, err = Send(aliceState)
		if err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
		if len(key) != keyLen {
			t.Fatalf("Send %d: key length %d, want %d", i, len(key), keyLen)
		}

		// Each key should differ from the previous.
		if prevKey != nil && bytes.Equal(key, prevKey) {
			t.Errorf("message key %d is the same as previous", i)
		}

		var bobKey MessageKey
		bobState, bobKey, err = Recv(bobState, pqrMsg)
		if err != nil {
			t.Fatalf("Recv %d: %v", i, err)
		}

		if !bytes.Equal(key, bobKey) {
			t.Errorf("message key mismatch at round %d", i)
		}

		prevKey = key
	}
}

// TestSendRecvBidirectionalV1 tests bidirectional V1 exchange.
func TestSendRecvBidirectionalV1(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	sharedCopy := make([]byte, 32)
	copy(sharedCopy, sharedSecret)

	// Pre-resolve both sides.
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

	// Alice sends to Bob.
	var pqrMsg []byte
	var key MessageKey
	aliceState, pqrMsg, key, err = Send(aliceState)
	if err != nil {
		t.Fatalf("Alice Send: %v", err)
	}
	var bobKey MessageKey
	bobState, bobKey, err = Recv(bobState, pqrMsg)
	if err != nil {
		t.Fatalf("Bob Recv: %v", err)
	}
	if !bytes.Equal(key, bobKey) {
		t.Error("A->B key mismatch")
	}

	// Bob sends to Alice.
	bobState, pqrMsg, key, err = Send(bobState)
	if err != nil {
		t.Fatalf("Bob Send: %v", err)
	}
	aliceState, bobKey, err = Recv(aliceState, pqrMsg)
	if err != nil {
		t.Fatalf("Alice Recv: %v", err)
	}
	if !bytes.Equal(key, bobKey) {
		t.Error("B->A key mismatch")
	}

	if len(aliceState) == 0 || len(bobState) == 0 {
		t.Error("states should be non-empty after bidirectional exchange")
	}
}

func TestSendRecvWithEpochAdvance(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	sharedCopy := make([]byte, 32)
	copy(sharedCopy, sharedSecret)

	// Pre-resolve both sides to V1 for epoch advance testing.
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

	// Send a message in epoch 0.
	var pqrMsg []byte
	var key MessageKey
	aliceState, pqrMsg, key, err = Send(aliceState)
	if err != nil {
		t.Fatalf("Send epoch 0: %v", err)
	}
	var bobKey MessageKey
	bobState, bobKey, err = Recv(bobState, pqrMsg)
	if err != nil {
		t.Fatalf("Recv epoch 0: %v", err)
	}
	if !bytes.Equal(key, bobKey) {
		t.Error("epoch 0 key mismatch")
	}

	// Advance both to epoch 1 via ReceiveKey.
	sckaOutput := randomBytes(t, 32)

	alice, err := Deserialize(aliceState)
	if err != nil {
		t.Fatalf("Deserialize alice: %v", err)
	}
	if err := alice.ReceiveKey(sckaOutput, 1); err != nil {
		t.Fatalf("alice.ReceiveKey(1): %v", err)
	}
	aliceState, err = alice.Serialize()
	if err != nil {
		t.Fatalf("alice.Serialize: %v", err)
	}
	alice.Zeroize()

	bob, err := Deserialize(bobState)
	if err != nil {
		t.Fatalf("Deserialize bob: %v", err)
	}
	if err := bob.ReceiveKey(sckaOutput, 1); err != nil {
		t.Fatalf("bob.ReceiveKey(1): %v", err)
	}
	bobState, err = bob.Serialize()
	if err != nil {
		t.Fatalf("bob.Serialize: %v", err)
	}
	bob.Zeroize()

	// Send a message in epoch 1.
	aliceState, pqrMsg, key, err = Send(aliceState)
	if err != nil {
		t.Fatalf("Send epoch 1: %v", err)
	}

	// Verify wire format shows epoch 1.
	wireEpoch := binary.BigEndian.Uint64(pqrMsg[0:8])
	if wireEpoch != 1 {
		t.Errorf("wire epoch: got %d, want 1", wireEpoch)
	}

	bobState, bobKey, err = Recv(bobState, pqrMsg)
	if err != nil {
		t.Fatalf("Recv epoch 1: %v", err)
	}
	if !bytes.Equal(key, bobKey) {
		t.Error("epoch 1 key mismatch")
	}

	if len(aliceState) == 0 || len(bobState) == 0 {
		t.Error("states should be non-empty")
	}
}

// TestRecvInvalidPQRMessageAfterV1 tests that invalid PQR messages are rejected
// after V1 negotiation is resolved.
func TestRecvInvalidPQRMessageAfterV1(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	s, err := Init(sharedSecret, DirectionB2A, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	state, err := s.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	s.Zeroize()

	tests := []struct {
		name   string
		pqrMsg []byte
	}{
		{"nil message", nil},
		{"empty message", []byte{}},
		{"too short", []byte{0x01, 0x02}},
		{"too long", make([]byte, pqrMsgSize+1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, recvErr := Recv(state, tt.pqrMsg)
			if recvErr == nil {
				t.Fatal("expected error for invalid PQR message")
			}
			var pqrErr *ErrPQRMessage
			if !errors.As(recvErr, &pqrErr) {
				t.Errorf("expected *ErrPQRMessage, got %T: %v", recvErr, recvErr)
			}
		})
	}
}

func TestSendInvalidState(t *testing.T) {
	_, _, _, err := Send([]byte{0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for invalid state")
	}
}

func TestRecvInvalidState(t *testing.T) {
	pqrMsg := make([]byte, pqrMsgSize)
	_, _, err := Recv([]byte{0x01, 0x02}, pqrMsg)
	if err == nil {
		t.Fatal("expected error for invalid state")
	}
}

func TestInitialStateSelfSession(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	state, err := InitialState(sharedSecret, DirectionA2B, true)
	if err != nil {
		t.Fatalf("InitialState: %v", err)
	}
	if len(state) == 0 {
		t.Fatal("serialized state is empty")
	}

	// Deserialize and verify maxJump is math.MaxUint32.
	s, err := Deserialize(state)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	defer s.Zeroize()

	if s.maxJump != math.MaxUint32 {
		t.Errorf("maxJump: got %d, want %d", s.maxJump, uint32(math.MaxUint32))
	}
}

func TestInitialStateNormalSession(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	state, err := InitialState(sharedSecret, DirectionA2B, false)
	if err != nil {
		t.Fatalf("InitialState: %v", err)
	}

	s, err := Deserialize(state)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	defer s.Zeroize()

	if s.maxJump != maxJump {
		t.Errorf("maxJump: got %d, want %d", s.maxJump, maxJump)
	}
}

func TestPQRMessageErrorString(t *testing.T) {
	err := &ErrPQRMessage{Reason: "bad format"}
	if err.Error() != "spqr: invalid PQR message: bad format" {
		t.Errorf("unexpected error string: %s", err.Error())
	}
}

// TestInitialStateWithParamsValidation tests parameter validation.
func TestInitialStateWithParamsValidation(t *testing.T) {
	t.Run("empty auth key", func(t *testing.T) {
		_, err := InitialStateWithParams(Params{
			AuthKey:    nil,
			Version:    VersionV1,
			Direction:  DirectionA2B,
			MinVersion: VersionV0,
			MaxJump:    maxJump,
		})
		if err == nil {
			t.Fatal("expected error for nil auth key")
		}
	})

	t.Run("min version exceeds version", func(t *testing.T) {
		_, err := InitialStateWithParams(Params{
			AuthKey:    randomBytes(t, 32),
			Version:    VersionV0,
			Direction:  DirectionA2B,
			MinVersion: VersionV1,
			MaxJump:    maxJump,
		})
		if err == nil {
			t.Fatal("expected error for minVersion > version")
		}
	})
}

// TestVersionNegotiationFailed tests the error type for failed negotiation.
func TestVersionNegotiationFailed(t *testing.T) {
	err := &ErrVersionNegotiationFailed{
		MinVersion: VersionV1,
		GotVersion: VersionV0,
	}
	expected := "spqr: version negotiation failed: minimum V1, got V0"
	if err.Error() != expected {
		t.Errorf("error string: got %q, want %q", err.Error(), expected)
	}
}

// TestVersionString tests the Version.String() method.
func TestVersionString(t *testing.T) {
	if VersionV0.String() != "V0" {
		t.Errorf("VersionV0.String(): got %q", VersionV0.String())
	}
	if VersionV1.String() != "V1" {
		t.Errorf("VersionV1.String(): got %q", VersionV1.String())
	}
	if Version(99).String() != "unknown(99)" {
		t.Errorf("Version(99).String(): got %q", Version(99).String())
	}
}

// TestV3SerializationRoundTrip tests V3 serialization for all states.
func TestV3SerializationRoundTrip(t *testing.T) {
	t.Run("pending", func(t *testing.T) {
		sharedSecret := randomBytes(t, 32)
		state, err := InitialState(sharedSecret, DirectionA2B, false)
		if err != nil {
			t.Fatalf("InitialState: %v", err)
		}

		// Round-trip.
		s, err := Deserialize(state)
		if err != nil {
			t.Fatalf("Deserialize: %v", err)
		}
		state2, err := s.Serialize()
		if err != nil {
			t.Fatalf("Serialize: %v", err)
		}
		s.Zeroize()

		if !bytes.Equal(state, state2) {
			t.Error("round-trip should produce identical bytes")
		}
	})

	t.Run("disabled_V0", func(t *testing.T) {
		sharedSecret := randomBytes(t, 32)
		state, err := InitialState(sharedSecret, DirectionA2B, false)
		if err != nil {
			t.Fatalf("InitialState: %v", err)
		}

		// Resolve to V0.
		state, _, err = Recv(state, []byte{})
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}

		// Round-trip.
		s, err := Deserialize(state)
		if err != nil {
			t.Fatalf("Deserialize: %v", err)
		}
		state2, err := s.Serialize()
		if err != nil {
			t.Fatalf("Serialize: %v", err)
		}
		s.Zeroize()

		if !bytes.Equal(state, state2) {
			t.Error("round-trip should produce identical bytes")
		}
	})

	t.Run("resolved_V1", func(t *testing.T) {
		sharedSecret := randomBytes(t, 32)
		s, err := Init(sharedSecret, DirectionA2B, maxJump)
		if err != nil {
			t.Fatalf("Init: %v", err)
		}
		state, err := s.Serialize()
		if err != nil {
			t.Fatalf("Serialize: %v", err)
		}
		s.Zeroize()

		// Round-trip.
		s2, err := Deserialize(state)
		if err != nil {
			t.Fatalf("Deserialize: %v", err)
		}
		state2, err := s2.Serialize()
		if err != nil {
			t.Fatalf("Serialize: %v", err)
		}
		s2.Zeroize()

		if !bytes.Equal(state, state2) {
			t.Error("round-trip should produce identical bytes")
		}
	})
}
