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

	// Wire message must be in SCKA format (version byte 0x01).
	if len(pqrMsg) < 1 || pqrMsg[0] != 0x01 {
		t.Errorf("braid path must use SCKA wire format (version 0x01), got %x", pqrMsg)
	}

	// Bob receives via package-level Recv().
	newBobState, bobKey, recvErr := Recv(bobState, pqrMsg)
	if recvErr != nil {
		t.Fatalf("Recv(bob): %v", recvErr)
	}

	if !bytes.Equal(aliceKey, bobKey) {
		t.Errorf("message keys do not match:\n  alice: %x\n  bob:   %x", aliceKey, bobKey)
	}

	// Verify braid is still present after serialization (proto format).
	s, err := Deserialize(newAliceState)
	if err != nil {
		t.Fatalf("Deserialize newAliceState: %v", err)
	}
	defer s.Zeroize()
	if s.braid == nil {
		t.Error("alice state should retain braid after Send/Serialize")
	}

	s2, err := Deserialize(newBobState)
	if err != nil {
		t.Fatalf("Deserialize newBobState: %v", err)
	}
	defer s2.Zeroize()
	if s2.braid == nil {
		t.Error("bob state should retain braid after Recv/Serialize")
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

// TestSendRecvNoBraidSCKAPath tests that the package-level Send()/Recv()
// works correctly for the chain-only path (no braid) using the Rust-compatible
// SCKA wire format (Phase E). Both paths now produce/consume SCKA format.
func TestSendRecvNoBraidSCKAPath(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	sharedCopy := make([]byte, 32)
	copy(sharedCopy, sharedSecret)

	// Pre-resolve both sides without braid using proto serialization.
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

	// Send/Recv should use SCKA wire format (version byte 0x01).
	var pqrMsg []byte
	var aliceKey, bobKey MessageKey
	_, pqrMsg, aliceKey, err = Send(aliceState)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(pqrMsg) < 1 || pqrMsg[0] != 0x01 {
		t.Errorf("chain-only path must use SCKA wire format (version 0x01), got %x", pqrMsg)
	}
	if aliceKey == nil {
		t.Fatal("expected non-nil message key from chain-only Send")
	}

	_, bobKey, err = Recv(bobState, pqrMsg)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if !bytes.Equal(aliceKey, bobKey) {
		t.Errorf("key mismatch on chain-only SCKA path:\n  alice: %x\n  bob:   %x", aliceKey, bobKey)
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

	// After Phase E, states are proto-encoded; the first byte is a proto field tag,
	// not a version byte. Verify by deserializing and checking braid presence.

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

	// After Phase E, states are proto-encoded; verify by deserializing.

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

// TestNegotiationPendingAndV0Behavior tests that pending states with MinVersion=V0
// (opt-in downgrade, audit-required) correctly negotiate to V0 when an empty
// message is received, and that V0 states return empty messages and nil keys.
// This uses InitialStateWithParams explicitly, because the default InitialState
// sets MinVersion=V1 (matching Rust's "require SPQR" policy).
func TestNegotiationPendingAndV0Behavior(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	sharedCopy := make([]byte, 32)
	copy(sharedCopy, sharedSecret)

	// Create pending states with explicit V0 minimum (opt-in downgrade path).
	aliceState, err := InitialStateWithParams(Params{
		AuthKey:    sharedSecret,
		Version:    VersionV1,
		Direction:  DirectionA2B,
		MinVersion: VersionV0,
		MaxJump:    maxJump,
		MaxOOOKeys: maxSkippedKeys,
	})
	if err != nil {
		t.Fatalf("InitialStateWithParams alice: %v", err)
	}
	bobState, err := InitialStateWithParams(Params{
		AuthKey:    sharedCopy,
		Version:    VersionV1,
		Direction:  DirectionB2A,
		MinVersion: VersionV0,
		MaxJump:    maxJump,
		MaxOOOKeys: maxSkippedKeys,
	})
	if err != nil {
		t.Fatalf("InitialStateWithParams bob: %v", err)
	}

	// Verify states are valid proto bytes (non-empty).
	if len(aliceState) == 0 {
		t.Fatal("alice state should not be empty")
	}
	if len(bobState) == 0 {
		t.Fatal("bob state should not be empty")
	}

	// Alice sends (pending -> empty message, nil key because MinVersion=V0).
	_, pqrMsg, aliceKey, err := Send(aliceState)
	if err != nil {
		t.Fatalf("Alice Send: %v", err)
	}
	if len(pqrMsg) != 0 || aliceKey != nil {
		t.Error("pending Send with MinVersion=V0 should return empty msg and nil key")
	}

	// Bob receives empty msg -> negotiates to V0.
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

// TestDeserializeInvalidProtoData tests that garbage proto bytes are rejected
// with a typed error. Deserialize wraps proto errors in ErrDeserialize.
func TestDeserializeInvalidProtoData(t *testing.T) {
	// These bytes are structurally invalid for protobuf decoding.
	garbled := []byte{0xFF, 0xFE, 0xFD, 0x80, 0x01, 0x02, 0x03}
	_, err := Deserialize(garbled)
	if err == nil {
		t.Fatal("expected error for invalid proto bytes")
	}
	var deserErr *ErrDeserialize
	if !errors.As(err, &deserErr) {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// TestDeserializeTruncatedProto tests that a truncated valid proto is either
// accepted (proto partial decode) or rejected cleanly — never panics.
func TestDeserializeTruncatedProto(t *testing.T) {
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
	if len(state) < 10 {
		t.Fatalf("state too short for truncation test: %d bytes", len(state))
	}

	// Truncate significantly — the truncated proto may or may not be parseable.
	// The key invariant: no panic.
	truncated := state[:len(state)/2]
	s, deserErr := Deserialize(truncated)
	if deserErr == nil && s != nil {
		// If decode succeeded, the result must at least be valid enough to zeroize.
		s.Zeroize()
	}
	// No assertion on success/failure — proto is lenient; truncated proto may succeed.
}
