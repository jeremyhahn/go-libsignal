package spqr

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// TestSendBraidRecvBraidDirectAliceToBob exercises SendBraid and RecvBraid
// in one direction (Alice to Bob) for many rounds, covering the core
// braid message path (braidMsg != nil). This avoids the epoch/counter
// conflicts that occur in bidirectional testing.
func TestSendBraidRecvBraidDirectAliceToBob(t *testing.T) {
	ss := randomBytes(t, 32)
	ssCopy := make([]byte, 32)
	copy(ssCopy, ss)

	kemAlice := mlkembraid.NewMLKEM768IncrementalKEM()
	kemBob := mlkembraid.NewMLKEM768IncrementalKEM()

	braidAlice, err := mlkembraid.InitAlice(ss, kemAlice, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}
	braidBob, err := mlkembraid.InitBob(ssCopy, kemBob, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitBob: %v", err)
	}

	alice, err := InitWithBraid(ss, DirectionA2B, uint32(maxJump), braidAlice)
	if err != nil {
		t.Fatalf("InitWithBraid alice: %v", err)
	}
	defer alice.Zeroize()

	bob, err := InitWithBraid(ssCopy, DirectionB2A, uint32(maxJump), braidBob)
	if err != nil {
		t.Fatalf("InitWithBraid bob: %v", err)
	}
	defer bob.Zeroize()

	// Alice sends to Bob for 50 rounds (one-directional).
	// This covers the braidMsg != nil path (SerializeSCKA) and the
	// MessageTypeNone fallback path.
	const rounds = 50
	for round := 0; round < rounds; round++ {
		alicePQR, aliceKey, sendErr := alice.SendBraid()
		if sendErr != nil {
			t.Fatalf("round %d Alice.SendBraid: %v", round, sendErr)
		}
		if len(alicePQR) == 0 {
			t.Fatalf("round %d: Alice.SendBraid returned empty message", round)
		}

		bobKey, recvErr := bob.RecvBraid(alicePQR)
		if recvErr != nil {
			t.Fatalf("round %d Bob.RecvBraid: %v", round, recvErr)
		}

		// Keys should match if both non-nil.
		if aliceKey != nil && bobKey != nil {
			if !bytes.Equal(aliceKey, bobKey) {
				t.Errorf("round %d A->B key mismatch", round)
			}
		}
	}
}

// TestSendBraidNoneMessageFallback tests that SendBraid produces a valid message
// even when braid.Send returns nil (None fallback). We test this by checking
// that the None message path is accessible from the initial Bob state where
// braid.Send may return a None message for certain state transitions.
func TestSendBraidNoneMessageFallback(t *testing.T) {
	ss := randomBytes(t, 32)
	kem := mlkembraid.NewMLKEM768IncrementalKEM()

	// Bob in its initial state does not immediately produce chunk messages on Send;
	// it waits for Alice's Hdr. When Bob.SendBraid() is called without receiving
	// anything from Alice first, braid.Send() returns a None message.
	braidBob, err := mlkembraid.InitBob(ss, kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitBob: %v", err)
	}

	bob, err := InitWithBraid(ss, DirectionB2A, uint32(maxJump), braidBob)
	if err != nil {
		t.Fatalf("InitWithBraid: %v", err)
	}
	defer bob.Zeroize()

	// Bob sends without receiving any Hdr first. This exercises the
	// None message fallback (braidMsg may be nil or MessageTypeNone).
	pqrMsg, mk, err := bob.SendBraid()
	if err != nil {
		t.Fatalf("SendBraid: %v", err)
	}
	// Should produce a non-empty message regardless of braid state.
	if len(pqrMsg) == 0 {
		t.Error("expected non-empty wire message from SendBraid even with None type")
	}
	// Message key should be non-nil after resolution with known chain.
	if len(mk) == 0 {
		t.Error("expected non-nil message key")
	}
}

// TestSendBraidProducesBraidMessage verifies that SendBraid produces a
// non-12-byte (variable-length) wire message when Alice has an active braid.
func TestSendBraidProducesBraidMessage(t *testing.T) {
	ss := randomBytes(t, 32)
	kem := mlkembraid.NewMLKEM768IncrementalKEM()
	braid, err := mlkembraid.InitAlice(ss, kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}

	s, err := InitWithBraid(ss, DirectionA2B, uint32(maxJump), braid)
	if err != nil {
		t.Fatalf("InitWithBraid: %v", err)
	}
	defer s.Zeroize()

	pqrMsg, mk, err := s.SendBraid()
	if err != nil {
		t.Fatalf("SendBraid: %v", err)
	}
	if len(pqrMsg) == 0 {
		t.Fatal("SendBraid should produce non-empty wire message")
	}
	// Variable-length format: should NOT be exactly 12 bytes.
	if len(pqrMsg) == legacyPQRMsgSize {
		t.Error("braid path should use variable-length format, not 12-byte legacy format")
	}
	if len(mk) == 0 {
		t.Error("SendBraid should return non-nil message key")
	}
	// The message should start with wireVersion byte.
	if pqrMsg[0] != wireVersion {
		t.Errorf("wire message version byte = %d, want %d", pqrMsg[0], wireVersion)
	}
}

// TestRecvBraidPendingResolvesToV1WithBraid tests that RecvBraid with a non-empty
// pqrMsg on a pending state resolves to V1 and then processes the message.
func TestRecvBraidPendingResolvesToV1WithBraid(t *testing.T) {
	ss := randomBytes(t, 32)
	ssCopy := make([]byte, 32)
	copy(ssCopy, ss)

	kemAlice := mlkembraid.NewMLKEM768IncrementalKEM()
	kemBob := mlkembraid.NewMLKEM768IncrementalKEM()

	braidAlice, err := mlkembraid.InitAlice(ss, kemAlice, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}
	braidBob, err := mlkembraid.InitBob(ssCopy, kemBob, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitBob: %v", err)
	}

	// Alice resolved with braid (sends real chunks).
	alice, err := InitWithBraid(ss, DirectionA2B, uint32(maxJump), braidAlice)
	if err != nil {
		t.Fatalf("InitWithBraid alice: %v", err)
	}
	defer alice.Zeroize()

	// Bob pending with braid.
	bob := &SPQR{
		chains:      make(map[uint64]*EpochChain),
		skippedKeys: make(map[SkippedKeyID]*secret.Secret),
		direction:   DirectionB2A,
		maxJump:     uint32(maxJump),
		negotiation: negotiationPending,
		version:     VersionV1,
		minVersion:  VersionV0,
		authKey:     ssCopy,
		braid:       braidBob,
	}
	defer bob.Zeroize()

	// Alice sends.
	pqrMsg, aliceKey, err := alice.SendBraid()
	if err != nil {
		t.Fatalf("Alice SendBraid: %v", err)
	}

	// Bob receives (pending → resolves to V1 → processes braid message).
	bobKey, err := bob.RecvBraid(pqrMsg)
	if err != nil {
		t.Fatalf("Bob RecvBraid (pending): %v", err)
	}

	if !bob.IsNegotiated() {
		t.Error("bob should be negotiated after RecvBraid with non-empty msg")
	}

	// Keys should match for the first message (counter=1, epoch=0).
	if aliceKey != nil && bobKey != nil {
		if !bytes.Equal(aliceKey, bobKey) {
			t.Error("alice and bob keys should match")
		}
	}
}
