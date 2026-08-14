package spqr

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
)

// TestWireMessageEpochOffset verifies that sckaToChainEpoch / chainToSckaEpoch are
// inverses of each other, and that a non-braid Send encodes epoch+1 in the SCKA wire
// bytes. This is the explicit Phase E audit target: Go chains are 0-indexed, SCKA wire
// is 1-indexed.
func TestWireMessageEpochOffset(t *testing.T) {
	// Verify sckaToChainEpoch / chainToSckaEpoch are inverses.
	for _, chainEp := range []uint64{0, 1, 5, 100, 1<<63 - 1} {
		scka := chainToSckaEpoch(chainEp)
		back := sckaToChainEpoch(scka)
		if back != chainEp {
			t.Errorf("round-trip epoch %d: chainToScka=%d, sckaToChain=%d, want %d",
				chainEp, scka, back, chainEp)
		}
		if scka != chainEp+1 {
			t.Errorf("chainToSckaEpoch(%d) = %d, want %d", chainEp, scka, chainEp+1)
		}
	}

	// Verify that non-braid Send produces SCKA bytes where epoch == state.epoch + 1.
	sharedSecret := randomBytes(t, 32)
	aliceState, err := InitialStateWithParams(Params{
		AuthKey:    sharedSecret,
		Version:    VersionV1,
		Direction:  DirectionA2B,
		MinVersion: VersionV1, // resolves immediately on Send
		MaxJump:    maxJump,
		MaxOOOKeys: maxSkippedKeys,
	})
	if err != nil {
		t.Fatalf("InitialStateWithParams: %v", err)
	}

	_, pqrMsg, mk, err := Send(aliceState)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if mk == nil {
		t.Fatal("expected non-nil message key after MinVersion=V1 resolution")
	}
	if len(pqrMsg) == 0 {
		t.Fatal("expected non-empty wire message after negotiation resolved")
	}

	// Parse the SCKA wire message using DeserializeSCKA and verify epoch = chain_epoch + 1.
	// Chain epoch is 0 for the initial state; SCKA epoch must be 1.
	msg, chainCounter, decErr := mlkembraid.DeserializeSCKA(pqrMsg)
	if decErr != nil {
		t.Fatalf("DeserializeSCKA: %v", decErr)
	}

	const wantSckaEpoch = uint64(1) // chain epoch 0 → SCKA epoch 1
	if msg.Epoch != wantSckaEpoch {
		t.Errorf("SCKA wire epoch: got %d, want %d (chain epoch 0 → SCKA epoch 1)",
			msg.Epoch, wantSckaEpoch)
	}
	const wantCounter = uint32(1) // first message key is at counter 1
	if chainCounter != wantCounter {
		t.Errorf("SCKA wire chain_counter: got %d, want %d", chainCounter, wantCounter)
	}
}
