//go:build slow

package session_test

// chain_jump_test.go — ports test_chain_jump_over_limit from the Rust upstream.
//
// Rust source: rust/protocol/tests/session.rs:245
// Rust commit: 98915c44
//
// Scenario:
//   Alice and Bob establish a PQXDH session. Alice sends MAX_FORWARD_JUMPS+1
//   messages (25,001) without Bob decrypting any of them — advancing her sender
//   chain counter 25,001 steps. She then sends one more message (the 25,002nd).
//   When Bob attempts to decrypt that last message the chain-key advancement
//   would require jumping 25,001 steps past his receiver-chain index, which
//   exceeds the maxFutureMessages cap of 25,000. The decrypt must return
//   session.ErrTooFarIntoFuture.
//
// Constant (rust/protocol/src/consts.rs:8):
//   pub const MAX_FORWARD_JUMPS: usize = 25_000;
//
// The Go equivalent is maxFutureMessages = 25000 in pkg/session/SessionCipher.go.
//
// Expected runtime: ~60–120 s on a modern workstation (25,002 AEAD operations).
// Invoke with:
//
//	GOWORK=off go test -race -count=1 -tags=slow -run TestRust_ChainJumpOverLimit ./pkg/session/...

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/session"
)

// maxForwardJumps mirrors the Rust constant MAX_FORWARD_JUMPS = 25_000
// (rust/protocol/src/consts.rs:8) and Go's maxFutureMessages in SessionCipher.go.
const maxForwardJumps = 25_000

// TestRust_ChainJumpOverLimit ports test_chain_jump_over_limit
// (rust/protocol/tests/session.rs:245).
//
// Alice sends MAX_FORWARD_JUMPS+1 messages that Bob never decrypts, then sends
// one more. Bob's attempt to decrypt that final message must fail with
// session.ErrTooFarIntoFuture because the required chain-key advance
// (25_001 steps) exceeds the 25_000 cap.
func TestRust_ChainJumpOverLimit(t *testing.T) {
	serializer := serialize.NewJSONSerializer()

	// Addresses mirror the Rust test literals.
	// Rust source: rust/protocol/tests/session.rs:261-263
	alice := newTestUser(t, "+14151111111", 1, serializer)
	bob := newTestUser(t, "+14151111112", 1, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	// Alice processes Bob's pre-key bundle to establish a session.
	bundle := bob.kyberBundle()
	if err := alice.sessionBuilder.ProcessBundle(bundle); err != nil {
		t.Fatalf("ProcessBundle: %v", err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)

	// Encrypt the first message as a PreKeySignalMessage so Bob can establish
	// his session. This counts as message #1 of the forward-jump sequence.
	firstMsg, err := aliceCipher.Encrypt([]byte("Yet another message for you"))
	if err != nil {
		t.Fatalf("encrypt first: %v", err)
	}
	firstBytes, err := firstMsg.Serialize()
	if err != nil {
		t.Fatalf("serialize first: %v", err)
	}
	firstPreKey, err := protocol.NewPreKeySignalMessageFromBytes(
		firstBytes,
		serializer.PreKeySignalMessage,
		serializer.SignalMessage,
	)
	if err != nil {
		t.Fatalf("parse first PreKeySignalMessage: %v", err)
	}

	// Bob processes the prekey portion to establish his receiver chain and
	// commits the deferred key-deletion actions. This mirrors the Rust
	// process_prekey_bundle call before the loop.
	processAndComplete(t, bob.sessionBuilder, firstPreKey)

	// Alice sends MAX_FORWARD_JUMPS more messages (messages #2 … #25_001)
	// without Bob decrypting any of them. Together with the first message
	// this is MAX_FORWARD_JUMPS+1 = 25_001 encrypts — exactly matching the
	// Rust loop `for _i in 0..(MAX_FORWARD_JUMPS + 1)`.
	for i := 0; i < maxForwardJumps; i++ {
		if _, err := aliceCipher.Encrypt([]byte("Yet another message for you")); err != nil {
			t.Fatalf("encrypt loop[%d]: %v", i, err)
		}
	}

	// Alice sends the message that tips over the limit (message #25_002).
	// This is `too_far` in the Rust test.
	tooFarMsg, err := aliceCipher.Encrypt([]byte("Now you have gone too far"))
	if err != nil {
		t.Fatalf("encrypt too_far: %v", err)
	}

	// Because the session is unacknowledged (Bob never replied), Alice wraps
	// every message as a PreKeySignalMessage. The inner WhisperMessage carries
	// the double-ratchet ciphertext and the counter Bob must validate.
	tooFarBytes, err := tooFarMsg.Serialize()
	if err != nil {
		t.Fatalf("serialize too_far: %v", err)
	}
	tooFarPreKey, err := protocol.NewPreKeySignalMessageFromBytes(
		tooFarBytes,
		serializer.PreKeySignalMessage,
		serializer.SignalMessage,
	)
	if err != nil {
		t.Fatalf("parse too_far as PreKeySignalMessage: %v", err)
	}

	// Bob attempts to decrypt the inner WhisperMessage. The chain-key advance
	// required (25_001 steps) exceeds the 25_000 cap; this must fail.
	//
	// Rust assertion: decrypt(...).is_err()
	// The Rust test does not specify which error, only that one is returned.
	// In Go the rejection may come from either:
	//   - session.ErrTooFarIntoFuture (Double Ratchet chain-key jump limit), or
	//   - the SPQR ratchet's own maxJump guard (also 25_000, fires first when
	//     PQ ratchet state is present in the session).
	// Both represent the same semantic: the message is too far ahead to decrypt.
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	_, decryptErr := bobCipher.Decrypt(tooFarPreKey.WhisperMessage())
	if decryptErr == nil {
		t.Fatal("expected error decrypting over-limit message, but decrypt succeeded")
	}
}
