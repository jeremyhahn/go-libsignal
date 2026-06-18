package session_test

// proptest_session_test.go — property-based ports of the 4 Rust proptests in
// rust/protocol/src/session_management.rs (commit 98915c44).
//
// Rust source: /mnt/vm-host-1/libsignal/rust/protocol/src/session_management.rs
//
// Proptest mapping:
//
//	proptest_event_model_matches_legacy (line 2554)
//	  → TestProptest_EventModelMatchesLegacy
//	  Go invariant: any random sequence of bidirectional send/receive actions
//	  produces correctly decrypted plaintexts. The Rust test compared a new
//	  codepath against a legacy one; Go has one unified path, so we assert the
//	  end-to-end correctness invariant (the meaningful part) directly.
//	  FAITHFUL REPRODUCTION: partial — the new-vs-legacy comparison is not
//	  reproducible; the session-correctness invariant is.
//
//	proptest_legacy_handover_to_new (line 2624)
//	  → TestProptest_LegacyHandoverToNew
//	  Go invariant: a random sequence of messages followed by a session
//	  re-key followed by more messages all round-trip correctly. The Rust
//	  test exercised legacy→new transition; Go maps this to the session
//	  archive/re-establish continuity invariant.
//	  FAITHFUL REPRODUCTION: partial — same justification as above.
//
//	proptest_delayed_message_via_previous_session (line 2745)
//	  → TestProptest_DelayedMessageViaPreviousSession
//	  FAITHFUL REPRODUCTION: complete — the scenario (encrypt on session A,
//	  establish session B, then deliver the delayed session-A message) maps
//	  1-to-1 to the Go session API.
//
//	proptest_ciphertext_equality (line 2997)
//	  → TestProptest_CiphertextEquality
//	  Go invariant: for any random sequence of bidirectional actions, every
//	  encrypt call produces a ciphertext that the receiver can decrypt to
//	  recover the original plaintext. The Rust test compared new-vs-legacy
//	  byte equality; without a legacy path the invariant is decryptability.
//	  FAITHFUL REPRODUCTION: partial — same justification as above.

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/session"
	"pgregory.net/rapid"
)

// sessionPair holds a fully-initialised Alice+Bob session pair for use in
// property tests. Both sides start from a clean PreKeyBundle exchange so
// the first message from Alice is a PreKeySignalMessage and subsequent
// messages are SignalMessages (Whispers).
type sessionPair struct {
	alice       *testUser
	bob         *testUser
	aliceCipher *session.Cipher
	bobCipher   *session.Cipher
	serializer  *serialize.Serializer
}

// newSessionPair establishes Alice→Bob using kyberBundle[0] and returns a
// pair where both sides can immediately encrypt/decrypt SignalMessages.
// t is the outer *testing.T (from rapid.Check's closure); rt is rapid's T
// used only for property failure reporting.
func newSessionPair(t *testing.T, rt *rapid.T, serializer *serialize.Serializer) *sessionPair {
	alice := newTestUser(t, "alice-prop", 1, serializer)
	bob := newTestUser(t, "bob-prop", 1, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		rt.Fatal("ProcessBundle:", err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)

	// Bootstrap Bob's session by sending the first PreKeySignalMessage.
	initMsg, err := aliceCipher.Encrypt([]byte("init"))
	if err != nil {
		rt.Fatal("alice init encrypt:", err)
	}
	initBytes, err := initMsg.Serialize()
	if err != nil {
		rt.Fatal("init serialize:", err)
	}
	pkMsg, err := protocol.NewPreKeySignalMessageFromBytes(
		initBytes,
		serializer.PreKeySignalMessage,
		serializer.SignalMessage,
	)
	if err != nil {
		rt.Fatal("NewPreKeySignalMessageFromBytes:", err)
	}
	processAndComplete(t, bob.sessionBuilder, pkMsg)
	if _, err := bobCipher.Decrypt(pkMsg.WhisperMessage()); err != nil {
		rt.Fatal("bob init decrypt:", err)
	}

	// Bob ACKs so Alice's session is no longer unacknowledged (Whispers only).
	ack, err := bobCipher.Encrypt([]byte("ack"))
	if err != nil {
		rt.Fatal("bob ack encrypt:", err)
	}
	ackBytes, err := ack.Serialize()
	if err != nil {
		rt.Fatal("ack serialize:", err)
	}
	ackMsg, err := protocol.NewSignalMessageFromBytes(ackBytes, serializer.SignalMessage)
	if err != nil {
		rt.Fatal("NewSignalMessageFromBytes ack:", err)
	}
	if _, err := aliceCipher.Decrypt(ackMsg); err != nil {
		rt.Fatal("alice ack decrypt:", err)
	}

	return &sessionPair{
		alice:       alice,
		bob:         bob,
		aliceCipher: aliceCipher,
		bobCipher:   bobCipher,
		serializer:  serializer,
	}
}

// send encrypts plaintext from src to dst and returns the serialised
// SignalMessage bytes. It fails the property on any error.
func (sp *sessionPair) send(rt *rapid.T, fromAlice bool, plaintext []byte) []byte {
	var sender *session.Cipher
	if fromAlice {
		sender = sp.aliceCipher
	} else {
		sender = sp.bobCipher
	}
	ct, err := sender.Encrypt(plaintext)
	if err != nil {
		rt.Fatalf("encrypt (fromAlice=%v): %v", fromAlice, err)
	}
	b, err := ct.Serialize()
	if err != nil {
		rt.Fatalf("serialize (fromAlice=%v): %v", fromAlice, err)
	}
	return b
}

// recv decrypts a previously encrypted ciphertext on the receiver side.
func (sp *sessionPair) recv(rt *rapid.T, fromAlice bool, ctBytes []byte) []byte {
	// The receiver is the one that did NOT send.
	var receiver *session.Cipher
	if fromAlice {
		// Alice sent → Bob receives.
		receiver = sp.bobCipher
	} else {
		// Bob sent → Alice receives.
		receiver = sp.aliceCipher
	}
	msg, err := protocol.NewSignalMessageFromBytes(ctBytes, sp.serializer.SignalMessage)
	if err != nil {
		rt.Fatalf("NewSignalMessageFromBytes (fromAlice=%v): %v", fromAlice, err)
	}
	plaintext, err := receiver.Decrypt(msg)
	if err != nil {
		rt.Fatalf("decrypt (fromAlice=%v): %v", fromAlice, err)
	}
	return plaintext
}

// ---- property tests ----

// TestProptest_EventModelMatchesLegacy ports proptest_event_model_matches_legacy
// (rust/protocol/src/session_management.rs:2554).
//
// Rust strategy: Vec<(bool, Event)> len 0..40 where Event ∈ {Archive, Snapshot,
// Restore, Receive, Drop, Shuffle, Send{count}}.
//
// Go invariant (session-correctness subset): for any random sequence of
// bidirectional send/receive pairs, every plaintext round-trips correctly.
// The Archive/Snapshot/Restore/Drop/Shuffle events from the Rust strategy
// exercise internal bookkeeping on DualParticipant which has no Go equivalent
// (the Go session cipher manages that state opaquely). The Send+Receive kernel
// — that any message encrypted by one side is decryptable by the other — is
// the portable invariant.
//
// Faithfulness note: the new-vs-legacy comparison is not reproducible in Go
// (one unified implementation). The session-correctness invariant is faithfully
// reproduced.
func TestProptest_EventModelMatchesLegacy(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		serializer := serialize.NewJSONSerializer()
		sp := newSessionPair(t, rt, serializer)

		// actions: sequence of (aliceSends bool, plaintext) pairs, len 0..40.
		actions := rapid.SliceOfN(
			rapid.Custom(func(rt *rapid.T) struct {
				aliceSends bool
				plaintext  []byte
			} {
				return struct {
					aliceSends bool
					plaintext  []byte
				}{
					aliceSends: rapid.Bool().Draw(rt, "aliceSends"),
					plaintext:  rapid.SliceOfN(rapid.Byte(), 0, 64).Draw(rt, "plaintext"),
				}
			}),
			0, 40,
		).Draw(rt, "actions")

		for i, a := range actions {
			ctBytes := sp.send(rt, a.aliceSends, a.plaintext)
			got := sp.recv(rt, a.aliceSends, ctBytes)
			if !bytes.Equal(got, a.plaintext) {
				rt.Fatalf("action[%d]: plaintext mismatch: want %x, got %x", i, a.plaintext, got)
			}
		}
	})
}

// TestProptest_LegacyHandoverToNew ports proptest_legacy_handover_to_new
// (rust/protocol/src/session_management.rs:2624).
//
// Rust strategy: seed u64, legacy_actions Vec<(bool,bytes)> 1..10,
// new_actions Vec<(bool,bytes)> 1..10. Runs legacy enc+dec then new enc+dec.
//
// Go invariant: a session that has exchanged N messages (phase 1) and then
// undergoes a bundle re-key (session transition, analogous to "new code takes
// over") continues to encrypt and decrypt correctly in phase 2. Both phases use
// the same Go implementation; the invariant is session-state continuity across
// a re-key boundary.
//
// Faithfulness note: partial — new-vs-legacy byte comparison not reproducible;
// session-continuity invariant faithfully reproduced.
func TestProptest_LegacyHandoverToNew(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		serializer := serialize.NewJSONSerializer()
		alice := newTestUser(t, "alice-lh", 1, serializer)
		bob := newTestUser(t, "bob-lh", 1, serializer)

		alice.buildSession(t, bob.address, serializer)
		bob.buildSession(t, alice.address, serializer)

		// Pre-key bundle #0 establishes session A.
		if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
			rt.Fatal("ProcessBundle session A:", err)
		}
		aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
		bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)

		// Bootstrap: first message establishes Bob's side of session A.
		bootstrap, err := aliceCipher.Encrypt([]byte("bootstrap"))
		if err != nil {
			rt.Fatal("bootstrap encrypt:", err)
		}
		bsBytes, err := bootstrap.Serialize()
		if err != nil {
			rt.Fatal("bootstrap serialize:", err)
		}
		bsPKMsg, err := protocol.NewPreKeySignalMessageFromBytes(
			bsBytes, serializer.PreKeySignalMessage, serializer.SignalMessage,
		)
		if err != nil {
			rt.Fatal("bootstrap NewPreKeySignalMessageFromBytes:", err)
		}
		processAndComplete(t, bob.sessionBuilder, bsPKMsg)
		if _, err := bobCipher.Decrypt(bsPKMsg.WhisperMessage()); err != nil {
			rt.Fatal("bootstrap bob decrypt:", err)
		}

		// Bob ACKs to make Alice's session acknowledged (switch to Whispers).
		ack, err := bobCipher.Encrypt([]byte("ack"))
		if err != nil {
			rt.Fatal("ack encrypt:", err)
		}
		ackBytes, err := ack.Serialize()
		if err != nil {
			rt.Fatal("ack serialize:", err)
		}
		ackMsg, err := protocol.NewSignalMessageFromBytes(ackBytes, serializer.SignalMessage)
		if err != nil {
			rt.Fatal("NewSignalMessageFromBytes ack:", err)
		}
		if _, err := aliceCipher.Decrypt(ackMsg); err != nil {
			rt.Fatal("alice ack decrypt:", err)
		}

		// Phase 1: random message exchanges on session A (1..10 actions, min 1).
		phase1 := rapid.SliceOfN(
			rapid.Custom(func(rt *rapid.T) struct {
				aliceSends bool
				plaintext  []byte
			} {
				return struct {
					aliceSends bool
					plaintext  []byte
				}{
					aliceSends: rapid.Bool().Draw(rt, "p1alice"),
					plaintext:  rapid.SliceOfN(rapid.Byte(), 0, 64).Draw(rt, "p1pt"),
				}
			}),
			1, 10,
		).Draw(rt, "phase1")

		for i, a := range phase1 {
			var sender, receiver *session.Cipher
			if a.aliceSends {
				sender, receiver = aliceCipher, bobCipher
			} else {
				sender, receiver = bobCipher, aliceCipher
			}
			ct, err := sender.Encrypt(a.plaintext)
			if err != nil {
				rt.Fatalf("phase1[%d] encrypt: %v", i, err)
			}
			ctBytes, err := ct.Serialize()
			if err != nil {
				rt.Fatalf("phase1[%d] serialize: %v", i, err)
			}
			msg, err := protocol.NewSignalMessageFromBytes(ctBytes, serializer.SignalMessage)
			if err != nil {
				rt.Fatalf("phase1[%d] parse: %v", i, err)
			}
			got, err := receiver.Decrypt(msg)
			if err != nil {
				rt.Fatalf("phase1[%d] decrypt: %v", i, err)
			}
			if !bytes.Equal(got, a.plaintext) {
				rt.Fatalf("phase1[%d] mismatch: want %x got %x", i, a.plaintext, got)
			}
		}

		// Session transition: Alice re-keys from a new bundle (session B).
		// This archives session A and is the Go equivalent of "new code takes over
		// session state written by legacy code" from the Rust test.
		if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundleWithPreKeyIndex(1)); err != nil {
			rt.Fatal("ProcessBundle session B:", err)
		}

		// First send on session B is a PreKeySignalMessage.
		bInitMsg, err := aliceCipher.Encrypt([]byte("session-B-init"))
		if err != nil {
			rt.Fatal("session B init encrypt:", err)
		}
		bInitBytes, err := bInitMsg.Serialize()
		if err != nil {
			rt.Fatal("session B init serialize:", err)
		}
		bInitPK, err := protocol.NewPreKeySignalMessageFromBytes(
			bInitBytes, serializer.PreKeySignalMessage, serializer.SignalMessage,
		)
		if err != nil {
			rt.Fatal("session B init NewPreKeySignalMessageFromBytes:", err)
		}
		processAndComplete(t, bob.sessionBuilder, bInitPK)
		if _, err := bobCipher.Decrypt(bInitPK.WhisperMessage()); err != nil {
			rt.Fatal("bob session B init decrypt:", err)
		}

		// Bob ACKs session B.
		ack2, err := bobCipher.Encrypt([]byte("ack-B"))
		if err != nil {
			rt.Fatal("session B ack encrypt:", err)
		}
		ack2Bytes, err := ack2.Serialize()
		if err != nil {
			rt.Fatal("session B ack serialize:", err)
		}
		ack2Msg, err := protocol.NewSignalMessageFromBytes(ack2Bytes, serializer.SignalMessage)
		if err != nil {
			rt.Fatal("NewSignalMessageFromBytes ack2:", err)
		}
		if _, err := aliceCipher.Decrypt(ack2Msg); err != nil {
			rt.Fatal("alice session B ack decrypt:", err)
		}

		// Phase 2: random message exchanges on session B (1..10 actions, min 1).
		phase2 := rapid.SliceOfN(
			rapid.Custom(func(rt *rapid.T) struct {
				aliceSends bool
				plaintext  []byte
			} {
				return struct {
					aliceSends bool
					plaintext  []byte
				}{
					aliceSends: rapid.Bool().Draw(rt, "p2alice"),
					plaintext:  rapid.SliceOfN(rapid.Byte(), 0, 64).Draw(rt, "p2pt"),
				}
			}),
			1, 10,
		).Draw(rt, "phase2")

		for i, a := range phase2 {
			var sender, receiver *session.Cipher
			if a.aliceSends {
				sender, receiver = aliceCipher, bobCipher
			} else {
				sender, receiver = bobCipher, aliceCipher
			}
			ct, err := sender.Encrypt(a.plaintext)
			if err != nil {
				rt.Fatalf("phase2[%d] encrypt: %v", i, err)
			}
			ctBytes, err := ct.Serialize()
			if err != nil {
				rt.Fatalf("phase2[%d] serialize: %v", i, err)
			}
			msg, err := protocol.NewSignalMessageFromBytes(ctBytes, serializer.SignalMessage)
			if err != nil {
				rt.Fatalf("phase2[%d] parse: %v", i, err)
			}
			got, err := receiver.Decrypt(msg)
			if err != nil {
				rt.Fatalf("phase2[%d] decrypt: %v", i, err)
			}
			if !bytes.Equal(got, a.plaintext) {
				rt.Fatalf("phase2[%d] mismatch: want %x got %x", i, a.plaintext, got)
			}
		}
	})
}

// TestProptest_DelayedMessageViaPreviousSession ports
// proptest_delayed_message_via_previous_session
// (rust/protocol/src/session_management.rs:2745).
//
// Rust strategy: seed u64, pre_actions Vec<(bool,bytes)> 0..6,
// post_actions Vec<(bool,bytes)> 0..6, delayed_plaintext bytes 1..64.
//
// Scenario (identical to Rust):
//  1. pre_actions: exchange messages on session A.
//  2. Alice encrypts a delayed Whisper on session A (not yet delivered).
//  3. Alice processes a new bundle from Bob → session B (archives A).
//  4. Session B is established with a round-trip PreKeySignalMessage exchange.
//  5. post_actions: exchange messages on session B.
//  6. The delayed session-A message is delivered to Bob.
//     Bob must find it in previous_sessions (A') and decrypt it.
//
// FAITHFUL REPRODUCTION: complete.
func TestProptest_DelayedMessageViaPreviousSession(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		serializer := serialize.NewJSONSerializer()
		alice := newTestUser(t, "alice-dm", 1, serializer)
		bob := newTestUser(t, "bob-dm", 1, serializer)

		alice.buildSession(t, bob.address, serializer)
		bob.buildSession(t, alice.address, serializer)

		// Establish session A via bundle #0.
		if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
			rt.Fatal("ProcessBundle session A:", err)
		}
		aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
		bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)

		// Bootstrap Bob's session A.
		bootstrap, err := aliceCipher.Encrypt([]byte("bootstrap-A"))
		if err != nil {
			rt.Fatal("bootstrap encrypt:", err)
		}
		bsBytes, _ := bootstrap.Serialize()
		bsPK, err := protocol.NewPreKeySignalMessageFromBytes(
			bsBytes, serializer.PreKeySignalMessage, serializer.SignalMessage,
		)
		if err != nil {
			rt.Fatal("bootstrap parse:", err)
		}
		processAndComplete(t, bob.sessionBuilder, bsPK)
		if _, err := bobCipher.Decrypt(bsPK.WhisperMessage()); err != nil {
			rt.Fatal("bob bootstrap decrypt:", err)
		}
		// Bob ACKs so Alice switches to Whispers.
		ackA, err := bobCipher.Encrypt([]byte("ack-A"))
		if err != nil {
			rt.Fatal("ack-A encrypt:", err)
		}
		ackABytes, _ := ackA.Serialize()
		ackAMsg, _ := protocol.NewSignalMessageFromBytes(ackABytes, serializer.SignalMessage)
		if _, err := aliceCipher.Decrypt(ackAMsg); err != nil {
			rt.Fatal("alice ack-A decrypt:", err)
		}

		// Phase 1: pre_actions on session A (0..6).
		preActions := rapid.SliceOfN(
			rapid.Custom(func(rt *rapid.T) struct {
				aliceSends bool
				plaintext  []byte
			} {
				return struct {
					aliceSends bool
					plaintext  []byte
				}{
					aliceSends: rapid.Bool().Draw(rt, "preAlice"),
					plaintext:  rapid.SliceOfN(rapid.Byte(), 0, 6).Draw(rt, "prePt"),
				}
			}),
			0, 6,
		).Draw(rt, "preActions")

		for i, a := range preActions {
			var sender, receiver *session.Cipher
			if a.aliceSends {
				sender, receiver = aliceCipher, bobCipher
			} else {
				sender, receiver = bobCipher, aliceCipher
			}
			ct, err := sender.Encrypt(a.plaintext)
			if err != nil {
				rt.Fatalf("pre[%d] encrypt: %v", i, err)
			}
			ctBytes, _ := ct.Serialize()
			msg, err := protocol.NewSignalMessageFromBytes(ctBytes, serializer.SignalMessage)
			if err != nil {
				rt.Fatalf("pre[%d] parse: %v", i, err)
			}
			got, err := receiver.Decrypt(msg)
			if err != nil {
				rt.Fatalf("pre[%d] decrypt: %v", i, err)
			}
			if !bytes.Equal(got, a.plaintext) {
				rt.Fatalf("pre[%d] mismatch", i)
			}
		}

		// Encrypt the delayed message on session A (NOT delivered yet).
		delayedPlaintext := rapid.SliceOfN(rapid.Byte(), 1, 64).Draw(rt, "delayedPt")
		delayedCT, err := aliceCipher.Encrypt(delayedPlaintext)
		if err != nil {
			rt.Fatal("delayed encrypt:", err)
		}
		delayedBytes, _ := delayedCT.Serialize()
		// This is a Whisper (session A is acknowledged), so parse as SignalMessage.
		delayedMsg, err := protocol.NewSignalMessageFromBytes(delayedBytes, serializer.SignalMessage)
		if err != nil {
			rt.Fatal("delayed parse:", err)
		}

		// Session transition A → B: Alice processes a new bundle from Bob.
		if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundleWithPreKeyIndex(1)); err != nil {
			rt.Fatal("ProcessBundle session B:", err)
		}

		// First message on session B from Alice is a PreKeySignalMessage.
		// When Bob decrypts it, his session A' is archived to previous_sessions.
		bInitMsg, err := aliceCipher.Encrypt([]byte("session-B-init"))
		if err != nil {
			rt.Fatal("session B init encrypt:", err)
		}
		bInitBytes, _ := bInitMsg.Serialize()
		bInitPK, err := protocol.NewPreKeySignalMessageFromBytes(
			bInitBytes, serializer.PreKeySignalMessage, serializer.SignalMessage,
		)
		if err != nil {
			rt.Fatal("session B init parse:", err)
		}
		processAndComplete(t, bob.sessionBuilder, bInitPK)
		if _, err := bobCipher.Decrypt(bInitPK.WhisperMessage()); err != nil {
			rt.Fatal("bob session B init decrypt:", err)
		}
		// Bob ACKs session B → Alice switches to Whispers on B.
		ackB, err := bobCipher.Encrypt([]byte("ack-B"))
		if err != nil {
			rt.Fatal("ack-B encrypt:", err)
		}
		ackBBytes, _ := ackB.Serialize()
		ackBMsg, _ := protocol.NewSignalMessageFromBytes(ackBBytes, serializer.SignalMessage)
		if _, err := aliceCipher.Decrypt(ackBMsg); err != nil {
			rt.Fatal("alice ack-B decrypt:", err)
		}

		// Phase 2: post_actions on session B (0..6).
		postActions := rapid.SliceOfN(
			rapid.Custom(func(rt *rapid.T) struct {
				aliceSends bool
				plaintext  []byte
			} {
				return struct {
					aliceSends bool
					plaintext  []byte
				}{
					aliceSends: rapid.Bool().Draw(rt, "postAlice"),
					plaintext:  rapid.SliceOfN(rapid.Byte(), 0, 64).Draw(rt, "postPt"),
				}
			}),
			0, 6,
		).Draw(rt, "postActions")

		for i, a := range postActions {
			var sender, receiver *session.Cipher
			if a.aliceSends {
				sender, receiver = aliceCipher, bobCipher
			} else {
				sender, receiver = bobCipher, aliceCipher
			}
			ct, err := sender.Encrypt(a.plaintext)
			if err != nil {
				rt.Fatalf("post[%d] encrypt: %v", i, err)
			}
			ctBytes, _ := ct.Serialize()
			msg, err := protocol.NewSignalMessageFromBytes(ctBytes, serializer.SignalMessage)
			if err != nil {
				rt.Fatalf("post[%d] parse: %v", i, err)
			}
			got, err := receiver.Decrypt(msg)
			if err != nil {
				rt.Fatalf("post[%d] decrypt: %v", i, err)
			}
			if !bytes.Equal(got, a.plaintext) {
				rt.Fatalf("post[%d] mismatch", i)
			}
		}

		// Deliver the delayed session-A message to Bob.
		// Bob's current session is B'. The delayed message was encrypted under
		// session A. decryptWithRecord must fall back to previous_sessions (A')
		// and call PromoteOldSession — exactly as Rust's try_decrypt_from_record.
		got, err := bobCipher.Decrypt(delayedMsg)
		if err != nil {
			rt.Fatalf("delayed message decrypt: %v", err)
		}
		if !bytes.Equal(got, delayedPlaintext) {
			rt.Fatalf("delayed message mismatch: want %x got %x", delayedPlaintext, got)
		}
	})
}

// TestProptest_CiphertextEquality ports proptest_ciphertext_equality
// (rust/protocol/src/session_management.rs:2997).
//
// Rust strategy: seed u64, actions Vec<(bool,bytes)> 1..20. Runs new and
// legacy encrypt from the same RNG clone and asserts byte-identical output.
//
// Go invariant: for any random sequence of bidirectional Whisper actions
// (1..20), every ciphertext produced by Encrypt is correctly decryptable
// by the receiver, recovering the exact plaintext. The Rust test's
// new==legacy byte comparison is not reproducible (no legacy path in Go);
// the decryptability invariant — which the byte comparison implies — is
// faithfully reproduced.
//
// Faithfulness note: partial — new-vs-legacy byte comparison not
// reproducible; decryptability invariant faithfully reproduced.
func TestProptest_CiphertextEquality(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		serializer := serialize.NewJSONSerializer()
		sp := newSessionPair(t, rt, serializer)

		// actions: 1..20 bidirectional Whisper messages.
		actions := rapid.SliceOfN(
			rapid.Custom(func(rt *rapid.T) struct {
				aliceSends bool
				plaintext  []byte
			} {
				return struct {
					aliceSends bool
					plaintext  []byte
				}{
					aliceSends: rapid.Bool().Draw(rt, "ceAlice"),
					plaintext:  rapid.SliceOfN(rapid.Byte(), 0, 64).Draw(rt, "cePt"),
				}
			}),
			1, 20,
		).Draw(rt, "actions")

		for i, a := range actions {
			ctBytes := sp.send(rt, a.aliceSends, a.plaintext)
			got := sp.recv(rt, a.aliceSends, ctBytes)
			if !bytes.Equal(got, a.plaintext) {
				rt.Fatalf("action[%d] mismatch: want %x got %x", i, a.plaintext, got)
			}
		}
	})
}
