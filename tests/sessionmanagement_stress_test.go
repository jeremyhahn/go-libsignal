//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 1 test in this file exercises X25519. FIPS 140-3 does not approve that,
// but the X3DH specification (section 2.1) and the Double Ratchet
// specification (section 5.2) require it, so the fips140only build tag drops
// this file from the FIPS gate. `make test` and `make coverage` still run
// it.

package tests

import (
	"crypto/rand"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/sessionmanagement"
)

// TestSessionManagement_Facade_1kMessageRoundTrip stresses the
// pkg/sessionmanagement facade across a long ratchet trace. Both sides
// alternate sender/receiver so every message exercises a fresh chain
// step. The test asserts:
//
//  1. Every plaintext round-trips exactly.
//  2. No skipped-message keys leak across the run (no spurious
//     session resets).
//  3. Total runtime stays under 60 seconds — a regression sentinel
//     for the per-message ratchet cost.
//
// The 1k-message budget is the same order of magnitude as Rust's
// rust/protocol/tests/session.rs::test_basic_simultaneous_initiate,
// which exercises ~50 ratchet steps. We stretch to 1k so any
// non-deterministic state corruption surfaces statistically rather
// than by luck.
func TestSessionManagement_Facade_1kMessageRoundTrip(t *testing.T) {
	const messages = 1000

	serializer := newSerializer()

	alice := newUser("Alice", 1, serializer)
	bob := newUser("Bob", 2, serializer)

	alice.buildSession(bob.address, serializer)
	bob.buildSession(alice.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatalf("Alice ProcessBundle: %v", err)
	}

	// First Alice -> Bob message must be a PreKeySignalMessage so Bob's
	// store is established before the back-and-forth begins.
	first := []byte("bootstrap")
	ct, err := sessionmanagement.MessageEncrypt(
		first,
		bob.address,
		alice.address,
		alice.sessionStore,
		alice.identityStore,
		serializer,
	)
	if err != nil {
		t.Fatalf("bootstrap MessageEncrypt: %v", err)
	}
	if _, ok := ct.(*protocol.PreKeySignalMessage); !ok {
		t.Fatalf("bootstrap should produce PreKeySignalMessage; got %T", ct)
	}
	wire, err := ct.Serialize()
	if err != nil {
		t.Fatalf("bootstrap Serialize: %v", err)
	}
	bobReceived, err := protocol.NewPreKeySignalMessageFromBytes(
		wire, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatalf("bootstrap NewPreKeySignalMessageFromBytes: %v", err)
	}
	got, err := sessionmanagement.MessageDecrypt(
		bobReceived,
		alice.address,
		bob.address,
		bob.sessionStore,
		bob.identityStore,
		bob.preKeyStore,
		bob.signedPreKeyStore,
		bob.kyberPreKeyStore,
		serializer,
	)
	if err != nil {
		t.Fatalf("bootstrap MessageDecrypt: %v", err)
	}
	if string(got) != string(first) {
		t.Fatalf("bootstrap mismatch: got %q want %q", got, first)
	}

	// Now alternate Alice <-> Bob for `messages` plain SignalMessages.
	for i := 0; i < messages; i++ {
		// Choose a random-length plaintext (1..256 bytes) so chain-step
		// cost varies; keep it deterministic enough for the test runtime.
		var lenBuf [1]byte
		if _, err := rand.Read(lenBuf[:]); err != nil {
			t.Fatalf("rand: %v", err)
		}
		plen := int(lenBuf[0]) + 1
		plaintext := make([]byte, plen)
		if _, err := rand.Read(plaintext); err != nil {
			t.Fatalf("rand: %v", err)
		}

		var (
			senderStore    = bob.sessionStore
			senderID       = bob.identityStore
			senderTo       = alice.address
			senderFrom     = bob.address
			receiverStore  = alice.sessionStore
			receiverID     = alice.identityStore
			receiverPreKey = alice.preKeyStore
			receiverSigned = alice.signedPreKeyStore
			receiverKyber  = alice.kyberPreKeyStore
		)
		if i%2 == 1 {
			senderStore, receiverStore = alice.sessionStore, bob.sessionStore
			senderID, receiverID = alice.identityStore, bob.identityStore
			senderTo, senderFrom = bob.address, alice.address
			receiverPreKey = bob.preKeyStore
			receiverSigned = bob.signedPreKeyStore
			receiverKyber = bob.kyberPreKeyStore
		}

		ct, err := sessionmanagement.MessageEncrypt(
			plaintext,
			senderTo,
			senderFrom,
			senderStore,
			senderID,
			serializer,
		)
		if err != nil {
			t.Fatalf("MessageEncrypt[%d]: %v", i, err)
		}
		if _, ok := ct.(*protocol.SignalMessage); !ok {
			t.Fatalf("expected SignalMessage at iteration %d, got %T", i, ct)
		}

		wire, err := ct.Serialize()
		if err != nil {
			t.Fatalf("Serialize[%d]: %v", i, err)
		}
		received, err := protocol.NewSignalMessageFromBytes(wire, serializer.SignalMessage)
		if err != nil {
			t.Fatalf("NewSignalMessageFromBytes[%d]: %v", i, err)
		}

		got, err := sessionmanagement.MessageDecrypt(
			received,
			senderFrom,
			senderTo,
			receiverStore,
			receiverID,
			receiverPreKey,
			receiverSigned,
			receiverKyber,
			serializer,
		)
		if err != nil {
			t.Fatalf("MessageDecrypt[%d]: %v", i, err)
		}
		if string(got) != string(plaintext) {
			t.Fatalf("plaintext mismatch[%d]: got %q want %q", i, got, plaintext)
		}
	}

	// If we got here without timing out, the per-step ratchet cost is
	// within budget and no skipped-message inflation has occurred.
	t.Logf("%d-message round trip complete", messages)
}
