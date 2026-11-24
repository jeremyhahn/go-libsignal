//go:build !fips140only

// FIPS 140-3 exemption (docs/FIPS.md): X3DH and the Double Ratchet require X25519, so the fips140only tag drops this file.

package tests

import (
	"strings"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/sessionmanagement"
)

// TestSessionManagement_FacadeBundleRoundTrip runs prekey and signal messages both ways through the pkg/sessionmanagement facade, as Rust session_management.
func TestSessionManagement_FacadeBundleRoundTrip(t *testing.T) {
	serializer := newSerializer()

	alice := newUser("Alice", 1, serializer)
	bob := newUser("Bob", 2, serializer)

	alice.buildSession(bob.address, serializer)
	bob.buildSession(alice.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatalf("Alice ProcessBundle: %v", err)
	}

	plaintext := []byte("hello from facade")
	ct, err := sessionmanagement.MessageEncrypt(
		plaintext,
		bob.address,
		alice.address,
		alice.sessionStore,
		alice.identityStore,
		serializer,
	)
	if err != nil {
		t.Fatalf("MessageEncrypt: %v", err)
	}

	if _, ok := ct.(*protocol.PreKeySignalMessage); !ok {
		t.Fatalf("expected PreKeySignalMessage on first encrypt, got %T", ct)
	}

	wireBytes, err := ct.Serialize()
	if err != nil {
		t.Fatalf("Serialize ct: %v", err)
	}

	bobReceivedPK, err := protocol.NewPreKeySignalMessageFromBytes(
		wireBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatalf("NewPreKeySignalMessageFromBytes: %v", err)
	}

	got, err := sessionmanagement.MessageDecrypt(
		bobReceivedPK,
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
		t.Fatalf("MessageDecrypt(prekey): %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("decrypt mismatch: got %q want %q", got, plaintext)
	}

	// Bob → Alice, plain SignalMessage path.
	response := []byte("ack from facade")
	ct2, err := sessionmanagement.MessageEncrypt(
		response,
		alice.address,
		bob.address,
		bob.sessionStore,
		bob.identityStore,
		serializer,
	)
	if err != nil {
		t.Fatalf("Bob MessageEncrypt: %v", err)
	}
	if _, ok := ct2.(*protocol.SignalMessage); !ok {
		t.Fatalf("expected SignalMessage on Bob's reply, got %T", ct2)
	}

	wire2, err := ct2.Serialize()
	if err != nil {
		t.Fatalf("Serialize ct2: %v", err)
	}
	aliceReceivedSM, err := protocol.NewSignalMessageFromBytes(
		wire2, serializer.SignalMessage)
	if err != nil {
		t.Fatalf("NewSignalMessageFromBytes: %v", err)
	}

	got2, err := sessionmanagement.MessageDecrypt(
		aliceReceivedSM,
		bob.address,
		alice.address,
		alice.sessionStore,
		alice.identityStore,
		alice.preKeyStore,
		alice.signedPreKeyStore,
		alice.kyberPreKeyStore,
		serializer,
	)
	if err != nil {
		t.Fatalf("Alice MessageDecrypt(signal): %v", err)
	}
	if string(got2) != string(response) {
		t.Fatalf("decrypt2 mismatch: got %q want %q", got2, response)
	}
}

// TestSessionManagement_MessageDecryptRejectsNonRoutableType verifies the
// facade rejects ciphertext kinds it cannot route, mirroring Rust's
// SignalProtocolError::InvalidArgument at session_management.rs:181.
func TestSessionManagement_MessageDecryptRejectsNonRoutableType(t *testing.T) {
	serializer := newSerializer()
	addr := protocol.NewSignalAddress("nobody", 0)

	plaintext := protocol.NewPlaintextContent([]byte{0x01, 0x02})

	_, err := sessionmanagement.MessageDecrypt(
		plaintext,
		addr,
		addr,
		nil, nil, nil, nil, nil,
		serializer,
	)
	if err == nil {
		t.Fatal("expected error for non-routable ciphertext")
	}
	typed, ok := err.(*sessionmanagement.InvalidCiphertextTypeError)
	if !ok {
		t.Fatalf("expected *InvalidCiphertextTypeError, got %T: %v", err, err)
	}
	if !strings.Contains(typed.Error(), "PlaintextContent") {
		t.Fatalf("error message should name kind PlaintextContent: %q", typed.Error())
	}
}

// TestSessionManagement_MessageDecryptRejectsNil verifies the facade
// returns InvalidCiphertextTypeError on a nil input.
func TestSessionManagement_MessageDecryptRejectsNil(t *testing.T) {
	serializer := newSerializer()
	addr := protocol.NewSignalAddress("nobody", 0)

	_, err := sessionmanagement.MessageDecrypt(
		nil,
		addr,
		addr,
		nil, nil, nil, nil, nil,
		serializer,
	)
	if err == nil {
		t.Fatal("expected error for nil ciphertext")
	}
	if _, ok := err.(*sessionmanagement.InvalidCiphertextTypeError); !ok {
		t.Fatalf("expected *InvalidCiphertextTypeError, got %T: %v", err, err)
	}
}
