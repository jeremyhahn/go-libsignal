//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 1 test in this file exercises X25519. FIPS 140-3 does not approve that,
// but the X3DH specification (section 2.1) and the Double Ratchet
// specification (section 5.2) require it, so the fips140only build tag drops
// this file from the FIPS gate. `make test` and `make coverage` still run
// it.

package session_test

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/session"
)

// TestProcessV3_NilSignedPreKey verifies that processV3 returns an error when
// LoadSignedPreKey returns (nil, nil) — i.e., the signed pre-key is not found.
// This exercises Session.go:242-244 (the errNoSignedPreKey path).
func TestProcessV3_NilSignedPreKey(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	// Alice builds a session with Bob's bundle (referencing Bob's signed pre-key ID=0).
	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundleNoOneTimePreKey()); err != nil {
		t.Fatal(err)
	}

	// Alice encrypts a message. This creates a PreKeySignalMessage referencing
	// Bob's signed pre-key ID.
	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("nil signed prekey"))
	if err != nil {
		t.Fatal(err)
	}
	msgBytes, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes,
		serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Remove the signed pre-key from Bob's store before calling Process.
	// LoadSignedPreKey will return (nil, nil) for this ID.
	signedPreKeyID := preKeyMsg.SignedPreKeyID()
	if err := bob.signedPreKeyStore.RemoveSignedPreKey(signedPreKeyID); err != nil {
		t.Fatalf("RemoveSignedPreKey: %v", err)
	}

	// Bob's Process should fail because the signed pre-key is not found.
	_, err = bob.sessionBuilder.Process(preKeyMsg)
	if err == nil {
		t.Fatal("expected error from Process() when signed pre-key is not found")
	}
}
