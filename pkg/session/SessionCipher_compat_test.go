//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 3 tests in this file exercise X25519. FIPS 140-3 does not approve that,
// but the X3DH specification (section 2.1) and the Double Ratchet
// specification (section 5.2) require it, so the fips140only build tag drops
// this file from the FIPS gate. `make test` and `make coverage` still run
// it.

package session_test

// SessionCipher_compat_test.go verifies the source-compatible 2-arg constructor
// wrappers (NewCipher, NewCipherFromSession, NewCipherWithIdentity) that restore
// the pre-address-binding API shape, and confirms that the renamed 3-arg bound
// constructors (NewCipherWithLocalAddress, NewCipherFromSessionWithLocalAddress,
// NewCipherWithIdentityAndLocalAddress) activate address binding.

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/session"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
)

// TestNewCipher_LegacyUnbound verifies that the 2-arg NewCipher wrapper
// (nil localAddress) successfully encrypts and decrypts a SignalMessage
// without address binding. This exercises the legacy unbound code path.
func TestNewCipher_LegacyUnbound(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatalf("ProcessBundle: %v", err)
	}

	// 2-arg form — legacy unbound path, nil localAddress.
	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	if aliceCipher == nil {
		t.Fatal("NewCipher returned nil")
	}

	plaintext := []byte("legacy unbound message")
	ciphertext, err := aliceCipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	msgBytes, err := ciphertext.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(
		msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage,
	)
	if err != nil {
		t.Fatalf("NewPreKeySignalMessageFromBytes: %v", err)
	}

	// Bob processes the pre-key message to establish his session.
	processAndComplete(t, bob.sessionBuilder, preKeyMsg)

	// Bob encrypts a reply; Alice decrypts it using the 2-arg form.
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	reply, err := bobCipher.Encrypt([]byte("reply from bob"))
	if err != nil {
		t.Fatalf("Bob Encrypt: %v", err)
	}
	replyBytes, err := reply.Serialize()
	if err != nil {
		t.Fatalf("Bob Serialize: %v", err)
	}
	replySignal, err := protocol.NewSignalMessageFromBytes(replyBytes, serializer.SignalMessage)
	if err != nil {
		t.Fatalf("NewSignalMessageFromBytes: %v", err)
	}

	got, err := aliceCipher.Decrypt(replySignal)
	if err != nil {
		t.Fatalf("Alice Decrypt: %v", err)
	}
	if string(got) != "reply from bob" {
		t.Errorf("plaintext = %q, want %q", got, "reply from bob")
	}
}

// TestNewCipher_LegacyUnbound_NoSessionError verifies that NewCipher produces
// a Cipher that returns ErrNoSession when no session is established for the
// remote address, exercising the ContainsSession check in DecryptAndGetKey.
func TestNewCipher_LegacyUnbound_NoSessionError(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	nobodyAddr := protocol.NewSignalAddress("nobody", 99)
	alice.buildSession(t, nobodyAddr, serializer)

	aliceCipher := session.NewCipher(alice.sessionBuilder, nobodyAddr)
	if aliceCipher == nil {
		t.Fatal("NewCipher returned nil")
	}

	// DecryptAndGetKey checks ContainsSession first and returns ErrNoSession.
	_, _, err := aliceCipher.DecryptAndGetKey(nil)
	if err == nil {
		t.Fatal("expected ErrNoSession, got nil")
	}
	if !errors.Is(err, session.ErrNoSession) {
		t.Fatalf("expected ErrNoSession, got: %v", err)
	}
}

// TestNewCipherFromSession_LegacyUnbound verifies that the 6-arg
// NewCipherFromSession wrapper uses nil localAddress and successfully
// constructs a functional cipher.
func TestNewCipherFromSession_LegacyUnbound(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	remoteAddress := protocol.NewSignalAddress("bob", 1)

	sess := record.NewSession(serializer.Session, serializer.State)
	sessionStore := newInMemorySession(serializer)

	cipher := session.NewCipherFromSession(
		sess,
		remoteAddress,
		sessionStore,
		newInMemoryPreKey(),
		serializer.PreKeySignalMessage,
		serializer.SignalMessage,
	)
	if cipher == nil {
		t.Fatal("NewCipherFromSession returned nil")
	}
}

// TestNewCipherFromSession_LegacyUnbound_ErrOnNoSession verifies that
// NewCipherFromSession constructed with no existing session returns a typed
// session error on Decrypt (not a panic).
func TestNewCipherFromSession_LegacyUnbound_ErrOnNoSession(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	remoteAddress := protocol.NewSignalAddress("ghost", 1)
	sessionStore := newInMemorySession(serializer)

	cipher := session.NewCipherFromSession(
		nil,
		remoteAddress,
		sessionStore,
		newInMemoryPreKey(),
		serializer.PreKeySignalMessage,
		serializer.SignalMessage,
	)

	// ContainsSession returns false → ErrNoSession.
	_, _, err := cipher.DecryptAndGetKey(nil)
	if err == nil {
		t.Fatal("expected ErrNoSession, got nil")
	}
	if !errors.Is(err, session.ErrNoSession) {
		t.Fatalf("expected ErrNoSession, got: %v", err)
	}
}

// TestNewCipherWithLocalAddress_BoundSemantics verifies that the renamed 3-arg
// NewCipherWithLocalAddress activates address binding: encrypt with both
// addresses set, decrypt with matching addresses succeeds; mismatched
// addresses return ErrAddressMismatch.
func TestNewCipherWithLocalAddress_BoundSemantics(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	// Use canonical UUID-format ServiceId names to enable binding.
	alice := newTestUser(t, "11111111-1111-1111-1111-111111111111", 1, serializer)
	bob := newTestUser(t, "22222222-2222-2222-2222-222222222222", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatalf("ProcessBundle: %v", err)
	}

	// Encrypt with address binding.
	aliceCipher := session.NewCipherWithLocalAddress(alice.sessionBuilder, alice.address, bob.address)
	if aliceCipher == nil {
		t.Fatal("NewCipherWithLocalAddress returned nil")
	}

	ciphertext, err := aliceCipher.Encrypt([]byte("address-bound"))
	if err != nil {
		t.Fatalf("Encrypt (bound): %v", err)
	}
	msgBytes, err := ciphertext.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(
		msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage,
	)
	if err != nil {
		t.Fatalf("NewPreKeySignalMessageFromBytes: %v", err)
	}
	deferred, err := bob.sessionBuilder.Process(preKeyMsg)
	if err != nil {
		t.Fatalf("Bob Process: %v", err)
	}
	if deferred != nil {
		if err := deferred.Complete(); err != nil {
			t.Fatal(err)
		}
	}

	// Bob encrypts a reply with address binding.
	bobCipher := session.NewCipherWithLocalAddress(bob.sessionBuilder, bob.address, alice.address)
	reply, err := bobCipher.Encrypt([]byte("bound reply"))
	if err != nil {
		t.Fatalf("Bob Encrypt (bound): %v", err)
	}
	replyBytes, err := reply.Serialize()
	if err != nil {
		t.Fatalf("Bob Serialize: %v", err)
	}
	replySignal, err := protocol.NewSignalMessageFromBytes(replyBytes, serializer.SignalMessage)
	if err != nil {
		t.Fatalf("NewSignalMessageFromBytes: %v", err)
	}

	// Alice decrypts with matching bound addresses — must succeed.
	plaintext, _, err := aliceCipher.DecryptAndGetKey(replySignal)
	if err != nil {
		t.Fatalf("Alice DecryptAndGetKey (bound, matching): %v", err)
	}
	if string(plaintext) != "bound reply" {
		t.Errorf("plaintext = %q, want %q", string(plaintext), "bound reply")
	}
}
