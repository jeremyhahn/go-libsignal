package session_test

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/session"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/state/store"
	"github.com/jeremyhahn/go-libsignal/pkg/util/keyhelper"
)

// TestSetIdentityStore verifies that SetIdentityStore wires an identity store
// into an existing Cipher (the path used by the sessionmanagement facade).
func TestSetIdentityStore(t *testing.T) {
	// Build the minimum required objects: a serializer and a session record
	// store, then create a Cipher without an identity store.
	ser := serialize.NewProtobufSerializer()
	remoteAddress := protocol.NewSignalAddress("bob", 1)

	sessionStore := newInMemorySession(ser)

	// NewCipherFromSession constructs a cipher with no identity store.
	cipher := session.NewCipherFromSession(
		record.NewSession(ser.Session, ser.State),
		remoteAddress,
		sessionStore,
		newInMemoryPreKey(),
		ser.PreKeySignalMessage,
		ser.SignalMessage,
	)

	// SetIdentityStore should wire the store in without panicking.
	identityKP, err := keyhelper.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("GenerateIdentityKeyPair: %v", err)
	}
	identityStore := newInMemoryIdentityKey(identityKP, 1)

	// SetIdentityStore wires the store in; verify it does not panic.
	cipher.SetIdentityStore(identityStore)

	// Calling SetIdentityStore a second time with a different store replaces it.
	identityKP2, err := keyhelper.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("GenerateIdentityKeyPair (second): %v", err)
	}
	identityStore2 := newInMemoryIdentityKey(identityKP2, 2)
	cipher.SetIdentityStore(identityStore2) // must not panic
}

// TestSetIdentityStore_NilStore verifies that SetIdentityStore accepts nil
// without panicking (identity checking is disabled when store is nil).
func TestSetIdentityStore_NilStore(t *testing.T) {
	ser := serialize.NewProtobufSerializer()
	remoteAddress := protocol.NewSignalAddress("alice", 1)
	sessionStore := newInMemorySession(ser)

	cipher := session.NewCipherFromSession(
		record.NewSession(ser.Session, ser.State),
		remoteAddress,
		sessionStore,
		newInMemoryPreKey(),
		ser.PreKeySignalMessage,
		ser.SignalMessage,
	)

	// SetIdentityStore(nil) must not panic.
	var nilStore store.IdentityKey
	cipher.SetIdentityStore(nilStore)
}
