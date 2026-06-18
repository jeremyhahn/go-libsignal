package session_test

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/session"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
)

// errLoadSessionStore is a session store that returns an error on LoadSession.
type errLoadSessionStore struct {
	inner *inMemorySession
}

func (e *errLoadSessionStore) LoadSession(address *protocol.SignalAddress) (*record.Session, error) {
	return nil, errors.New("session store: load failed")
}

func (e *errLoadSessionStore) StoreSession(address *protocol.SignalAddress, r *record.Session) error {
	return e.inner.StoreSession(address, r)
}

func (e *errLoadSessionStore) ContainsSession(address *protocol.SignalAddress) (bool, error) {
	return e.inner.ContainsSession(address)
}

func (e *errLoadSessionStore) DeleteSession(address *protocol.SignalAddress) error {
	return e.inner.DeleteSession(address)
}

func (e *errLoadSessionStore) DeleteAllSessions() error {
	return e.inner.DeleteAllSessions()
}

func (e *errLoadSessionStore) GetSubDeviceSessions(name string) ([]uint32, error) {
	return nil, nil
}

// errContainsSessionStore is a session store that returns an error on ContainsSession.
type errContainsSessionStore struct {
	inner *inMemorySession
}

func (e *errContainsSessionStore) LoadSession(address *protocol.SignalAddress) (*record.Session, error) {
	return e.inner.LoadSession(address)
}

func (e *errContainsSessionStore) StoreSession(address *protocol.SignalAddress, r *record.Session) error {
	return e.inner.StoreSession(address, r)
}

func (e *errContainsSessionStore) ContainsSession(address *protocol.SignalAddress) (bool, error) {
	return false, errors.New("session store: contains failed")
}

func (e *errContainsSessionStore) DeleteSession(address *protocol.SignalAddress) error {
	return e.inner.DeleteSession(address)
}

func (e *errContainsSessionStore) DeleteAllSessions() error {
	return e.inner.DeleteAllSessions()
}

func (e *errContainsSessionStore) GetSubDeviceSessions(name string) ([]uint32, error) {
	return nil, nil
}

// ================== Encrypt: LoadSession error ==================

// TestEncryptLoadSessionError verifies that Encrypt returns an error when the
// session store's LoadSession fails.
// This exercises SessionCipher.go:118-120.
func TestEncryptLoadSessionError(t *testing.T) {
	ser := serialize.NewProtobufSerializer()
	remoteAddress := protocol.NewSignalAddress("bob", 1)

	inner := newInMemorySession(ser)
	errStore := &errLoadSessionStore{inner: inner}

	cipher := session.NewCipherFromSession(
		record.NewSession(ser.Session, ser.State),
		remoteAddress,
		errStore,
		newInMemoryPreKey(),
		ser.PreKeySignalMessage,
		ser.SignalMessage,
	)

	_, err := cipher.Encrypt([]byte("hello"))
	if err == nil {
		t.Fatal("expected error from LoadSession in Encrypt")
	}
}

// ================== DecryptAndGetKey: ContainsSession error ==================

// TestDecryptAndGetKeyContainsSessionError verifies that DecryptAndGetKey
// returns an error when ContainsSession fails in the session store.
// This exercises SessionCipher.go:293-295.
// ContainsSession is called before the message is accessed, so a nil
// SignalMessage pointer is safe to pass here.
func TestDecryptAndGetKeyContainsSessionError(t *testing.T) {
	ser := serialize.NewProtobufSerializer()
	remoteAddress := protocol.NewSignalAddress("bob", 1)

	inner := newInMemorySession(ser)
	errStore := &errContainsSessionStore{inner: inner}

	cipher := session.NewCipherFromSession(
		record.NewSession(ser.Session, ser.State),
		remoteAddress,
		errStore,
		newInMemoryPreKey(),
		ser.PreKeySignalMessage,
		ser.SignalMessage,
	)

	// ContainsSession returns an error before the message is dereferenced.
	_, _, err := cipher.DecryptAndGetKey(nil)
	if err == nil {
		t.Fatal("expected error from ContainsSession in DecryptAndGetKey")
	}
}

// ================== DecryptAndGetKey: LoadSession error after ContainsSession ==================

// TestDecryptAndGetKeyLoadSessionError verifies that DecryptAndGetKey returns
// an error when LoadSession fails after ContainsSession succeeds.
// This exercises SessionCipher.go:302-304.
//
// errLoadSessionStore.ContainsSession delegates to inner, which has the
// session stored (returns true). But LoadSession always returns an error.
func TestDecryptAndGetKeyLoadSessionError(t *testing.T) {
	ser := serialize.NewProtobufSerializer()
	remoteAddress := protocol.NewSignalAddress("alice", 1)

	// Populate inner so ContainsSession returns true, but LoadSession errors.
	populated := newInMemorySession(ser)
	if err := populated.StoreSession(remoteAddress, record.NewSession(ser.Session, ser.State)); err != nil {
		t.Fatal(err)
	}
	finalStore := &errLoadSessionStore{inner: populated}

	cipher := session.NewCipherFromSession(
		record.NewSession(ser.Session, ser.State),
		remoteAddress,
		finalStore,
		newInMemoryPreKey(),
		ser.PreKeySignalMessage,
		ser.SignalMessage,
	)

	// ContainsSession succeeds (inner has session), but LoadSession errors.
	_, _, err := cipher.DecryptAndGetKey(nil)
	if err == nil {
		t.Fatal("expected error from LoadSession in DecryptAndGetKey")
	}
}
