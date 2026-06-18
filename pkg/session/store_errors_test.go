package session_test

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/session"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/state/store"
)

// ================== Error store helpers ==================

// errStoreSessionStore wraps an inMemorySession but returns an error on StoreSession.
type errStoreSessionStore struct {
	inner *inMemorySession
}

func (e *errStoreSessionStore) LoadSession(address *protocol.SignalAddress) (*record.Session, error) {
	return e.inner.LoadSession(address)
}

func (e *errStoreSessionStore) StoreSession(address *protocol.SignalAddress, r *record.Session) error {
	return errors.New("session store: store failed")
}

func (e *errStoreSessionStore) ContainsSession(address *protocol.SignalAddress) (bool, error) {
	return e.inner.ContainsSession(address)
}

func (e *errStoreSessionStore) DeleteSession(address *protocol.SignalAddress) error {
	return e.inner.DeleteSession(address)
}

func (e *errStoreSessionStore) DeleteAllSessions() error {
	return e.inner.DeleteAllSessions()
}

func (e *errStoreSessionStore) GetSubDeviceSessions(name string) ([]uint32, error) {
	return nil, nil
}

// errSaveIdentityStore wraps inMemoryIdentityKey but returns an error on SaveIdentity.
type errSaveIdentityStore struct {
	inner *inMemoryIdentityKey
}

func (e *errSaveIdentityStore) GetIdentityKeyPair() *identity.KeyPair {
	return e.inner.GetIdentityKeyPair()
}

func (e *errSaveIdentityStore) GetLocalRegistrationId() uint32 {
	return e.inner.GetLocalRegistrationId()
}

func (e *errSaveIdentityStore) SaveIdentity(address *protocol.SignalAddress, identityKey *identity.Key) (store.IdentityChange, error) {
	return 0, errors.New("identity store: save failed")
}

func (e *errSaveIdentityStore) IsTrustedIdentity(address *protocol.SignalAddress, identityKey *identity.Key, direction store.Direction) (bool, error) {
	return e.inner.IsTrustedIdentity(address, identityKey, direction)
}

func (e *errSaveIdentityStore) GetIdentity(address *protocol.SignalAddress) (*identity.Key, error) {
	return e.inner.GetIdentity(address)
}

// errIsTrustedIdentityStore wraps inMemoryIdentityKey but returns an error on IsTrustedIdentity.
type errIsTrustedIdentityStore struct {
	inner *inMemoryIdentityKey
}

func (e *errIsTrustedIdentityStore) GetIdentityKeyPair() *identity.KeyPair {
	return e.inner.GetIdentityKeyPair()
}

func (e *errIsTrustedIdentityStore) GetLocalRegistrationId() uint32 {
	return e.inner.GetLocalRegistrationId()
}

func (e *errIsTrustedIdentityStore) SaveIdentity(address *protocol.SignalAddress, identityKey *identity.Key) (store.IdentityChange, error) {
	return e.inner.SaveIdentity(address, identityKey)
}

func (e *errIsTrustedIdentityStore) IsTrustedIdentity(address *protocol.SignalAddress, identityKey *identity.Key, direction store.Direction) (bool, error) {
	return false, errors.New("identity store: is-trusted failed")
}

func (e *errIsTrustedIdentityStore) GetIdentity(address *protocol.SignalAddress) (*identity.Key, error) {
	return e.inner.GetIdentity(address)
}

// errRemovePreKeyStore wraps inMemoryPreKey but returns an error on RemovePreKey.
type errRemovePreKeyStore struct {
	inner *inMemoryPreKey
}

func (e *errRemovePreKeyStore) LoadPreKey(id uint32) (*record.PreKey, error) {
	return e.inner.LoadPreKey(id)
}

func (e *errRemovePreKeyStore) StorePreKey(id uint32, r *record.PreKey) error {
	return e.inner.StorePreKey(id, r)
}

func (e *errRemovePreKeyStore) ContainsPreKey(id uint32) (bool, error) {
	return e.inner.ContainsPreKey(id)
}

func (e *errRemovePreKeyStore) RemovePreKey(id uint32) error {
	return errors.New("pre-key store: remove failed")
}

// errLoadSignedPreKeyStore wraps inMemorySignedPreKey but returns an error on LoadSignedPreKey.
type errLoadSignedPreKeyStore struct {
	inner *inMemorySignedPreKey
}

func (e *errLoadSignedPreKeyStore) LoadSignedPreKey(id uint32) (*record.SignedPreKey, error) {
	return nil, errors.New("signed-pre-key store: load failed")
}

func (e *errLoadSignedPreKeyStore) LoadSignedPreKeys() ([]*record.SignedPreKey, error) {
	return e.inner.LoadSignedPreKeys()
}

func (e *errLoadSignedPreKeyStore) StoreSignedPreKey(id uint32, r *record.SignedPreKey) error {
	return e.inner.StoreSignedPreKey(id, r)
}

func (e *errLoadSignedPreKeyStore) ContainsSignedPreKey(id uint32) (bool, error) {
	return e.inner.ContainsSignedPreKey(id)
}

func (e *errLoadSignedPreKeyStore) RemoveSignedPreKey(id uint32) error {
	return e.inner.RemoveSignedPreKey(id)
}

// ================== Complete() error paths ==================

// TestComplete_StoreSessionError verifies that DeferredActions.Complete returns
// an error when the session store's StoreSession fails.
// This exercises Session.go:132-134.
func TestComplete_StoreSessionError(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundleNoOneTimePreKey()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("store error test"))
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

	// Build Bob's session builder with a StoreSession-erroring store.
	errStore := &errStoreSessionStore{inner: bob.sessionStore}
	bob.sessionBuilder = session.NewBuilderWithKyber(
		errStore,
		bob.preKeyStore,
		bob.signedPreKeyStore,
		bob.identityStore,
		bob.kyberPreKeyStore,
		alice.address,
		serializer,
	)

	// Process succeeds because we use a store that can load but not store.
	deferred, err := bob.sessionBuilder.Process(preKeyMsg)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}
	if deferred == nil {
		t.Fatal("expected non-nil deferred actions")
	}

	// Complete should fail because StoreSession returns an error.
	completeErr := deferred.Complete()
	if completeErr == nil {
		t.Fatal("expected error from Complete() when StoreSession fails")
	}
}

// TestComplete_SaveIdentityError verifies that DeferredActions.Complete returns
// an error when the identity store's SaveIdentity fails.
// This exercises Session.go:137-139.
func TestComplete_SaveIdentityError(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundleNoOneTimePreKey()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("save identity error test"))
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

	// Build Bob's session builder with a SaveIdentity-erroring identity store.
	errIdentityStore := &errSaveIdentityStore{inner: bob.identityStore}
	bob.sessionBuilder = session.NewBuilderWithKyber(
		bob.sessionStore,
		bob.preKeyStore,
		bob.signedPreKeyStore,
		errIdentityStore,
		bob.kyberPreKeyStore,
		alice.address,
		serializer,
	)

	deferred, err := bob.sessionBuilder.Process(preKeyMsg)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}
	if deferred == nil {
		t.Fatal("expected non-nil deferred actions")
	}

	// Complete should fail because SaveIdentity returns an error.
	completeErr := deferred.Complete()
	if completeErr == nil {
		t.Fatal("expected error from Complete() when SaveIdentity fails")
	}
}

// TestComplete_RemovePreKeyError verifies that DeferredActions.Complete returns
// an error when the pre-key store's RemovePreKey fails.
// This exercises Session.go:153-155.
func TestComplete_RemovePreKeyError(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)

	// Use a bundle WITH a one-time pre-key so that UnsignedPreKeyID is set.
	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("remove prekey error test"))
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

	// Build Bob's session builder with a RemovePreKey-erroring pre-key store.
	// The pre-key must already exist so LoadPreKey (during Process) succeeds.
	errPKStore := &errRemovePreKeyStore{inner: bob.preKeyStore}
	bob.sessionBuilder = session.NewBuilderWithKyber(
		bob.sessionStore,
		errPKStore,
		bob.signedPreKeyStore,
		bob.identityStore,
		bob.kyberPreKeyStore,
		alice.address,
		serializer,
	)

	deferred, err := bob.sessionBuilder.Process(preKeyMsg)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}
	if deferred == nil {
		t.Fatal("expected non-nil deferred")
	}

	// The pre-key ID must be non-nil for RemovePreKey to be called.
	if deferred.UnsignedPreKeyID == nil {
		t.Fatal("expected non-nil UnsignedPreKeyID: kyberBundle() includes a one-time pre-key, so the message must carry a pre-key ID")
	}

	completeErr := deferred.Complete()
	if completeErr == nil {
		t.Fatal("expected error from Complete() when RemovePreKey fails")
	}
}

// ================== Process() error paths ==================

// TestProcess_LoadSessionError verifies that Process returns an error when the
// session store's LoadSession fails.
// This exercises Session.go:170-172.
func TestProcess_LoadSessionError(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundleNoOneTimePreKey()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("process load error"))
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

	// Bob's session builder uses a store that errors on LoadSession.
	errStore := &errLoadSessionStore{inner: bob.sessionStore}
	bob.sessionBuilder = session.NewBuilderWithKyber(
		errStore,
		bob.preKeyStore,
		bob.signedPreKeyStore,
		bob.identityStore,
		bob.kyberPreKeyStore,
		alice.address,
		serializer,
	)

	_, err = bob.sessionBuilder.Process(preKeyMsg)
	if err == nil {
		t.Fatal("expected error from Process() when LoadSession fails")
	}
}

// TestProcess_IsTrustedIdentityError verifies that Process returns an error
// when the identity store's IsTrustedIdentity fails.
// This exercises Session.go:177-179.
func TestProcess_IsTrustedIdentityError(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundleNoOneTimePreKey()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("trusted identity error"))
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

	// Bob's builder uses an identity store that errors on IsTrustedIdentity.
	errIDStore := &errIsTrustedIdentityStore{inner: bob.identityStore}
	bob.sessionBuilder = session.NewBuilderWithKyber(
		bob.sessionStore,
		bob.preKeyStore,
		bob.signedPreKeyStore,
		errIDStore,
		bob.kyberPreKeyStore,
		alice.address,
		serializer,
	)

	_, err = bob.sessionBuilder.Process(preKeyMsg)
	if err == nil {
		t.Fatal("expected error from Process() when IsTrustedIdentity fails")
	}
}

// ================== processV3() error paths ==================

// TestProcessV3_LoadSignedPreKeyError verifies that processV3 returns an error
// when LoadSignedPreKey fails.
// This exercises Session.go:239-241.
func TestProcessV3_LoadSignedPreKeyError(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundleNoOneTimePreKey()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("load signed prekey error"))
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

	// Bob's builder uses a signed-pre-key store that errors on LoadSignedPreKey.
	errSPKStore := &errLoadSignedPreKeyStore{inner: bob.signedPreKeyStore}
	bob.sessionBuilder = session.NewBuilderWithKyber(
		bob.sessionStore,
		bob.preKeyStore,
		errSPKStore,
		bob.identityStore,
		bob.kyberPreKeyStore,
		alice.address,
		serializer,
	)

	_, err = bob.sessionBuilder.Process(preKeyMsg)
	if err == nil {
		t.Fatal("expected error from Process() when LoadSignedPreKey fails")
	}
}

// TestProcessV3_LoadPreKeyError verifies that processV3 returns an error
// when LoadPreKey fails for a message containing a pre-key ID.
// This exercises Session.go:259-261.
func TestProcessV3_LoadPreKeyError(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)

	// Use a bundle WITH a one-time pre-key so that the PreKeyID is set in the message.
	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("load prekey error"))
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

	// The message must carry a pre-key ID because kyberBundle() includes a one-time pre-key.
	if preKeyMsg.PreKeyID() == nil {
		t.Fatal("expected non-nil PreKeyID: kyberBundle() includes a one-time pre-key, so the message must carry a pre-key ID")
	}

	// Bob's builder uses a pre-key store that errors on LoadPreKey.
	bob.sessionBuilder = session.NewBuilderWithKyber(
		bob.sessionStore,
		&errLoadPreKeyStoreImpl{inner: bob.preKeyStore},
		bob.signedPreKeyStore,
		bob.identityStore,
		bob.kyberPreKeyStore,
		alice.address,
		serializer,
	)

	_, err = bob.sessionBuilder.Process(preKeyMsg)
	if err == nil {
		t.Fatal("expected error from Process() when LoadPreKey fails")
	}
}

// errLoadPreKeyStoreImpl wraps inMemoryPreKey but returns an error on LoadPreKey.
type errLoadPreKeyStoreImpl struct {
	inner *inMemoryPreKey
}

func (e *errLoadPreKeyStoreImpl) LoadPreKey(id uint32) (*record.PreKey, error) {
	return nil, errors.New("pre-key store: load failed")
}

func (e *errLoadPreKeyStoreImpl) StorePreKey(id uint32, r *record.PreKey) error {
	return e.inner.StorePreKey(id, r)
}

func (e *errLoadPreKeyStoreImpl) ContainsPreKey(id uint32) (bool, error) {
	return e.inner.ContainsPreKey(id)
}

func (e *errLoadPreKeyStoreImpl) RemovePreKey(id uint32) error {
	return e.inner.RemovePreKey(id)
}

// ================== ProcessBundle() error paths ==================

// TestProcessBundle_IsTrustedIdentityError verifies that ProcessBundle returns
// an error when IsTrustedIdentity fails.
// This exercises Session.go:373-375.
func TestProcessBundle_IsTrustedIdentityError(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	// Alice's builder uses an identity store that errors on IsTrustedIdentity.
	errIDStore := &errIsTrustedIdentityStore{inner: alice.identityStore}
	alice.sessionBuilder = session.NewBuilderWithKyber(
		alice.sessionStore,
		alice.preKeyStore,
		alice.signedPreKeyStore,
		errIDStore,
		alice.kyberPreKeyStore,
		bob.address,
		serializer,
	)

	err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle())
	if err == nil {
		t.Fatal("expected error from ProcessBundle() when IsTrustedIdentity fails")
	}
}

// TestProcessBundle_LoadSessionError verifies that ProcessBundle returns an
// error when the session store's LoadSession fails.
// This exercises Session.go:420-422.
func TestProcessBundle_LoadSessionError(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	// Alice's builder uses a session store that errors on LoadSession.
	errStore := &errLoadSessionStore{inner: alice.sessionStore}
	alice.sessionBuilder = session.NewBuilderWithKyber(
		errStore,
		alice.preKeyStore,
		alice.signedPreKeyStore,
		alice.identityStore,
		alice.kyberPreKeyStore,
		bob.address,
		serializer,
	)

	err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle())
	if err == nil {
		t.Fatal("expected error from ProcessBundle() when LoadSession fails")
	}
}

// TestProcessBundle_StoreSessionError verifies that ProcessBundle returns an
// error when the session store's StoreSession fails.
// This exercises Session.go:529-531.
func TestProcessBundle_StoreSessionError(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	// Alice's builder uses a session store that succeeds on LoadSession
	// but errors on StoreSession.
	errStore := &errStoreSessionStore{inner: alice.sessionStore}
	alice.sessionBuilder = session.NewBuilderWithKyber(
		errStore,
		alice.preKeyStore,
		alice.signedPreKeyStore,
		alice.identityStore,
		alice.kyberPreKeyStore,
		bob.address,
		serializer,
	)

	err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle())
	if err == nil {
		t.Fatal("expected error from ProcessBundle() when StoreSession fails")
	}
}

// TestProcessBundle_SaveIdentityError verifies that ProcessBundle returns an
// error when the identity store's SaveIdentity fails.
// This exercises Session.go:532-534.
func TestProcessBundle_SaveIdentityError(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	// Alice's builder uses an identity store that errors on SaveIdentity.
	errIDStore := &errSaveIdentityStore{inner: alice.identityStore}
	alice.sessionBuilder = session.NewBuilderWithKyber(
		alice.sessionStore,
		alice.preKeyStore,
		alice.signedPreKeyStore,
		errIDStore,
		alice.kyberPreKeyStore,
		bob.address,
		serializer,
	)

	err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle())
	if err == nil {
		t.Fatal("expected error from ProcessBundle() when SaveIdentity fails")
	}
}
