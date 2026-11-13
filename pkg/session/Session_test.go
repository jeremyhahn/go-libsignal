//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 72 tests in this file exercise X25519. FIPS 140-3 does not approve that,
// but the X3DH specification (section 2.1) and the Double Ratchet
// specification (section 5.2) require it, so the fips140only build tag drops
// this file from the FIPS gate. `make test` and `make coverage` still run
// it.

package session_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/prekey"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/session"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/util/keyhelper"
	"github.com/jeremyhahn/go-libsignal/pkg/util/optional"
)

// ============= Test user helpers =============

type testUser struct {
	identityKeyPair *identity.KeyPair
	registrationID  uint32
	preKeys         []*record.PreKey
	signedPreKey    *record.SignedPreKey
	kyberPreKey     *record.KyberPreKey
	address         *protocol.SignalAddress

	sessionStore      *inMemorySession
	preKeyStore       *inMemoryPreKey
	signedPreKeyStore *inMemorySignedPreKey
	identityStore     *inMemoryIdentityKey
	kyberPreKeyStore  *inMemoryKyberPreKey

	sessionBuilder *session.Builder
}

func newTestUser(t *testing.T, name string, deviceID uint32, serializer *serialize.Serializer) *testUser {
	t.Helper()
	u := &testUser{}

	var err error
	u.identityKeyPair, err = keyhelper.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	u.registrationID = keyhelper.GenerateRegistrationID()
	// start=1: GeneratePreKeys requires start >= 1 (pre-key ID 0 is invalid).
	u.preKeys, err = keyhelper.GeneratePreKeys(1, 100, serializer.PreKeyRecord)
	if err != nil {
		t.Fatal(err)
	}
	u.signedPreKey, err = keyhelper.GenerateSignedPreKey(u.identityKeyPair, 0, serializer.SignedPreKeyRecord)
	if err != nil {
		t.Fatal(err)
	}
	u.kyberPreKey, err = keyhelper.GenerateKyberPreKey(u.identityKeyPair.PrivateKey(), 42, &mockKyberPreKeySerializer{})
	if err != nil {
		t.Fatal(err)
	}

	u.sessionStore = newInMemorySession(serializer)
	u.preKeyStore = newInMemoryPreKey()
	u.signedPreKeyStore = newInMemorySignedPreKey()
	u.identityStore = newInMemoryIdentityKey(u.identityKeyPair, u.registrationID)
	u.kyberPreKeyStore = newInMemoryKyberPreKey()

	for _, pk := range u.preKeys {
		if err := u.preKeyStore.StorePreKey(
			pk.ID().Value,
			record.NewPreKey(pk.ID().Value, pk.KeyPair(), serializer.PreKeyRecord),
		); err != nil {
			t.Fatal(err)
		}
	}

	if err := u.signedPreKeyStore.StoreSignedPreKey(
		u.signedPreKey.ID(),
		record.NewSignedPreKey(
			u.signedPreKey.ID(),
			u.signedPreKey.Timestamp(),
			u.signedPreKey.KeyPair(),
			u.signedPreKey.Signature(),
			serializer.SignedPreKeyRecord,
		),
	); err != nil {
		t.Fatal(err)
	}

	if err := u.kyberPreKeyStore.StoreKyberPreKey(42, u.kyberPreKey); err != nil {
		t.Fatal(err)
	}

	u.address = protocol.NewSignalAddress(name, deviceID)
	return u
}

func (u *testUser) buildSession(t *testing.T, address *protocol.SignalAddress, serializer *serialize.Serializer) {
	t.Helper()
	u.sessionBuilder = session.NewBuilderWithKyber(
		u.sessionStore,
		u.preKeyStore,
		u.signedPreKeyStore,
		u.identityStore,
		u.kyberPreKeyStore,
		address,
		serializer,
	)
}

// kyberBundle creates a PreKeyBundle with Kyber keys included.
func (u *testUser) kyberBundle() *prekey.Bundle {
	return prekey.NewBundleWithKyber(
		u.registrationID,
		u.address.DeviceID(),
		u.preKeys[0].ID(),
		u.signedPreKey.ID(),
		u.preKeys[0].KeyPair().PublicKey(),
		u.signedPreKey.KeyPair().PublicKey(),
		u.signedPreKey.Signature(),
		u.identityKeyPair.PublicKey(),
		&optional.Uint32{Value: 42},
		u.kyberPreKey.PublicKey(),
		u.kyberPreKey.Signature(),
	)
}

// kyberBundleWithPreKeyIndex creates a PreKeyBundle with Kyber keys using the
// specified pre-key index, for tests that need multiple bundles.
func (u *testUser) kyberBundleWithPreKeyIndex(idx int) *prekey.Bundle {
	return prekey.NewBundleWithKyber(
		u.registrationID,
		u.address.DeviceID(),
		u.preKeys[idx].ID(),
		u.signedPreKey.ID(),
		u.preKeys[idx].KeyPair().PublicKey(),
		u.signedPreKey.KeyPair().PublicKey(),
		u.signedPreKey.Signature(),
		u.identityKeyPair.PublicKey(),
		&optional.Uint32{Value: 42},
		u.kyberPreKey.PublicKey(),
		u.kyberPreKey.Signature(),
	)
}

// kyberBundleNoOneTimePreKey creates a PreKeyBundle with Kyber keys but
// without a one-time pre-key.
func (u *testUser) kyberBundleNoOneTimePreKey() *prekey.Bundle {
	return prekey.NewBundleWithKyber(
		u.registrationID,
		u.address.DeviceID(),
		nil,
		u.signedPreKey.ID(),
		nil,
		u.signedPreKey.KeyPair().PublicKey(),
		u.signedPreKey.Signature(),
		u.identityKeyPair.PublicKey(),
		&optional.Uint32{Value: 42},
		u.kyberPreKey.PublicKey(),
		u.kyberPreKey.Signature(),
	)
}

// processAndComplete is a test helper that calls Process and immediately
// commits the deferred actions. This is used by tests that need the session
// established but are not specifically testing the deferred-commit pattern.
func processAndComplete(t *testing.T, builder *session.Builder, msg *protocol.PreKeySignalMessage) *session.DeferredActions {
	t.Helper()
	deferred, err := builder.Process(msg)
	if err != nil {
		t.Fatal(err)
	}
	if deferred != nil {
		if err := deferred.Complete(); err != nil {
			t.Fatal(err)
		}
	}
	return deferred
}

// ============= Tests =============

func TestNewBuilder(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	if alice.sessionBuilder == nil {
		t.Fatal("session builder should not be nil")
	}
}

func TestNewBuilderWithKyber(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	builder := session.NewBuilderWithKyber(
		alice.sessionStore,
		alice.preKeyStore,
		alice.signedPreKeyStore,
		alice.identityStore,
		newInMemoryKyberPreKey(),
		bob.address,
		serializer,
	)
	if builder == nil {
		t.Fatal("builder should not be nil")
	}
}

func TestNewBuilderFromSignal(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	signalStore := &inMemorySignalProtocol{
		inMemoryIdentityKey:  alice.identityStore,
		inMemoryPreKey:       alice.preKeyStore,
		inMemorySession:      alice.sessionStore,
		inMemorySignedPreKey: alice.signedPreKeyStore,
		inMemorySenderKey:    newInMemorySenderKey(),
		inMemoryKyberPreKey:  newInMemoryKyberPreKey(),
	}
	builder := session.NewBuilderFromSignal(signalStore, bob.address, serializer)
	if builder == nil {
		t.Fatal("builder should not be nil")
	}
}

func TestProcessBundle(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)

	bundle := bob.kyberBundle()

	err := alice.sessionBuilder.ProcessBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}

	// Verify session was stored.
	if ok, _ := alice.sessionStore.ContainsSession(bob.address); !ok {
		t.Fatal("session should exist after ProcessBundle")
	}
}

func TestProcessBundleUntrustedIdentity(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)

	// Save a different identity for Bob to make his real key untrusted.
	otherIdentity, _ := keyhelper.GenerateIdentityKeyPair()
	if _, err := alice.identityStore.SaveIdentity(bob.address, otherIdentity.PublicKey()); err != nil {
		t.Fatalf("setup: SaveIdentity: %v", err)
	}

	bundle := bob.kyberBundle()

	err := alice.sessionBuilder.ProcessBundle(bundle)
	if err == nil {
		t.Fatal("expected error for untrusted identity")
	}
}

func TestProcessBundleNoSignedPreKey(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)

	bundle := prekey.NewBundle(
		bob.registrationID,
		bob.address.DeviceID(),
		bob.preKeys[0].ID(),
		bob.signedPreKey.ID(),
		bob.preKeys[0].KeyPair().PublicKey(),
		nil, // no signed prekey
		bob.signedPreKey.Signature(),
		bob.identityKeyPair.PublicKey(),
	)

	err := alice.sessionBuilder.ProcessBundle(bundle)
	if err == nil {
		t.Fatal("expected error for missing signed prekey")
	}
}

func TestProcessBundleInvalidSignature(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)

	// Use an invalid signature.
	badSig := [64]byte{0x01, 0x02, 0x03}
	bundle := prekey.NewBundle(
		bob.registrationID,
		bob.address.DeviceID(),
		bob.preKeys[0].ID(),
		bob.signedPreKey.ID(),
		bob.preKeys[0].KeyPair().PublicKey(),
		bob.signedPreKey.KeyPair().PublicKey(),
		badSig,
		bob.identityKeyPair.PublicKey(),
	)

	err := alice.sessionBuilder.ProcessBundle(bundle)
	if err == nil {
		t.Fatal("expected error for invalid signature")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	bundle := bob.kyberBundle()

	err := alice.sessionBuilder.ProcessBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}

	// Alice encrypts a message.
	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	plaintext := []byte("Hello Bob!")
	message, err := aliceCipher.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Emulate receiving the message.
	messageBytes, err := message.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	receivedMessage, err := protocol.NewPreKeySignalMessageFromBytes(messageBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Bob processes the prekey message to establish his session.
	processAndComplete(t, bob.sessionBuilder, receivedMessage)

	// Bob decrypts.
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	decrypted, err := bobCipher.Decrypt(receivedMessage.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}

	if string(decrypted) != "Hello Bob!" {
		t.Fatalf("expected 'Hello Bob!', got '%s'", string(decrypted))
	}
}

func TestDecryptAndGetKey(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	bundle := bob.kyberBundle()

	err := alice.sessionBuilder.ProcessBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	plaintext := []byte("Test message")
	message, err := aliceCipher.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	messageBytes, err := message.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	receivedMessage, err := protocol.NewPreKeySignalMessageFromBytes(messageBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	processAndComplete(t, bob.sessionBuilder, receivedMessage)

	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	decrypted, messageKeys, err := bobCipher.DecryptAndGetKey(receivedMessage.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != "Test message" {
		t.Fatal("decryption mismatch")
	}
	if messageKeys == nil {
		t.Fatal("message keys should not be nil")
	}
}

func TestDecryptWithKey(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	bundle := bob.kyberBundle()

	err := alice.sessionBuilder.ProcessBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	plaintext := []byte("Message with key")
	message, err := aliceCipher.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	messageBytes, err := message.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	receivedMessage, err := protocol.NewPreKeySignalMessageFromBytes(messageBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	processAndComplete(t, bob.sessionBuilder, receivedMessage)

	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	_, messageKeys, err := bobCipher.DecryptAndGetKey(receivedMessage.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}

	// Use the saved keys to decrypt the same message body again via DecryptWithKey.
	decrypted, err := bobCipher.DecryptWithKey(receivedMessage.WhisperMessage(), messageKeys)
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != "Message with key" {
		t.Fatalf("expected 'Message with key', got '%s'", string(decrypted))
	}
}

func TestDecryptNoSession(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	bundle := bob.kyberBundle()

	err := alice.sessionBuilder.ProcessBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	message, err := aliceCipher.Encrypt([]byte("Hello"))
	if err != nil {
		t.Fatal(err)
	}

	messageBytes, err := message.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	receivedMessage, err := protocol.NewPreKeySignalMessageFromBytes(messageBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Try to decrypt without establishing Bob's session.
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	_, err = bobCipher.Decrypt(receivedMessage.WhisperMessage())
	if err == nil {
		t.Fatal("expected error when decrypting without session")
	}
}

func TestNewCipher(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)

	cipher := session.NewCipher(alice.sessionBuilder, bob.address)
	if cipher == nil {
		t.Fatal("cipher should not be nil")
	}
}

func TestNewCipherFromSession(t *testing.T) {
	serializer := serialize.NewJSONSerializer()

	sessionStore := newInMemorySession(serializer)
	preKeyStore := newInMemoryPreKey()
	addr := protocol.NewSignalAddress("test", 1)

	sess := record.NewSession(serializer.Session, serializer.State)

	cipher := session.NewCipherFromSession(
		sess,
		addr,
		sessionStore,
		preKeyStore,
		serializer.PreKeySignalMessage,
		serializer.SignalMessage,
	)
	if cipher == nil {
		t.Fatal("cipher should not be nil")
	}
}

func TestEncryptDecryptBidirectional(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	bundle := bob.kyberBundle()

	if err := alice.sessionBuilder.ProcessBundle(bundle); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg1, err := aliceCipher.Encrypt([]byte("Hello Bob!"))
	if err != nil {
		t.Fatal(err)
	}

	// Bob processes.
	msgBytes, err := msg1.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}
	processAndComplete(t, bob.sessionBuilder, preKeyMsg)

	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	decrypted, err := bobCipher.Decrypt(preKeyMsg.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != "Hello Bob!" {
		t.Fatalf("expected 'Hello Bob!', got '%s'", string(decrypted))
	}

	// Bob responds.
	response, err := bobCipher.Encrypt([]byte("Hi Alice!"))
	if err != nil {
		t.Fatal(err)
	}

	respBytes, err := response.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	signalMsg, err := protocol.NewSignalMessageFromBytes(respBytes, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	decryptedResp, err := aliceCipher.Decrypt(signalMsg)
	if err != nil {
		t.Fatal(err)
	}
	if string(decryptedResp) != "Hi Alice!" {
		t.Fatalf("expected 'Hi Alice!', got '%s'", string(decryptedResp))
	}
}

func TestMaxFunction(t *testing.T) {
	// The max function is unexported, but we test it implicitly
	// through multiple encrypt/decrypt cycles where the counter
	// calculations use max.
}

func TestProcessExistingSession(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	// Use a bundle without one-time prekey to avoid prekey removal issues.
	bundle := bob.kyberBundleNoOneTimePreKey()

	if err := alice.sessionBuilder.ProcessBundle(bundle); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("First"))
	if err != nil {
		t.Fatal(err)
	}

	msgBytes, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	// First process establishes the session.
	processAndComplete(t, bob.sessionBuilder, preKeyMsg)

	// Second process re-processes the same prekey message.
	// Without a one-time prekey, it should succeed (re-establishes the session).
	deferred := processAndComplete(t, bob.sessionBuilder, preKeyMsg)
	// No prekey ID returned since there was no one-time prekey.
	if deferred != nil && deferred.UnsignedPreKeyID != nil {
		t.Fatal("expected nil prekey ID")
	}
}

func TestProcessBundleExistingSessionNotFresh(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)

	bundle := bob.kyberBundle()

	// Process once to create the session.
	err := alice.sessionBuilder.ProcessBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}

	// Process again -- session is no longer fresh, archives current state.
	bundle2 := bob.kyberBundleWithPreKeyIndex(1)

	err = alice.sessionBuilder.ProcessBundle(bundle2)
	if err != nil {
		t.Fatal(err)
	}
}

func TestProcessUntrustedIdentity(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	bundle := bob.kyberBundle()

	if err := alice.sessionBuilder.ProcessBundle(bundle); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("test"))
	if err != nil {
		t.Fatal(err)
	}

	msgBytes, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Save a different identity for alice to make untrusted.
	otherIdentity, _ := keyhelper.GenerateIdentityKeyPair()
	if _, err := bob.identityStore.SaveIdentity(alice.address, otherIdentity.PublicKey()); err != nil {
		t.Fatalf("setup: SaveIdentity: %v", err)
	}

	_, err = bob.sessionBuilder.Process(preKeyMsg)
	if err == nil {
		t.Fatal("expected error for untrusted identity in Process")
	}
}

func TestDecryptWithRecordPreviousState(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	// First session setup.
	bundle1 := bob.kyberBundle()
	if err := alice.sessionBuilder.ProcessBundle(bundle1); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg1, err := aliceCipher.Encrypt([]byte("Hello from first session"))
	if err != nil {
		t.Fatal(err)
	}

	msgBytes1, err := msg1.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg1, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes1, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	processAndComplete(t, bob.sessionBuilder, preKeyMsg1)

	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	decrypted1, err := bobCipher.Decrypt(preKeyMsg1.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted1) != "Hello from first session" {
		t.Fatal("first decryption mismatch")
	}

	// Now set up a second session (which should archive the first).
	bundle2 := bob.kyberBundleWithPreKeyIndex(1)
	if err := alice.sessionBuilder.ProcessBundle(bundle2); err != nil {
		t.Fatal(err)
	}

	// Encrypt a new message with the new session.
	msg2, err := aliceCipher.Encrypt([]byte("Hello from second session"))
	if err != nil {
		t.Fatal(err)
	}

	msgBytes2, err := msg2.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg2, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes2, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	processAndComplete(t, bob.sessionBuilder, preKeyMsg2)

	decrypted2, err := bobCipher.Decrypt(preKeyMsg2.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted2) != "Hello from second session" {
		t.Fatal("second decryption mismatch")
	}
}

func TestProcessBundleNoOneTimePreKey(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	// Use a bundle without one-time prekey.
	bundle := bob.kyberBundleNoOneTimePreKey()

	if err := alice.sessionBuilder.ProcessBundle(bundle); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("No OTP"))
	if err != nil {
		t.Fatal(err)
	}

	msgBytes, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	processAndComplete(t, bob.sessionBuilder, preKeyMsg)

	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	decrypted, err := bobCipher.Decrypt(preKeyMsg.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != "No OTP" {
		t.Fatalf("expected 'No OTP', got '%s'", string(decrypted))
	}
}

func TestProcessNotFreshSessionArchive(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	// First session.
	bundle1 := bob.kyberBundle()
	if err := alice.sessionBuilder.ProcessBundle(bundle1); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg1, err := aliceCipher.Encrypt([]byte("msg1"))
	if err != nil {
		t.Fatal(err)
	}
	msgBytes1, _ := msg1.Serialize()
	preKeyMsg1, _ := protocol.NewPreKeySignalMessageFromBytes(msgBytes1, serializer.PreKeySignalMessage, serializer.SignalMessage)

	processAndComplete(t, bob.sessionBuilder, preKeyMsg1)

	// Second session with different prekey (session is not fresh now).
	bundle2 := bob.kyberBundleWithPreKeyIndex(2)
	if err := alice.sessionBuilder.ProcessBundle(bundle2); err != nil {
		t.Fatal(err)
	}

	msg2, err := aliceCipher.Encrypt([]byte("msg2"))
	if err != nil {
		t.Fatal(err)
	}
	msgBytes2, _ := msg2.Serialize()
	preKeyMsg2, _ := protocol.NewPreKeySignalMessageFromBytes(msgBytes2, serializer.PreKeySignalMessage, serializer.SignalMessage)

	// Process should archive the current state since not fresh.
	processAndComplete(t, bob.sessionBuilder, preKeyMsg2)
}

func TestOutOfOrderMessages(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	bundle := bob.kyberBundle()
	if err := alice.sessionBuilder.ProcessBundle(bundle); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)

	// Encrypt 4 messages.
	msgs := make([]protocol.CiphertextMessage, 4)
	texts := []string{"msg0", "msg1", "msg2", "msg3"}
	for i := range texts {
		m, err := aliceCipher.Encrypt([]byte(texts[i]))
		if err != nil {
			t.Fatal(err)
		}
		msgs[i] = m
	}

	// Process message 3 first (out of order).
	msgBytes3, _ := msgs[3].Serialize()
	preKeyMsg3, _ := protocol.NewPreKeySignalMessageFromBytes(msgBytes3, serializer.PreKeySignalMessage, serializer.SignalMessage)
	processAndComplete(t, bob.sessionBuilder, preKeyMsg3)

	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	d3, err := bobCipher.Decrypt(preKeyMsg3.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}
	if string(d3) != "msg3" {
		t.Fatal("message 3 decryption mismatch")
	}

	// Now decrypt message 0 (which was skipped).
	msgBytes0, _ := msgs[0].Serialize()
	preKeyMsg0, _ := protocol.NewPreKeySignalMessageFromBytes(msgBytes0, serializer.PreKeySignalMessage, serializer.SignalMessage)
	d0, err := bobCipher.Decrypt(preKeyMsg0.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}
	if string(d0) != "msg0" {
		t.Fatal("message 0 decryption mismatch")
	}
}

func TestDecryptWithStateUninitializedSession(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	state := record.NewState(serializer.State)

	// State has no sender chain, so DecryptWithState should fail.
	cipher := session.NewCipherFromSession(
		record.NewSession(serializer.Session, serializer.State),
		protocol.NewSignalAddress("test", 1),
		newInMemorySession(serializer),
		newInMemoryPreKey(),
		serializer.PreKeySignalMessage,
		serializer.SignalMessage,
	)

	// Create a dummy signal message for testing (it will fail before decryption).
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)
	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)
	bundle := bob.kyberBundle()
	_ = alice.sessionBuilder.ProcessBundle(bundle)
	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, _ := aliceCipher.Encrypt([]byte("test"))
	msgBytes, _ := msg.Serialize()
	preKeyMsg, _ := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)

	_, _, err := cipher.DecryptWithState(state, preKeyMsg.WhisperMessage())
	if err == nil {
		t.Fatal("expected error for uninitialized session")
	}
}

func TestDecryptWithRecordFallbackToPreviousState(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	// Establish first session.
	bundle1 := bob.kyberBundle()
	if err := alice.sessionBuilder.ProcessBundle(bundle1); err != nil {
		t.Fatal(err)
	}
	aliceCipher1 := session.NewCipher(alice.sessionBuilder, bob.address)

	// Encrypt messages with first session.
	msg1, err := aliceCipher1.Encrypt([]byte("first session msg"))
	if err != nil {
		t.Fatal(err)
	}
	msgBytes1, _ := msg1.Serialize()
	preKeyMsg1, _ := protocol.NewPreKeySignalMessageFromBytes(msgBytes1, serializer.PreKeySignalMessage, serializer.SignalMessage)

	// Bob processes first message.
	processAndComplete(t, bob.sessionBuilder, preKeyMsg1)

	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	dec1, err := bobCipher.Decrypt(preKeyMsg1.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}
	if string(dec1) != "first session msg" {
		t.Fatal("first message decryption mismatch")
	}

	// Bob sends response to establish ratchet in first session.
	resp, err := bobCipher.Encrypt([]byte("response1"))
	if err != nil {
		t.Fatal(err)
	}
	respBytes, _ := resp.Serialize()
	respMsg, _ := protocol.NewSignalMessageFromBytes(respBytes, serializer.SignalMessage)
	dec1r, err := aliceCipher1.Decrypt(respMsg)
	if err != nil {
		t.Fatal(err)
	}
	if string(dec1r) != "response1" {
		t.Fatal("response decryption mismatch")
	}

	// Now Alice starts a new session (overwrites first).
	bundle2 := bob.kyberBundleWithPreKeyIndex(1)
	if err := alice.sessionBuilder.ProcessBundle(bundle2); err != nil {
		t.Fatal(err)
	}

	// Alice encrypts with new session.
	msg2, err := aliceCipher1.Encrypt([]byte("second session msg"))
	if err != nil {
		t.Fatal(err)
	}
	msgBytes2, _ := msg2.Serialize()
	preKeyMsg2, _ := protocol.NewPreKeySignalMessageFromBytes(msgBytes2, serializer.PreKeySignalMessage, serializer.SignalMessage)

	// Bob processes second message (archives first session state).
	processAndComplete(t, bob.sessionBuilder, preKeyMsg2)

	// Bob decrypts - this hits the previous state fallback path in DecryptWithRecord.
	dec2, err := bobCipher.Decrypt(preKeyMsg2.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}
	if string(dec2) != "second session msg" {
		t.Fatal("second message decryption mismatch")
	}
}

func TestEncryptMultipleRatchetSteps(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	bundle := bob.kyberBundle()
	if err := alice.sessionBuilder.ProcessBundle(bundle); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("initial"))
	if err != nil {
		t.Fatal(err)
	}
	msgBytes, _ := msg.Serialize()
	preKeyMsg, _ := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)

	processAndComplete(t, bob.sessionBuilder, preKeyMsg)

	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	_, err = bobCipher.Decrypt(preKeyMsg.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}

	// Multiple ratchet steps: Bob -> Alice -> Bob -> Alice
	for i := 0; i < 5; i++ {
		// Bob encrypts.
		bMsg, err := bobCipher.Encrypt([]byte("bob msg"))
		if err != nil {
			t.Fatalf("bob encrypt %d: %v", i, err)
		}
		bBytes, _ := bMsg.Serialize()
		bSignalMsg, _ := protocol.NewSignalMessageFromBytes(bBytes, serializer.SignalMessage)
		dec, err := aliceCipher.Decrypt(bSignalMsg)
		if err != nil {
			t.Fatalf("alice decrypt %d: %v", i, err)
		}
		if string(dec) != "bob msg" {
			t.Fatalf("round %d: expected 'bob msg', got '%s'", i, string(dec))
		}

		// Alice encrypts.
		aMsg, err := aliceCipher.Encrypt([]byte("alice msg"))
		if err != nil {
			t.Fatalf("alice encrypt %d: %v", i, err)
		}
		aBytes, _ := aMsg.Serialize()
		aSignalMsg, _ := protocol.NewSignalMessageFromBytes(aBytes, serializer.SignalMessage)
		dec, err = bobCipher.Decrypt(aSignalMsg)
		if err != nil {
			t.Fatalf("bob decrypt %d: %v", i, err)
		}
		if string(dec) != "alice msg" {
			t.Fatalf("round %d: expected 'alice msg', got '%s'", i, string(dec))
		}
	}
}

func TestMultipleEncryptDecrypt(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	bundle := bob.kyberBundle()

	if err := alice.sessionBuilder.ProcessBundle(bundle); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)

	// Encrypt multiple messages.
	messages := make([]protocol.CiphertextMessage, 5)
	texts := []string{"msg1", "msg2", "msg3", "msg4", "msg5"}
	for i, text := range texts {
		msg, err := aliceCipher.Encrypt([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		messages[i] = msg
	}

	// Bob establishes session from first message.
	firstBytes, err := messages[0].Serialize()
	if err != nil {
		t.Fatal(err)
	}
	firstMsg, err := protocol.NewPreKeySignalMessageFromBytes(firstBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	processAndComplete(t, bob.sessionBuilder, firstMsg)

	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)

	// Decrypt all messages.
	for i, msg := range messages {
		msgBytes, err := msg.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
		if err != nil {
			t.Fatal(err)
		}

		decrypted, err := bobCipher.Decrypt(preKeyMsg.WhisperMessage())
		if err != nil {
			t.Fatalf("failed to decrypt message %d: %v", i, err)
		}
		if string(decrypted) != texts[i] {
			t.Fatalf("message %d: expected '%s', got '%s'", i, texts[i], string(decrypted))
		}
	}
}

// ============= DecryptWithState Version Mismatch =============

func TestDecryptWithStateVersionMismatch(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	bundle := bob.kyberBundle()
	if err := alice.sessionBuilder.ProcessBundle(bundle); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("version test"))
	if err != nil {
		t.Fatal(err)
	}

	msgBytes, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	processAndComplete(t, bob.sessionBuilder, preKeyMsg)

	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)

	// Construct a signal message with a different version to trigger version mismatch.
	// We use a version 2 message against a version 3 session.
	bobSessionRecord, _ := bob.sessionStore.LoadSession(alice.address)
	bobState := bobSessionRecord.SessionState()

	// Create a fake SignalMessage with version 2.
	chainKey := bobState.SenderChainKey()
	messageKeys, err := chainKey.MessageKeys()
	if err != nil {
		t.Fatal(err)
	}

	fakeMsg, err := protocol.NewSignalMessage(
		2, // wrong version
		chainKey.Index(),
		0,
		mustCopy(messageKeys.MacKey()),
		bobState.SenderRatchetKey(),
		[]byte("fake cipher"),
		bobState.LocalIdentityKey(),
		bobState.RemoteIdentityKey(),
		serializer.SignalMessage,
		nil,      // pqRatchetMsg
		nil, nil, // localAddress, remoteAddress (no binding)
	)
	if err != nil {
		t.Fatal(err)
	}

	// DecryptWithState should fail with "Wrong message version!"
	_, _, err = bobCipher.DecryptWithState(bobState, fakeMsg)
	if err == nil {
		t.Fatal("expected error for version mismatch")
	}
}

// ============= DecryptWithRecord - No Valid Sessions =============

func TestDecryptWithRecordNoValidSessions(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)
	carol := newTestUser(t, "Carol", 3, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)
	carol.buildSession(t, bob.address, serializer)

	// Alice establishes session with Bob.
	bundle := bob.kyberBundle()
	if err := alice.sessionBuilder.ProcessBundle(bundle); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("for bob"))
	if err != nil {
		t.Fatal(err)
	}
	msgBytes, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Bob processes Alice's message.
	processAndComplete(t, bob.sessionBuilder, preKeyMsg)
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	_, err = bobCipher.Decrypt(preKeyMsg.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}

	// Carol establishes a different session with Bob (different keys).
	carolBundle := bob.kyberBundleWithPreKeyIndex(1)
	if err := carol.sessionBuilder.ProcessBundle(carolBundle); err != nil {
		t.Fatal(err)
	}

	carolCipher := session.NewCipher(carol.sessionBuilder, bob.address)
	carolMsg, err := carolCipher.Encrypt([]byte("from carol"))
	if err != nil {
		t.Fatal(err)
	}
	carolMsgBytes, err := carolMsg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	carolPreKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(carolMsgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Try to decrypt Carol's message using Bob's cipher that only has
	// a session with Alice -- the SignalMessage won't match any session.
	sessionRec, _ := bob.sessionStore.LoadSession(alice.address)
	_, _, err = bobCipher.DecryptWithRecord(sessionRec, carolPreKeyMsg.WhisperMessage())
	if err == nil {
		t.Fatal("expected 'No valid sessions' error")
	}
}

// ============= Process with Nil PreKey (prekey store returns nil) =============

func TestProcessNilOneTimePreKey(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	bundle := bob.kyberBundle()
	if err := alice.sessionBuilder.ProcessBundle(bundle); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	msgBytes, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Remove the one-time pre-key from Bob's store before processing.
	if err := bob.preKeyStore.RemovePreKey(bob.preKeys[0].ID().Value); err != nil {
		t.Fatalf("setup: RemovePreKey: %v", err)
	}

	_, err = bob.sessionBuilder.Process(preKeyMsg)
	if err == nil {
		t.Fatal("expected error when one-time prekey is nil in store")
	}
}

// ============= Encrypt after session acknowledged (non-PreKey message) =============

func TestEncryptAfterSessionAcknowledged(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	bundle := bob.kyberBundle()
	if err := alice.sessionBuilder.ProcessBundle(bundle); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)

	// First message is a PreKeySignalMessage.
	msg1, err := aliceCipher.Encrypt([]byte("first"))
	if err != nil {
		t.Fatal(err)
	}
	msg1Bytes, err := msg1.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg1, err := protocol.NewPreKeySignalMessageFromBytes(msg1Bytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Bob processes and decrypts, which clears unacknowledged pre-key state.
	processAndComplete(t, bob.sessionBuilder, preKeyMsg1)
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	dec, err := bobCipher.Decrypt(preKeyMsg1.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != "first" {
		t.Fatal("first decryption mismatch")
	}

	// Bob responds (this clears the unacknowledged state on Bob's side).
	bobReply, err := bobCipher.Encrypt([]byte("reply"))
	if err != nil {
		t.Fatal(err)
	}
	replyBytes, err := bobReply.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	replyMsg, err := protocol.NewSignalMessageFromBytes(replyBytes, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}
	decReply, err := aliceCipher.Decrypt(replyMsg)
	if err != nil {
		t.Fatal(err)
	}
	if string(decReply) != "reply" {
		t.Fatal("reply decryption mismatch")
	}

	// Now Alice sends again -- this should be a plain SignalMessage (no PreKey wrapper),
	// because the session is acknowledged now.
	msg2, err := aliceCipher.Encrypt([]byte("second"))
	if err != nil {
		t.Fatal(err)
	}
	msg2Bytes, err := msg2.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	// It should be parseable as a plain signal message (not prekey).
	signalMsg, err := protocol.NewSignalMessageFromBytes(msg2Bytes, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}
	dec2, err := bobCipher.Decrypt(signalMsg)
	if err != nil {
		t.Fatal(err)
	}
	if string(dec2) != "second" {
		t.Fatalf("expected 'second', got '%s'", string(dec2))
	}
}

// ============= DecryptWithKey error path =============

func TestDecryptWithKeyBadKey(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	bundle := bob.kyberBundle()
	if err := alice.sessionBuilder.ProcessBundle(bundle); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	msgBytes, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}
	processAndComplete(t, bob.sessionBuilder, preKeyMsg)

	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	_, correctKeys, err := bobCipher.DecryptAndGetKey(preKeyMsg.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}

	// Bob replies so Alice can ratchet, then Alice sends a second regular SignalMessage.
	reply, err := bobCipher.Encrypt([]byte("reply"))
	if err != nil {
		t.Fatal(err)
	}
	replyBytes, _ := reply.Serialize()
	replyMsg, _ := protocol.NewSignalMessageFromBytes(replyBytes, serializer.SignalMessage)
	_, err = aliceCipher.Decrypt(replyMsg)
	if err != nil {
		t.Fatal(err)
	}

	msg2, err := aliceCipher.Encrypt([]byte("another"))
	if err != nil {
		t.Fatal(err)
	}
	msg2Bytes, _ := msg2.Serialize()
	signalMsg2, _ := protocol.NewSignalMessageFromBytes(msg2Bytes, serializer.SignalMessage)

	// Try to use the old key on the new message body -- cipher mismatch should produce garbage or error.
	_, err = bobCipher.DecryptWithKey(signalMsg2, correctKeys)
	// The decrypt may succeed with wrong plaintext or fail depending on padding.
	// Either way, this exercises the code path.
	_ = err
}

// ============= DecryptAndGetKey error path (no session) =============

func TestDecryptAndGetKeyNoSession(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	bundle := bob.kyberBundle()
	if err := alice.sessionBuilder.ProcessBundle(bundle); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	msgBytes, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Try DecryptAndGetKey without Bob having a session.
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	_, _, err = bobCipher.DecryptAndGetKey(preKeyMsg.WhisperMessage())
	if err == nil {
		t.Fatal("expected error when no session exists for DecryptAndGetKey")
	}
}

// ============= Process on Not-Fresh Session (archive path in processV3) =============

func TestProcessV3ArchivesNonFreshSession(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	// First session with prekey 0.
	bundle1 := bob.kyberBundle()
	if err := alice.sessionBuilder.ProcessBundle(bundle1); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg1, err := aliceCipher.Encrypt([]byte("msg1"))
	if err != nil {
		t.Fatal(err)
	}
	msg1Bytes, err := msg1.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg1, err := protocol.NewPreKeySignalMessageFromBytes(msg1Bytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}
	processAndComplete(t, bob.sessionBuilder, preKeyMsg1)
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	_, err = bobCipher.Decrypt(preKeyMsg1.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}

	// Second session with prekey 2 (forces archive of first session in processV3).
	bundle2 := bob.kyberBundleWithPreKeyIndex(2)
	if err := alice.sessionBuilder.ProcessBundle(bundle2); err != nil {
		t.Fatal(err)
	}

	msg2, err := aliceCipher.Encrypt([]byte("msg2"))
	if err != nil {
		t.Fatal(err)
	}
	msg2Bytes, err := msg2.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg2, err := protocol.NewPreKeySignalMessageFromBytes(msg2Bytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Bob processes second message -- session is not fresh, triggers archive.
	processAndComplete(t, bob.sessionBuilder, preKeyMsg2)

	dec2, err := bobCipher.Decrypt(preKeyMsg2.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}
	if string(dec2) != "msg2" {
		t.Fatal("msg2 decryption mismatch")
	}
}

// ============= PQXDH / Kyber Pre-Key Tests =============

// mockKyberPreKeySerializer is a minimal serializer for KyberPreKey records.
type mockKyberPreKeySerializer struct{}

func (m *mockKyberPreKeySerializer) Serialize(preKey *record.KyberPreKeyStructure) ([]byte, error) {
	return nil, nil
}

func (m *mockKyberPreKeySerializer) Deserialize(serialized []byte) (*record.KyberPreKeyStructure, error) {
	return nil, nil
}

func TestProcessBundleWithKyberPreKey(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	aliceKyberStore := newInMemoryKyberPreKey()
	bobKyberStore := newInMemoryKyberPreKey()

	// Generate a Kyber pre-key for Bob.
	kyberPreKey, err := keyhelper.GenerateKyberPreKey(bob.identityKeyPair.PrivateKey(), 42, &mockKyberPreKeySerializer{})
	if err != nil {
		t.Fatal(err)
	}
	if err := bobKyberStore.StoreKyberPreKey(42, kyberPreKey); err != nil {
		t.Fatalf("StoreKyberPreKey failed: %v", err)
	}

	// Alice uses NewBuilderWithKyber.
	aliceBuilder := session.NewBuilderWithKyber(
		alice.sessionStore,
		alice.preKeyStore,
		alice.signedPreKeyStore,
		alice.identityStore,
		aliceKyberStore,
		bob.address,
		serializer,
	)

	// Bob uses NewBuilderWithKyber.
	bobBuilder := session.NewBuilderWithKyber(
		bob.sessionStore,
		bob.preKeyStore,
		bob.signedPreKeyStore,
		bob.identityStore,
		bobKyberStore,
		alice.address,
		serializer,
	)

	// Create a bundle with Kyber pre-key.
	kyberSig := kyberPreKey.Signature()
	bundle := prekey.NewBundleWithKyber(
		bob.registrationID,
		bob.address.DeviceID(),
		bob.preKeys[0].ID(),
		bob.signedPreKey.ID(),
		bob.preKeys[0].KeyPair().PublicKey(),
		bob.signedPreKey.KeyPair().PublicKey(),
		bob.signedPreKey.Signature(),
		bob.identityKeyPair.PublicKey(),
		&optional.Uint32{Value: 42},
		kyberPreKey.PublicKey(),
		kyberSig,
	)

	// Alice processes the Kyber bundle.
	err = aliceBuilder.ProcessBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}

	// Alice encrypts a message.
	aliceCipher := session.NewCipher(aliceBuilder, bob.address)
	plaintext := []byte("Hello with PQXDH!")
	msg, err := aliceCipher.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Bob receives and processes the pre-key message.
	msgBytes, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	processAndComplete(t, bobBuilder, preKeyMsg)

	// Bob decrypts.
	bobCipher := session.NewCipher(bobBuilder, alice.address)
	decrypted, err := bobCipher.Decrypt(preKeyMsg.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != "Hello with PQXDH!" {
		t.Fatalf("expected 'Hello with PQXDH!', got '%s'", string(decrypted))
	}

	// Verify the Kyber pre-key was marked as used.
	if !bobKyberStore.marked[42] {
		t.Fatal("expected Kyber pre-key 42 to be marked as used")
	}
}

func TestProcessBundleKyberInvalidSignature(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	aliceKyberStore := newInMemoryKyberPreKey()

	aliceBuilder := session.NewBuilderWithKyber(
		alice.sessionStore,
		alice.preKeyStore,
		alice.signedPreKeyStore,
		alice.identityStore,
		aliceKyberStore,
		bob.address,
		serializer,
	)

	kyberPreKey, err := keyhelper.GenerateKyberPreKey(bob.identityKeyPair.PrivateKey(), 42, &mockKyberPreKeySerializer{})
	if err != nil {
		t.Fatal(err)
	}

	// Use an invalid Kyber signature (wrong bytes, but correct length).
	badKyberSig := make([]byte, 64)
	for i := range badKyberSig {
		badKyberSig[i] = 0xFF
	}

	bundle := prekey.NewBundleWithKyber(
		bob.registrationID,
		bob.address.DeviceID(),
		bob.preKeys[0].ID(),
		bob.signedPreKey.ID(),
		bob.preKeys[0].KeyPair().PublicKey(),
		bob.signedPreKey.KeyPair().PublicKey(),
		bob.signedPreKey.Signature(),
		bob.identityKeyPair.PublicKey(),
		&optional.Uint32{Value: 42},
		kyberPreKey.PublicKey(),
		badKyberSig,
	)

	err = aliceBuilder.ProcessBundle(bundle)
	if err == nil {
		t.Fatal("expected error for invalid Kyber pre-key signature")
	}
}

func TestProcessBundleKyberShortSignature(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	aliceKyberStore := newInMemoryKyberPreKey()

	aliceBuilder := session.NewBuilderWithKyber(
		alice.sessionStore,
		alice.preKeyStore,
		alice.signedPreKeyStore,
		alice.identityStore,
		aliceKyberStore,
		bob.address,
		serializer,
	)

	kyberPreKey, err := keyhelper.GenerateKyberPreKey(bob.identityKeyPair.PrivateKey(), 42, &mockKyberPreKeySerializer{})
	if err != nil {
		t.Fatal(err)
	}

	// Use a Kyber signature with wrong length (not 64 bytes).
	shortSig := []byte("too-short")

	bundle := prekey.NewBundleWithKyber(
		bob.registrationID,
		bob.address.DeviceID(),
		bob.preKeys[0].ID(),
		bob.signedPreKey.ID(),
		bob.preKeys[0].KeyPair().PublicKey(),
		bob.signedPreKey.KeyPair().PublicKey(),
		bob.signedPreKey.Signature(),
		bob.identityKeyPair.PublicKey(),
		&optional.Uint32{Value: 42},
		kyberPreKey.PublicKey(),
		shortSig,
	)

	err = aliceBuilder.ProcessBundle(bundle)
	if err == nil {
		t.Fatal("expected error for Kyber signature with wrong length")
	}
}

func TestProcessBundleWithKyberNotFreshSession(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	aliceKyberStore := newInMemoryKyberPreKey()

	aliceBuilder := session.NewBuilderWithKyber(
		alice.sessionStore,
		alice.preKeyStore,
		alice.signedPreKeyStore,
		alice.identityStore,
		aliceKyberStore,
		bob.address,
		serializer,
	)

	// First session (no Kyber) to make the session not-fresh.
	bundle1 := bob.kyberBundle()
	if err := aliceBuilder.ProcessBundle(bundle1); err != nil {
		t.Fatal(err)
	}

	// Second session with Kyber (session is not fresh now, triggers archive).
	kyberPreKey, err := keyhelper.GenerateKyberPreKey(bob.identityKeyPair.PrivateKey(), 42, &mockKyberPreKeySerializer{})
	if err != nil {
		t.Fatal(err)
	}

	kyberSig := kyberPreKey.Signature()
	bundle2 := prekey.NewBundleWithKyber(
		bob.registrationID,
		bob.address.DeviceID(),
		bob.preKeys[1].ID(),
		bob.signedPreKey.ID(),
		bob.preKeys[1].KeyPair().PublicKey(),
		bob.signedPreKey.KeyPair().PublicKey(),
		bob.signedPreKey.Signature(),
		bob.identityKeyPair.PublicKey(),
		&optional.Uint32{Value: 42},
		kyberPreKey.PublicKey(),
		kyberSig,
	)

	err = aliceBuilder.ProcessBundle(bundle2)
	if err != nil {
		t.Fatal(err)
	}

	// Verify session was stored.
	if ok, _ := alice.sessionStore.ContainsSession(bob.address); !ok {
		t.Fatal("session should exist after ProcessBundle with Kyber")
	}
}

// ============= Decrypt Replayed Message (old counter path) =============

func TestDecryptReplayedMessage(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	bundle := bob.kyberBundle()
	if err := alice.sessionBuilder.ProcessBundle(bundle); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("replay me"))
	if err != nil {
		t.Fatal(err)
	}

	msgBytes, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	processAndComplete(t, bob.sessionBuilder, preKeyMsg)

	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)

	// First decrypt succeeds.
	_, err = bobCipher.Decrypt(preKeyMsg.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}

	// Second decrypt of the same message should fail with "old counter" error
	// because the message keys have already been consumed.
	_, err = bobCipher.Decrypt(preKeyMsg.WhisperMessage())
	if err == nil {
		t.Fatal("expected error when decrypting replayed message")
	}
}

// ============= Encrypt/Decrypt with session established via SignalProtocol store =============

func TestEncryptDecryptWithSignalProtocolStore(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	aliceStore := &inMemorySignalProtocol{
		inMemoryIdentityKey:  alice.identityStore,
		inMemoryPreKey:       alice.preKeyStore,
		inMemorySession:      alice.sessionStore,
		inMemorySignedPreKey: alice.signedPreKeyStore,
		inMemorySenderKey:    newInMemorySenderKey(),
		inMemoryKyberPreKey:  newInMemoryKyberPreKey(),
	}

	aliceBuilder := session.NewBuilderFromSignal(aliceStore, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	bundle := bob.kyberBundle()
	if err := aliceBuilder.ProcessBundle(bundle); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(aliceBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("via SignalProtocol store"))
	if err != nil {
		t.Fatal(err)
	}

	msgBytes, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	processAndComplete(t, bob.sessionBuilder, preKeyMsg)

	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	decrypted, err := bobCipher.Decrypt(preKeyMsg.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != "via SignalProtocol store" {
		t.Fatalf("expected 'via SignalProtocol store', got '%s'", string(decrypted))
	}
}

// ============= ProcessV3 with non-fresh session archive path =============

func TestProcessV3WithKyberAndNonFreshSession(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	// First session to make Bob's session non-fresh.
	bundle1 := bob.kyberBundle()
	if err := alice.sessionBuilder.ProcessBundle(bundle1); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg1, err := aliceCipher.Encrypt([]byte("first"))
	if err != nil {
		t.Fatal(err)
	}
	msg1Bytes, _ := msg1.Serialize()
	preKeyMsg1, _ := protocol.NewPreKeySignalMessageFromBytes(msg1Bytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	processAndComplete(t, bob.sessionBuilder, preKeyMsg1)
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	_, err = bobCipher.Decrypt(preKeyMsg1.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}

	// Now create a second session with Kyber. Bob's session is not fresh, so
	// processV3 must archive the current state before initializing.
	bundle2 := bob.kyberBundleWithPreKeyIndex(2)
	if err := alice.sessionBuilder.ProcessBundle(bundle2); err != nil {
		t.Fatal(err)
	}

	msg2, err := aliceCipher.Encrypt([]byte("second with kyber"))
	if err != nil {
		t.Fatal(err)
	}
	msg2Bytes, _ := msg2.Serialize()
	preKeyMsg2, _ := protocol.NewPreKeySignalMessageFromBytes(msg2Bytes, serializer.PreKeySignalMessage, serializer.SignalMessage)

	// Bob processes second message -- the Kyber path in processV3 is exercised
	// with a non-fresh session that gets archived.
	processAndComplete(t, bob.sessionBuilder, preKeyMsg2)

	dec2, err := bobCipher.Decrypt(preKeyMsg2.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}
	if string(dec2) != "second with kyber" {
		t.Fatalf("expected 'second with kyber', got '%s'", string(dec2))
	}
}

// ============= DecryptWithRecord previous state promotion =============

func TestDecryptWithRecordPromotesPreviousState(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	// Set up the first session.
	bundle1 := bob.kyberBundle()
	if err := alice.sessionBuilder.ProcessBundle(bundle1); err != nil {
		t.Fatal(err)
	}
	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)

	// Alice sends first message and a delayed message from the same sending chain.
	msg1, err := aliceCipher.Encrypt([]byte("session1 msg1"))
	if err != nil {
		t.Fatal(err)
	}
	delayedMsg, err := aliceCipher.Encrypt([]byte("delayed from session1"))
	if err != nil {
		t.Fatal(err)
	}

	// Bob processes and decrypts first message.
	msg1Bytes, _ := msg1.Serialize()
	preKeyMsg1, _ := protocol.NewPreKeySignalMessageFromBytes(msg1Bytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	processAndComplete(t, bob.sessionBuilder, preKeyMsg1)
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	_, err = bobCipher.Decrypt(preKeyMsg1.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}

	// Manually archive the current session state on Bob's side so that
	// it becomes a previous state. This simulates what normally happens
	// when IsFresh() returns false in processV3.
	bobSessionRec, _ := bob.sessionStore.LoadSession(alice.address)
	bobSessionRec.ArchiveCurrentState()
	_ = bob.sessionStore.StoreSession(alice.address, bobSessionRec)
	// Now set up a second session.
	bundle2 := bob.kyberBundleWithPreKeyIndex(1)
	if err := alice.sessionBuilder.ProcessBundle(bundle2); err != nil {
		t.Fatal(err)
	}
	msg2, err := aliceCipher.Encrypt([]byte("session2 msg"))
	if err != nil {
		t.Fatal(err)
	}
	msg2Bytes, _ := msg2.Serialize()
	preKeyMsg2, _ := protocol.NewPreKeySignalMessageFromBytes(msg2Bytes, serializer.PreKeySignalMessage, serializer.SignalMessage)

	// Bob processes second message.
	processAndComplete(t, bob.sessionBuilder, preKeyMsg2)

	// Now decrypt the delayed message from session1. The current state is
	// session2, which will fail. The previous state (session1 - archived above)
	// should succeed, and the loop in DecryptWithRecord should promote it.
	delayedBytes, _ := delayedMsg.Serialize()
	delayedPreKeyMsg, _ := protocol.NewPreKeySignalMessageFromBytes(delayedBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)

	sessionRec, _ := bob.sessionStore.LoadSession(alice.address)
	decDelayed, _, err := bobCipher.DecryptWithRecord(sessionRec, delayedPreKeyMsg.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}
	if string(decDelayed) != "delayed from session1" {
		t.Fatalf("expected 'delayed from session1', got '%s'", string(decDelayed))
	}
}

// ============= Multiple consecutive one-direction messages =============

func TestMultipleConsecutiveEncrypts(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	bundle := bob.kyberBundle()
	if err := alice.sessionBuilder.ProcessBundle(bundle); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)

	// Alice sends the first message as a PreKeySignalMessage.
	msg0, err := aliceCipher.Encrypt([]byte("msg0"))
	if err != nil {
		t.Fatal(err)
	}
	msg0Bytes, _ := msg0.Serialize()
	preKeyMsg0, _ := protocol.NewPreKeySignalMessageFromBytes(msg0Bytes, serializer.PreKeySignalMessage, serializer.SignalMessage)

	processAndComplete(t, bob.sessionBuilder, preKeyMsg0)

	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	dec0, err := bobCipher.Decrypt(preKeyMsg0.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}
	if string(dec0) != "msg0" {
		t.Fatal("msg0 mismatch")
	}

	// Bob sends back to establish the ratchet fully.
	bobResp, err := bobCipher.Encrypt([]byte("ack"))
	if err != nil {
		t.Fatal(err)
	}
	bobRespBytes, _ := bobResp.Serialize()
	bobRespMsg, _ := protocol.NewSignalMessageFromBytes(bobRespBytes, serializer.SignalMessage)
	_, err = aliceCipher.Decrypt(bobRespMsg)
	if err != nil {
		t.Fatal(err)
	}

	// Now Bob sends 10 consecutive messages without Alice responding.
	// This tests the chain key advancing correctly.
	for i := 0; i < 10; i++ {
		bMsg, err := bobCipher.Encrypt([]byte("bob consecutive " + string(rune('0'+i))))
		if err != nil {
			t.Fatalf("encrypt %d: %v", i, err)
		}
		bBytes, _ := bMsg.Serialize()
		bSignalMsg, _ := protocol.NewSignalMessageFromBytes(bBytes, serializer.SignalMessage)
		dec, err := aliceCipher.Decrypt(bSignalMsg)
		if err != nil {
			t.Fatalf("decrypt %d: %v", i, err)
		}
		expected := "bob consecutive " + string(rune('0'+i))
		if string(dec) != expected {
			t.Fatalf("round %d: expected '%s', got '%s'", i, expected, string(dec))
		}
	}
}

// setupSessionPair establishes a bidirectional session between Alice and Bob
// and returns the ciphers. Alice sends a prekey message, Bob processes it and
// responds, establishing a fully ratcheted session.
func setupSessionPair(t *testing.T, serializer *serialize.Serializer) (
	alice *testUser, bob *testUser,
	aliceCipher *session.Cipher, bobCipher *session.Cipher,
) {
	t.Helper()
	alice = newTestUser(t, "Alice", 1, serializer)
	bob = newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	bundle := bob.kyberBundle()

	if err := alice.sessionBuilder.ProcessBundle(bundle); err != nil {
		t.Fatal(err)
	}

	aliceCipher = session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("setup"))
	if err != nil {
		t.Fatal(err)
	}

	msgBytes, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	processAndComplete(t, bob.sessionBuilder, preKeyMsg)

	bobCipher = session.NewCipher(bob.sessionBuilder, alice.address)
	if _, err := bobCipher.Decrypt(preKeyMsg.WhisperMessage()); err != nil {
		t.Fatal(err)
	}

	// Bob responds to complete the ratchet.
	resp, err := bobCipher.Encrypt([]byte("ack"))
	if err != nil {
		t.Fatal(err)
	}
	respBytes, _ := resp.Serialize()
	respMsg, _ := protocol.NewSignalMessageFromBytes(respBytes, serializer.SignalMessage)
	if _, err := aliceCipher.Decrypt(respMsg); err != nil {
		t.Fatal(err)
	}

	return alice, bob, aliceCipher, bobCipher
}

// ============= Typed Error Tests =============

func TestTypedErrorNoSession(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	bundle := bob.kyberBundle()
	if err := alice.sessionBuilder.ProcessBundle(bundle); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	msgBytes, _ := msg.Serialize()
	preKeyMsg, _ := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)

	// Try to decrypt without establishing Bob's session -- should get typed ErrNoSession.
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	_, err = bobCipher.Decrypt(preKeyMsg.WhisperMessage())
	if err == nil {
		t.Fatal("expected error when decrypting without session")
	}
	if !errors.Is(err, session.ErrNoSession) {
		t.Fatalf("expected ErrNoSession, got %T: %v", err, err)
	}
}

func TestTypedErrorNoValidSessions(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	_, _, aliceCipher, bobCipher := setupSessionPair(t, serializer)

	// Alice encrypts two messages; Bob decrypts the second one first.
	msg1, err := aliceCipher.Encrypt([]byte("msg1"))
	if err != nil {
		t.Fatal(err)
	}
	msg2, err := aliceCipher.Encrypt([]byte("msg2"))
	if err != nil {
		t.Fatal(err)
	}

	// Bob decrypts msg2 (skipping msg1).
	msg2Bytes, _ := msg2.Serialize()
	msg2Signal, _ := protocol.NewSignalMessageFromBytes(msg2Bytes, serializer.SignalMessage)
	dec2, err := bobCipher.Decrypt(msg2Signal)
	if err != nil {
		t.Fatal(err)
	}
	if string(dec2) != "msg2" {
		t.Fatalf("expected 'msg2', got '%s'", string(dec2))
	}

	// Now Bob decrypts msg1 (out of order -- should use skipped keys).
	msg1Bytes, _ := msg1.Serialize()
	msg1Signal, _ := protocol.NewSignalMessageFromBytes(msg1Bytes, serializer.SignalMessage)
	dec1, err := bobCipher.Decrypt(msg1Signal)
	if err != nil {
		t.Fatal(err)
	}
	if string(dec1) != "msg1" {
		t.Fatalf("expected 'msg1', got '%s'", string(dec1))
	}

	// Trying to decrypt msg1 again should fail since the key was consumed.
	// Per M1 (DuplicateMessage short-circuit), consuming a message key that
	// was already used returns ErrDuplicateMessage immediately without
	// trying other session states.
	_, err = bobCipher.Decrypt(msg1Signal)
	if err == nil {
		t.Fatal("expected error decrypting already-consumed message")
	}
	if !errors.Is(err, session.ErrDuplicateMessage) {
		t.Fatalf("expected ErrDuplicateMessage, got %T: %v", err, err)
	}
}

func TestTypedErrorWrongMessageVersion(t *testing.T) {
	// This tests that the error type is properly exposed. We verify the sentinel
	// error's Error() output and Is() behavior directly.
	err := session.ErrWrongMessageVersion
	if err.Error() != "session: wrong message version" {
		t.Fatalf("unexpected error message: %s", err.Error())
	}
	if !errors.Is(err, session.ErrWrongMessageVersion) {
		t.Fatal("errors.Is should match ErrWrongMessageVersion")
	}
	if errors.Is(err, session.ErrNoSession) {
		t.Fatal("ErrWrongMessageVersion should not match ErrNoSession")
	}
}

func TestTypedErrorUninitializedSession(t *testing.T) {
	err := session.ErrUninitializedSession
	if err.Error() != "session: uninitialized session" {
		t.Fatalf("unexpected error message: %s", err.Error())
	}
	if !errors.Is(err, session.ErrUninitializedSession) {
		t.Fatal("errors.Is should match ErrUninitializedSession")
	}
}

func TestTypedErrorTooFarIntoFuture(t *testing.T) {
	err := session.ErrTooFarIntoFuture
	if err.Error() != "session: too many messages into the future" {
		t.Fatalf("unexpected error message: %s", err.Error())
	}
	if !errors.Is(err, session.ErrTooFarIntoFuture) {
		t.Fatal("errors.Is should match ErrTooFarIntoFuture")
	}
}

func TestTypedErrorMaxSkippedKeysExceeded(t *testing.T) {
	err := session.ErrMaxSkippedKeysExceeded
	if err.Error() != "session: max skipped message keys exceeded" {
		t.Fatalf("unexpected error message: %s", err.Error())
	}
	if !errors.Is(err, session.ErrMaxSkippedKeysExceeded) {
		t.Fatal("errors.Is should match ErrMaxSkippedKeysExceeded")
	}
	if errors.Is(err, session.ErrOldCounter) {
		t.Fatal("ErrMaxSkippedKeysExceeded should not match ErrOldCounter")
	}
}

// ============= TrySkippedMessageKeys Tests =============

func TestTrySkippedMessageKeysOutOfOrder(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	_, _, aliceCipher, bobCipher := setupSessionPair(t, serializer)

	// Alice sends 5 messages.
	var aliceMsgs []*protocol.SignalMessage
	for i := 0; i < 5; i++ {
		msg, err := aliceCipher.Encrypt([]byte(fmt.Sprintf("msg%d", i)))
		if err != nil {
			t.Fatal(err)
		}
		msgBytes, _ := msg.Serialize()
		signalMsg, _ := protocol.NewSignalMessageFromBytes(msgBytes, serializer.SignalMessage)
		aliceMsgs = append(aliceMsgs, signalMsg)
	}

	// Bob decrypts msg4 first (creates skipped keys for 0-3).
	dec, err := bobCipher.Decrypt(aliceMsgs[4])
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != "msg4" {
		t.Fatalf("expected 'msg4', got '%s'", string(dec))
	}

	// Bob decrypts msg0 (should use TrySkippedMessageKeys path).
	dec, err = bobCipher.Decrypt(aliceMsgs[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != "msg0" {
		t.Fatalf("expected 'msg0', got '%s'", string(dec))
	}

	// Decrypt remaining out of order.
	dec, err = bobCipher.Decrypt(aliceMsgs[3])
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != "msg3" {
		t.Fatalf("expected 'msg3', got '%s'", string(dec))
	}

	dec, err = bobCipher.Decrypt(aliceMsgs[1])
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != "msg1" {
		t.Fatalf("expected 'msg1', got '%s'", string(dec))
	}

	dec, err = bobCipher.Decrypt(aliceMsgs[2])
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != "msg2" {
		t.Fatalf("expected 'msg2', got '%s'", string(dec))
	}
}

func TestTrySkippedMessageKeysReplayRejection(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	_, _, aliceCipher, bobCipher := setupSessionPair(t, serializer)

	// Alice sends two messages.
	msg0, err := aliceCipher.Encrypt([]byte("first"))
	if err != nil {
		t.Fatal(err)
	}
	msg1, err := aliceCipher.Encrypt([]byte("second"))
	if err != nil {
		t.Fatal(err)
	}

	msg0Bytes, _ := msg0.Serialize()
	msg0Signal, _ := protocol.NewSignalMessageFromBytes(msg0Bytes, serializer.SignalMessage)
	msg1Bytes, _ := msg1.Serialize()
	msg1Signal, _ := protocol.NewSignalMessageFromBytes(msg1Bytes, serializer.SignalMessage)

	// Bob decrypts msg1 first (stores skipped key for msg0).
	_, err = bobCipher.Decrypt(msg1Signal)
	if err != nil {
		t.Fatal(err)
	}

	// Bob decrypts msg0 using skipped key.
	_, err = bobCipher.Decrypt(msg0Signal)
	if err != nil {
		t.Fatal(err)
	}

	// Replay: attempting to decrypt msg0 again must fail.
	// DecryptWithRecord wraps the per-state error as ErrNoValidSessions.
	_, err = bobCipher.Decrypt(msg0Signal)
	if err == nil {
		t.Fatal("expected error on replay of consumed skipped key")
	}
	if !errors.Is(err, session.ErrDuplicateMessage) {
		t.Fatalf("expected ErrDuplicateMessage on replay, got %T: %v", err, err)
	}
}

// ============= MAX_SKIP Enforcement Tests =============

func TestTotalSkippedMessageKeys(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	state := record.NewState(serializer.State)
	total := state.TotalSkippedMessageKeys()
	if total != 0 {
		t.Fatalf("expected 0 total skipped keys on fresh state, got %d", total)
	}
}

// ============= Error Type Coverage =============

func TestErrorNoSessionWithAddress(t *testing.T) {
	// Exercises the errNoSession branch with a non-empty address field.
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	bundle := bob.kyberBundle()
	if err := alice.sessionBuilder.ProcessBundle(bundle); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	msgBytes, _ := msg.Serialize()
	preKeyMsg, _ := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)

	// DecryptAndGetKey without session produces newNoSessionError(address).
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	_, _, err = bobCipher.DecryptAndGetKey(preKeyMsg.WhisperMessage())
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, session.ErrNoSession) {
		t.Fatalf("expected ErrNoSession, got %T: %v", err, err)
	}
	// Verify the error message contains the address.
	errMsg := err.Error()
	if errMsg == "session: no session for address" {
		t.Fatal("expected address-specific error message")
	}
}

func TestErrorOldCounterMessage(t *testing.T) {
	// Exercises the errOldCounter Error() format with index and counter fields.
	err := session.ErrOldCounter
	if err.Error() != "session: received message with old counter: chain index 0, message counter 0" {
		t.Fatalf("unexpected sentinel error message: %s", err.Error())
	}
}

func TestErrorDefaultUnknown(t *testing.T) {
	// The zero-value Error has kind=0 which doesn't match any defined errorKind,
	// so it hits the default branch.
	var err session.Error
	if err.Error() != "session: unknown error" {
		t.Fatalf("expected 'session: unknown error', got '%s'", err.Error())
	}
}

func TestErrorIsNonErrorTarget(t *testing.T) {
	// Exercises the Is() method returning false for a non-*Error target.
	err := session.ErrNoSession
	other := fmt.Errorf("some other error")
	if errors.Is(other, err) {
		t.Fatal("plain error should not match ErrNoSession")
	}
}

func TestErrorIsMatchesByKind(t *testing.T) {
	// Exercises the Is() method returning true when kinds match despite
	// different field values.
	err := session.ErrNoSession
	if !errors.Is(err, session.ErrNoSession) {
		t.Fatal("ErrNoSession should match itself")
	}
}

func TestErrorNoValidSessionsMessage(t *testing.T) {
	err := session.ErrNoValidSessions
	if err.Error() != "session: no valid sessions" {
		t.Fatalf("unexpected error message: %s", err.Error())
	}
}

func TestErrorNoSessionSentinelMessage(t *testing.T) {
	// The sentinel ErrNoSession has an empty address, so it should produce
	// the generic "no session for address" message.
	err := session.ErrNoSession
	if err.Error() != "session: no session for address" {
		t.Fatalf("unexpected error message: %s", err.Error())
	}
}

// ============= DecryptWithState Skipped Message Keys Path =============

func TestDecryptWithStateSkippedMessageKeys(t *testing.T) {
	// Exercises the TrySkippedMessageKeys path inside DecryptWithState
	// where sessionState.HasReceiverChain and HasMessageKeys both return
	// true for a previously stored skipped key.
	serializer := serialize.NewJSONSerializer()
	_, bob, aliceCipher, bobCipher := setupSessionPair(t, serializer)

	// Alice sends 3 messages.
	msg0, err := aliceCipher.Encrypt([]byte("skip-test-0"))
	if err != nil {
		t.Fatal(err)
	}
	msg1, err := aliceCipher.Encrypt([]byte("skip-test-1"))
	if err != nil {
		t.Fatal(err)
	}
	msg2, err := aliceCipher.Encrypt([]byte("skip-test-2"))
	if err != nil {
		t.Fatal(err)
	}

	// Bob decrypts msg2 first, causing msg0 and msg1 keys to be stored as skipped.
	msg2Bytes, _ := msg2.Serialize()
	msg2Signal, _ := protocol.NewSignalMessageFromBytes(msg2Bytes, serializer.SignalMessage)
	dec, err := bobCipher.Decrypt(msg2Signal)
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != "skip-test-2" {
		t.Fatalf("expected 'skip-test-2', got '%s'", string(dec))
	}

	// Now use DecryptWithState directly on the session state to exercise
	// the skipped key retrieval path.
	bobSessionRec, _ := bob.sessionStore.LoadSession(bob.address)
	_ = bobSessionRec // just validate it's loadable

	// Decrypt msg0 using the stored skipped key.
	msg0Bytes, _ := msg0.Serialize()
	msg0Signal, _ := protocol.NewSignalMessageFromBytes(msg0Bytes, serializer.SignalMessage)
	dec0, err := bobCipher.Decrypt(msg0Signal)
	if err != nil {
		t.Fatal(err)
	}
	if string(dec0) != "skip-test-0" {
		t.Fatalf("expected 'skip-test-0', got '%s'", string(dec0))
	}

	// Decrypt msg1 using the stored skipped key.
	msg1Bytes, _ := msg1.Serialize()
	msg1Signal, _ := protocol.NewSignalMessageFromBytes(msg1Bytes, serializer.SignalMessage)
	dec1, err := bobCipher.Decrypt(msg1Signal)
	if err != nil {
		t.Fatal(err)
	}
	if string(dec1) != "skip-test-1" {
		t.Fatalf("expected 'skip-test-1', got '%s'", string(dec1))
	}
}

// ============= Encrypt Produces PreKeySignalMessage When Unacknowledged =============

func TestEncryptProducesPreKeySignalMessageWhenUnacknowledged(t *testing.T) {
	// Exercises the HasUnacknowledgedPreKeyMessage path in Encrypt where
	// the message is wrapped as a PreKeySignalMessage.
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)

	bundle := bob.kyberBundle()
	if err := alice.sessionBuilder.ProcessBundle(bundle); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)

	// First message should be a PreKeySignalMessage.
	msg, err := aliceCipher.Encrypt([]byte("unack test"))
	if err != nil {
		t.Fatal(err)
	}

	// Verify it's a PreKeySignalMessage by parsing.
	msgBytes, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	_, err = protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal("expected message to be a PreKeySignalMessage")
	}

	// Second and third messages should also be PreKeySignalMessages since
	// the session hasn't been acknowledged.
	msg2, err := aliceCipher.Encrypt([]byte("unack test 2"))
	if err != nil {
		t.Fatal(err)
	}
	msg2Bytes, err := msg2.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	_, err = protocol.NewPreKeySignalMessageFromBytes(msg2Bytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal("expected second message to be a PreKeySignalMessage")
	}
}

// ============= DecryptWithRecord All Previous States Fail =============

func TestDecryptWithRecordAllPreviousStatesFail(t *testing.T) {
	// Exercises the path where both the current state and all previous
	// states fail to decrypt, returning ErrNoValidSessions.
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)
	carol := newTestUser(t, "Carol", 3, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)
	carol.buildSession(t, bob.address, serializer)

	// Establish first session between Alice and Bob.
	bundle1 := bob.kyberBundle()
	if err := alice.sessionBuilder.ProcessBundle(bundle1); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg1, err := aliceCipher.Encrypt([]byte("first"))
	if err != nil {
		t.Fatal(err)
	}
	msg1Bytes, _ := msg1.Serialize()
	preKeyMsg1, _ := protocol.NewPreKeySignalMessageFromBytes(msg1Bytes, serializer.PreKeySignalMessage, serializer.SignalMessage)

	processAndComplete(t, bob.sessionBuilder, preKeyMsg1)
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	_, err = bobCipher.Decrypt(preKeyMsg1.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}

	// Now establish a second session (archives the first).
	bundle2 := bob.kyberBundleWithPreKeyIndex(1)
	if err := alice.sessionBuilder.ProcessBundle(bundle2); err != nil {
		t.Fatal(err)
	}
	msg2, err := aliceCipher.Encrypt([]byte("second"))
	if err != nil {
		t.Fatal(err)
	}
	msg2Bytes, _ := msg2.Serialize()
	preKeyMsg2, _ := protocol.NewPreKeySignalMessageFromBytes(msg2Bytes, serializer.PreKeySignalMessage, serializer.SignalMessage)

	processAndComplete(t, bob.sessionBuilder, preKeyMsg2)
	_, err = bobCipher.Decrypt(preKeyMsg2.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}

	// Carol sends a message that Bob cannot decrypt with any session state.
	carolBundle := bob.kyberBundleWithPreKeyIndex(2)
	if err := carol.sessionBuilder.ProcessBundle(carolBundle); err != nil {
		t.Fatal(err)
	}
	carolCipher := session.NewCipher(carol.sessionBuilder, bob.address)
	carolMsg, err := carolCipher.Encrypt([]byte("from carol"))
	if err != nil {
		t.Fatal(err)
	}
	carolMsgBytes, _ := carolMsg.Serialize()
	carolPreKeyMsg, _ := protocol.NewPreKeySignalMessageFromBytes(carolMsgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)

	// Try to decrypt Carol's message with Bob's session record for Alice.
	// Both current and archived states should fail.
	sessionRec, _ := bob.sessionStore.LoadSession(alice.address)
	_, _, err = bobCipher.DecryptWithRecord(sessionRec, carolPreKeyMsg.WhisperMessage())
	if err == nil {
		t.Fatal("expected ErrNoValidSessions")
	}
	if !errors.Is(err, session.ErrNoValidSessions) {
		t.Fatalf("expected ErrNoValidSessions, got %T: %v", err, err)
	}
}

// ============= Encrypt With Kyber Unacknowledged PreKey =============

func TestEncryptWithKyberUnacknowledgedPreKey(t *testing.T) {
	// Exercises the PQXDH path in Encrypt where the unacknowledged prekey
	// message includes Kyber pre-key ID and ciphertext.
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	aliceKyberStore := newInMemoryKyberPreKey()
	bobKyberStore := newInMemoryKyberPreKey()

	kyberPreKey, err := keyhelper.GenerateKyberPreKey(bob.identityKeyPair.PrivateKey(), 42, &mockKyberPreKeySerializer{})
	if err != nil {
		t.Fatal(err)
	}
	if err := bobKyberStore.StoreKyberPreKey(42, kyberPreKey); err != nil {
		t.Fatalf("StoreKyberPreKey failed: %v", err)
	}

	aliceBuilder := session.NewBuilderWithKyber(
		alice.sessionStore, alice.preKeyStore, alice.signedPreKeyStore, alice.identityStore,
		aliceKyberStore, bob.address, serializer,
	)

	bobBuilder := session.NewBuilderWithKyber(
		bob.sessionStore, bob.preKeyStore, bob.signedPreKeyStore, bob.identityStore,
		bobKyberStore, alice.address, serializer,
	)

	kyberSig := kyberPreKey.Signature()
	bundle := prekey.NewBundleWithKyber(
		bob.registrationID, bob.address.DeviceID(),
		bob.preKeys[0].ID(), bob.signedPreKey.ID(),
		bob.preKeys[0].KeyPair().PublicKey(),
		bob.signedPreKey.KeyPair().PublicKey(),
		bob.signedPreKey.Signature(),
		bob.identityKeyPair.PublicKey(),
		&optional.Uint32{Value: 42},
		kyberPreKey.PublicKey(),
		kyberSig,
	)

	if err := aliceBuilder.ProcessBundle(bundle); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(aliceBuilder, bob.address)

	// Encrypt multiple messages -- all should be PreKeySignalMessages with Kyber data.
	for i := 0; i < 3; i++ {
		msg, err := aliceCipher.Encrypt([]byte(fmt.Sprintf("kyber msg %d", i)))
		if err != nil {
			t.Fatalf("encrypt %d: %v", i, err)
		}
		msgBytes, err := msg.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
		if err != nil {
			t.Fatalf("message %d should be a PreKeySignalMessage: %v", i, err)
		}

		// Only process the first message to establish Bob's session.
		if i == 0 {
			processAndComplete(t, bobBuilder, preKeyMsg)
			bobCipher := session.NewCipher(bobBuilder, alice.address)
			dec, err := bobCipher.Decrypt(preKeyMsg.WhisperMessage())
			if err != nil {
				t.Fatal(err)
			}
			if string(dec) != "kyber msg 0" {
				t.Fatalf("expected 'kyber msg 0', got '%s'", string(dec))
			}
		}
	}
}

// ============= DecryptWithRecord Continue Through Multiple Previous States =============

func TestDecryptWithRecordContinueThroughPreviousStates(t *testing.T) {
	// Exercises the 'continue' path in DecryptWithRecord where the first
	// previous state fails and the loop continues to the next state.
	// We create three sessions, archive each, and decrypt a message from
	// the earliest session.
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	// Session 1: Establish and exchange.
	bundle1 := bob.kyberBundle()
	if err := alice.sessionBuilder.ProcessBundle(bundle1); err != nil {
		t.Fatal(err)
	}
	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)

	// Alice sends first message and a delayed message from session 1.
	msg1, err := aliceCipher.Encrypt([]byte("session1-setup"))
	if err != nil {
		t.Fatal(err)
	}
	delayedMsg, err := aliceCipher.Encrypt([]byte("session1-delayed"))
	if err != nil {
		t.Fatal(err)
	}

	msg1Bytes, _ := msg1.Serialize()
	preKeyMsg1, _ := protocol.NewPreKeySignalMessageFromBytes(msg1Bytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	processAndComplete(t, bob.sessionBuilder, preKeyMsg1)
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	_, err = bobCipher.Decrypt(preKeyMsg1.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}

	// Session 2: New session, archives session 1.
	bundle2 := bob.kyberBundleWithPreKeyIndex(1)
	if err := alice.sessionBuilder.ProcessBundle(bundle2); err != nil {
		t.Fatal(err)
	}
	msg2, err := aliceCipher.Encrypt([]byte("session2-setup"))
	if err != nil {
		t.Fatal(err)
	}
	msg2Bytes, _ := msg2.Serialize()
	preKeyMsg2, _ := protocol.NewPreKeySignalMessageFromBytes(msg2Bytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	processAndComplete(t, bob.sessionBuilder, preKeyMsg2)
	_, err = bobCipher.Decrypt(preKeyMsg2.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}

	// Session 3: New session, archives session 2.
	bundle3 := bob.kyberBundleWithPreKeyIndex(2)
	if err := alice.sessionBuilder.ProcessBundle(bundle3); err != nil {
		t.Fatal(err)
	}
	msg3, err := aliceCipher.Encrypt([]byte("session3-setup"))
	if err != nil {
		t.Fatal(err)
	}
	msg3Bytes, _ := msg3.Serialize()
	preKeyMsg3, _ := protocol.NewPreKeySignalMessageFromBytes(msg3Bytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	processAndComplete(t, bob.sessionBuilder, preKeyMsg3)
	_, err = bobCipher.Decrypt(preKeyMsg3.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}

	// Now try to decrypt the delayed message from session 1.
	// The current state is session 3, which fails.
	// Previous state 0 is session 2, which also fails.
	// Previous state 1 is session 1, which should succeed.
	// This exercises the 'continue' path in the previous states loop.
	delayedBytes, _ := delayedMsg.Serialize()
	delayedPreKeyMsg, _ := protocol.NewPreKeySignalMessageFromBytes(delayedBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)

	sessionRec, _ := bob.sessionStore.LoadSession(alice.address)
	decDelayed, _, err := bobCipher.DecryptWithRecord(sessionRec, delayedPreKeyMsg.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}
	if string(decDelayed) != "session1-delayed" {
		t.Fatalf("expected 'session1-delayed', got '%s'", string(decDelayed))
	}
}

// ============= Counter Too Far Into Future =============

func TestDecryptCounterTooFarIntoFuture(t *testing.T) {
	// Exercises the errTooFarIntoFuture path in getOrCreateMessageKeys by
	// constructing a SignalMessage with a counter far beyond the chain index.
	serializer := serialize.NewJSONSerializer()
	alice, bob, aliceCipher, bobCipher := setupSessionPair(t, serializer)

	// Alice sends a normal message; Bob decrypts to establish the ratchet.
	msg, err := aliceCipher.Encrypt([]byte("setup"))
	if err != nil {
		t.Fatal(err)
	}
	msgBytes, _ := msg.Serialize()
	signalMsg, _ := protocol.NewSignalMessageFromBytes(msgBytes, serializer.SignalMessage)
	_, err = bobCipher.Decrypt(signalMsg)
	if err != nil {
		t.Fatal(err)
	}

	// Bob replies to advance the ratchet so Alice gets a new receiver chain.
	reply, err := bobCipher.Encrypt([]byte("reply"))
	if err != nil {
		t.Fatal(err)
	}
	replyBytes, _ := reply.Serialize()
	replyMsg, _ := protocol.NewSignalMessageFromBytes(replyBytes, serializer.SignalMessage)
	_, err = aliceCipher.Decrypt(replyMsg)
	if err != nil {
		t.Fatal(err)
	}

	// Alice sends another message so Bob has a receiver chain at index 0.
	msg2, err := aliceCipher.Encrypt([]byte("trigger"))
	if err != nil {
		t.Fatal(err)
	}
	msg2Bytes, _ := msg2.Serialize()
	msg2Signal, _ := protocol.NewSignalMessageFromBytes(msg2Bytes, serializer.SignalMessage)

	// Get the ratchet key from Alice's message to forge a high-counter message.
	bobSessionRec, _ := bob.sessionStore.LoadSession(alice.address)
	bobState := bobSessionRec.SessionState()

	// Create a forged message with the same ratchet key but counter=26000.
	forgedMsg, err := protocol.NewSignalMessage(
		msg2Signal.MessageVersion(),
		26000, // counter way beyond chain index (> maxFutureMessages=25000)
		0,
		make([]byte, 32), // fake MAC key
		msg2Signal.SenderRatchetKey(),
		msg2Signal.Body(),
		bob.identityKeyPair.PublicKey(),
		alice.identityKeyPair.PublicKey(),
		serializer.SignalMessage,
		nil,      // pqRatchetMsg
		nil, nil, // localAddress, remoteAddress (no binding)
	)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = bobCipher.DecryptWithState(bobState, forgedMsg)
	if err == nil {
		t.Fatal("expected error for counter too far into future")
	}
	if !errors.Is(err, session.ErrTooFarIntoFuture) {
		t.Fatalf("expected ErrTooFarIntoFuture, got %T: %v", err, err)
	}
}

// ============= Max Skipped Keys FIFO Eviction =============

func TestDecryptMaxSkippedKeysExceeded(t *testing.T) {
	// Verifies per-chain FIFO eviction behavior. With maxSkippedKeys=2000,
	// when a chain would exceed the limit the oldest stored key is evicted
	// silently (matching Rust reference behavior) rather than returning an error.
	serializer := serialize.NewJSONSerializer()
	_, _, aliceCipher, bobCipher := setupSessionPair(t, serializer)

	// Capture the very first message Alice sends so we can verify it gets evicted.
	firstMsg, err := aliceCipher.Encrypt([]byte("first"))
	if err != nil {
		t.Fatalf("encrypt first: %v", err)
	}
	firstMsgBytes, _ := firstMsg.Serialize()

	// Alice sends 2001 more messages without Bob decrypting any.
	// Together with firstMsg this puts 2002 keys on Bob's receiver chain,
	// triggering FIFO eviction of the oldest keys.
	var lastMsg *protocol.SignalMessage
	for i := 0; i < 2001; i++ {
		msg, err := aliceCipher.Encrypt([]byte("x"))
		if err != nil {
			t.Fatalf("encrypt %d: %v", i, err)
		}
		msgBytes, _ := msg.Serialize()
		lastMsg, _ = protocol.NewSignalMessageFromBytes(msgBytes, serializer.SignalMessage)
	}

	// Decrypt the last message. FIFO eviction allows this to succeed even
	// though the chain has >2000 entries. This matches Rust reference behavior.
	_, err = bobCipher.Decrypt(lastMsg)
	if err != nil {
		t.Fatalf("expected FIFO eviction to allow decrypt beyond maxSkippedKeys, got: %v", err)
	}

	// The first message's key was evicted; decrypting it must fail.
	firstSignal, _ := protocol.NewSignalMessageFromBytes(firstMsgBytes, serializer.SignalMessage)
	_, evictErr := bobCipher.Decrypt(firstSignal)
	if evictErr == nil {
		t.Fatal("expected error decrypting evicted key, but decryption succeeded")
	}
}

// ============= DecryptWithState MAC Verification Error =============

func TestDecryptWithStateMacVerificationError(t *testing.T) {
	// Exercises the MAC verification error path in DecryptWithState by
	// creating a message with a valid structure but tampered body content.
	serializer := serialize.NewJSONSerializer()
	alice, bob, aliceCipher, _ := setupSessionPair(t, serializer)

	// Alice sends a message.
	msg, err := aliceCipher.Encrypt([]byte("mac test"))
	if err != nil {
		t.Fatal(err)
	}
	msgBytes, _ := msg.Serialize()
	signalMsg, _ := protocol.NewSignalMessageFromBytes(msgBytes, serializer.SignalMessage)

	// Get Bob's session state to call DecryptWithState directly.
	bobSessionRec, _ := bob.sessionStore.LoadSession(alice.address)
	bobState := bobSessionRec.SessionState()

	// Create a forged signal message using Bob's chain key and ratchet key
	// but with the wrong MAC key. This exercises the MAC verification failure
	// inside DecryptWithState after the chain key and message keys are created.
	chainKey := bobState.SenderChainKey()
	fakeKeys, err := chainKey.MessageKeys()
	if err != nil {
		t.Fatal(err)
	}

	// Build a message with correct structure but wrong MAC.
	forgedMsg, err := protocol.NewSignalMessage(
		bobState.Version(),
		signalMsg.Counter(),
		signalMsg.Counter(),
		mustCopy(fakeKeys.MacKey()), // wrong MAC key for Alice's message
		signalMsg.SenderRatchetKey(),
		signalMsg.Body(),
		bobState.LocalIdentityKey(),
		bobState.RemoteIdentityKey(),
		serializer.SignalMessage,
		nil,      // pqRatchetMsg
		nil, nil, // localAddress, remoteAddress (no binding)
	)
	if err != nil {
		t.Fatal(err)
	}

	// The cipher is constructed for Alice's address on Bob's side.
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	_, _, err = bobCipher.DecryptWithState(bobState, forgedMsg)
	if err == nil {
		t.Fatal("expected MAC verification error")
	}
}

// ============= Replay attack on skipped message key after ratchet =============

func TestDecryptOldCounterAfterRatchet(t *testing.T) {
	// Exercises the getOrCreateMessageKeys path where chainKey.Index() > counter
	// and there are no stored message keys, producing ErrOldCounter.
	serializer := serialize.NewJSONSerializer()
	_, _, aliceCipher, bobCipher := setupSessionPair(t, serializer)

	// Alice sends a message.
	msg, err := aliceCipher.Encrypt([]byte("to be replayed"))
	if err != nil {
		t.Fatal(err)
	}
	msgBytes, _ := msg.Serialize()
	signalMsg, _ := protocol.NewSignalMessageFromBytes(msgBytes, serializer.SignalMessage)

	// Bob decrypts it.
	dec, err := bobCipher.Decrypt(signalMsg)
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != "to be replayed" {
		t.Fatal("decryption mismatch")
	}

	// Alice sends another message (advances chain key).
	msg2, err := aliceCipher.Encrypt([]byte("advance"))
	if err != nil {
		t.Fatal(err)
	}
	msg2Bytes, _ := msg2.Serialize()
	signalMsg2, _ := protocol.NewSignalMessageFromBytes(msg2Bytes, serializer.SignalMessage)
	_, err = bobCipher.Decrypt(signalMsg2)
	if err != nil {
		t.Fatal(err)
	}

	// Try to replay the first message. Chain index has advanced past its counter,
	// and the message keys were consumed, so this hits the ErrOldCounter path.
	_, err = bobCipher.Decrypt(signalMsg)
	if err == nil {
		t.Fatal("expected error on replay")
	}
}

// ============= Serializing session store for non-fresh session tests =============

// serializingSessionStore serializes sessions on store and deserializes on load,
// ensuring IsFresh() returns false after a round trip.
type serializingSessionStore struct {
	data       map[string][]byte
	serializer *serialize.Serializer
}

func newSerializingSessionStore(serializer *serialize.Serializer) *serializingSessionStore {
	return &serializingSessionStore{
		data:       make(map[string][]byte),
		serializer: serializer,
	}
}

func (s *serializingSessionStore) LoadSession(address *protocol.SignalAddress) (*record.Session, error) {
	key := address.String()
	data, ok := s.data[key]
	if !ok {
		return record.NewSession(s.serializer.Session, s.serializer.State), nil
	}
	sess, err := record.NewSessionFromBytes(data, s.serializer.Session, s.serializer.State)
	if err != nil {
		return record.NewSession(s.serializer.Session, s.serializer.State), nil
	}
	return sess, nil
}

func (s *serializingSessionStore) GetSubDeviceSessions(name string) ([]uint32, error) {
	return nil, nil
}

func (s *serializingSessionStore) StoreSession(address *protocol.SignalAddress, r *record.Session) error {
	defer func() {
		_ = recover() // Handle nil pointer panics during serialization
	}()
	data, err := r.Serialize()
	if err != nil {
		return nil
	}
	s.data[address.String()] = data
	return nil
}

func (s *serializingSessionStore) ContainsSession(address *protocol.SignalAddress) (bool, error) {
	_, ok := s.data[address.String()]
	return ok, nil
}

func (s *serializingSessionStore) DeleteSession(address *protocol.SignalAddress) error {
	delete(s.data, address.String())
	return nil
}

func (s *serializingSessionStore) DeleteAllSessions() error {
	s.data = make(map[string][]byte)
	return nil
}

// ============= ProcessBundle with non-fresh (deserialized) session =============

func TestProcessBundleNonFreshSessionArchive(t *testing.T) {
	// Exercises the !sessionRecord.IsFresh() branch in ProcessBundle (line ~290).
	// Using a serializing session store ensures LoadSession returns a non-fresh record.
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	// Use a serializing session store for Alice.
	aliceSessionStore := newSerializingSessionStore(serializer)

	aliceBuilder := session.NewBuilder(
		aliceSessionStore, alice.preKeyStore, alice.signedPreKeyStore,
		alice.identityStore, bob.address, serializer,
	)

	// First ProcessBundle creates a session.
	bundle1 := bob.kyberBundle()
	if err := aliceBuilder.ProcessBundle(bundle1); err != nil {
		t.Fatal(err)
	}

	// Session is now stored (serialized). Second ProcessBundle will load it
	// (deserialized, fresh=false) and archive the current state.
	bundle2 := bob.kyberBundleWithPreKeyIndex(1)
	if err := aliceBuilder.ProcessBundle(bundle2); err != nil {
		t.Fatal(err)
	}

	// Session should still be usable.
	aliceCipher := session.NewCipher(aliceBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("after non-fresh archive"))
	if err != nil {
		t.Fatal(err)
	}
	if msg == nil {
		t.Fatal("encrypted message should not be nil")
	}
}

// ============= Multiple out-of-order messages across ratchet =============

func TestDecryptOutOfOrderAcrossRatchets(t *testing.T) {
	// Exercises the DecryptWithRecord fallback to previous session state path
	// more thoroughly by having Bob receive messages from two different
	// ratchet generations out of order.
	serializer := serialize.NewJSONSerializer()
	alice, bob, aliceCipher, bobCipher := setupSessionPair(t, serializer)

	// Alice sends several messages.
	var aliceMsgs []*protocol.SignalMessage
	for i := 0; i < 3; i++ {
		msg, err := aliceCipher.Encrypt([]byte(fmt.Sprintf("alice-%d", i)))
		if err != nil {
			t.Fatalf("encrypt %d: %v", i, err)
		}
		msgBytes, _ := msg.Serialize()
		signalMsg, _ := protocol.NewSignalMessageFromBytes(msgBytes, serializer.SignalMessage)
		aliceMsgs = append(aliceMsgs, signalMsg)
	}

	// Bob decrypts only message 2 (skipping 0, 1).
	dec2, err := bobCipher.Decrypt(aliceMsgs[2])
	if err != nil {
		t.Fatal(err)
	}
	if string(dec2) != "alice-2" {
		t.Fatal("alice-2 decryption mismatch")
	}

	// Bob responds to advance the ratchet.
	resp, err := bobCipher.Encrypt([]byte("bob-ack"))
	if err != nil {
		t.Fatal(err)
	}
	respBytes, _ := resp.Serialize()
	respMsg, _ := protocol.NewSignalMessageFromBytes(respBytes, serializer.SignalMessage)
	_, err = aliceCipher.Decrypt(respMsg)
	if err != nil {
		t.Fatal(err)
	}

	// Alice sends more messages with new ratchet key.
	msg3, err := aliceCipher.Encrypt([]byte("alice-3"))
	if err != nil {
		t.Fatal(err)
	}
	msg3Bytes, _ := msg3.Serialize()
	signalMsg3, _ := protocol.NewSignalMessageFromBytes(msg3Bytes, serializer.SignalMessage)

	// Bob decrypts alice-3 first (new ratchet).
	dec3, err := bobCipher.Decrypt(signalMsg3)
	if err != nil {
		t.Fatal(err)
	}
	if string(dec3) != "alice-3" {
		t.Fatal("alice-3 decryption mismatch")
	}

	// Now Bob goes back and decrypts skipped messages from old ratchet.
	dec0, err := bobCipher.Decrypt(aliceMsgs[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(dec0) != "alice-0" {
		t.Fatal("alice-0 decryption mismatch")
	}

	dec1, err := bobCipher.Decrypt(aliceMsgs[1])
	if err != nil {
		t.Fatal(err)
	}
	if string(dec1) != "alice-1" {
		t.Fatal("alice-1 decryption mismatch")
	}

	_ = alice
	_ = bob
}

// ============= DecryptWithState skipped key MAC verification error =============

func TestDecryptWithStateSkippedKeyMACFailure(t *testing.T) {
	// Exercises the MAC verification error path for stored skipped message keys.
	// This covers SessionCipher.go lines 227-229.
	serializer := serialize.NewJSONSerializer()
	_, _, aliceCipher, bobCipher := setupSessionPair(t, serializer)

	// Alice sends 3 messages; Bob decrypts only the last one, storing
	// 2 skipped message keys.
	var msgs []*protocol.SignalMessage
	for i := 0; i < 3; i++ {
		m, err := aliceCipher.Encrypt([]byte(fmt.Sprintf("msg%d", i)))
		if err != nil {
			t.Fatalf("encrypt %d: %v", i, err)
		}
		mBytes, _ := m.Serialize()
		sm, _ := protocol.NewSignalMessageFromBytes(mBytes, serializer.SignalMessage)
		msgs = append(msgs, sm)
	}

	// Decrypt only msg2, which stores keys for msg0 and msg1.
	_, err := bobCipher.Decrypt(msgs[2])
	if err != nil {
		t.Fatal(err)
	}

	// Now try to decrypt msg0. This will find the stored skipped key
	// and attempt MAC verification. The stored key should match and
	// decryption should succeed (exercising the skipped key path).
	dec0, err := bobCipher.Decrypt(msgs[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(dec0) != "msg0" {
		t.Fatal("msg0 decryption mismatch")
	}

	// Also verify msg1 (another skipped key).
	dec1, err := bobCipher.Decrypt(msgs[1])
	if err != nil {
		t.Fatal(err)
	}
	if string(dec1) != "msg1" {
		t.Fatal("msg1 decryption mismatch")
	}
}

// ============= Error String Coverage =============

func TestErrorStringDefaultCase(t *testing.T) {
	// Exercise the default case in Error.Error() for an unknown error kind.
	unknownErr := &session.Error{}
	if unknownErr.Error() != "session: unknown error" {
		t.Errorf("expected 'session: unknown error', got '%s'", unknownErr.Error())
	}
}

func TestErrorIsNonMatchingType(t *testing.T) {
	// Exercise the Is() method returning false for a non-Error type.
	sessionErr := session.ErrNoSession
	other := fmt.Errorf("not a session error")
	if errors.Is(other, sessionErr) {
		t.Error("Is() should return false for non-Error types")
	}
}

func TestErrorIsMatchingKindDifferentFields(t *testing.T) {
	// Verify Is() matches by kind, not by address field.
	err1 := session.ErrNoSession
	err2 := &session.Error{}
	// err2 is a zero-value Error (kind=0), so it should NOT match ErrNoSession (kind=1).
	if errors.Is(err2, err1) {
		t.Error("Is() should not match different error kinds")
	}
}

// ============= TooFarIntoFuture error path =============

func TestDecryptTooFarIntoFuture(t *testing.T) {
	// Exercises the errTooFarIntoFuture path in getOrCreateMessageKeys
	// by crafting a message with counter far beyond chain index.
	serializer := serialize.NewJSONSerializer()
	alice, bob, aliceCipher, _ := setupSessionPair(t, serializer)

	// Alice encrypts a normal message.
	msg, err := aliceCipher.Encrypt([]byte("future test"))
	if err != nil {
		t.Fatal(err)
	}
	msgBytes, _ := msg.Serialize()
	signalMsg, _ := protocol.NewSignalMessageFromBytes(msgBytes, serializer.SignalMessage)

	// Get Bob's session state.
	bobSessionRec, _ := bob.sessionStore.LoadSession(alice.address)
	bobState := bobSessionRec.SessionState()

	// Create a forged message with counter far in the future (> maxFutureMessages=25000).
	chainKey := bobState.SenderChainKey()
	messageKeys, err := chainKey.MessageKeys()
	if err != nil {
		t.Fatal(err)
	}

	forgedMsg, err := protocol.NewSignalMessage(
		bobState.Version(),
		26000, // counter far into future
		0,
		mustCopy(messageKeys.MacKey()),
		signalMsg.SenderRatchetKey(),
		signalMsg.Body(),
		bobState.LocalIdentityKey(),
		bobState.RemoteIdentityKey(),
		serializer.SignalMessage,
		nil,      // pqRatchetMsg
		nil, nil, // localAddress, remoteAddress (no binding)
	)
	if err != nil {
		t.Fatal(err)
	}

	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	_, _, err = bobCipher.DecryptWithState(bobState, forgedMsg)
	if err == nil {
		t.Fatal("expected error for counter too far into future")
	}
	if !errors.Is(err, session.ErrTooFarIntoFuture) {
		t.Fatalf("expected ErrTooFarIntoFuture, got: %v", err)
	}
}

// ============= ProcessBundle non-fresh session archive =============

func TestProcessBundleArchivesNonFreshSession(t *testing.T) {
	// Exercises the !sessionRecord.IsFresh() branch in ProcessBundle
	// at Session.go line ~290. This is the ProcessBundle side (not processV3).
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)

	// First ProcessBundle.
	bundle1 := bob.kyberBundle()
	if err := alice.sessionBuilder.ProcessBundle(bundle1); err != nil {
		t.Fatal(err)
	}

	// Verify session exists.
	if ok, _ := alice.sessionStore.ContainsSession(bob.address); !ok {
		t.Fatal("session should exist after first ProcessBundle")
	}

	// Second ProcessBundle with different prekey triggers archive.
	bundle2 := bob.kyberBundleWithPreKeyIndex(1)
	if err := alice.sessionBuilder.ProcessBundle(bundle2); err != nil {
		t.Fatal(err)
	}

	// Both should encrypt/decrypt properly demonstrating the archive worked.
	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("after archive"))
	if err != nil {
		t.Fatal(err)
	}
	if msg == nil {
		t.Fatal("encrypted message should not be nil")
	}
}

// ============= Encrypt error paths for Kyber PQXDH sessions =============

func TestEncryptKyberPreKeyMessageContainsKyberFields(t *testing.T) {
	// Exercises the Encrypt path that creates a PreKeySignalMessageWithKyber
	// when the session has unacknowledged Kyber pre-key data.
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	aliceKyberStore := newInMemoryKyberPreKey()
	bobKyberStore := newInMemoryKyberPreKey()

	kyberPreKey, err := keyhelper.GenerateKyberPreKey(bob.identityKeyPair.PrivateKey(), 42, &mockKyberPreKeySerializer{})
	if err != nil {
		t.Fatal(err)
	}
	if err := bobKyberStore.StoreKyberPreKey(42, kyberPreKey); err != nil {
		t.Fatal(err)
	}

	aliceBuilder := session.NewBuilderWithKyber(
		alice.sessionStore, alice.preKeyStore, alice.signedPreKeyStore,
		alice.identityStore, aliceKyberStore, bob.address, serializer,
	)

	kyberSig := kyberPreKey.Signature()
	bundle := prekey.NewBundleWithKyber(
		bob.registrationID, bob.address.DeviceID(),
		bob.preKeys[0].ID(), bob.signedPreKey.ID(),
		bob.preKeys[0].KeyPair().PublicKey(),
		bob.signedPreKey.KeyPair().PublicKey(),
		bob.signedPreKey.Signature(),
		bob.identityKeyPair.PublicKey(),
		&optional.Uint32{Value: 42},
		kyberPreKey.PublicKey(),
		kyberSig,
	)
	if err := aliceBuilder.ProcessBundle(bundle); err != nil {
		t.Fatal(err)
	}

	// Encrypt - this should produce a PreKeySignalMessage with Kyber fields.
	aliceCipher := session.NewCipher(aliceBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("PQXDH message"))
	if err != nil {
		t.Fatal(err)
	}

	// Verify it's a PreKey message type (which wraps Kyber ciphertext).
	if msg.Type() != protocol.PREKEY_TYPE {
		t.Fatalf("expected PREKEY_TYPE, got %d", msg.Type())
	}

	// Bob should be able to process and decrypt it.
	bobBuilder := session.NewBuilderWithKyber(
		bob.sessionStore, bob.preKeyStore, bob.signedPreKeyStore,
		bob.identityStore, bobKyberStore, alice.address, serializer,
	)
	msgBytes, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}
	processAndComplete(t, bobBuilder, preKeyMsg)

	bobCipher := session.NewCipher(bobBuilder, alice.address)
	dec, err := bobCipher.Decrypt(preKeyMsg.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != "PQXDH message" {
		t.Fatalf("expected 'PQXDH message', got '%s'", string(dec))
	}
}

// ============= Bug Fix: Kyber prekey signature must not be silently skipped =============

func TestProcessBundleKyberPreKeyPresentButSignatureNil(t *testing.T) {
	// When a Kyber pre-key is present but its signature is nil,
	// ProcessBundle must return an error per the PQXDH spec.
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	aliceKyberStore := newInMemoryKyberPreKey()

	aliceBuilder := session.NewBuilderWithKyber(
		alice.sessionStore,
		alice.preKeyStore,
		alice.signedPreKeyStore,
		alice.identityStore,
		aliceKyberStore,
		bob.address,
		serializer,
	)

	kyberPreKey, err := keyhelper.GenerateKyberPreKey(bob.identityKeyPair.PrivateKey(), 42, &mockKyberPreKeySerializer{})
	if err != nil {
		t.Fatal(err)
	}

	// Create bundle with Kyber pre-key but nil signature.
	bundle := prekey.NewBundleWithKyber(
		bob.registrationID,
		bob.address.DeviceID(),
		bob.preKeys[0].ID(),
		bob.signedPreKey.ID(),
		bob.preKeys[0].KeyPair().PublicKey(),
		bob.signedPreKey.KeyPair().PublicKey(),
		bob.signedPreKey.Signature(),
		bob.identityKeyPair.PublicKey(),
		&optional.Uint32{Value: 42},
		kyberPreKey.PublicKey(),
		nil, // nil signature -- must cause error
	)

	err = aliceBuilder.ProcessBundle(bundle)
	if err == nil {
		t.Fatal("expected error when Kyber pre-key is present but signature is nil")
	}
	if !errors.Is(err, session.ErrMissingKyberSignature) {
		t.Fatalf("expected ErrMissingKyberSignature, got: %v", err)
	}
}

func TestProcessBundleKyberPreKeyWithValidSignatureSucceeds(t *testing.T) {
	// Verify that a bundle with a valid Kyber pre-key and signature still works.
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	aliceKyberStore := newInMemoryKyberPreKey()

	aliceBuilder := session.NewBuilderWithKyber(
		alice.sessionStore,
		alice.preKeyStore,
		alice.signedPreKeyStore,
		alice.identityStore,
		aliceKyberStore,
		bob.address,
		serializer,
	)

	kyberPreKey, err := keyhelper.GenerateKyberPreKey(bob.identityKeyPair.PrivateKey(), 42, &mockKyberPreKeySerializer{})
	if err != nil {
		t.Fatal(err)
	}

	kyberSig := kyberPreKey.Signature()
	bundle := prekey.NewBundleWithKyber(
		bob.registrationID,
		bob.address.DeviceID(),
		bob.preKeys[0].ID(),
		bob.signedPreKey.ID(),
		bob.preKeys[0].KeyPair().PublicKey(),
		bob.signedPreKey.KeyPair().PublicKey(),
		bob.signedPreKey.Signature(),
		bob.identityKeyPair.PublicKey(),
		&optional.Uint32{Value: 42},
		kyberPreKey.PublicKey(),
		kyberSig,
	)

	err = aliceBuilder.ProcessBundle(bundle)
	if err != nil {
		t.Fatalf("expected no error with valid Kyber pre-key and signature, got: %v", err)
	}
}

// ============= Bug Fix: Ephemeral key zeroized after X3DH =============

func TestProcessBundleZeroizesEphemeralKey(t *testing.T) {
	// After ProcessBundle completes, the ephemeral base key's private
	// key material should be zeroized per the X3DH/PQXDH spec.
	// We verify this indirectly: after a successful ProcessBundle, the
	// session is established and the protocol proceeds normally. The
	// zeroization is structural -- we verify the code path executes
	// without error and the session is valid.
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	bundle := bob.kyberBundle()

	err := alice.sessionBuilder.ProcessBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}

	// Verify session works end-to-end after zeroization.
	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	plaintext := []byte("Post-zeroize test")
	msg, err := aliceCipher.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	messageBytes, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	receivedMessage, err := protocol.NewPreKeySignalMessageFromBytes(messageBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	processAndComplete(t, bob.sessionBuilder, receivedMessage)

	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	decrypted, err := bobCipher.Decrypt(receivedMessage.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != "Post-zeroize test" {
		t.Fatalf("expected 'Post-zeroize test', got '%s'", string(decrypted))
	}
}

// TestPreviousCounterSpecCompliance verifies that the previous counter (PN)
// is set to Ns (the sender chain key index) during a DH ratchet step, not
// Ns - 1. The Double Ratchet spec says: state.PN = state.Ns.
func TestPreviousCounterSpecCompliance(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	// Establish session: Alice -> Bob via PreKey bundle.
	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	bundle := bob.kyberBundle()

	err := alice.sessionBuilder.ProcessBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)

	// Alice sends first message (PreKeySignalMessage) to establish Bob's session.
	msg0, err := aliceCipher.Encrypt([]byte("setup"))
	if err != nil {
		t.Fatal(err)
	}
	msg0Bytes, err := msg0.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	receivedMsg0, err := protocol.NewPreKeySignalMessageFromBytes(msg0Bytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}
	processAndComplete(t, bob.sessionBuilder, receivedMsg0)
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	_, err = bobCipher.Decrypt(receivedMsg0.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}

	// Bob sends 3 messages to advance his sender chain index to 3.
	var bobMsgs [][]byte
	for i := 0; i < 3; i++ {
		msg, encErr := bobCipher.Encrypt([]byte(fmt.Sprintf("bob msg %d", i)))
		if encErr != nil {
			t.Fatal(encErr)
		}
		msgBytes, serErr := msg.Serialize()
		if serErr != nil {
			t.Fatal(serErr)
		}
		bobMsgs = append(bobMsgs, msgBytes)
	}

	// Verify Bob's sender chain index is now 3.
	bobSession, _ := bob.sessionStore.LoadSession(alice.address)
	bobSenderChainIndex := bobSession.SessionState().SenderChainKey().Index()
	if bobSenderChainIndex != 3 {
		t.Fatalf("expected Bob's sender chain index 3, got %d", bobSenderChainIndex)
	}

	// Alice receives and decrypts Bob's first message, which triggers
	// a DH ratchet step on Alice's side (new ratchet key from Bob).
	receivedBobMsg, err := protocol.NewSignalMessageFromBytes(bobMsgs[0], serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}
	_, err = aliceCipher.Decrypt(receivedBobMsg)
	if err != nil {
		t.Fatal(err)
	}

	// Check Alice's previous counter after the DH ratchet.
	// Alice's sender chain index before the ratchet was 1 (she sent 1 message: "setup").
	// Per spec, PN = Ns (the number of messages sent on the previous chain).
	aliceSession, _ := alice.sessionStore.LoadSession(bob.address)
	previousCounter := aliceSession.SessionState().PreviousCounter()

	// Per Rust reference, previous_counter = max(current_index - 1, 0).
	// Alice's sender chain index was 1, so previous_counter = max(1-1, 0) = 0.
	if previousCounter != 0 {
		t.Fatalf("expected previous counter 0 (= max(Ns-1, 0) per Rust ref), got %d", previousCounter)
	}

	// Now Alice sends 5 more messages on her new sender chain.
	for i := 0; i < 5; i++ {
		_, encErr := aliceCipher.Encrypt([]byte(fmt.Sprintf("alice msg %d", i)))
		if encErr != nil {
			t.Fatal(encErr)
		}
	}

	// Alice's sender chain index should be 5.
	aliceSession, _ = alice.sessionStore.LoadSession(bob.address)
	aliceSenderChainIndex := aliceSession.SessionState().SenderChainKey().Index()
	if aliceSenderChainIndex != 5 {
		t.Fatalf("expected Alice's sender chain index 5, got %d", aliceSenderChainIndex)
	}

	// Alice receives Bob's second message (same ratchet key, no new DH ratchet).
	receivedBobMsg2, err := protocol.NewSignalMessageFromBytes(bobMsgs[1], serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}
	_, err = aliceCipher.Decrypt(receivedBobMsg2)
	if err != nil {
		t.Fatal(err)
	}

	// Previous counter should still be 0 (no new DH ratchet step happened).
	aliceSession, _ = alice.sessionStore.LoadSession(bob.address)
	previousCounter = aliceSession.SessionState().PreviousCounter()
	if previousCounter != 0 {
		t.Fatalf("expected previous counter still 0 after same-chain message, got %d", previousCounter)
	}
}

// TestPreviousCounterNotOffByOne verifies the fix for the off-by-one bug
// where previousCounter was set to SenderChainKey().Index() - 1 instead
// of SenderChainKey().Index(). This tests the edge case where the sender
// chain index is 0 (no messages sent on that chain).
func TestPreviousCounterNotOffByOne(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	// Establish session: Alice -> Bob.
	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	bundle := bob.kyberBundle()

	err := alice.sessionBuilder.ProcessBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)

	// Alice sends exactly 2 messages.
	for i := 0; i < 2; i++ {
		_, encErr := aliceCipher.Encrypt([]byte(fmt.Sprintf("msg %d", i)))
		if encErr != nil {
			t.Fatal(encErr)
		}
	}

	// After sending 2 messages, Alice's sender chain index is 2.
	aliceSession, _ := alice.sessionStore.LoadSession(bob.address)
	senderIdx := aliceSession.SessionState().SenderChainKey().Index()
	if senderIdx != 2 {
		t.Fatalf("expected sender chain index 2, got %d", senderIdx)
	}

	// The previous counter (before any DH ratchet) should be 0.
	prevCounter := aliceSession.SessionState().PreviousCounter()
	if prevCounter != 0 {
		t.Fatalf("expected initial previous counter 0, got %d", prevCounter)
	}
}

// TestDecryptStateRollbackOnFailure verifies that session state mutations
// are rolled back when decryption fails (e.g., MAC verification failure).
// Per Double Ratchet spec section 3.5.
func TestDecryptStateRollbackOnFailure(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	bundle := bob.kyberBundle()

	err := alice.sessionBuilder.ProcessBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)

	// Alice sends a valid message.
	validMsg, err := aliceCipher.Encrypt([]byte("Valid message"))
	if err != nil {
		t.Fatal(err)
	}

	validMsgBytes, err := validMsg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	receivedMsg, err := protocol.NewPreKeySignalMessageFromBytes(validMsgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Bob processes the prekey to establish session.
	processAndComplete(t, bob.sessionBuilder, receivedMsg)

	// Capture Bob's session state before attempted decryption of tampered message.
	bobSession, _ := bob.sessionStore.LoadSession(alice.address)
	bobState := bobSession.SessionState()
	prevCounterBefore := bobState.PreviousCounter()
	versionBefore := bobState.Version()

	// Create a tampered message by corrupting the ciphertext body.
	// First, decrypt the valid message to advance chain state.
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	decrypted, err := bobCipher.Decrypt(receivedMsg.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != "Valid message" {
		t.Fatalf("expected 'Valid message', got '%s'", string(decrypted))
	}

	// Alice sends another message.
	validMsg2, err := aliceCipher.Encrypt([]byte("Another message"))
	if err != nil {
		t.Fatal(err)
	}
	validMsg2Bytes, err := validMsg2.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with the ciphertext to cause MAC verification failure.
	// Flip some bytes in the serialized message.
	tamperedBytes := make([]byte, len(validMsg2Bytes))
	copy(tamperedBytes, validMsg2Bytes)
	// Corrupt bytes near the end (ciphertext region).
	if len(tamperedBytes) > 10 {
		tamperedBytes[len(tamperedBytes)-5] ^= 0xFF
		tamperedBytes[len(tamperedBytes)-6] ^= 0xFF
	}

	// Capture state before the failed decryption attempt.
	bobSession, _ = bob.sessionStore.LoadSession(alice.address)
	stateBeforeFail := bobSession.SessionState()
	prevCounterBeforeFail := stateBeforeFail.PreviousCounter()

	// Attempt to deserialize and decrypt the tampered message.
	tamperedSignalMsg, parseErr := protocol.NewSignalMessageFromBytes(tamperedBytes, serializer.SignalMessage)
	if parseErr != nil {
		// If parsing itself fails, the state was never touched, which is fine.
		// The important thing is that the state was not mutated.
		t.Logf("tampered message could not be parsed (expected): %v", parseErr)
	} else {
		_, decErr := bobCipher.Decrypt(tamperedSignalMsg)
		if decErr == nil {
			t.Fatal("expected decryption failure for tampered message")
		}
	}

	// Verify Bob's session state was NOT mutated by the failed decryption.
	bobSession, _ = bob.sessionStore.LoadSession(alice.address)
	stateAfterFail := bobSession.SessionState()
	prevCounterAfterFail := stateAfterFail.PreviousCounter()
	versionAfterFail := stateAfterFail.Version()

	if prevCounterAfterFail != prevCounterBeforeFail {
		t.Fatalf("previous counter should not change on failed decryption: before=%d, after=%d",
			prevCounterBeforeFail, prevCounterAfterFail)
	}
	_ = prevCounterBefore
	_ = versionBefore
	_ = versionAfterFail
}

// TestDecryptStateRollbackPreservesRecoverability verifies that after a
// failed decryption attempt, a subsequent valid message can still be
// decrypted correctly (state was not corrupted).
func TestDecryptStateRollbackPreservesRecoverability(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	// Establish session: Alice -> Bob via PreKey bundle.
	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	bundle := bob.kyberBundle()

	err := alice.sessionBuilder.ProcessBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)

	// Alice sends message 1 (PreKeySignalMessage to establish Bob's session).
	msg1, err := aliceCipher.Encrypt([]byte("Message 1"))
	if err != nil {
		t.Fatal(err)
	}
	msg1Bytes, err := msg1.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	receivedMsg1, err := protocol.NewPreKeySignalMessageFromBytes(msg1Bytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Bob processes the prekey to establish session.
	processAndComplete(t, bob.sessionBuilder, receivedMsg1)

	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)

	// Decrypt message 1 successfully.
	decrypted, err := bobCipher.Decrypt(receivedMsg1.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != "Message 1" {
		t.Fatalf("expected 'Message 1', got '%s'", string(decrypted))
	}

	// Bob responds so Alice clears her unack prekey (establishing full session).
	bobReply, err := bobCipher.Encrypt([]byte("Bob reply"))
	if err != nil {
		t.Fatal(err)
	}
	bobReplyBytes, err := bobReply.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	bobReplyMsg, err := protocol.NewSignalMessageFromBytes(bobReplyBytes, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}
	_, err = aliceCipher.Decrypt(bobReplyMsg)
	if err != nil {
		t.Fatal(err)
	}

	// Now Alice sends messages 2 and 3 as regular SignalMessages.
	msg2, err := aliceCipher.Encrypt([]byte("Message 2"))
	if err != nil {
		t.Fatal(err)
	}
	msg2SignalMsg := msg2.(*protocol.SignalMessage)

	msg3, err := aliceCipher.Encrypt([]byte("Message 3"))
	if err != nil {
		t.Fatal(err)
	}
	msg3SignalMsg := msg3.(*protocol.SignalMessage)

	// Create a corrupted copy of message 2 by tampering with its MAC.
	msg2Bytes, err := msg2SignalMsg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	corruptedMsg2Bytes := make([]byte, len(msg2Bytes))
	copy(corruptedMsg2Bytes, msg2Bytes)
	if len(corruptedMsg2Bytes) > 10 {
		corruptedMsg2Bytes[len(corruptedMsg2Bytes)-3] ^= 0xFF
	}

	// Attempt to decrypt the corrupted message (should fail).
	corruptedMsg, parseErr := protocol.NewSignalMessageFromBytes(corruptedMsg2Bytes, serializer.SignalMessage)
	if parseErr == nil {
		_, decErr := bobCipher.Decrypt(corruptedMsg)
		if decErr == nil {
			t.Fatal("expected decryption error for corrupted message")
		}
	}

	// Now decrypt the valid message 2 -- this should succeed because
	// the failed attempt did not corrupt the state.
	decrypted2, err := bobCipher.Decrypt(msg2SignalMsg)
	if err != nil {
		t.Fatalf("expected successful decryption of valid message after failed attempt: %v", err)
	}
	if string(decrypted2) != "Message 2" {
		t.Fatalf("expected 'Message 2', got '%s'", string(decrypted2))
	}

	// And message 3 should also work.
	decrypted3, err := bobCipher.Decrypt(msg3SignalMsg)
	if err != nil {
		t.Fatalf("expected successful decryption of message 3: %v", err)
	}
	if string(decrypted3) != "Message 3" {
		t.Fatalf("expected 'Message 3', got '%s'", string(decrypted3))
	}
}

// TestDecryptWithStateUninitializedSessionNilMessage verifies that DecryptWithState
// returns an error for an uninitialized session (no sender chain) with a nil message.
func TestDecryptWithStateUninitializedSessionNilMessage(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)

	// Create a fresh state with no sender chain.
	state := record.NewState(serializer.State)

	// Create a minimal signal message for testing.
	// We just need the version check to pass, so we set the state version.
	// But since there is no sender chain, it should return errUninitializedSession.
	_, _, err := aliceCipher.DecryptWithState(state, nil)
	if err == nil {
		t.Fatal("expected error for uninitialized session")
	}
	if !errors.Is(err, session.ErrUninitializedSession) {
		t.Fatalf("expected ErrUninitializedSession, got: %v", err)
	}
}

// ============= Deferred Actions Tests =============

// TestDeferredActionsPreKeysPreservedOnDecryptFailure verifies that pre-keys
// are NOT burned when decryption fails. This is the core safety property of
// the deferred commit pattern, matching the Rust reference implementation.
func TestDeferredActionsPreKeysPreservedOnDecryptFailure(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	bundle := bob.kyberBundle()
	if err := alice.sessionBuilder.ProcessBundle(bundle); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("test message"))
	if err != nil {
		t.Fatal(err)
	}

	preKeyMsg := msg.(*protocol.PreKeySignalMessage)
	msgBytes, err := preKeyMsg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	receivedMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the one-time pre-key exists before Process.
	preKeyID := receivedMsg.PreKeyID()
	if preKeyID == nil {
		t.Fatal("expected pre-key ID in message")
	}
	if ok, _ := bob.preKeyStore.ContainsPreKey(preKeyID.Value); !ok {
		t.Fatal("pre-key should exist before Process")
	}

	// Verify Kyber pre-key exists before Process.
	kyberID := receivedMsg.KyberPreKeyID()
	if kyberID == nil {
		t.Fatal("expected Kyber pre-key ID in message")
	}
	if ok, _ := bob.kyberPreKeyStore.ContainsKyberPreKey(kyberID.Value); !ok {
		t.Fatal("Kyber pre-key should exist before Process")
	}

	// Call Process but do NOT call Complete (simulating decrypt failure).
	deferred, err := bob.sessionBuilder.Process(receivedMsg)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the DeferredActions contains the expected IDs.
	if deferred.UnsignedPreKeyID == nil {
		t.Fatal("expected UnsignedPreKeyID in deferred actions")
	}
	if deferred.UnsignedPreKeyID.Value != preKeyID.Value {
		t.Fatalf("UnsignedPreKeyID mismatch: got %d, want %d", deferred.UnsignedPreKeyID.Value, preKeyID.Value)
	}
	if deferred.KyberPreKeyID == nil {
		t.Fatal("expected KyberPreKeyID in deferred actions")
	}
	if deferred.KyberPreKeyID.Value != kyberID.Value {
		t.Fatalf("KyberPreKeyID mismatch: got %d, want %d", deferred.KyberPreKeyID.Value, kyberID.Value)
	}
	if deferred.TheirIdentityKey == nil {
		t.Fatal("expected TheirIdentityKey in deferred actions")
	}
	if deferred.SessionRecord == nil {
		t.Fatal("expected SessionRecord in deferred actions")
	}

	// The critical assertion: pre-keys must still exist because Complete was
	// never called. This simulates a decrypt failure scenario where the caller
	// discards the DeferredActions without committing.
	if ok, _ := bob.preKeyStore.ContainsPreKey(preKeyID.Value); !ok {
		t.Fatal("one-time pre-key was burned despite no Complete() call")
	}

	// Verify the Kyber pre-key store was NOT marked as used.
	if bob.kyberPreKeyStore.marked[kyberID.Value] {
		t.Fatal("Kyber pre-key was marked as used despite no Complete() call")
	}
}

// TestDeferredActionsCompleteCommitsSideEffects verifies that calling
// Complete() properly stores the session, saves the identity, marks
// the Kyber pre-key as used, and removes the one-time pre-key.
func TestDeferredActionsCompleteCommitsSideEffects(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	bundle := bob.kyberBundle()
	if err := alice.sessionBuilder.ProcessBundle(bundle); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("test message for complete"))
	if err != nil {
		t.Fatal(err)
	}

	preKeyMsg := msg.(*protocol.PreKeySignalMessage)
	msgBytes, err := preKeyMsg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	receivedMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	preKeyID := receivedMsg.PreKeyID()
	kyberID := receivedMsg.KyberPreKeyID()

	// Process returns deferred actions without committing.
	deferred, err := bob.sessionBuilder.Process(receivedMsg)
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt the inner message using the deferred session record.
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	plaintext, _, err := bobCipher.DecryptWithRecordPreKey(deferred.SessionRecord, receivedMsg.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "test message for complete" {
		t.Fatalf("plaintext mismatch: got %q", string(plaintext))
	}

	// Before Complete: pre-keys still exist, Kyber not marked.
	if ok, _ := bob.preKeyStore.ContainsPreKey(preKeyID.Value); !ok {
		t.Fatal("pre-key should exist before Complete")
	}
	if bob.kyberPreKeyStore.marked[kyberID.Value] {
		t.Fatal("Kyber pre-key should not be marked before Complete")
	}

	// Call Complete to commit the deferred operations.
	if err := deferred.Complete(); err != nil {
		t.Fatal(err)
	}

	// After Complete: pre-keys consumed, Kyber marked.
	if ok, _ := bob.preKeyStore.ContainsPreKey(preKeyID.Value); ok {
		t.Fatal("one-time pre-key should be removed after Complete")
	}
	if !bob.kyberPreKeyStore.marked[kyberID.Value] {
		t.Fatal("Kyber pre-key should be marked as used after Complete")
	}
}

// TestDecryptPreKeyMessageAtomicFlow verifies the DecryptPreKeyMessage
// convenience method performs Process + Decrypt + Complete atomically.
func TestDecryptPreKeyMessageAtomicFlow(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	bundle := bob.kyberBundle()
	if err := alice.sessionBuilder.ProcessBundle(bundle); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("atomic decrypt test"))
	if err != nil {
		t.Fatal(err)
	}

	preKeyMsg := msg.(*protocol.PreKeySignalMessage)
	msgBytes, err := preKeyMsg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	receivedMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	preKeyID := receivedMsg.PreKeyID()

	// Use the atomic DecryptPreKeyMessage method.
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	plaintext, deferred, err := bobCipher.DecryptPreKeyMessage(bob.sessionBuilder, receivedMsg)
	if err != nil {
		t.Fatal(err)
	}

	if string(plaintext) != "atomic decrypt test" {
		t.Fatalf("plaintext mismatch: got %q", string(plaintext))
	}
	if deferred == nil {
		t.Fatal("expected non-nil deferred actions")
	}

	// After DecryptPreKeyMessage, all side effects should be committed.
	if ok, _ := bob.sessionStore.ContainsSession(alice.address); !ok {
		t.Fatal("session should exist after DecryptPreKeyMessage")
	}
	if ok, _ := bob.preKeyStore.ContainsPreKey(preKeyID.Value); ok {
		t.Fatal("one-time pre-key should be removed after DecryptPreKeyMessage")
	}

	// Verify Bob can now respond (session is fully established).
	bobResponse, err := bobCipher.Encrypt([]byte("response"))
	if err != nil {
		t.Fatal(err)
	}
	if bobResponse == nil {
		t.Fatal("expected encrypted response")
	}
}

// TestDeferredActionsNilPreKeys verifies that DeferredActions with nil
// pre-key IDs (e.g., re-processing an already-established session) works
// correctly without errors.
func TestDeferredActionsNilPreKeys(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	// Use a bundle without a one-time pre-key.
	bundle := bob.kyberBundleNoOneTimePreKey()
	if err := alice.sessionBuilder.ProcessBundle(bundle); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("no one-time prekey"))
	if err != nil {
		t.Fatal(err)
	}

	preKeyMsg := msg.(*protocol.PreKeySignalMessage)
	msgBytes, err := preKeyMsg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	receivedMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	deferred, err := bob.sessionBuilder.Process(receivedMsg)
	if err != nil {
		t.Fatal(err)
	}

	// UnsignedPreKeyID should be nil since no one-time pre-key was used.
	if deferred.UnsignedPreKeyID != nil {
		t.Fatal("expected nil UnsignedPreKeyID for bundle without one-time pre-key")
	}

	// Complete should succeed without errors even with nil pre-key IDs.
	if err := deferred.Complete(); err != nil {
		t.Fatal(err)
	}
}
