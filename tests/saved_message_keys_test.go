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
	"github.com/jeremyhahn/go-libsignal/pkg/keys/message"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/session"
	"testing"
)

// TestSavedMessageKeys tests the ability to save message keys for use in
// decrypting messages in the future.
func TestSavedMessageKeys(t *testing.T) {

	// Create a serializer object that will be used to encode/decode data.
	serializer := newSerializer()

	// Create our users who will talk to each other.
	alice := newUser("Alice", 1, serializer)
	bob := newUser("Bob", 2, serializer)

	// Create a session builder to create a session between Alice -> Bob.
	alice.buildSession(bob.address, serializer)
	bob.buildSession(alice.address, serializer)

	// Create a PreKeyBundle from Bob's prekey records with Kyber keys.
	retrievedPreKey := bob.kyberBundle()

	// Process Bob's retrieved prekey to establish a session.
	err := alice.sessionBuilder.ProcessBundle(retrievedPreKey)
	if err != nil {
		t.Fatalf("Unable to process retrieved prekey bundle: %v", err)
	}

	// Create a session cipher to encrypt messages to Bob.
	plaintextMessage := []byte("Hello!")
	sessionCipher := session.NewCipherWithLocalAddress(alice.sessionBuilder, alice.address, bob.address)
	message, err := sessionCipher.Encrypt(plaintextMessage)
	if err != nil {
		t.Fatalf("Unable to encrypt message: %v", err)
	}

	///////////// RECEIVER SESSION CREATION ///////////////

	// Emulate receiving the message as JSON over the network.
	messageBytes, err := message.Serialize()
	if err != nil {
		t.Fatalf("Unable to serialize message: %v", err)
	}
	receivedMessage, err := protocol.NewPreKeySignalMessageFromBytes(messageBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatalf("Unable to emulate receiving message as bytes: %v", err)
	}

	// Create a session builder and process the prekey message with deferred side effects.
	deferred, err := bob.sessionBuilder.Process(receivedMessage)
	if err != nil {
		t.Fatalf("Unable to process prekeysignal message: %v", err)
	}

	// Decrypt the inner message using the deferred session record.
	bobSessionCipher := session.NewCipherWithLocalAddress(bob.sessionBuilder, bob.address, alice.address)
	msg, key, err := bobSessionCipher.DecryptWithRecordPreKey(deferred.SessionRecord, receivedMessage.WhisperMessage())
	if err != nil {
		t.Fatalf("Unable to decrypt message: %v", err)
	}

	// Commit the deferred side effects after successful decryption.
	if err := deferred.Complete(); err != nil {
		t.Fatalf("Unable to complete deferred actions: %v", err)
	}
	if string(msg) != string(plaintextMessage) {
		t.Fatalf("Decrypted string does not match - expected %q, got %q", string(plaintextMessage), string(msg))
	}

	// Try using the message key to decrypt the message again.
	for i := 0; i < 10; i++ {
		testDecryptingWithKey(bobSessionCipher, receivedMessage.WhisperMessage(), key, plaintextMessage, t)
	}
}

func testDecryptingWithKey(cipher *session.Cipher, receivedMessage *protocol.SignalMessage, key *message.Keys, plaintextMessage []byte, t *testing.T) {
	msg, err := cipher.DecryptWithKey(receivedMessage, key)
	if err != nil {
		t.Fatalf("Unable to decrypt message with key: %v", err)
	}
	if string(msg) != string(plaintextMessage) {
		t.Fatalf("Decrypted string does not match - expected %q, got %q", string(plaintextMessage), string(msg))
	}
}
