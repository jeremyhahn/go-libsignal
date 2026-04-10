package tests

import (
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/session"
	"testing"
)

// TestSessionBuilder checks building of a session.
func TestSessionBuilder(t *testing.T) {

	// Create a serializer object that will be used to encode/decode data.
	serializer := newSerializer()

	// Create our users who will talk to each other.
	alice := newUser("Alice", 1, serializer)
	bob := newUser("Bob", 2, serializer)

	// Create a session builder to create a session between Alice -> Bob.
	alice.buildSession(bob.address, serializer)
	bob.buildSession(alice.address, serializer)

	// Create a PreKeyBundle from Bob's prekey records and other
	// data, including Kyber keys for PQXDH.
	// Fetch Bob's prekey
	retrievedPreKey := bob.kyberBundle()

	// Process Bob's retrieved prekey to establish a session.
	err := alice.sessionBuilder.ProcessBundle(retrievedPreKey)
	if err != nil {
		t.Fatalf("Unable to process retrieved prekey bundle: %v", err)
	}

	// Create a session cipher to encrypt messages to Bob.
	plaintextMessage := []byte("Hello!")
	sessionCipher := session.NewCipher(alice.sessionBuilder, bob.address)
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
		t.Fatalf("Unable to deserialize PreKeySignalMessage from bytes: %v", err)
	}

	// Create a session builder and decrypt the prekey message in one step.
	// This uses the deferred pattern: Process + Decrypt + Complete atomically.
	bobSessionCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	msg, _, err := bobSessionCipher.DecryptPreKeyMessage(bob.sessionBuilder, receivedMessage)
	if err != nil {
		t.Fatalf("Unable to process/decrypt prekeysignal message: %v", err)
	}
	if string(msg) != string(plaintextMessage) {
		t.Fatalf("Decrypted message mismatch: got %q, want %q", string(msg), string(plaintextMessage))
	}

	// Send a response to Alice
	plaintextResponse := []byte("oui!")
	response, err := bobSessionCipher.Encrypt(plaintextResponse)
	if err != nil {
		t.Fatalf("Unable to encrypt response: %v", err)
	}

	responseBytes, err := response.Serialize()
	if err != nil {
		t.Fatalf("Unable to serialize response: %v", err)
	}
	responseMessage, err := protocol.NewSignalMessageFromBytes(responseBytes, serializer.SignalMessage)
	if err != nil {
		t.Fatalf("Unable to deserialize SignalMessage from bytes: %v", err)
	}

	deResponse, err := sessionCipher.Decrypt(responseMessage)
	if err != nil {
		t.Fatalf("Unable to decrypt response from Bob: %v", err)
	}
	if string(deResponse) != string(plaintextResponse) {
		t.Fatalf("Decrypted response mismatch: got %q, want %q", string(deResponse), string(plaintextResponse))
	}
}

// TestSessionRoundtrip checks sending messages back and forth from users.
func TestSessionRoundtrip(t *testing.T) {

	// Create a serializer object that will be used to encode/decode data.
	serializer := newSerializer()

	// Create our users who will talk to each other.
	alice := newUser("Alice", 1, serializer)
	bob := newUser("Bob", 2, serializer)

	// Create a session builder to create a session between Alice -> Bob.
	alice.buildSession(bob.address, serializer)
	bob.buildSession(alice.address, serializer)

	///////////// SENDER SESSION CREATION ///////////////

	// Create a PreKeyBundle from Bob's prekey records with Kyber keys.
	// Fetch Bob's prekey
	retrievedPreKey := bob.kyberBundle()

	// Process Bob's retrieved prekey to establish a session.
	err := alice.sessionBuilder.ProcessBundle(retrievedPreKey)
	if err != nil {
		t.Fatalf("Unable to process retrieved prekey bundle: %v", err)
	}

	// Create a session cipher to encrypt messages to Bob.
	aliceSessionCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	aliceMessageStrings1, aliceMessages1 := sendMessages(1000, aliceSessionCipher, serializer, t)

	///////////// RECEIVER SESSION CREATION ///////////////

	// Create a session builder
	bobSessionCipher := session.NewCipher(bob.sessionBuilder, alice.address)

	// Process and decrypt the first prekey message using the deferred pattern.
	firstPreKeyMsg := aliceMessages1[0].(*protocol.PreKeySignalMessage)
	firstPlaintext, _, err := bobSessionCipher.DecryptPreKeyMessage(bob.sessionBuilder, firstPreKeyMsg)
	if err != nil {
		t.Fatalf("Unable to process/decrypt prekeysignal message: %v", err)
	}

	// Verify the first message, then decrypt the rest as regular SignalMessages.
	if string(firstPlaintext) != aliceMessageStrings1[0] {
		t.Fatalf("first message mismatch: got %q, want %q", string(firstPlaintext), aliceMessageStrings1[0])
	}

	/////////// ROUND TRIP 1 ////////////
	receiveMessages(aliceMessages1[1:], aliceMessageStrings1[1:], bobSessionCipher, t)

	// Let Bob encrypt and send some messages.
	bobMessageStrings1, bobMessages1 := sendMessages(1000, bobSessionCipher, serializer, t)

	// Let Alice decrypt the messages from Bob.
	receiveMessages(bobMessages1, bobMessageStrings1, aliceSessionCipher, t)

	/////////// ROUND TRIP 2 ////////////
	aliceMessageStrings2, aliceMessages2 := sendMessages(1000, aliceSessionCipher, serializer, t)
	receiveMessages(aliceMessages2, aliceMessageStrings2, bobSessionCipher, t)

	bobMessageStrings2, bobMessages2 := sendMessages(1000, bobSessionCipher, serializer, t)
	receiveMessages(bobMessages2, bobMessageStrings2, aliceSessionCipher, t)

	/////////// ROUND TRIP 3 ////////////
	aliceMessageStrings3, aliceMessages3 := sendMessages(1000, aliceSessionCipher, serializer, t)
	receiveMessages(aliceMessages3, aliceMessageStrings3, bobSessionCipher, t)

	bobMessageStrings3, bobMessages3 := sendMessages(1000, bobSessionCipher, serializer, t)
	receiveMessages(bobMessages3, bobMessageStrings3, aliceSessionCipher, t)
}

// TestSessionOutOfOrder checks sending messages out of order.
func TestSessionOutOfOrder(t *testing.T) {

	// Create a serializer object that will be used to encode/decode data.
	serializer := newSerializer()

	// Create our users who will talk to each other.
	alice := newUser("Alice", 1, serializer)
	bob := newUser("Bob", 2, serializer)

	// Create a session builder to create a session between Alice -> Bob.
	alice.buildSession(bob.address, serializer)
	bob.buildSession(alice.address, serializer)

	///////////// SENDER SESSION CREATION ///////////////

	// Create a PreKeyBundle from Bob's prekey records with Kyber keys.
	// Fetch Bob's prekey
	retrievedPreKey := bob.kyberBundle()

	// Process Bob's retrieved prekey to establish a session.
	err := alice.sessionBuilder.ProcessBundle(retrievedPreKey)
	if err != nil {
		t.Fatalf("Unable to process retrieved prekey bundle: %v", err)
	}

	// Create a session cipher to encrypt messages to Bob.
	aliceSessionCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	aliceMessageStrings, aliceMessages := sendMessages(4, aliceSessionCipher, serializer, t)

	///////////// RECEIVER SESSION CREATION ///////////////

	// Create a session builder
	bobSessionCipher := session.NewCipher(bob.sessionBuilder, alice.address)

	// Process and decrypt message [3] using the deferred pattern.
	preKeyMsg3 := aliceMessages[3].(*protocol.PreKeySignalMessage)
	plaintext3, _, err := bobSessionCipher.DecryptPreKeyMessage(bob.sessionBuilder, preKeyMsg3)
	if err != nil {
		t.Fatalf("Unable to process/decrypt prekeysignal message: %v", err)
	}

	/////////// ROUND TRIP 1 ////////////
	if string(plaintext3) != aliceMessageStrings[3] {
		t.Fatalf("message 3 mismatch: got %q, want %q", string(plaintext3), aliceMessageStrings[3])
	}
	receiveMessages([]protocol.CiphertextMessage{aliceMessages[0]}, []string{aliceMessageStrings[0]}, bobSessionCipher, t)

}

// sendMessages will generate and return a list of plaintext and encrypted messages.
func sendMessages(count int, cipher *session.Cipher, serializer *serialize.Serializer, t *testing.T) ([]string, []protocol.CiphertextMessage) {
	texts := []string{
		"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.",
		"Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.",
		"Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.",
		"Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.",
	}
	messageStrings := make([]string, count)
	for i := 0; i < count; i++ {
		messageStrings[i] = texts[i%len(texts)]
	}

	messages := make([]protocol.CiphertextMessage, count)
	for i, str := range messageStrings {
		msg := encryptMessage(str, cipher, serializer, t)
		messages[i] = msg
	}

	return messageStrings, messages
}

// receiveMessages is a helper function to receive a bunch of encrypted messages and decrypt them.
func receiveMessages(messages []protocol.CiphertextMessage, messageStrings []string, cipher *session.Cipher, t *testing.T) {
	for i, receivedMessage := range messages {
		msg := decryptMessage(receivedMessage, cipher, t)
		if messageStrings[i] != msg {
			t.Fatalf("Decrypted message mismatch at index %d: got %q, want %q", i, msg, messageStrings[i])
		}
	}
}

// encryptMessage is a helper function to send encrypted messages with the given cipher.
func encryptMessage(message string, cipher *session.Cipher, serializer *serialize.Serializer, t *testing.T) protocol.CiphertextMessage {
	plaintextMessage := []byte(message)
	encrypted, err := cipher.Encrypt(plaintextMessage)
	if err != nil {
		t.Fatalf("Unable to encrypt message: %v", err)
	}

	// Emulate receiving the message as JSON over the network.
	serializedBytes, err := encrypted.Serialize()
	if err != nil {
		t.Fatalf("Unable to serialize encrypted message: %v", err)
	}
	var encryptedMessage protocol.CiphertextMessage
	switch encrypted.(type) {
	case *protocol.PreKeySignalMessage:
		encryptedMessage, err = protocol.NewPreKeySignalMessageFromBytes(serializedBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	case *protocol.SignalMessage:
		encryptedMessage, err = protocol.NewSignalMessageFromBytes(serializedBytes, serializer.SignalMessage)
	}

	if err != nil {
		t.Fatalf("Unable to deserialize message from bytes: %v", err)
	}

	return encryptedMessage
}

// decryptMessage is a helper function to decrypt messages of a session.
func decryptMessage(message protocol.CiphertextMessage, cipher *session.Cipher, t *testing.T) string {
	switch m := message.(type) {
	case *protocol.PreKeySignalMessage:
		return decryptMessage(m.WhisperMessage(), cipher, t)
	}

	msg, err := cipher.Decrypt(message.(*protocol.SignalMessage))
	if err != nil {
		t.Fatalf("Unable to decrypt message: %v", err)
	}

	return string(msg)
}
