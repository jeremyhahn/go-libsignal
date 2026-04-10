package tests

import (
	"github.com/jeremyhahn/go-libsignal/pkg/groups"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/session"
	"testing"
)

// TestGroupSessionBuilder checks building of a group session.
func TestGroupSessionBuilder(t *testing.T) {

	// Create a serializer object that will be used to encode/decode data.
	serializer := newSerializer()

	// Create our users who will talk to each other.
	alice := newUser("Alice", 1, serializer)
	bob := newUser("Bob", 2, serializer)
	// The group name must match the UUID-formatted distribution ID used in
	// GroupCipher.Decrypt store lookups. With a zero distribution ID [16]byte{},
	// the formatted UUID is "00000000-0000-0000-0000-000000000000".
	groupName := "00000000-0000-0000-0000-000000000000"

	// ***** Build one-to-one session with group members *****

	// Create a session builder to create a session between Alice -> Bob.
	alice.buildSession(bob.address, serializer)
	bob.buildSession(alice.address, serializer)

	// Create a PreKeyBundle from Bob's prekey records with Kyber keys.
	retrivedPreKey := bob.kyberBundle()

	// Process Bob's retrieved prekey to establish a session.
	err := alice.sessionBuilder.ProcessBundle(retrivedPreKey)
	if err != nil {
		t.Fatalf("Unable to process retrieved prekey bundle: %v", err)
	}

	// Create a session builder to create a session between Alice -> Bob.
	aliceSenderKeyName := protocol.NewSenderKeyName(groupName, alice.address)
	aliceSkdm, err := alice.groupBuilder.Create([16]byte{}, aliceSenderKeyName)
	if err != nil {
		t.Fatalf("Unable to create group session: %v", err)
	}
	aliceSendingCipher := groups.NewGroupCipher(alice.groupBuilder, aliceSenderKeyName, alice.senderKeyStore)

	// Create a one-to-one session cipher to encrypt the skdm to Bob.
	aliceBobSessionCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	aliceSkdmBytes, err := aliceSkdm.Serialize()
	if err != nil {
		t.Fatalf("Unable to serialize skdm: %v", err)
	}
	encryptedSkdm, err := aliceBobSessionCipher.Encrypt(aliceSkdmBytes)
	if err != nil {
		t.Fatalf("Unable to encrypt skdm: %v", err)
	}

	// ***** Bob receive senderkey distribution message from Alice *****

	// Emulate receiving the message as JSON over the network.
	encryptedSkdmBytes, err := encryptedSkdm.Serialize()
	if err != nil {
		t.Fatalf("Unable to serialize encrypted skdm: %v", err)
	}
	receivedMessage, err := protocol.NewPreKeySignalMessageFromBytes(encryptedSkdmBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatalf("Unable to deserialize PreKeySignalMessage from bytes: %v", err)
	}

	// Create a session builder and decrypt the prekey message using the deferred pattern.
	bobAliceSessionCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	msg, _, err := bobAliceSessionCipher.DecryptPreKeyMessage(bob.sessionBuilder, receivedMessage)
	if err != nil {
		t.Fatalf("Unable to process/decrypt prekeysignal message: %v", err)
	}

	bobReceivedSkdm, err := protocol.NewSenderKeyDistributionMessageFromBytes(msg, serializer.SenderKeyDistributionMessage)
	if err != nil {
		t.Fatalf("Unable to create senderkey distribution message from bytes: %v", err)
	}

	// ***** Alice Send *****

	// Encrypt some messages to send with Alice's group cipher
	alicePlainMessages, aliceEncryptedMessages := sendGroupMessages(1000, aliceSendingCipher, serializer, t)

	// Build bob's side of the session.
	if err := bob.groupBuilder.Process(aliceSenderKeyName, bobReceivedSkdm); err != nil {
		t.Fatalf("Process() error: %v", err)
	}
	receivingBobCipher := groups.NewGroupCipher(bob.groupBuilder, aliceSenderKeyName, bob.senderKeyStore)

	// Decrypt the messages sent by alice.
	receiveGroupMessages(aliceEncryptedMessages, alicePlainMessages, receivingBobCipher, t)

	// ***** Bob send senderkey distribution message to Alice *****

	// Create a group builder with Bob's address.
	bobSenderKeyName := protocol.NewSenderKeyName(groupName, bob.address)
	bobSkdm, err := bob.groupBuilder.Create([16]byte{}, bobSenderKeyName)
	if err != nil {
		t.Fatalf("Unable to create group session: %v", err)
	}
	bobSendingCipher := groups.NewGroupCipher(bob.groupBuilder, bobSenderKeyName, bob.senderKeyStore)

	// Encrypt the senderKey distribution message to send to Alice.
	bobSkdmBytes, err := bobSkdm.Serialize()
	if err != nil {
		t.Fatalf("Unable to serialize bob skdm: %v", err)
	}
	bobEncryptedSkdm, err := bobAliceSessionCipher.Encrypt(bobSkdmBytes)
	if err != nil {
		t.Fatalf("Unable to encrypt bob skdm: %v", err)
	}

	// Emulate receiving the message as JSON over the network.
	bobEncryptedSkdmBytes, err := bobEncryptedSkdm.Serialize()
	if err != nil {
		t.Fatalf("Unable to serialize bob encrypted skdm: %v", err)
	}
	aliceReceivedMessage, err := protocol.NewSignalMessageFromBytes(bobEncryptedSkdmBytes, serializer.SignalMessage)
	if err != nil {
		t.Fatalf("Unable to deserialize SignalMessage from bytes: %v", err)
	}

	// ***** Alice receives senderkey distribution message from Bob *****

	// Decrypt the received message.
	msg, err = aliceBobSessionCipher.Decrypt(aliceReceivedMessage)
	if err != nil {
		t.Fatalf("Unable to decrypt message: %v", err)
	}
	aliceReceivedSkdm, err := protocol.NewSenderKeyDistributionMessageFromBytes(msg, serializer.SenderKeyDistributionMessage)
	if err != nil {
		t.Fatalf("Unable to create senderkey distribution message from bytes: %v", err)
	}

	// ***** Bob Send *****

	// Encrypt some messages to send with Bob's group cipher
	bobPlainMessages, bobEncryptedMessages := sendGroupMessages(1000, bobSendingCipher, serializer, t)

	// Build alice's side of the session.
	if err := alice.groupBuilder.Process(bobSenderKeyName, aliceReceivedSkdm); err != nil {
		t.Fatalf("Process() error: %v", err)
	}
	receivingAliceCipher := groups.NewGroupCipher(alice.groupBuilder, bobSenderKeyName, alice.senderKeyStore)

	// Decrypt the messages sent by bob.
	receiveGroupMessages(bobEncryptedMessages, bobPlainMessages, receivingAliceCipher, t)
}

// sendGroupMessages will generate and return a list of plaintext and encrypted messages.
func sendGroupMessages(count int, cipher *groups.GroupCipher, serializer *serialize.Serializer, t *testing.T) ([]string, []protocol.CiphertextMessage) {
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
		msg := encryptGroupMessage(str, cipher, serializer, t)
		messages[i] = msg
	}

	return messageStrings, messages
}

// receiveGroupMessages is a helper function to receive a bunch of encrypted messages and decrypt them.
func receiveGroupMessages(messages []protocol.CiphertextMessage, messageStrings []string, cipher *groups.GroupCipher, t *testing.T) {
	for i, receivedMessage := range messages {
		msg := decryptGroupMessage(receivedMessage, cipher, t)
		if messageStrings[i] != msg {
			t.Fatalf("Decrypted message mismatch at index %d: got %q, want %q", i, msg, messageStrings[i])
		}
	}
}

// encryptGroupMessage is a helper function to send encrypted messages with the given cipher.
func encryptGroupMessage(message string, cipher *groups.GroupCipher, serializer *serialize.Serializer, t *testing.T) protocol.CiphertextMessage {
	plaintextMessage := []byte(message)
	encrypted, err := cipher.Encrypt([16]byte{}, plaintextMessage)
	if err != nil {
		t.Fatalf("Unable to encrypt message: %v", err)
	}

	// Emulate receiving the message as JSON over the network.
	var encryptedMessage protocol.CiphertextMessage
	switch message := encrypted.(type) {
	case *protocol.SenderKeyMessage:
		signedBytes, err := message.SignedSerialize()
		if err != nil {
			t.Fatalf("Unable to signed serialize message: %v", err)
		}
		encryptedMessage, err = protocol.NewSenderKeyMessageFromBytes(signedBytes, serializer.SenderKeyMessage)
		if err != nil {
			t.Fatalf("Unable to deserialize SenderKeyMessage from bytes: %v", err)
		}
	}

	return encryptedMessage
}

// decryptGroupMessage is a helper function to decrypt messages of a session.
func decryptGroupMessage(message protocol.CiphertextMessage, cipher *groups.GroupCipher, t *testing.T) string {
	senderKeyMessage := message.(*protocol.SenderKeyMessage)

	msg, err := cipher.Decrypt(senderKeyMessage)
	if err != nil {
		t.Fatalf("Unable to decrypt message: %v", err)
	}

	return string(msg)
}
