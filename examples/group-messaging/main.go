// Package main demonstrates SenderKey group messaging with three participants.
//
// Flow:
//  1. Alice creates a group session and obtains a SenderKeyDistributionMessage (SKDM).
//  2. Alice distributes the SKDM to Bob and Charlie (they each call Process).
//  3. Alice encrypts "Hello, group!" with her GroupCipher.
//  4. Bob and Charlie each independently decrypt the message.
//
// The example uses a single distribution ID shared by all participants. The
// SenderKeyName binds the group ID (derived from the distribution UUID) to
// the sender's SignalAddress, ensuring each sender's key chain is independent.
//
// Run: GOWORK=off go run ./examples/group-messaging/
package main

import (
	"fmt"
	"log"

	"github.com/jeremyhahn/go-libsignal/pkg/groups"
	groupRecord "github.com/jeremyhahn/go-libsignal/pkg/groups/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
)

// memSenderKeyStore is an in-memory implementation of groups/state/store.SenderKey.
type memSenderKeyStore struct {
	store map[string]*groupRecord.SenderKey
}

func newMemSenderKeyStore() *memSenderKeyStore {
	return &memSenderKeyStore{store: make(map[string]*groupRecord.SenderKey)}
}

func (s *memSenderKeyStore) StoreSenderKey(name *protocol.SenderKeyName, rec *groupRecord.SenderKey) error {
	s.store[name.GroupID()+name.Sender().String()] = rec
	return nil
}

func (s *memSenderKeyStore) LoadSenderKey(name *protocol.SenderKeyName) (*groupRecord.SenderKey, error) {
	return s.store[name.GroupID()+name.Sender().String()], nil
}

func main() {
	ser := serialize.NewJSONSerializer()

	// The distribution ID uniquely identifies this SenderKey distribution.
	// It is a random 16-byte UUID generated once when Alice creates the group.
	var distributionID [16]byte
	copy(distributionID[:], []byte{
		0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
	})

	// Alice is the sender; the group ID is derived from the distribution ID.
	aliceAddress := protocol.NewSignalAddress("alice", 1)
	groupID := groups.DistributionIDToGroupID(distributionID)
	aliceSKName := protocol.NewSenderKeyName(groupID, aliceAddress)

	// Alice's store and builder.
	aliceStore := newMemSenderKeyStore()
	aliceBuilder := groups.NewGroupSessionBuilder(aliceStore, ser)

	// Create the group session: generates signing key + chain key, stores them,
	// and returns a SenderKeyDistributionMessage for distribution.
	skdm, err := aliceBuilder.Create(distributionID, aliceSKName)
	if err != nil {
		log.Fatalf("Alice Create: %v", err)
	}
	defer skdm.Release()

	// Serialize the SKDM as it would travel over the network.
	skdmBytes, err := skdm.Serialize()
	if err != nil {
		log.Fatalf("SKDM Serialize: %v", err)
	}

	// Bob processes Alice's SKDM.
	bobStore := newMemSenderKeyStore()
	bobBuilder := groups.NewGroupSessionBuilder(bobStore, ser)
	receivedSkdmBob, err := protocol.NewSenderKeyDistributionMessageFromBytes(skdmBytes, ser.SenderKeyDistributionMessage)
	if err != nil {
		log.Fatalf("Bob deserialize SKDM: %v", err)
	}
	defer receivedSkdmBob.Release()
	if err := bobBuilder.Process(aliceSKName, receivedSkdmBob); err != nil {
		log.Fatalf("Bob Process: %v", err)
	}

	// Charlie processes Alice's SKDM.
	charlieStore := newMemSenderKeyStore()
	charlieBuilder := groups.NewGroupSessionBuilder(charlieStore, ser)
	receivedSkdmCharlie, err := protocol.NewSenderKeyDistributionMessageFromBytes(skdmBytes, ser.SenderKeyDistributionMessage)
	if err != nil {
		log.Fatalf("Charlie deserialize SKDM: %v", err)
	}
	defer receivedSkdmCharlie.Release()
	if err := charlieBuilder.Process(aliceSKName, receivedSkdmCharlie); err != nil {
		log.Fatalf("Charlie Process: %v", err)
	}

	// Alice encrypts a group message.
	aliceCipher := groups.NewGroupCipher(aliceBuilder, aliceSKName, aliceStore)
	encrypted, err := aliceCipher.Encrypt(distributionID, []byte("Hello, group!"))
	if err != nil {
		log.Fatalf("Alice Encrypt: %v", err)
	}

	// Serialize and deserialize the SenderKeyMessage as it would travel over the wire.
	senderKeyMsg := encrypted.(*protocol.SenderKeyMessage)
	signedBytes, err := senderKeyMsg.SignedSerialize()
	if err != nil {
		log.Fatalf("SenderKeyMessage SignedSerialize: %v", err)
	}

	// Bob decrypts.
	bobMsg, err := protocol.NewSenderKeyMessageFromBytes(signedBytes, ser.SenderKeyMessage)
	if err != nil {
		log.Fatalf("Bob deserialize SenderKeyMessage: %v", err)
	}
	bobCipher := groups.NewGroupCipher(bobBuilder, aliceSKName, bobStore)
	bobPlaintext, err := bobCipher.Decrypt(bobMsg)
	if err != nil {
		log.Fatalf("Bob Decrypt: %v", err)
	}

	// Charlie decrypts (independent copy of the serialized message).
	charlieMsg, err := protocol.NewSenderKeyMessageFromBytes(signedBytes, ser.SenderKeyMessage)
	if err != nil {
		log.Fatalf("Charlie deserialize SenderKeyMessage: %v", err)
	}
	charlieCipher := groups.NewGroupCipher(charlieBuilder, aliceSKName, charlieStore)
	charliePlaintext, err := charlieCipher.Decrypt(charlieMsg)
	if err != nil {
		log.Fatalf("Charlie Decrypt: %v", err)
	}

	fmt.Printf("Bob received from Alice: %s\n", bobPlaintext)
	fmt.Printf("Charlie received from Alice: %s\n", charliePlaintext)
}
