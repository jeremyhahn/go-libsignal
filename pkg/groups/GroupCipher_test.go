//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 17 tests in this file exercise X25519. FIPS 140-3 does not approve that,
// but the X3DH key agreement specification (section 2.1) requires it, so the
// fips140only build tag drops this file from the FIPS gate. `make test` and
// `make coverage` still run it.

package groups

import (
	"bytes"
	"errors"
	"testing"

	groupRecord "github.com/jeremyhahn/go-libsignal/pkg/groups/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
)

// testDistributionID is a fixed distribution ID for tests. The formatted
// UUID string "01020304-0506-0708-090a-0b0c0d0e0f10" is used as the
// group ID in SenderKeyName lookups.
var testDistributionID = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

// testGroupID returns the UUID-formatted group ID that Decrypt derives
// from testDistributionID.
func testGroupID() string {
	return distributionIDToGroupID(testDistributionID)
}

func TestNewGroupCipher(t *testing.T) {
	store := newInMemorySenderKeyStore()
	serializer := newTestSerializer()
	builder := NewGroupSessionBuilder(store, serializer)

	address := protocol.NewSignalAddress("alice", 1)
	senderKeyName := protocol.NewSenderKeyName(testGroupID(), address)

	cipher := NewGroupCipher(builder, senderKeyName, store)
	if cipher == nil {
		t.Fatal("NewGroupCipher() returned nil")
	}
}

func TestGroupCipherEncryptDecrypt(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	groupID := testGroupID()

	// Alice (sender)
	aliceStore := newInMemorySenderKeyStore()
	aliceBuilder := NewGroupSessionBuilder(aliceStore, serializer)
	aliceAddress := protocol.NewSignalAddress("alice", 1)
	senderKeyName := protocol.NewSenderKeyName(groupID, aliceAddress)

	// Create group session and get SKDM
	skdm, err := aliceBuilder.Create(testDistributionID, senderKeyName)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	defer skdm.Release()

	aliceCipher := NewGroupCipher(aliceBuilder, senderKeyName, aliceStore)

	// Bob (receiver) processes the SKDM
	bobStore := newInMemorySenderKeyStore()
	bobBuilder := NewGroupSessionBuilder(bobStore, serializer)

	skdmBytes, err := skdm.Serialize()
	if err != nil {
		t.Fatalf("SKDM Serialize() error: %v", err)
	}
	receivedSkdm, err := protocol.NewSenderKeyDistributionMessageFromBytes(skdmBytes, serializer.SenderKeyDistributionMessage)
	if err != nil {
		t.Fatalf("NewSenderKeyDistributionMessageFromBytes() error: %v", err)
	}
	defer receivedSkdm.Release()
	if err := bobBuilder.Process(senderKeyName, receivedSkdm); err != nil {
		t.Fatalf("Process() error: %v", err)
	}
	bobCipher := NewGroupCipher(bobBuilder, senderKeyName, bobStore)

	// Encrypt a message
	plaintext := []byte("Hello, group!")
	encrypted, err := aliceCipher.Encrypt(testDistributionID, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	// Simulate sending over the network
	senderKeyMessage := encrypted.(*protocol.SenderKeyMessage)
	signedBytes, err := senderKeyMessage.SignedSerialize()
	if err != nil {
		t.Fatalf("SignedSerialize() error: %v", err)
	}
	receivedMsg, err := protocol.NewSenderKeyMessageFromBytes(signedBytes, serializer.SenderKeyMessage)
	if err != nil {
		t.Fatalf("NewSenderKeyMessageFromBytes() error: %v", err)
	}

	// Decrypt
	decrypted, err := bobCipher.Decrypt(receivedMsg)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted = %q, want %q", string(decrypted), string(plaintext))
	}
}

func TestGroupCipherEncryptMultipleMessages(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	groupID := testGroupID()

	aliceStore := newInMemorySenderKeyStore()
	aliceBuilder := NewGroupSessionBuilder(aliceStore, serializer)
	aliceAddress := protocol.NewSignalAddress("alice", 1)
	senderKeyName := protocol.NewSenderKeyName(groupID, aliceAddress)

	skdm, err := aliceBuilder.Create(testDistributionID, senderKeyName)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	defer skdm.Release()

	aliceCipher := NewGroupCipher(aliceBuilder, senderKeyName, aliceStore)

	bobStore := newInMemorySenderKeyStore()
	bobBuilder := NewGroupSessionBuilder(bobStore, serializer)
	skdmBytes, err := skdm.Serialize()
	if err != nil {
		t.Fatalf("SKDM Serialize() error: %v", err)
	}
	receivedSkdm, err := protocol.NewSenderKeyDistributionMessageFromBytes(skdmBytes, serializer.SenderKeyDistributionMessage)
	if err != nil {
		t.Fatalf("NewSenderKeyDistributionMessageFromBytes() error: %v", err)
	}
	defer receivedSkdm.Release()
	if err := bobBuilder.Process(senderKeyName, receivedSkdm); err != nil {
		t.Fatalf("Process() error: %v", err)
	}
	bobCipher := NewGroupCipher(bobBuilder, senderKeyName, bobStore)

	messages := []string{
		"Message 1",
		"Message 2",
		"Message 3 with more content",
		"Message 4",
	}

	// Encrypt all messages
	encryptedMsgs := make([]*protocol.SenderKeyMessage, len(messages))
	for i, msg := range messages {
		enc, err := aliceCipher.Encrypt(testDistributionID, []byte(msg))
		if err != nil {
			t.Fatalf("Encrypt(%d) error: %v", i, err)
		}
		skm := enc.(*protocol.SenderKeyMessage)
		signedBytes, err := skm.SignedSerialize()
		if err != nil {
			t.Fatalf("SignedSerialize(%d) error: %v", i, err)
		}
		received, err := protocol.NewSenderKeyMessageFromBytes(signedBytes, serializer.SenderKeyMessage)
		if err != nil {
			t.Fatalf("NewSenderKeyMessageFromBytes(%d) error: %v", i, err)
		}
		encryptedMsgs[i] = received
	}

	// Decrypt all messages in order
	for i, encMsg := range encryptedMsgs {
		decrypted, err := bobCipher.Decrypt(encMsg)
		if err != nil {
			t.Fatalf("Decrypt(%d) error: %v", i, err)
		}
		if string(decrypted) != messages[i] {
			t.Errorf("Decrypt(%d) = %q, want %q", i, string(decrypted), messages[i])
		}
	}
}

func TestGroupCipherDecryptNoSession(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	groupID := testGroupID()

	// Alice creates and encrypts
	aliceStore := newInMemorySenderKeyStore()
	aliceBuilder := NewGroupSessionBuilder(aliceStore, serializer)
	aliceAddress := protocol.NewSignalAddress("alice", 1)
	senderKeyName := protocol.NewSenderKeyName(groupID, aliceAddress)

	created, err := aliceBuilder.Create(testDistributionID, senderKeyName)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	defer created.Release()
	aliceCipher := NewGroupCipher(aliceBuilder, senderKeyName, aliceStore)

	encrypted, err := aliceCipher.Encrypt(testDistributionID, []byte("test"))
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	// Bob has no session - LoadSenderKey returns nil.
	bobStore := newInMemorySenderKeyStore()
	bobBuilder := NewGroupSessionBuilder(bobStore, serializer)
	bobCipher := NewGroupCipher(bobBuilder, senderKeyName, bobStore)

	skm := encrypted.(*protocol.SenderKeyMessage)
	signedBytes, err := skm.SignedSerialize()
	if err != nil {
		t.Fatalf("SignedSerialize() error: %v", err)
	}
	received, err := protocol.NewSenderKeyMessageFromBytes(signedBytes, serializer.SenderKeyMessage)
	if err != nil {
		t.Fatalf("NewSenderKeyMessageFromBytes() error: %v", err)
	}

	_, err = bobCipher.Decrypt(received)
	if err == nil {
		t.Fatal("Decrypt with nil sender key record should return error")
	}
	if !errors.Is(err, ErrNilSenderKeyRecord) {
		t.Errorf("Decrypt error = %v, want ErrNilSenderKeyRecord", err)
	}
}

func TestGroupCipherEncryptNoSession(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	groupID := testGroupID()

	store := newInMemorySenderKeyStore()
	builder := NewGroupSessionBuilder(store, serializer)
	address := protocol.NewSignalAddress("alice", 1)
	senderKeyName := protocol.NewSenderKeyName(groupID, address)

	// Do not create a session, directly try to encrypt
	cipher := NewGroupCipher(builder, senderKeyName, store)

	_, err := cipher.Encrypt(testDistributionID, []byte("test"))
	if err == nil {
		t.Fatal("Encrypt with nil sender key record should return error")
	}
	if !errors.Is(err, ErrNilSenderKeyRecord) {
		t.Errorf("Encrypt error = %v, want ErrNilSenderKeyRecord", err)
	}
}

func TestGroupCipherDecryptWrongKeyID(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	groupID := testGroupID()

	// Alice creates group with one key ID
	aliceStore := newInMemorySenderKeyStore()
	aliceBuilder := NewGroupSessionBuilder(aliceStore, serializer)
	aliceAddress := protocol.NewSignalAddress("alice", 1)
	senderKeyName := protocol.NewSenderKeyName(groupID, aliceAddress)

	skdm, err := aliceBuilder.Create(testDistributionID, senderKeyName)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	defer skdm.Release()
	aliceCipher := NewGroupCipher(aliceBuilder, senderKeyName, aliceStore)

	// Bob receives SKDM
	bobStore := newInMemorySenderKeyStore()
	bobBuilder := NewGroupSessionBuilder(bobStore, serializer)
	skdmBytes, _ := skdm.Serialize()
	receivedSkdm, _ := protocol.NewSenderKeyDistributionMessageFromBytes(skdmBytes, serializer.SenderKeyDistributionMessage)
	defer receivedSkdm.Release()
	if err := bobBuilder.Process(senderKeyName, receivedSkdm); err != nil {
		t.Fatalf("Process() error: %v", err)
	}
	_ = NewGroupCipher(bobBuilder, senderKeyName, bobStore)

	// Encrypt a message
	enc, err := aliceCipher.Encrypt(testDistributionID, []byte("test"))
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	// Use a cipher bound to a name that has no record in the store for the
	// distribution ID in the message. The message's distribution ID will
	// derive the correct group ID, but the sender address "nonexistent"
	// won't have any record.
	emptyKeyName := protocol.NewSenderKeyName(groupID, protocol.NewSignalAddress("nonexistent", 1))
	emptyCipher := NewGroupCipher(bobBuilder, emptyKeyName, bobStore)

	skm := enc.(*protocol.SenderKeyMessage)
	signedBytes, _ := skm.SignedSerialize()
	received, _ := protocol.NewSenderKeyMessageFromBytes(signedBytes, serializer.SenderKeyMessage)

	// This should fail because there's no sender key record for this sender
	_, err = emptyCipher.Decrypt(received)
	if err == nil {
		t.Error("Decrypt with wrong key ID should return error")
	}
	if !errors.Is(err, ErrNilSenderKeyRecord) {
		t.Errorf("Decrypt error = %v, want ErrNilSenderKeyRecord", err)
	}
}

func TestGroupCipherDecryptDuplicateMessage(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	groupID := testGroupID()

	aliceStore := newInMemorySenderKeyStore()
	aliceBuilder := NewGroupSessionBuilder(aliceStore, serializer)
	aliceAddress := protocol.NewSignalAddress("alice", 1)
	senderKeyName := protocol.NewSenderKeyName(groupID, aliceAddress)

	skdm, err := aliceBuilder.Create(testDistributionID, senderKeyName)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	defer skdm.Release()

	aliceCipher := NewGroupCipher(aliceBuilder, senderKeyName, aliceStore)

	bobStore := newInMemorySenderKeyStore()
	bobBuilder := NewGroupSessionBuilder(bobStore, serializer)
	skdmBytes, _ := skdm.Serialize()
	receivedSkdm, _ := protocol.NewSenderKeyDistributionMessageFromBytes(skdmBytes, serializer.SenderKeyDistributionMessage)
	defer receivedSkdm.Release()
	if err := bobBuilder.Process(senderKeyName, receivedSkdm); err != nil {
		t.Fatalf("Process() error: %v", err)
	}
	bobCipher := NewGroupCipher(bobBuilder, senderKeyName, bobStore)

	// Encrypt and serialize
	enc, _ := aliceCipher.Encrypt(testDistributionID, []byte("hello"))
	skm := enc.(*protocol.SenderKeyMessage)
	signedBytes, _ := skm.SignedSerialize()
	received1, _ := protocol.NewSenderKeyMessageFromBytes(signedBytes, serializer.SenderKeyMessage)
	received2, _ := protocol.NewSenderKeyMessageFromBytes(signedBytes, serializer.SenderKeyMessage)

	// Decrypt first time should succeed
	_, err = bobCipher.Decrypt(received1)
	if err != nil {
		t.Fatalf("First Decrypt() error: %v", err)
	}

	// Decrypt duplicate should fail with "old counter" error
	_, err = bobCipher.Decrypt(received2)
	if err == nil {
		t.Error("Decrypting duplicate message should return error")
	}
}

func TestGroupCipherDecryptInvalidSignature(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	groupID := testGroupID()

	// Alice creates and encrypts
	aliceStore := newInMemorySenderKeyStore()
	aliceBuilder := NewGroupSessionBuilder(aliceStore, serializer)
	aliceAddress := protocol.NewSignalAddress("alice", 1)
	senderKeyName := protocol.NewSenderKeyName(groupID, aliceAddress)

	skdm, err := aliceBuilder.Create(testDistributionID, senderKeyName)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	defer skdm.Release()
	aliceCipher := NewGroupCipher(aliceBuilder, senderKeyName, aliceStore)

	// Bob receives Alice's real SKDM
	bobStore := newInMemorySenderKeyStore()
	bobBuilder := NewGroupSessionBuilder(bobStore, serializer)
	skdmBytes, _ := skdm.Serialize()
	receivedSkdm, _ := protocol.NewSenderKeyDistributionMessageFromBytes(skdmBytes, serializer.SenderKeyDistributionMessage)
	defer receivedSkdm.Release()
	if err := bobBuilder.Process(senderKeyName, receivedSkdm); err != nil {
		t.Fatalf("Process() error: %v", err)
	}
	bobCipher := NewGroupCipher(bobBuilder, senderKeyName, bobStore)

	// Encrypt a message with Alice
	enc, err := aliceCipher.Encrypt(testDistributionID, []byte("test"))
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	// Get the signed bytes and tamper with the ciphertext to invalidate the signature
	skm := enc.(*protocol.SenderKeyMessage)
	signedBytes, _ := skm.SignedSerialize()

	// Create a tampered message with the correct distribution ID but
	// modified ciphertext so the signature doesn't match.
	tamperedStruct := &protocol.SenderKeyMessageStructure{
		DistributionID: testDistributionID,
		ID:             skm.KeyID(),
		Iteration:      skm.Iteration(),
		CipherText:     append([]byte{0xFF}, skm.Ciphertext()...),
		Version:        protocol.SenderKeyCurrentVersion,
		Signature:      signedBytes[len(signedBytes)-64:], // reuse old signature
	}
	tampered, err := protocol.NewSenderKeyMessageFromStruct(tamperedStruct, serializer.SenderKeyMessage)
	if err != nil {
		t.Fatalf("NewSenderKeyMessageFromStruct() error: %v", err)
	}

	// Bob tries to decrypt - signature should fail verification
	_, err = bobCipher.Decrypt(tampered)
	if err == nil {
		t.Error("Decrypt with invalid signature should return error")
	}
}

func TestGroupCipherDecryptEmptyRecord(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	groupID := testGroupID()

	aliceStore := newInMemorySenderKeyStore()
	aliceBuilder := NewGroupSessionBuilder(aliceStore, serializer)
	aliceAddress := protocol.NewSignalAddress("alice", 1)
	senderKeyName := protocol.NewSenderKeyName(groupID, aliceAddress)

	created, err := aliceBuilder.Create(testDistributionID, senderKeyName)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	defer created.Release()
	aliceCipher := NewGroupCipher(aliceBuilder, senderKeyName, aliceStore)

	// Encrypt
	enc, _ := aliceCipher.Encrypt(testDistributionID, []byte("test"))
	skm := enc.(*protocol.SenderKeyMessage)
	signedBytes, _ := skm.SignedSerialize()
	received, _ := protocol.NewSenderKeyMessageFromBytes(signedBytes, serializer.SenderKeyMessage)

	// Bob has an empty record (no states) stored under the correct group ID
	bobStore := newInMemorySenderKeyStore()
	bobBuilder := NewGroupSessionBuilder(bobStore, serializer)
	emptyRec := groupRecord.NewSenderKey(serializer.SenderKeyRecord, serializer.SenderKeyState)
	if err := bobStore.StoreSenderKey(senderKeyName, emptyRec); err != nil {
		t.Fatalf("StoreSenderKey() error: %v", err)
	}

	bobCipher := NewGroupCipher(bobBuilder, senderKeyName, bobStore)

	_, err = bobCipher.Decrypt(received)
	if err == nil {
		t.Error("Decrypt with empty record should return error")
	}
	if !errors.Is(err, ErrNoSenderKey) {
		t.Errorf("Decrypt error = %v, want ErrNoSenderKey", err)
	}
}

func TestGroupCipherEncryptEmptyState(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	groupID := testGroupID()

	store := newInMemorySenderKeyStore()
	builder := NewGroupSessionBuilder(store, serializer)
	address := protocol.NewSignalAddress("alice", 1)
	senderKeyName := protocol.NewSenderKeyName(groupID, address)

	cipher := NewGroupCipher(builder, senderKeyName, store)

	// Store an empty record
	emptyRec := groupRecord.NewSenderKey(serializer.SenderKeyRecord, serializer.SenderKeyState)
	if err := store.StoreSenderKey(senderKeyName, emptyRec); err != nil {
		t.Fatalf("StoreSenderKey() error: %v", err)
	}

	_, err := cipher.Encrypt(testDistributionID, []byte("test"))
	if err == nil {
		t.Error("Encrypt with empty sender key state should return error")
	}
}

func TestGroupCipherDecryptTooFarInFuture(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	groupID := testGroupID()

	aliceStore := newInMemorySenderKeyStore()
	aliceBuilder := NewGroupSessionBuilder(aliceStore, serializer)
	aliceAddress := protocol.NewSignalAddress("alice", 1)
	senderKeyName := protocol.NewSenderKeyName(groupID, aliceAddress)

	skdm, err := aliceBuilder.Create(testDistributionID, senderKeyName)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	defer skdm.Release()

	aliceCipher := NewGroupCipher(aliceBuilder, senderKeyName, aliceStore)

	bobStore := newInMemorySenderKeyStore()
	bobBuilder := NewGroupSessionBuilder(bobStore, serializer)
	skdmBytes, _ := skdm.Serialize()
	receivedSkdm, _ := protocol.NewSenderKeyDistributionMessageFromBytes(skdmBytes, serializer.SenderKeyDistributionMessage)
	defer receivedSkdm.Release()
	if err := bobBuilder.Process(senderKeyName, receivedSkdm); err != nil {
		t.Fatalf("Process() error: %v", err)
	}
	bobCipher := NewGroupCipher(bobBuilder, senderKeyName, bobStore)

	// Encrypt 25002 messages so the chain advances past 25000
	for i := 0; i < 25002; i++ {
		_, err := aliceCipher.Encrypt(testDistributionID, []byte("msg"))
		if err != nil {
			t.Fatalf("Encrypt(%d) error: %v", i, err)
		}
	}

	// Encrypt one more message at iteration 25002
	enc, err := aliceCipher.Encrypt(testDistributionID, []byte("far future"))
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}
	skm := enc.(*protocol.SenderKeyMessage)
	signedBytes, _ := skm.SignedSerialize()
	received, _ := protocol.NewSenderKeyMessageFromBytes(signedBytes, serializer.SenderKeyMessage)

	// Bob's chain is at iteration 0, message is at 25002
	// Difference > 25000, should get "Over 25000 messages into the future" error
	_, err = bobCipher.Decrypt(received)
	if err == nil {
		t.Error("Decrypt with message >25000 into the future should return error")
	}
}

func TestGroupCipherOutOfOrderDecrypt(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	groupID := testGroupID()

	aliceStore := newInMemorySenderKeyStore()
	aliceBuilder := NewGroupSessionBuilder(aliceStore, serializer)
	aliceAddress := protocol.NewSignalAddress("alice", 1)
	senderKeyName := protocol.NewSenderKeyName(groupID, aliceAddress)

	skdm, err := aliceBuilder.Create(testDistributionID, senderKeyName)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	defer skdm.Release()

	aliceCipher := NewGroupCipher(aliceBuilder, senderKeyName, aliceStore)

	bobStore := newInMemorySenderKeyStore()
	bobBuilder := NewGroupSessionBuilder(bobStore, serializer)
	skdmBytes, err := skdm.Serialize()
	if err != nil {
		t.Fatalf("SKDM Serialize() error: %v", err)
	}
	receivedSkdm, err := protocol.NewSenderKeyDistributionMessageFromBytes(skdmBytes, serializer.SenderKeyDistributionMessage)
	if err != nil {
		t.Fatalf("NewSenderKeyDistributionMessageFromBytes() error: %v", err)
	}
	defer receivedSkdm.Release()
	if err := bobBuilder.Process(senderKeyName, receivedSkdm); err != nil {
		t.Fatalf("Process() error: %v", err)
	}
	bobCipher := NewGroupCipher(bobBuilder, senderKeyName, bobStore)

	// Encrypt 3 messages
	enc1, _ := aliceCipher.Encrypt(testDistributionID, []byte("msg1"))
	enc2, _ := aliceCipher.Encrypt(testDistributionID, []byte("msg2"))
	enc3, _ := aliceCipher.Encrypt(testDistributionID, []byte("msg3"))

	// Simulate network transfer
	toReceived := func(enc protocol.CiphertextMessage) *protocol.SenderKeyMessage {
		skm := enc.(*protocol.SenderKeyMessage)
		signedBytes, _ := skm.SignedSerialize()
		received, _ := protocol.NewSenderKeyMessageFromBytes(signedBytes, serializer.SenderKeyMessage)
		return received
	}

	r1 := toReceived(enc1)
	r2 := toReceived(enc2)
	r3 := toReceived(enc3)

	// Decrypt out of order: 3, 1, 2
	dec3, err := bobCipher.Decrypt(r3)
	if err != nil {
		t.Fatalf("Decrypt(msg3) error: %v", err)
	}
	if string(dec3) != "msg3" {
		t.Errorf("Decrypt(msg3) = %q, want %q", string(dec3), "msg3")
	}

	dec1, err := bobCipher.Decrypt(r1)
	if err != nil {
		t.Fatalf("Decrypt(msg1) error: %v", err)
	}
	if string(dec1) != "msg1" {
		t.Errorf("Decrypt(msg1) = %q, want %q", string(dec1), "msg1")
	}

	dec2, err := bobCipher.Decrypt(r2)
	if err != nil {
		t.Fatalf("Decrypt(msg2) error: %v", err)
	}
	if string(dec2) != "msg2" {
		t.Errorf("Decrypt(msg2) = %q, want %q", string(dec2), "msg2")
	}
}

// failingSenderKeyMessageSerializer is a serializer that fails on Serialize
// but delegates Deserialize to a real serializer. This is used to trigger
// the error path in verifySignature where Serialize returns an error.
type failingSenderKeyMessageSerializer struct {
	real protocol.SenderKeyMessageSerializer
}

func (f *failingSenderKeyMessageSerializer) Serialize(msg *protocol.SenderKeyMessageStructure) ([]byte, error) {
	return nil, errors.New("forced serialization error")
}

func (f *failingSenderKeyMessageSerializer) Deserialize(serialized []byte) (*protocol.SenderKeyMessageStructure, error) {
	return f.real.Deserialize(serialized)
}

func TestGroupCipherDecryptMismatchedKeyID(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	groupID := testGroupID()

	// Alice creates and encrypts
	aliceStore := newInMemorySenderKeyStore()
	aliceBuilder := NewGroupSessionBuilder(aliceStore, serializer)
	aliceAddress := protocol.NewSignalAddress("alice", 1)
	senderKeyName := protocol.NewSenderKeyName(groupID, aliceAddress)

	skdm, err := aliceBuilder.Create(testDistributionID, senderKeyName)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	defer skdm.Release()
	aliceCipher := NewGroupCipher(aliceBuilder, senderKeyName, aliceStore)

	// Bob processes Alice's SKDM (so Bob has a non-empty record)
	bobStore := newInMemorySenderKeyStore()
	bobBuilder := NewGroupSessionBuilder(bobStore, serializer)
	skdmBytes, _ := skdm.Serialize()
	receivedSkdm, _ := protocol.NewSenderKeyDistributionMessageFromBytes(skdmBytes, serializer.SenderKeyDistributionMessage)
	defer receivedSkdm.Release()
	if err := bobBuilder.Process(senderKeyName, receivedSkdm); err != nil {
		t.Fatalf("Process() error: %v", err)
	}
	bobCipher := NewGroupCipher(bobBuilder, senderKeyName, bobStore)

	// Encrypt a message with Alice
	enc, err := aliceCipher.Encrypt(testDistributionID, []byte("test"))
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	// Construct a message with a different key ID that won't match
	// any state in Bob's record.
	skm := enc.(*protocol.SenderKeyMessage)
	wrongKeyIDStruct := &protocol.SenderKeyMessageStructure{
		DistributionID: testDistributionID,
		ID:             skm.KeyID() + 999, // wrong key ID
		Iteration:      skm.Iteration(),
		CipherText:     skm.Ciphertext(),
		Version:        protocol.SenderKeyCurrentVersion,
		Signature:      make([]byte, 64),
	}
	wrongKeyIDMsg, err := protocol.NewSenderKeyMessageFromStruct(wrongKeyIDStruct, serializer.SenderKeyMessage)
	if err != nil {
		t.Fatalf("NewSenderKeyMessageFromStruct() error: %v", err)
	}

	// Decrypt should fail with GetSenderKeyStateByID error
	_, err = bobCipher.Decrypt(wrongKeyIDMsg)
	if err == nil {
		t.Error("Decrypt with mismatched key ID should return error")
	}
}

func TestGroupCipherDecryptSerializeError(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	groupID := testGroupID()

	// Alice creates and encrypts
	aliceStore := newInMemorySenderKeyStore()
	aliceBuilder := NewGroupSessionBuilder(aliceStore, serializer)
	aliceAddress := protocol.NewSignalAddress("alice", 1)
	senderKeyName := protocol.NewSenderKeyName(groupID, aliceAddress)

	skdm, err := aliceBuilder.Create(testDistributionID, senderKeyName)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	defer skdm.Release()
	aliceCipher := NewGroupCipher(aliceBuilder, senderKeyName, aliceStore)

	// Bob processes Alice's SKDM
	bobStore := newInMemorySenderKeyStore()
	bobBuilder := NewGroupSessionBuilder(bobStore, serializer)
	skdmBytes, _ := skdm.Serialize()
	receivedSkdm, _ := protocol.NewSenderKeyDistributionMessageFromBytes(skdmBytes, serializer.SenderKeyDistributionMessage)
	defer receivedSkdm.Release()
	if err := bobBuilder.Process(senderKeyName, receivedSkdm); err != nil {
		t.Fatalf("Process() error: %v", err)
	}
	bobCipher := NewGroupCipher(bobBuilder, senderKeyName, bobStore)

	// Encrypt a valid message
	enc, err := aliceCipher.Encrypt(testDistributionID, []byte("test"))
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	// Create a SenderKeyMessage that uses a failing serializer.
	// When verifySignature calls Serialize(), it will fail.
	skm := enc.(*protocol.SenderKeyMessage)
	failingSerializer := &failingSenderKeyMessageSerializer{real: serializer.SenderKeyMessage}
	badMsg, err := protocol.NewSenderKeyMessageFromStruct(
		&protocol.SenderKeyMessageStructure{
			DistributionID: testDistributionID,
			ID:             skm.KeyID(),
			Iteration:      skm.Iteration(),
			CipherText:     skm.Ciphertext(),
			Version:        protocol.SenderKeyCurrentVersion,
			Signature:      make([]byte, 64),
		},
		failingSerializer,
	)
	if err != nil {
		t.Fatalf("NewSenderKeyMessageFromStruct() error: %v", err)
	}

	// Decrypt should fail because verifySignature cannot serialize the message
	_, err = bobCipher.Decrypt(badMsg)
	if err == nil {
		t.Error("Decrypt with failing serializer should return error")
	}
}

func TestGroupCipherEncryptNilStore(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	builder := NewGroupSessionBuilder(newInMemorySenderKeyStore(), serializer)
	address := protocol.NewSignalAddress("alice", 1)
	senderKeyName := protocol.NewSenderKeyName(testGroupID(), address)

	cipher := NewGroupCipher(builder, senderKeyName, nil)

	_, err := cipher.Encrypt(testDistributionID, []byte("test"))
	if err == nil {
		t.Fatal("Encrypt with nil store should return error")
	}
	if !errors.Is(err, ErrNilSenderKeyStore) {
		t.Errorf("Encrypt error = %v, want ErrNilSenderKeyStore", err)
	}
}

func TestGroupCipherDecryptNilStore(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	groupID := testGroupID()

	// Create a valid encrypted message from Alice
	aliceStore := newInMemorySenderKeyStore()
	aliceBuilder := NewGroupSessionBuilder(aliceStore, serializer)
	aliceAddress := protocol.NewSignalAddress("alice", 1)
	senderKeyName := protocol.NewSenderKeyName(groupID, aliceAddress)

	created, err := aliceBuilder.Create(testDistributionID, senderKeyName)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	defer created.Release()
	aliceCipher := NewGroupCipher(aliceBuilder, senderKeyName, aliceStore)

	enc, err := aliceCipher.Encrypt(testDistributionID, []byte("test"))
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}
	skm := enc.(*protocol.SenderKeyMessage)
	signedBytes, err := skm.SignedSerialize()
	if err != nil {
		t.Fatalf("SignedSerialize() error: %v", err)
	}
	received, err := protocol.NewSenderKeyMessageFromBytes(signedBytes, serializer.SenderKeyMessage)
	if err != nil {
		t.Fatalf("NewSenderKeyMessageFromBytes() error: %v", err)
	}

	// Bob has nil store
	bobBuilder := NewGroupSessionBuilder(newInMemorySenderKeyStore(), serializer)
	bobCipher := NewGroupCipher(bobBuilder, senderKeyName, nil)

	_, err = bobCipher.Decrypt(received)
	if err == nil {
		t.Fatal("Decrypt with nil store should return error")
	}
	if !errors.Is(err, ErrNilSenderKeyStore) {
		t.Errorf("Decrypt error = %v, want ErrNilSenderKeyStore", err)
	}
}

func TestGroupCipherDecryptTooFarInFutureErrorType(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	groupID := testGroupID()

	aliceStore := newInMemorySenderKeyStore()
	aliceBuilder := NewGroupSessionBuilder(aliceStore, serializer)
	aliceAddress := protocol.NewSignalAddress("alice", 1)
	senderKeyName := protocol.NewSenderKeyName(groupID, aliceAddress)

	skdm, err := aliceBuilder.Create(testDistributionID, senderKeyName)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	defer skdm.Release()

	aliceCipher := NewGroupCipher(aliceBuilder, senderKeyName, aliceStore)

	bobStore := newInMemorySenderKeyStore()
	bobBuilder := NewGroupSessionBuilder(bobStore, serializer)
	skdmBytes, _ := skdm.Serialize()
	receivedSkdm, _ := protocol.NewSenderKeyDistributionMessageFromBytes(skdmBytes, serializer.SenderKeyDistributionMessage)
	defer receivedSkdm.Release()
	if err := bobBuilder.Process(senderKeyName, receivedSkdm); err != nil {
		t.Fatalf("Process() error: %v", err)
	}
	bobCipher := NewGroupCipher(bobBuilder, senderKeyName, bobStore)

	// Encrypt 25002 messages so the chain advances past 25000
	for i := 0; i < 25002; i++ {
		_, err := aliceCipher.Encrypt(testDistributionID, []byte("msg"))
		if err != nil {
			t.Fatalf("Encrypt(%d) error: %v", i, err)
		}
	}

	enc, err := aliceCipher.Encrypt(testDistributionID, []byte("far future"))
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}
	skm := enc.(*protocol.SenderKeyMessage)
	signedBytes, _ := skm.SignedSerialize()
	received, _ := protocol.NewSenderKeyMessageFromBytes(signedBytes, serializer.SenderKeyMessage)

	_, err = bobCipher.Decrypt(received)
	if err == nil {
		t.Fatal("Decrypt with message >25000 into the future should return error")
	}
	if !errors.Is(err, ErrTooManyFutureMessages) {
		t.Errorf("Decrypt error = %v, want ErrTooManyFutureMessages", err)
	}
}

func TestGroupCipherDecryptDuplicateMessageErrorType(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	groupID := testGroupID()

	aliceStore := newInMemorySenderKeyStore()
	aliceBuilder := NewGroupSessionBuilder(aliceStore, serializer)
	aliceAddress := protocol.NewSignalAddress("alice", 1)
	senderKeyName := protocol.NewSenderKeyName(groupID, aliceAddress)

	skdm, err := aliceBuilder.Create(testDistributionID, senderKeyName)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	defer skdm.Release()

	aliceCipher := NewGroupCipher(aliceBuilder, senderKeyName, aliceStore)

	bobStore := newInMemorySenderKeyStore()
	bobBuilder := NewGroupSessionBuilder(bobStore, serializer)
	skdmBytes, _ := skdm.Serialize()
	receivedSkdm, _ := protocol.NewSenderKeyDistributionMessageFromBytes(skdmBytes, serializer.SenderKeyDistributionMessage)
	defer receivedSkdm.Release()
	if err := bobBuilder.Process(senderKeyName, receivedSkdm); err != nil {
		t.Fatalf("Process() error: %v", err)
	}
	bobCipher := NewGroupCipher(bobBuilder, senderKeyName, bobStore)

	enc, _ := aliceCipher.Encrypt(testDistributionID, []byte("hello"))
	skm := enc.(*protocol.SenderKeyMessage)
	signedBytes, _ := skm.SignedSerialize()
	received1, _ := protocol.NewSenderKeyMessageFromBytes(signedBytes, serializer.SenderKeyMessage)
	received2, _ := protocol.NewSenderKeyMessageFromBytes(signedBytes, serializer.SenderKeyMessage)

	_, err = bobCipher.Decrypt(received1)
	if err != nil {
		t.Fatalf("First Decrypt() error: %v", err)
	}

	_, err = bobCipher.Decrypt(received2)
	if err == nil {
		t.Fatal("Decrypting duplicate message should return error")
	}
	if !errors.Is(err, ErrOldCounter) {
		t.Errorf("Decrypt error = %v, want ErrOldCounter", err)
	}
}

func TestGroupCipherDecryptInvalidSignatureErrorType(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	groupID := testGroupID()

	aliceStore := newInMemorySenderKeyStore()
	aliceBuilder := NewGroupSessionBuilder(aliceStore, serializer)
	aliceAddress := protocol.NewSignalAddress("alice", 1)
	senderKeyName := protocol.NewSenderKeyName(groupID, aliceAddress)

	skdm, err := aliceBuilder.Create(testDistributionID, senderKeyName)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	defer skdm.Release()
	aliceCipher := NewGroupCipher(aliceBuilder, senderKeyName, aliceStore)

	bobStore := newInMemorySenderKeyStore()
	bobBuilder := NewGroupSessionBuilder(bobStore, serializer)
	skdmBytes, _ := skdm.Serialize()
	receivedSkdm, _ := protocol.NewSenderKeyDistributionMessageFromBytes(skdmBytes, serializer.SenderKeyDistributionMessage)
	defer receivedSkdm.Release()
	if err := bobBuilder.Process(senderKeyName, receivedSkdm); err != nil {
		t.Fatalf("Process() error: %v", err)
	}
	bobCipher := NewGroupCipher(bobBuilder, senderKeyName, bobStore)

	enc, err := aliceCipher.Encrypt(testDistributionID, []byte("test"))
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	skm := enc.(*protocol.SenderKeyMessage)
	signedBytes, _ := skm.SignedSerialize()

	tamperedStruct := &protocol.SenderKeyMessageStructure{
		DistributionID: testDistributionID,
		ID:             skm.KeyID(),
		Iteration:      skm.Iteration(),
		CipherText:     append([]byte{0xFF}, skm.Ciphertext()...),
		Version:        protocol.SenderKeyCurrentVersion,
		Signature:      signedBytes[len(signedBytes)-64:],
	}
	tampered, err := protocol.NewSenderKeyMessageFromStruct(tamperedStruct, serializer.SenderKeyMessage)
	if err != nil {
		t.Fatalf("NewSenderKeyMessageFromStruct() error: %v", err)
	}

	_, err = bobCipher.Decrypt(tampered)
	if err == nil {
		t.Fatal("Decrypt with invalid signature should return error")
	}
	if !errors.Is(err, ErrSignatureVerification) {
		t.Errorf("Decrypt error = %v, want ErrSignatureVerification", err)
	}
}

func TestErrorMessages(t *testing.T) {
	tests := []struct {
		name     string
		err      *Error
		contains string
	}{
		{
			name:     "nil sender key store",
			err:      ErrNilSenderKeyStore,
			contains: "nil sender key store",
		},
		{
			name:     "nil sender key record",
			err:      ErrNilSenderKeyRecord,
			contains: "nil sender key record",
		},
		{
			name:     "nil sender key state",
			err:      ErrNilSenderKeyState,
			contains: "nil sender key state",
		},
		{
			name:     "no sender key",
			err:      newNoSenderKeyError("test-group-abc"),
			contains: "no sender key for: test-group-abc",
		},
		{
			name:     "no sender key for ID",
			err:      ErrNoSenderKeyForID,
			contains: "no sender key for ID",
		},
		{
			name:     "invalid sender key session",
			err:      ErrInvalidSenderKeySession,
			contains: "invalid sender key session",
		},
		{
			name:     "signature verification",
			err:      ErrSignatureVerification,
			contains: "signature verification",
		},
		{
			name:     "too many future messages",
			err:      ErrTooManyFutureMessages,
			contains: "over 25000 messages",
		},
		{
			name:     "old counter",
			err:      newOldCounterError(10, 5),
			contains: "old counter: chain=10, message=5",
		},
		{
			name:     "unknown error kind",
			err:      &Error{kind: errorKind(999)},
			contains: "unknown error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			if msg == "" {
				t.Fatal("Error() returned empty string")
			}
			if !contains(msg, tt.contains) {
				t.Errorf("Error() = %q, want substring %q", msg, tt.contains)
			}
		})
	}
}

// contains checks if s contains substr (avoids importing strings package).
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestErrorIsNonErrorTarget(t *testing.T) {
	err := ErrNilSenderKeyStore
	// errors.Is with a non-*Error target should return false
	if errors.Is(err, errors.New("some other error")) {
		t.Error("Is() should return false for non-*Error target")
	}
}

func TestErrorIsMatchesKind(t *testing.T) {
	// A concrete error with extra fields should match its sentinel by kind
	concrete := newOldCounterError(50, 3)
	if !errors.Is(concrete, ErrOldCounter) {
		t.Error("concrete old counter error should match ErrOldCounter sentinel")
	}

	concrete2 := newNoSenderKeyError("group-xyz")
	if !errors.Is(concrete2, ErrNoSenderKey) {
		t.Error("concrete no sender key error should match ErrNoSenderKey sentinel")
	}
}

func TestErrorIsMismatchedKind(t *testing.T) {
	if errors.Is(ErrNilSenderKeyStore, ErrNilSenderKeyRecord) {
		t.Error("Is() should return false for different error kinds")
	}
}

// TestDecryptUsesDistributionIDFromMessage verifies that Decrypt uses the
// distribution_id embedded in the SenderKeyMessage for the store lookup,
// matching the Rust reference group_decrypt behavior. A message encrypted
// with distribution_id A must be looked up in the store under the group ID
// derived from distribution_id A, regardless of what group ID the
// GroupCipher was constructed with.
func TestDecryptUsesDistributionIDFromMessage(t *testing.T) {
	serializer := serialize.NewJSONSerializer()

	distA := [16]byte{0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44,
		0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xAA, 0xBB}
	groupIDA := distributionIDToGroupID(distA)

	aliceAddress := protocol.NewSignalAddress("alice", 1)
	senderKeyNameA := protocol.NewSenderKeyName(groupIDA, aliceAddress)

	// Alice: create session and encrypt under distribution A
	aliceStore := newInMemorySenderKeyStore()
	aliceBuilder := NewGroupSessionBuilder(aliceStore, serializer)
	skdm, err := aliceBuilder.Create(distA, senderKeyNameA)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	defer skdm.Release()
	aliceCipher := NewGroupCipher(aliceBuilder, senderKeyNameA, aliceStore)

	plaintext := []byte("message for distribution A")
	enc, err := aliceCipher.Encrypt(distA, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	// Bob: process SKDM under the correct group ID derived from distA
	bobStore := newInMemorySenderKeyStore()
	bobBuilder := NewGroupSessionBuilder(bobStore, serializer)
	skdmBytes, _ := skdm.Serialize()
	receivedSkdm, _ := protocol.NewSenderKeyDistributionMessageFromBytes(
		skdmBytes, serializer.SenderKeyDistributionMessage)
	defer receivedSkdm.Release()
	if err := bobBuilder.Process(senderKeyNameA, receivedSkdm); err != nil {
		t.Fatal(err)
	}

	// Bob's cipher is constructed with a DIFFERENT group ID string ("wrong-group"),
	// but Decrypt should still succeed because it uses the distribution ID
	// from the message (distA) to derive the store lookup key.
	wrongName := protocol.NewSenderKeyName("wrong-group", aliceAddress)
	bobCipher := NewGroupCipher(bobBuilder, wrongName, bobStore)

	// Simulate network transfer
	skm := enc.(*protocol.SenderKeyMessage)
	signedBytes, _ := skm.SignedSerialize()
	received, _ := protocol.NewSenderKeyMessageFromBytes(signedBytes, serializer.SenderKeyMessage)

	// Verify the message carries distribution A
	if received.DistributionID() != distA {
		t.Fatalf("message distribution ID = %x, want %x",
			received.DistributionID(), distA)
	}

	// Decrypt must succeed using the message's distribution ID, not "wrong-group"
	decrypted, err := bobCipher.Decrypt(received)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypt() = %q, want %q", string(decrypted), string(plaintext))
	}
}

// TestDecryptNoRecordForDistributionID verifies that Decrypt returns
// ErrNilSenderKeyRecord when the store has no record for the distribution
// ID embedded in the message, even if a record exists for the group ID
// the cipher was constructed with.
func TestDecryptNoRecordForDistributionID(t *testing.T) {
	serializer := serialize.NewJSONSerializer()

	distA := [16]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00}
	groupIDA := distributionIDToGroupID(distA)

	aliceAddress := protocol.NewSignalAddress("alice", 1)
	senderKeyNameA := protocol.NewSenderKeyName(groupIDA, aliceAddress)

	// Alice: create session and encrypt under distribution A
	aliceStore := newInMemorySenderKeyStore()
	aliceBuilder := NewGroupSessionBuilder(aliceStore, serializer)
	created, err := aliceBuilder.Create(distA, senderKeyNameA)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	defer created.Release()
	aliceCipher := NewGroupCipher(aliceBuilder, senderKeyNameA, aliceStore)

	enc, err := aliceCipher.Encrypt(distA, []byte("test"))
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	// Bob: has a session for distribution B (different from A) but NOT for A.
	distB := [16]byte{0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
		0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00}
	groupIDB := distributionIDToGroupID(distB)
	senderKeyNameB := protocol.NewSenderKeyName(groupIDB, aliceAddress)

	bobStore := newInMemorySenderKeyStore()
	bobBuilder := NewGroupSessionBuilder(bobStore, serializer)

	// Create a session for distribution B so the store is not empty
	createdB, err := bobBuilder.Create(distB, senderKeyNameB)
	if err != nil {
		t.Fatalf("Create(distB) error: %v", err)
	}
	defer createdB.Release()

	// Bob's cipher is constructed with the B group ID
	bobCipher := NewGroupCipher(bobBuilder, senderKeyNameB, bobStore)

	// Simulate network transfer of Alice's message (which carries distA)
	skm := enc.(*protocol.SenderKeyMessage)
	signedBytes, _ := skm.SignedSerialize()
	received, _ := protocol.NewSenderKeyMessageFromBytes(signedBytes, serializer.SenderKeyMessage)

	// Decrypt must fail because the store has no record for distribution A
	_, err = bobCipher.Decrypt(received)
	if err == nil {
		t.Fatal("Decrypt should fail when store has no record for message's distribution ID")
	}
	if !errors.Is(err, ErrNilSenderKeyRecord) {
		t.Errorf("Decrypt error = %v, want ErrNilSenderKeyRecord", err)
	}
}

// TestDistributionIDToGroupID verifies the UUID formatting helper.
func TestDistributionIDToGroupID(t *testing.T) {
	tests := []struct {
		name string
		id   [16]byte
		want string
	}{
		{
			name: "all zeros",
			id:   [16]byte{},
			want: "00000000-0000-0000-0000-000000000000",
		},
		{
			name: "sequential bytes",
			id:   [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			want: "01020304-0506-0708-090a-0b0c0d0e0f10",
		},
		{
			name: "all 0xFF",
			id:   [16]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			want: "ffffffff-ffff-ffff-ffff-ffffffffffff",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := distributionIDToGroupID(tt.id)
			if got != tt.want {
				t.Errorf("distributionIDToGroupID() = %q, want %q", got, tt.want)
			}
		})
	}
}
