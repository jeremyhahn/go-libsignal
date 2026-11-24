// Package groups is responsible for setting up group SenderKey encrypted sessions.
// Once a session has been established, GroupCipher can be used to encrypt/decrypt
// messages in that session.
//
// The built sessions are unidirectional: they can be used either for sending or
// for receiving, but not both. Sessions are constructed per (groupId + senderId +
// deviceId) tuple. Remote logical users are identified by their senderId, and each
// logical recipientId can have multiple physical devices.
package groups

import (
	"github.com/jeremyhahn/go-libsignal/pkg/groups/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/groups/state/store"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"github.com/jeremyhahn/go-libsignal/pkg/util/keyhelper"
)

// NewGroupSessionBuilder will return a new group session builder.
func NewGroupSessionBuilder(senderKeyStore store.SenderKey,
	serializer *serialize.Serializer) *SessionBuilder {

	return &SessionBuilder{
		senderKeyStore: senderKeyStore,
		serializer:     serializer,
	}
}

// SessionBuilder is a structure for building group sessions.
type SessionBuilder struct {
	senderKeyStore store.SenderKey
	serializer     *serialize.Serializer
}

// Process will process an incoming group message and set up the corresponding
// session for it.
func (b *SessionBuilder) Process(senderKeyName *protocol.SenderKeyName,
	msg *protocol.SenderKeyDistributionMessage) error {

	senderKeyRecord, err := b.senderKeyStore.LoadSenderKey(senderKeyName)
	if err != nil {
		return err
	}
	if senderKeyRecord == nil {
		senderKeyRecord = record.NewSenderKey(b.serializer.SenderKeyRecord, b.serializer.SenderKeyState)
	}
	// ChainKey returns an owned plaintext copy. The receiver state copies it
	// into locked memory, so wipe this copy once the state is built.
	chainKey := distributionChainKey(msg)
	defer crypto.Zeroize(chainKey)
	senderKeyRecord.AddSenderKeyState(msg.Version(), msg.ID(), msg.Iteration(), chainKey, msg.SignatureKey())
	return b.senderKeyStore.StoreSenderKey(senderKeyName, senderKeyRecord)
}

// distributionChainKey returns the owned chain key copy Process wipes. It is
// a variable so tests can observe that the copy is wiped.
var distributionChainKey = func(msg *protocol.SenderKeyDistributionMessage) []byte {
	return msg.ChainKey()
}

// Create will create a new group session for the given name.
// The distributionID identifies the SenderKey distribution for routing.
// The returned message holds the chain key seed in locked memory, which the
// garbage collector never frees; the caller must call its Release once it has
// been serialized and sent.
func (b *SessionBuilder) Create(distributionID [16]byte, senderKeyName *protocol.SenderKeyName) (*protocol.SenderKeyDistributionMessage, error) {
	// Load the senderkey by name
	senderKeyRecord, err := b.senderKeyStore.LoadSenderKey(senderKeyName)
	if err != nil {
		return nil, err
	}

	// If the record is empty, generate new keys.
	if senderKeyRecord == nil || senderKeyRecord.IsEmpty() {
		senderKeyRecord = record.NewSenderKey(b.serializer.SenderKeyRecord, b.serializer.SenderKeyState)
		signingKey, err := keyhelper.GenerateSenderSigningKey()
		if err != nil {
			return nil, err
		}
		senderKey, err := keyhelper.GenerateSenderKey()
		if err != nil {
			return nil, err
		}
		senderKeyRecord.SetSenderKeyState(
			protocol.SenderKeyCurrentVersion,
			keyhelper.GenerateSenderKeyID(), 0,
			senderKey,
			signingKey,
		)
		if err := b.senderKeyStore.StoreSenderKey(senderKeyName, senderKeyRecord); err != nil {
			return nil, err
		}
	}

	// Get the senderkey state.
	state, err := senderKeyRecord.SenderKeyState()
	if err != nil {
		return nil, err
	}

	// Create the group message to return. The seed goes to the message as a
	// locked clone, never as a heap copy; the caller calls Release on it.
	chainKey := state.SenderChainKey()
	seed, err := chainKey.SeedSecret()
	if err != nil {
		return nil, err
	}
	senderKeyDistributionMessage := protocol.NewSenderKeyDistributionMessageFromSecret(
		distributionID,
		state.KeyID(),
		chainKey.Iteration(),
		seed,
		state.SigningKey().PublicKey(),
		b.serializer.SenderKeyDistributionMessage,
		protocol.SenderKeyCurrentVersion,
	)

	return senderKeyDistributionMessage, nil
}
