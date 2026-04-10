package tests

import (
	"github.com/jeremyhahn/go-libsignal/pkg/groups"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/prekey"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/session"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/util/keyhelper"
	"github.com/jeremyhahn/go-libsignal/pkg/util/optional"
)

// user is a structure for a signal user.
type user struct {
	name     string
	deviceID uint32
	address  *protocol.SignalAddress

	identityKeyPair *identity.KeyPair
	registrationID  uint32

	preKeys      []*record.PreKey
	signedPreKey *record.SignedPreKey
	kyberPreKey  *record.KyberPreKey

	sessionStore      *InMemorySession
	preKeyStore       *InMemoryPreKey
	signedPreKeyStore *InMemorySignedPreKey
	identityStore     *InMemoryIdentityKey
	senderKeyStore    *InMemorySenderKey
	kyberPreKeyStore  *InMemoryKyberPreKey

	sessionBuilder *session.Builder
	groupBuilder   *groups.SessionBuilder
}

// buildSession will build a session with the given address using
// NewBuilderWithKyber for PQXDH support.
func (u *user) buildSession(address *protocol.SignalAddress, serializer *serialize.Serializer) {
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

// kyberBundle creates a PreKeyBundle with Kyber keys included for PQXDH.
func (u *user) kyberBundle() *prekey.Bundle {
	return prekey.NewBundleWithKyber(
		u.registrationID,
		u.deviceID,
		u.preKeys[0].ID(),
		u.signedPreKey.ID(),
		u.preKeys[0].KeyPair().PublicKey(),
		u.signedPreKey.KeyPair().PublicKey(),
		u.signedPreKey.Signature(),
		u.identityKeyPair.PublicKey(),
		&optional.Uint32{Value: 42},
		u.kyberPreKey.KeyPair().Public,
		u.kyberPreKey.Signature(),
	)
}

// buildGroupSession will build a group session using sender keys.
func (u *user) buildGroupSession(serializer *serialize.Serializer) {
	u.groupBuilder = groups.NewGroupSessionBuilder(u.senderKeyStore, serializer)
}

// newUser creates a new signal user for session testing.
func newUser(name string, deviceID uint32, serializer *serialize.Serializer) *user {
	signalUser := &user{}

	// Generate an identity keypair
	signalUser.identityKeyPair, _ = keyhelper.GenerateIdentityKeyPair()

	// Generate a registration id
	signalUser.registrationID = keyhelper.GenerateRegistrationID()

	// Generate PreKeys
	signalUser.preKeys, _ = keyhelper.GeneratePreKeys(0, 100, serializer.PreKeyRecord)

	// Generate Signed PreKey
	signalUser.signedPreKey, _ = keyhelper.GenerateSignedPreKey(signalUser.identityKeyPair, 0, serializer.SignedPreKeyRecord)

	// Generate Kyber Pre-Key for PQXDH support.
	signalUser.kyberPreKey, _ = keyhelper.GenerateKyberPreKey(signalUser.identityKeyPair.PrivateKey(), 42, &mockKyberPreKeySerializer{})

	// Create all our record stores using an in-memory implementation.
	signalUser.sessionStore = NewInMemorySession(serializer)
	signalUser.preKeyStore = NewInMemoryPreKey()
	signalUser.signedPreKeyStore = NewInMemorySignedPreKey()
	signalUser.identityStore = NewInMemoryIdentityKey(signalUser.identityKeyPair, signalUser.registrationID)
	signalUser.senderKeyStore = NewInMemorySenderKey()
	signalUser.kyberPreKeyStore = NewInMemoryKyberPreKey()

	// Put all our pre keys in our local stores.
	for i := range signalUser.preKeys {
		signalUser.preKeyStore.StorePreKey(
			signalUser.preKeys[i].ID().Value,
			record.NewPreKey(signalUser.preKeys[i].ID().Value, signalUser.preKeys[i].KeyPair(), serializer.PreKeyRecord),
		)
	}

	// Store our own signed prekey
	signalUser.signedPreKeyStore.StoreSignedPreKey(
		signalUser.signedPreKey.ID(),
		record.NewSignedPreKey(
			signalUser.signedPreKey.ID(),
			signalUser.signedPreKey.Timestamp(),
			signalUser.signedPreKey.KeyPair(),
			signalUser.signedPreKey.Signature(),
			serializer.SignedPreKeyRecord,
		),
	)

	// Store our Kyber pre-key.
	if err := signalUser.kyberPreKeyStore.StoreKyberPreKey(42, signalUser.kyberPreKey); err != nil {
		panic(err)
	}

	// Create a remote address that we'll be building our session with.
	signalUser.name = name
	signalUser.deviceID = deviceID
	signalUser.address = protocol.NewSignalAddress(name, deviceID)

	// Create a group session builder
	signalUser.buildGroupSession(serializer)

	return signalUser
}
