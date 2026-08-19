package tests

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

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

// uuidFromName derives a deterministic UUID-format string from an arbitrary
// name. This ensures test addresses pass ServiceId validation, which is required
// by SerializeAddresses when address binding is in effect (proto field 6).
func uuidFromName(name string) string {
	h := sha256.Sum256([]byte(name))
	b := h[:16]
	// Force RFC 4122 version 4 and variant bits for a well-formed UUID.
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	s := hex.EncodeToString(b)
	return fmt.Sprintf("%s-%s-%s-%s-%s", s[0:8], s[8:12], s[12:16], s[16:20], s[20:32])
}

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
		u.kyberPreKey.PublicKey(),
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
		if err := signalUser.preKeyStore.StorePreKey(
			signalUser.preKeys[i].ID().Value,
			record.NewPreKey(signalUser.preKeys[i].ID().Value, signalUser.preKeys[i].KeyPair(), serializer.PreKeyRecord),
		); err != nil {
			panic(err)
		}
	}

	// Store our own signed prekey
	if err := signalUser.signedPreKeyStore.StoreSignedPreKey(
		signalUser.signedPreKey.ID(),
		record.NewSignedPreKey(
			signalUser.signedPreKey.ID(),
			signalUser.signedPreKey.Timestamp(),
			signalUser.signedPreKey.KeyPair(),
			signalUser.signedPreKey.Signature(),
			serializer.SignedPreKeyRecord,
		),
	); err != nil {
		panic(err)
	}

	// Store our Kyber pre-key.
	if err := signalUser.kyberPreKeyStore.StoreKyberPreKey(42, signalUser.kyberPreKey); err != nil {
		panic(err)
	}

	// Create a remote address that we'll be building our session with.
	// Convert the human-readable name to a UUID-format string so that
	// SerializeAddresses (proto field 6 address binding) succeeds for all
	// test scenarios that supply both local and remote addresses to the cipher.
	signalUser.name = name
	signalUser.deviceID = deviceID
	signalUser.address = protocol.NewSignalAddress(uuidFromName(name), deviceID)

	// Create a group session builder
	signalUser.buildGroupSession(serializer)

	return signalUser
}
