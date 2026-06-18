package tests

import (
	"fmt"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	groupRecord "github.com/jeremyhahn/go-libsignal/pkg/groups/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/state/store"
)

// Define some in-memory stores for testing.

// NewInMemoryIdentityKey returns an in-memory IdentityKey store populated
// with the given identity key pair and local registration ID.
func NewInMemoryIdentityKey(identityKey *identity.KeyPair, localRegistrationID uint32) *InMemoryIdentityKey {
	return &InMemoryIdentityKey{
		trustedKeys:         make(map[*protocol.SignalAddress]*identity.Key),
		identityKeyPair:     identityKey,
		localRegistrationID: localRegistrationID,
	}
}

type InMemoryIdentityKey struct {
	trustedKeys         map[*protocol.SignalAddress]*identity.Key
	identityKeyPair     *identity.KeyPair
	localRegistrationID uint32
}

func (i *InMemoryIdentityKey) GetIdentityKeyPair() *identity.KeyPair {
	return i.identityKeyPair
}

func (i *InMemoryIdentityKey) GetLocalRegistrationId() uint32 {
	return i.localRegistrationID
}

func (i *InMemoryIdentityKey) SaveIdentity(address *protocol.SignalAddress, identityKey *identity.Key) (store.IdentityChange, error) {
	prev, existed := i.trustedKeys[address]
	i.trustedKeys[address] = identityKey
	if existed && prev != identityKey && prev.Fingerprint() != identityKey.Fingerprint() {
		return store.IdentityChangeReplacedExisting, nil
	}
	return store.IdentityChangeNewOrUnchanged, nil
}

func (i *InMemoryIdentityKey) IsTrustedIdentity(address *protocol.SignalAddress, identityKey *identity.Key, direction store.Direction) (bool, error) {
	trusted := i.trustedKeys[address]
	return (trusted == nil || trusted.Fingerprint() == identityKey.Fingerprint()), nil
}

func (i *InMemoryIdentityKey) GetIdentity(address *protocol.SignalAddress) (*identity.Key, error) {
	return i.trustedKeys[address], nil
}

// Compile-time interface check.
var _ store.IdentityKey = (*InMemoryIdentityKey)(nil)

// NewInMemoryPreKey returns an in-memory PreKey store.
func NewInMemoryPreKey() *InMemoryPreKey {
	return &InMemoryPreKey{
		store: make(map[uint32]*record.PreKey),
	}
}

type InMemoryPreKey struct {
	store map[uint32]*record.PreKey
}

func (i *InMemoryPreKey) LoadPreKey(preKeyID uint32) (*record.PreKey, error) {
	return i.store[preKeyID], nil
}

func (i *InMemoryPreKey) StorePreKey(preKeyID uint32, preKeyRecord *record.PreKey) error {
	i.store[preKeyID] = preKeyRecord
	return nil
}

func (i *InMemoryPreKey) ContainsPreKey(preKeyID uint32) (bool, error) {
	_, ok := i.store[preKeyID]
	return ok, nil
}

func (i *InMemoryPreKey) RemovePreKey(preKeyID uint32) error {
	delete(i.store, preKeyID)
	return nil
}

// Compile-time interface check.
var _ store.PreKey = (*InMemoryPreKey)(nil)

// NewInMemorySession returns an in-memory Session store using the provided serializer.
func NewInMemorySession(serializer *serialize.Serializer) *InMemorySession {
	return &InMemorySession{
		sessions:   make(map[*protocol.SignalAddress]*record.Session),
		serializer: serializer,
	}
}

type InMemorySession struct {
	sessions   map[*protocol.SignalAddress]*record.Session
	serializer *serialize.Serializer
}

func (i *InMemorySession) LoadSession(address *protocol.SignalAddress) (*record.Session, error) {
	ok, err := i.ContainsSession(address)
	if err != nil {
		return nil, err
	}
	if ok {
		return i.sessions[address], nil
	}
	sessionRecord := record.NewSession(i.serializer.Session, i.serializer.State)
	i.sessions[address] = sessionRecord
	return sessionRecord, nil
}

func (i *InMemorySession) GetSubDeviceSessions(name string) ([]uint32, error) {
	var deviceIDs []uint32
	for key := range i.sessions {
		if key.Name() == name && key.DeviceID() != 1 {
			deviceIDs = append(deviceIDs, key.DeviceID())
		}
	}
	return deviceIDs, nil
}

func (i *InMemorySession) StoreSession(remoteAddress *protocol.SignalAddress, record *record.Session) error {
	i.sessions[remoteAddress] = record
	return nil
}

func (i *InMemorySession) ContainsSession(remoteAddress *protocol.SignalAddress) (bool, error) {
	_, ok := i.sessions[remoteAddress]
	return ok, nil
}

func (i *InMemorySession) DeleteSession(remoteAddress *protocol.SignalAddress) error {
	delete(i.sessions, remoteAddress)
	return nil
}

func (i *InMemorySession) DeleteAllSessions() error {
	i.sessions = make(map[*protocol.SignalAddress]*record.Session)
	return nil
}

// Compile-time interface check.
var _ store.Session = (*InMemorySession)(nil)

// NewInMemorySignedPreKey returns an in-memory SignedPreKey store.
func NewInMemorySignedPreKey() *InMemorySignedPreKey {
	return &InMemorySignedPreKey{
		store: make(map[uint32]*record.SignedPreKey),
	}
}

type InMemorySignedPreKey struct {
	store map[uint32]*record.SignedPreKey
}

func (i *InMemorySignedPreKey) LoadSignedPreKey(signedPreKeyID uint32) (*record.SignedPreKey, error) {
	return i.store[signedPreKeyID], nil
}

func (i *InMemorySignedPreKey) LoadSignedPreKeys() ([]*record.SignedPreKey, error) {
	var preKeys []*record.SignedPreKey
	for _, record := range i.store {
		preKeys = append(preKeys, record)
	}
	return preKeys, nil
}

func (i *InMemorySignedPreKey) StoreSignedPreKey(signedPreKeyID uint32, record *record.SignedPreKey) error {
	i.store[signedPreKeyID] = record
	return nil
}

func (i *InMemorySignedPreKey) ContainsSignedPreKey(signedPreKeyID uint32) (bool, error) {
	_, ok := i.store[signedPreKeyID]
	return ok, nil
}

func (i *InMemorySignedPreKey) RemoveSignedPreKey(signedPreKeyID uint32) error {
	delete(i.store, signedPreKeyID)
	return nil
}

// Compile-time interface check.
var _ store.SignedPreKey = (*InMemorySignedPreKey)(nil)

func NewInMemorySenderKey() *InMemorySenderKey {
	return &InMemorySenderKey{
		store: make(map[string]*groupRecord.SenderKey),
	}
}

type InMemorySenderKey struct {
	store map[string]*groupRecord.SenderKey
}

// senderKeyNameKey returns a string key for map lookup based on the
// SenderKeyName's group ID and sender address, not pointer identity.
func senderKeyNameKey(name *protocol.SenderKeyName) string {
	return fmt.Sprintf("%s::%s::%d", name.GroupID(), name.Sender().Name(), name.Sender().DeviceID())
}

func (i *InMemorySenderKey) StoreSenderKey(senderKeyName *protocol.SenderKeyName, keyRecord *groupRecord.SenderKey) error {
	i.store[senderKeyNameKey(senderKeyName)] = keyRecord
	return nil
}

func (i *InMemorySenderKey) LoadSenderKey(senderKeyName *protocol.SenderKeyName) (*groupRecord.SenderKey, error) {
	return i.store[senderKeyNameKey(senderKeyName)], nil
}

// InMemoryKyberPreKey is an in-memory store for Kyber pre-keys.
type InMemoryKyberPreKey struct {
	store  map[uint32]*record.KyberPreKey
	marked map[uint32]bool
}

// NewInMemoryKyberPreKey creates a new in-memory Kyber pre-key store.
func NewInMemoryKyberPreKey() *InMemoryKyberPreKey {
	return &InMemoryKyberPreKey{
		store:  make(map[uint32]*record.KyberPreKey),
		marked: make(map[uint32]bool),
	}
}

// LoadKyberPreKey loads a Kyber pre-key by ID.
func (i *InMemoryKyberPreKey) LoadKyberPreKey(kyberPreKeyID uint32) (*record.KyberPreKey, error) {
	return i.store[kyberPreKeyID], nil
}

// StoreKyberPreKey stores a Kyber pre-key by ID.
func (i *InMemoryKyberPreKey) StoreKyberPreKey(kyberPreKeyID uint32, kyberPreKey *record.KyberPreKey) error {
	i.store[kyberPreKeyID] = kyberPreKey
	return nil
}

// MarkKyberPreKeyUsed marks a Kyber pre-key as used. The signedPreKeyID and
// baseKey parameters enable last-resort key replay detection in production
// implementations.
func (i *InMemoryKyberPreKey) MarkKyberPreKeyUsed(kyberPreKeyID uint32, _ uint32, _ ecc.ECPublicKeyable) error {
	i.marked[kyberPreKeyID] = true
	return nil
}

// ContainsKyberPreKey returns (true, nil) if the store contains a Kyber pre-key with the given ID.
func (i *InMemoryKyberPreKey) ContainsKyberPreKey(kyberPreKeyID uint32) (bool, error) {
	_, ok := i.store[kyberPreKeyID]
	return ok, nil
}

// Verify interface compliance.
var _ store.KyberPreKey = (*InMemoryKyberPreKey)(nil)

// mockKyberPreKeySerializer is a minimal serializer for KyberPreKey records.
type mockKyberPreKeySerializer struct{}

func (m *mockKyberPreKeySerializer) Serialize(_ *record.KyberPreKeyStructure) ([]byte, error) {
	return nil, nil
}

func (m *mockKyberPreKeySerializer) Deserialize(_ []byte) (*record.KyberPreKeyStructure, error) {
	return nil, nil
}
