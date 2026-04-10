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

// IdentityKeyStore
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

func (i *InMemoryIdentityKey) SaveIdentity(address *protocol.SignalAddress, identityKey *identity.Key) {
	i.trustedKeys[address] = identityKey
}

func (i *InMemoryIdentityKey) IsTrustedIdentity(address *protocol.SignalAddress, identityKey *identity.Key, direction store.Direction) bool {
	trusted := i.trustedKeys[address]
	return (trusted == nil || trusted.Fingerprint() == identityKey.Fingerprint())
}

func (i *InMemoryIdentityKey) GetIdentity(address *protocol.SignalAddress) (*identity.Key, error) {
	return i.trustedKeys[address], nil
}

// PreKeyStore
func NewInMemoryPreKey() *InMemoryPreKey {
	return &InMemoryPreKey{
		store: make(map[uint32]*record.PreKey),
	}
}

type InMemoryPreKey struct {
	store map[uint32]*record.PreKey
}

func (i *InMemoryPreKey) LoadPreKey(preKeyID uint32) *record.PreKey {
	return i.store[preKeyID]
}

func (i *InMemoryPreKey) StorePreKey(preKeyID uint32, preKeyRecord *record.PreKey) {
	i.store[preKeyID] = preKeyRecord
}

func (i *InMemoryPreKey) ContainsPreKey(preKeyID uint32) bool {
	_, ok := i.store[preKeyID]
	return ok
}

func (i *InMemoryPreKey) RemovePreKey(preKeyID uint32) {
	delete(i.store, preKeyID)
}

// SessionStore
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

func (i *InMemorySession) LoadSession(address *protocol.SignalAddress) *record.Session {
	if i.ContainsSession(address) {
		return i.sessions[address]
	}
	sessionRecord := record.NewSession(i.serializer.Session, i.serializer.State)
	i.sessions[address] = sessionRecord

	return sessionRecord
}

func (i *InMemorySession) GetSubDeviceSessions(name string) []uint32 {
	var deviceIDs []uint32

	for key := range i.sessions {
		if key.Name() == name && key.DeviceID() != 1 {
			deviceIDs = append(deviceIDs, key.DeviceID())
		}
	}

	return deviceIDs
}

func (i *InMemorySession) StoreSession(remoteAddress *protocol.SignalAddress, record *record.Session) {
	i.sessions[remoteAddress] = record
}

func (i *InMemorySession) ContainsSession(remoteAddress *protocol.SignalAddress) bool {
	_, ok := i.sessions[remoteAddress]
	return ok
}

func (i *InMemorySession) DeleteSession(remoteAddress *protocol.SignalAddress) {
	delete(i.sessions, remoteAddress)
}

func (i *InMemorySession) DeleteAllSessions() {
	i.sessions = make(map[*protocol.SignalAddress]*record.Session)
}

// SignedPreKeyStore
func NewInMemorySignedPreKey() *InMemorySignedPreKey {
	return &InMemorySignedPreKey{
		store: make(map[uint32]*record.SignedPreKey),
	}
}

type InMemorySignedPreKey struct {
	store map[uint32]*record.SignedPreKey
}

func (i *InMemorySignedPreKey) LoadSignedPreKey(signedPreKeyID uint32) *record.SignedPreKey {
	return i.store[signedPreKeyID]
}

func (i *InMemorySignedPreKey) LoadSignedPreKeys() []*record.SignedPreKey {
	var preKeys []*record.SignedPreKey

	for _, record := range i.store {
		preKeys = append(preKeys, record)
	}

	return preKeys
}

func (i *InMemorySignedPreKey) StoreSignedPreKey(signedPreKeyID uint32, record *record.SignedPreKey) {
	i.store[signedPreKeyID] = record
}

func (i *InMemorySignedPreKey) ContainsSignedPreKey(signedPreKeyID uint32) bool {
	_, ok := i.store[signedPreKeyID]
	return ok
}

func (i *InMemorySignedPreKey) RemoveSignedPreKey(signedPreKeyID uint32) {
	delete(i.store, signedPreKeyID)
}

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

// ContainsKyberPreKey returns true if the store contains a Kyber pre-key with the given ID.
func (i *InMemoryKyberPreKey) ContainsKyberPreKey(kyberPreKeyID uint32) bool {
	_, ok := i.store[kyberPreKeyID]
	return ok
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
