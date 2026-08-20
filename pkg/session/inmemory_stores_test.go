// In-memory store implementations shared by this package's tests.
//
// They live in their own file, untagged, because they perform no cryptography
// themselves -- tests that are excluded from the FIPS gate (docs/FIPS.md) and
// tests that are not both need them.

package session_test

import (
	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	groupRecord "github.com/jeremyhahn/go-libsignal/pkg/groups/state/record"
	groupStore "github.com/jeremyhahn/go-libsignal/pkg/groups/state/store"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/state/store"
)

// ============= In-memory store implementations =============

type inMemoryIdentityKey struct {
	trustedKeys         map[string]*identity.Key
	identityKeyPair     *identity.KeyPair
	localRegistrationID uint32
}

func newInMemoryIdentityKey(identityKey *identity.KeyPair, localRegistrationID uint32) *inMemoryIdentityKey {
	return &inMemoryIdentityKey{
		trustedKeys:         make(map[string]*identity.Key),
		identityKeyPair:     identityKey,
		localRegistrationID: localRegistrationID,
	}
}

func (i *inMemoryIdentityKey) GetIdentityKeyPair() *identity.KeyPair {
	return i.identityKeyPair
}

func (i *inMemoryIdentityKey) GetLocalRegistrationId() uint32 {
	return i.localRegistrationID
}

func (i *inMemoryIdentityKey) SaveIdentity(address *protocol.SignalAddress, identityKey *identity.Key) (store.IdentityChange, error) {
	prev, existed := i.trustedKeys[address.String()]
	i.trustedKeys[address.String()] = identityKey
	if existed && prev != identityKey {
		return store.IdentityChangeReplacedExisting, nil
	}
	return store.IdentityChangeNewOrUnchanged, nil
}

func (i *inMemoryIdentityKey) IsTrustedIdentity(address *protocol.SignalAddress, identityKey *identity.Key, direction store.Direction) (bool, error) {
	trusted := i.trustedKeys[address.String()]
	return trusted == nil || trusted.Fingerprint() == identityKey.Fingerprint(), nil
}

func (i *inMemoryIdentityKey) GetIdentity(address *protocol.SignalAddress) (*identity.Key, error) {
	return i.trustedKeys[address.String()], nil
}

type inMemoryPreKey struct {
	store map[uint32]*record.PreKey
}

func newInMemoryPreKey() *inMemoryPreKey {
	return &inMemoryPreKey{store: make(map[uint32]*record.PreKey)}
}

func (i *inMemoryPreKey) LoadPreKey(preKeyID uint32) (*record.PreKey, error) {
	return i.store[preKeyID], nil
}

func (i *inMemoryPreKey) StorePreKey(preKeyID uint32, preKeyRecord *record.PreKey) error {
	i.store[preKeyID] = preKeyRecord
	return nil
}

func (i *inMemoryPreKey) ContainsPreKey(preKeyID uint32) (bool, error) {
	_, ok := i.store[preKeyID]
	return ok, nil
}

func (i *inMemoryPreKey) RemovePreKey(preKeyID uint32) error {
	delete(i.store, preKeyID)
	return nil
}

type inMemorySession struct {
	sessions   map[string]*record.Session
	serializer *serialize.Serializer
}

func newInMemorySession(serializer *serialize.Serializer) *inMemorySession {
	return &inMemorySession{
		sessions:   make(map[string]*record.Session),
		serializer: serializer,
	}
}

func (i *inMemorySession) LoadSession(address *protocol.SignalAddress) (*record.Session, error) {
	ok, err := i.ContainsSession(address)
	if err != nil {
		return nil, err
	}
	if ok {
		return i.sessions[address.String()], nil
	}
	sessionRecord := record.NewSession(i.serializer.Session, i.serializer.State)
	i.sessions[address.String()] = sessionRecord
	return sessionRecord, nil
}

func (i *inMemorySession) GetSubDeviceSessions(name string) ([]uint32, error) {
	return nil, nil
}

func (i *inMemorySession) StoreSession(remoteAddress *protocol.SignalAddress, record *record.Session) error {
	i.sessions[remoteAddress.String()] = record
	return nil
}

func (i *inMemorySession) ContainsSession(remoteAddress *protocol.SignalAddress) (bool, error) {
	_, ok := i.sessions[remoteAddress.String()]
	return ok, nil
}

func (i *inMemorySession) DeleteSession(remoteAddress *protocol.SignalAddress) error {
	delete(i.sessions, remoteAddress.String())
	return nil
}

func (i *inMemorySession) DeleteAllSessions() error {
	i.sessions = make(map[string]*record.Session)
	return nil
}

type inMemorySignedPreKey struct {
	store map[uint32]*record.SignedPreKey
}

func newInMemorySignedPreKey() *inMemorySignedPreKey {
	return &inMemorySignedPreKey{store: make(map[uint32]*record.SignedPreKey)}
}

func (i *inMemorySignedPreKey) LoadSignedPreKey(signedPreKeyID uint32) (*record.SignedPreKey, error) {
	return i.store[signedPreKeyID], nil
}

func (i *inMemorySignedPreKey) LoadSignedPreKeys() ([]*record.SignedPreKey, error) {
	var preKeys []*record.SignedPreKey
	for _, r := range i.store {
		preKeys = append(preKeys, r)
	}
	return preKeys, nil
}

func (i *inMemorySignedPreKey) StoreSignedPreKey(signedPreKeyID uint32, record *record.SignedPreKey) error {
	i.store[signedPreKeyID] = record
	return nil
}

func (i *inMemorySignedPreKey) ContainsSignedPreKey(signedPreKeyID uint32) (bool, error) {
	_, ok := i.store[signedPreKeyID]
	return ok, nil
}

func (i *inMemorySignedPreKey) RemoveSignedPreKey(signedPreKeyID uint32) error {
	delete(i.store, signedPreKeyID)
	return nil
}

// inMemorySignalProtocol combines all stores to implement store.SignalProtocol.
type inMemorySignalProtocol struct {
	*inMemoryIdentityKey
	*inMemoryPreKey
	*inMemorySession
	*inMemorySignedPreKey
	*inMemorySenderKey
	*inMemoryKyberPreKey
}

type inMemorySenderKey struct {
	store map[*protocol.SenderKeyName]*groupRecord.SenderKey
}

func newInMemorySenderKey() *inMemorySenderKey {
	return &inMemorySenderKey{store: make(map[*protocol.SenderKeyName]*groupRecord.SenderKey)}
}

func (i *inMemorySenderKey) StoreSenderKey(senderKeyName *protocol.SenderKeyName, keyRecord *groupRecord.SenderKey) error {
	i.store[senderKeyName] = keyRecord
	return nil
}

func (i *inMemorySenderKey) LoadSenderKey(senderKeyName *protocol.SenderKeyName) (*groupRecord.SenderKey, error) {
	return i.store[senderKeyName], nil
}

type inMemoryKyberPreKey struct {
	store  map[uint32]*record.KyberPreKey
	marked map[uint32]bool
}

func newInMemoryKyberPreKey() *inMemoryKyberPreKey {
	return &inMemoryKyberPreKey{
		store:  make(map[uint32]*record.KyberPreKey),
		marked: make(map[uint32]bool),
	}
}

func (i *inMemoryKyberPreKey) LoadKyberPreKey(kyberPreKeyID uint32) (*record.KyberPreKey, error) {
	return i.store[kyberPreKeyID], nil
}

func (i *inMemoryKyberPreKey) StoreKyberPreKey(kyberPreKeyID uint32, record *record.KyberPreKey) error {
	i.store[kyberPreKeyID] = record
	return nil
}

func (i *inMemoryKyberPreKey) MarkKyberPreKeyUsed(kyberPreKeyID uint32, _ uint32, _ ecc.ECPublicKeyable) error {
	i.marked[kyberPreKeyID] = true
	return nil
}

func (i *inMemoryKyberPreKey) ContainsKyberPreKey(kyberPreKeyID uint32) (bool, error) {
	_, ok := i.store[kyberPreKeyID]
	return ok, nil
}

// Verify interface compliance.
var _ store.IdentityKey = (*inMemoryIdentityKey)(nil)
var _ store.PreKey = (*inMemoryPreKey)(nil)
var _ store.Session = (*inMemorySession)(nil)
var _ store.SignedPreKey = (*inMemorySignedPreKey)(nil)
var _ store.KyberPreKey = (*inMemoryKyberPreKey)(nil)
var _ groupStore.SenderKey = (*inMemorySenderKey)(nil)
