// Package main demonstrates a minimal Alice-to-Bob single-message exchange
// using the Signal Protocol X3DH key agreement and Double Ratchet encryption.
//
// Flow:
//  1. Generate identity key pairs and pre-key bundles for Alice and Bob.
//  2. Alice builds a session by processing Bob's pre-key bundle (X3DH).
//  3. Alice encrypts "Hello, Bob!" producing a PreKeySignalMessage.
//  4. Bob processes the PreKeySignalMessage to establish his side of the session.
//  5. Bob decrypts and recovers the plaintext.
//
// Run: GOWORK=off go run ./examples/simple-session/
package main

import (
	"fmt"
	"log"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/prekey"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/session"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/state/store"
	"github.com/jeremyhahn/go-libsignal/pkg/util/keyhelper"
	"github.com/jeremyhahn/go-libsignal/pkg/util/optional"
)

// ---- in-memory store implementations ----

type memIdentityStore struct {
	keyPair        *identity.KeyPair
	registrationID uint32
	trusted        map[string]*identity.Key
}

func newMemIdentityStore(kp *identity.KeyPair, regID uint32) *memIdentityStore {
	return &memIdentityStore{keyPair: kp, registrationID: regID, trusted: make(map[string]*identity.Key)}
}

func (s *memIdentityStore) GetIdentityKeyPair() *identity.KeyPair { return s.keyPair }
func (s *memIdentityStore) GetLocalRegistrationId() uint32        { return s.registrationID }
func (s *memIdentityStore) SaveIdentity(addr *protocol.SignalAddress, key *identity.Key) (store.IdentityChange, error) {
	prev, existed := s.trusted[addr.String()]
	s.trusted[addr.String()] = key
	if existed && prev != key {
		return store.IdentityChangeReplacedExisting, nil
	}
	return store.IdentityChangeNewOrUnchanged, nil
}
func (s *memIdentityStore) IsTrustedIdentity(addr *protocol.SignalAddress, key *identity.Key, _ store.Direction) (bool, error) {
	t := s.trusted[addr.String()]
	return t == nil || t.Fingerprint() == key.Fingerprint(), nil
}
func (s *memIdentityStore) GetIdentity(addr *protocol.SignalAddress) (*identity.Key, error) {
	return s.trusted[addr.String()], nil
}

type memPreKeyStore struct{ store map[uint32]*record.PreKey }

func newMemPreKeyStore() *memPreKeyStore {
	return &memPreKeyStore{store: make(map[uint32]*record.PreKey)}
}
func (s *memPreKeyStore) LoadPreKey(id uint32) (*record.PreKey, error)  { return s.store[id], nil }
func (s *memPreKeyStore) StorePreKey(id uint32, r *record.PreKey) error { s.store[id] = r; return nil }
func (s *memPreKeyStore) ContainsPreKey(id uint32) (bool, error) {
	_, ok := s.store[id]
	return ok, nil
}
func (s *memPreKeyStore) RemovePreKey(id uint32) error { delete(s.store, id); return nil }

type memSignedPreKeyStore struct {
	store map[uint32]*record.SignedPreKey
}

func newMemSignedPreKeyStore() *memSignedPreKeyStore {
	return &memSignedPreKeyStore{store: make(map[uint32]*record.SignedPreKey)}
}
func (s *memSignedPreKeyStore) LoadSignedPreKey(id uint32) (*record.SignedPreKey, error) {
	return s.store[id], nil
}
func (s *memSignedPreKeyStore) LoadSignedPreKeys() ([]*record.SignedPreKey, error) {
	var out []*record.SignedPreKey
	for _, v := range s.store {
		out = append(out, v)
	}
	return out, nil
}
func (s *memSignedPreKeyStore) StoreSignedPreKey(id uint32, r *record.SignedPreKey) error {
	s.store[id] = r
	return nil
}
func (s *memSignedPreKeyStore) ContainsSignedPreKey(id uint32) (bool, error) {
	_, ok := s.store[id]
	return ok, nil
}
func (s *memSignedPreKeyStore) RemoveSignedPreKey(id uint32) error { delete(s.store, id); return nil }

type memSessionStore struct {
	sessions   map[string]*record.Session
	serializer *serialize.Serializer
}

func newMemSessionStore(ser *serialize.Serializer) *memSessionStore {
	return &memSessionStore{sessions: make(map[string]*record.Session), serializer: ser}
}
func (s *memSessionStore) LoadSession(addr *protocol.SignalAddress) (*record.Session, error) {
	if r, ok := s.sessions[addr.String()]; ok {
		return r, nil
	}
	return record.NewSession(s.serializer.Session, s.serializer.State), nil
}
func (s *memSessionStore) GetSubDeviceSessions(_ string) ([]uint32, error) { return nil, nil }
func (s *memSessionStore) StoreSession(addr *protocol.SignalAddress, r *record.Session) error {
	s.sessions[addr.String()] = r
	return nil
}
func (s *memSessionStore) ContainsSession(addr *protocol.SignalAddress) (bool, error) {
	_, ok := s.sessions[addr.String()]
	return ok, nil
}
func (s *memSessionStore) DeleteSession(addr *protocol.SignalAddress) error {
	delete(s.sessions, addr.String())
	return nil
}
func (s *memSessionStore) DeleteAllSessions() error {
	s.sessions = make(map[string]*record.Session)
	return nil
}

type memKyberPreKeyStore struct {
	store  map[uint32]*record.KyberPreKey
	marked map[uint32]bool
}

func newMemKyberPreKeyStore() *memKyberPreKeyStore {
	return &memKyberPreKeyStore{store: make(map[uint32]*record.KyberPreKey), marked: make(map[uint32]bool)}
}
func (s *memKyberPreKeyStore) LoadKyberPreKey(id uint32) (*record.KyberPreKey, error) {
	return s.store[id], nil
}
func (s *memKyberPreKeyStore) StoreKyberPreKey(id uint32, r *record.KyberPreKey) error {
	s.store[id] = r
	return nil
}
func (s *memKyberPreKeyStore) MarkKyberPreKeyUsed(id uint32, _ uint32, _ ecc.ECPublicKeyable) error {
	s.marked[id] = true
	return nil
}
func (s *memKyberPreKeyStore) ContainsKyberPreKey(id uint32) (bool, error) {
	_, ok := s.store[id]
	return ok, nil
}

// noopKyberSerializer satisfies record.KyberPreKeySerializer for in-memory use only.
type noopKyberSerializer struct{}

func (n *noopKyberSerializer) Serialize(_ *record.KyberPreKeyStructure) ([]byte, error) {
	return nil, nil
}
func (n *noopKyberSerializer) Deserialize(_ []byte) (*record.KyberPreKeyStructure, error) {
	return nil, nil
}

// ---- main ----

func main() {
	ser := serialize.NewProtobufSerializer()

	// Generate Alice's key material.
	aliceIdentityKP, err := keyhelper.GenerateIdentityKeyPair()
	if err != nil {
		log.Fatalf("generate Alice identity: %v", err)
	}
	aliceRegID := keyhelper.GenerateRegistrationID()
	aliceAddress := protocol.NewSignalAddress("alice", 1)

	// Generate Bob's key material.
	bobIdentityKP, err := keyhelper.GenerateIdentityKeyPair()
	if err != nil {
		log.Fatalf("generate Bob identity: %v", err)
	}
	bobRegID := keyhelper.GenerateRegistrationID()
	bobAddress := protocol.NewSignalAddress("bob", 1)

	bobPreKeys, err := keyhelper.GeneratePreKeys(0, 1, ser.PreKeyRecord)
	if err != nil {
		log.Fatalf("generate Bob pre-keys: %v", err)
	}
	bobSignedPreKey, err := keyhelper.GenerateSignedPreKey(bobIdentityKP, 0, ser.SignedPreKeyRecord)
	if err != nil {
		log.Fatalf("generate Bob signed pre-key: %v", err)
	}
	bobKyberPreKey, err := keyhelper.GenerateKyberPreKey(bobIdentityKP.PrivateKey(), 1, &noopKyberSerializer{})
	if err != nil {
		log.Fatalf("generate Bob kyber pre-key: %v", err)
	}

	// Set up Alice's stores.
	aliceSessionStore := newMemSessionStore(ser)
	alicePreKeyStore := newMemPreKeyStore()
	aliceSignedPreKeyStore := newMemSignedPreKeyStore()
	aliceIdentityStore := newMemIdentityStore(aliceIdentityKP, aliceRegID)
	aliceKyberStore := newMemKyberPreKeyStore()

	// Set up Bob's stores and populate with his keys.
	bobSessionStore := newMemSessionStore(ser)
	bobPreKeyStore := newMemPreKeyStore()
	bobSignedPreKeyStore := newMemSignedPreKeyStore()
	bobIdentityStore := newMemIdentityStore(bobIdentityKP, bobRegID)
	bobKyberStore := newMemKyberPreKeyStore()

	if err := bobPreKeyStore.StorePreKey(
		bobPreKeys[0].ID().Value,
		record.NewPreKey(bobPreKeys[0].ID().Value, bobPreKeys[0].KeyPair(), ser.PreKeyRecord),
	); err != nil {
		log.Fatalf("store Bob pre-key: %v", err)
	}
	if err := bobSignedPreKeyStore.StoreSignedPreKey(
		bobSignedPreKey.ID(),
		record.NewSignedPreKey(bobSignedPreKey.ID(), bobSignedPreKey.Timestamp(),
			bobSignedPreKey.KeyPair(), bobSignedPreKey.Signature(), ser.SignedPreKeyRecord),
	); err != nil {
		log.Fatalf("store Bob signed pre-key: %v", err)
	}
	if err := bobKyberStore.StoreKyberPreKey(1, bobKyberPreKey); err != nil {
		log.Fatalf("store Bob kyber pre-key: %v", err)
	}

	// Alice builds a session toward Bob by processing Bob's pre-key bundle.
	aliceBuilder := session.NewBuilderWithKyber(
		aliceSessionStore, alicePreKeyStore, aliceSignedPreKeyStore,
		aliceIdentityStore, aliceKyberStore, bobAddress, ser,
	)
	bobBundle := prekey.NewBundleWithKyber(
		bobRegID, bobAddress.DeviceID(),
		bobPreKeys[0].ID(),
		bobSignedPreKey.ID(),
		bobPreKeys[0].KeyPair().PublicKey(),
		bobSignedPreKey.KeyPair().PublicKey(),
		bobSignedPreKey.Signature(),
		bobIdentityKP.PublicKey(),
		&optional.Uint32{Value: 1},
		bobKyberPreKey.KeyPair().Public,
		bobKyberPreKey.Signature(),
	)
	if err := aliceBuilder.ProcessBundle(bobBundle); err != nil {
		log.Fatalf("Alice ProcessBundle: %v", err)
	}

	// Alice encrypts "Hello, Bob!". Passing Alice's own address as localAddress
	// activates address binding (SignalMessage field 6), which is what Rust
	// libsignal always does when the local address is known; the two-argument
	// NewCipher leaves the message unbound and open to address substitution.
	aliceCipher := session.NewCipherWithLocalAddress(aliceBuilder, aliceAddress, bobAddress)
	ciphertext, err := aliceCipher.Encrypt([]byte("Hello, Bob!"))
	if err != nil {
		log.Fatalf("Alice Encrypt: %v", err)
	}
	ciphertextBytes, err := ciphertext.Serialize()
	if err != nil {
		log.Fatalf("serialize ciphertext: %v", err)
	}

	// Deserialize as a PreKeySignalMessage (first message always is one).
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(
		ciphertextBytes, ser.PreKeySignalMessage, ser.SignalMessage,
	)
	if err != nil {
		log.Fatalf("deserialize PreKeySignalMessage: %v", err)
	}

	// Bob's builder processes the PreKeySignalMessage to establish the session.
	bobBuilder := session.NewBuilderWithKyber(
		bobSessionStore, bobPreKeyStore, bobSignedPreKeyStore,
		bobIdentityStore, bobKyberStore, aliceAddress, ser,
	)
	deferred, err := bobBuilder.Process(preKeyMsg)
	if err != nil {
		log.Fatalf("Bob Process: %v", err)
	}
	if deferred != nil {
		if err := deferred.Complete(); err != nil {
			log.Fatalf("Bob deferred.Complete: %v", err)
		}
	}

	// Bob decrypts, likewise bound to his own address.
	bobCipher := session.NewCipherWithLocalAddress(bobBuilder, bobAddress, aliceAddress)
	plaintext, err := bobCipher.Decrypt(preKeyMsg.WhisperMessage())
	if err != nil {
		log.Fatalf("Bob Decrypt: %v", err)
	}

	fmt.Printf("Alice -> Bob: %s\n", plaintext)
}
