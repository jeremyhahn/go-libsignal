// Package main demonstrates a Sealed Sender V1 message from Alice to Bob.
//
// Flow:
//  1. Generate a trust root key pair (simulates the Signal server root of trust).
//  2. Generate a server certificate signed by the trust root.
//  3. Generate identity keys for Alice (sender) and Bob (recipient).
//  4. Alice establishes a session with Bob via X3DH (ProcessBundle).
//  5. Create a SenderCertificate for Alice, signed by the server key.
//  6. Alice encrypts using SealedSenderEncrypt — Bob's identity is hidden from the server.
//  7. Bob decrypts using SealedSenderDecryptWithKyber and recovers the plaintext + sender UUID.
//
// Run: GOWORK=off go run ./examples/sealed-sender/
package main

import (
	"fmt"
	"log"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/prekey"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/sealed"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/session"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/state/store"
	"github.com/jeremyhahn/go-libsignal/pkg/util/keyhelper"
	"github.com/jeremyhahn/go-libsignal/pkg/util/optional"
)

// ---- in-memory stores ----

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

// GetIdentityKey implements the optional sessionIdentityStore interface used
// internally by SealedSenderDecryptToUSMC to look up remote identity keys.
func (s *memIdentityStore) GetIdentityKey(addr *protocol.SignalAddress) (ecc.ECPublicKeyable, error) {
	k := s.trusted[addr.String()]
	if k != nil {
		return k.PublicKey(), nil
	}
	return nil, nil
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

// noopKyberSerializer satisfies record.KyberPreKeySerializer for in-memory use.
type noopKyberSerializer struct{}

func (n *noopKyberSerializer) Serialize(_ *record.KyberPreKeyStructure) ([]byte, error) {
	return nil, nil
}
func (n *noopKyberSerializer) Deserialize(_ []byte) (*record.KyberPreKeyStructure, error) {
	return nil, nil
}

// ---- main ----

func main() {
	// SealedSenderEncrypt/Decrypt use the protobuf serializer internally.
	ser := serialize.NewProtobufSerializer()

	// --- Step 1: Trust root (simulates the Signal server root key). ---
	trustRootKP, err := ecc.GenerateKeyPair()
	if err != nil {
		log.Fatalf("generate trust root: %v", err)
	}

	// --- Step 2: Server certificate signed by the trust root. ---
	serverKP, err := ecc.GenerateKeyPair()
	if err != nil {
		log.Fatalf("generate server key pair: %v", err)
	}
	serverCert, err := sealed.NewServerCertificate(1, serverKP.PublicKey(), trustRootKP.PrivateKey())
	if err != nil {
		log.Fatalf("NewServerCertificate: %v", err)
	}

	// --- Step 3: Alice and Bob identity keys. ---
	aliceKP, err := ecc.GenerateKeyPair()
	if err != nil {
		log.Fatalf("generate Alice key pair: %v", err)
	}
	aliceIdentityKP := identity.NewKeyPair(identity.NewKey(aliceKP.PublicKey()), aliceKP.PrivateKey())
	aliceUUID := "alice-00000000-0000-0000-0000-000000000001"

	bobKP, err := ecc.GenerateKeyPair()
	if err != nil {
		log.Fatalf("generate Bob key pair: %v", err)
	}
	bobIdentityKP := identity.NewKeyPair(identity.NewKey(bobKP.PublicKey()), bobKP.PrivateKey())
	bobUUID := "bob-00000000-0000-0000-0000-000000000002"
	bobAddress := protocol.NewSignalAddress(bobUUID, 1)
	bobRegID := keyhelper.GenerateRegistrationID()

	// --- Step 4: Bob's pre-keys. ---
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

	// Set up stores.
	aliceSessionStore := newMemSessionStore(ser)
	alicePreKeyStore := newMemPreKeyStore()
	aliceSignedPreKeyStore := newMemSignedPreKeyStore()
	aliceIdentityStore := newMemIdentityStore(aliceIdentityKP, keyhelper.GenerateRegistrationID())
	aliceKyberStore := newMemKyberPreKeyStore()

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

	// Alice establishes session with Bob via X3DH (PQXDH).
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

	// --- Step 5: Alice's sender certificate, signed by the server. ---
	senderCert, err := sealed.NewSenderCertificate(
		aliceUUID,
		nil, // no E.164 phone number
		aliceIdentityKP.PublicKey().PublicKey(),
		1,          // Alice's device ID
		9999999999, // expiration: far future
		serverCert,
		serverKP.PrivateKey(),
	)
	if err != nil {
		log.Fatalf("NewSenderCertificate: %v", err)
	}

	// --- Step 6: Alice seals the message. ---
	plaintext := []byte("Hello, Bob! This is sealed.")
	ciphertext, err := sealed.SealedSenderEncrypt(
		bobAddress, senderCert, plaintext,
		aliceSessionStore, aliceIdentityStore,
	)
	if err != nil {
		log.Fatalf("SealedSenderEncrypt: %v", err)
	}

	// --- Step 7: Bob decrypts. ---
	// validationTime=1000 is well within the certificate's expiry (9999999999).
	result, err := sealed.SealedSenderDecryptWithKyber(
		ciphertext,
		trustRootKP.PublicKey(),
		1000, // validation timestamp (ms since epoch)
		bobUUID, nil, 1,
		bobSessionStore, bobIdentityStore,
		bobPreKeyStore, bobSignedPreKeyStore,
		bobKyberStore,
	)
	if err != nil {
		log.Fatalf("SealedSenderDecrypt: %v", err)
	}

	fmt.Printf("Bob received from %s: %s\n", result.SenderUUID, result.Message)
}
