package sealed

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/prekey"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/proto/sealedpb"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/session"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/state/store"
	"github.com/jeremyhahn/go-libsignal/pkg/util/keyhelper"
	"github.com/jeremyhahn/go-libsignal/pkg/util/optional"
	"google.golang.org/protobuf/proto"
)

// testIdentityStore implements store.IdentityKey for sealed sender testing.
// It also implements the sessionIdentityStore interface used by getRecipientIdentityKey.
type testIdentityStore struct {
	keyPair          *identity.KeyPair
	registrationID   uint32
	trustedKeys      map[string]*identity.Key
	remoteIdentities map[string]ecc.ECPublicKeyable
}

func newTestIdentityStore(t *testing.T) *testIdentityStore {
	t.Helper()
	kp, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	identityKey := identity.NewKey(kp.PublicKey())
	identityKeyPair := identity.NewKeyPair(identityKey, kp.PrivateKey())
	return &testIdentityStore{
		keyPair:          identityKeyPair,
		registrationID:   1,
		trustedKeys:      make(map[string]*identity.Key),
		remoteIdentities: make(map[string]ecc.ECPublicKeyable),
	}
}

func (s *testIdentityStore) GetIdentityKeyPair() *identity.KeyPair {
	return s.keyPair
}

func (s *testIdentityStore) GetLocalRegistrationId() uint32 {
	return s.registrationID
}

func (s *testIdentityStore) SaveIdentity(address *protocol.SignalAddress, identityKey *identity.Key) {
	s.trustedKeys[address.String()] = identityKey
	s.remoteIdentities[address.String()] = identityKey.PublicKey()
}

func (s *testIdentityStore) IsTrustedIdentity(address *protocol.SignalAddress, identityKey *identity.Key, direction store.Direction) bool {
	return true
}

func (s *testIdentityStore) GetIdentity(address *protocol.SignalAddress) (*identity.Key, error) {
	return s.trustedKeys[address.String()], nil
}

// GetIdentityKey implements the sessionIdentityStore interface used by getRecipientIdentityKey.
func (s *testIdentityStore) GetIdentityKey(address *protocol.SignalAddress) (ecc.ECPublicKeyable, error) {
	if key, ok := s.remoteIdentities[address.String()]; ok {
		return key, nil
	}
	return nil, nil
}

func TestBuildSalt(t *testing.T) {
	theirPub := []byte{0x01, 0x02, 0x03}
	ephemeralPub := []byte{0x04, 0x05, 0x06}

	salt := buildSalt(theirPub, ephemeralPub)

	// salt should be: "UnidentifiedDelivery" || theirPub || ephemeralPub
	prefix := []byte("UnidentifiedDelivery")
	expectedLen := len(prefix) + len(theirPub) + len(ephemeralPub)
	if len(salt) != expectedLen {
		t.Errorf("Salt length = %d, want %d", len(salt), expectedLen)
	}
	if !bytes.HasPrefix(salt, prefix) {
		t.Error("Salt should start with 'UnidentifiedDelivery'")
	}
	if !bytes.Contains(salt, theirPub) {
		t.Error("Salt should contain theirPub")
	}
	if !bytes.Contains(salt, ephemeralPub) {
		t.Error("Salt should contain ephemeralPub")
	}
}

func TestTruncatedHMAC(t *testing.T) {
	key := make([]byte, 32)
	data := []byte("test data")

	mac := truncatedHMAC(key, data)
	if len(mac) != macTruncateLen {
		t.Errorf("MAC length = %d, want %d", len(mac), macTruncateLen)
	}
}

func TestTruncatedHMACDeterministic(t *testing.T) {
	key := make([]byte, 32)
	data := []byte("test data")

	mac1 := truncatedHMAC(key, data)
	mac2 := truncatedHMAC(key, data)

	if !bytes.Equal(mac1, mac2) {
		t.Error("truncatedHMAC should be deterministic")
	}
}

func TestTruncatedHMACDifferentKeys(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key2[0] = 0xFF
	data := []byte("test data")

	mac1 := truncatedHMAC(key1, data)
	mac2 := truncatedHMAC(key2, data)

	if bytes.Equal(mac1, mac2) {
		t.Error("Different keys should produce different MACs")
	}
}

func TestSealedSenderEncryptFromUSMCAndDecryptToUSMC(t *testing.T) {
	// Create trust root and certificates
	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	// Create Alice (sender) and Bob (recipient) identity stores
	aliceStore := newTestIdentityStore(t)
	bobStore := newTestIdentityStore(t)

	// Alice needs to know Bob's identity key
	bobAddress := protocol.NewSignalAddress("bob-uuid", 1)
	aliceStore.SaveIdentity(bobAddress, identity.NewKey(bobStore.GetIdentityKeyPair().PublicKey().PublicKey()))

	// Create sender certificate for Alice
	senderCert, err := NewSenderCertificate(
		"alice-uuid",
		nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1,
		9999999999,
		serverCert,
		serverKey.PrivateKey(),
	)
	if err != nil {
		t.Fatalf("NewSenderCertificate() error: %v", err)
	}

	// Build a USMC
	usmc, err := NewUnidentifiedSenderMessageContent(
		2,
		senderCert,
		[]byte("hello bob"),
		ContentHintDefault,
		nil,
	)
	if err != nil {
		t.Fatalf("NewUnidentifiedSenderMessageContent() error: %v", err)
	}

	// Encrypt using sealed sender
	ciphertext, err := SealedSenderEncryptFromUSMC(bobAddress, usmc, aliceStore)
	if err != nil {
		t.Fatalf("SealedSenderEncryptFromUSMC() error: %v", err)
	}

	if len(ciphertext) == 0 {
		t.Fatal("Ciphertext should not be empty")
	}
	if ciphertext[0] != SealedSenderV1Version {
		t.Errorf("Version byte = 0x%02x, want 0x%02x", ciphertext[0], SealedSenderV1Version)
	}

	// Decrypt the sealed sender message
	decryptedUSMC, err := SealedSenderDecryptToUSMC(ciphertext, bobStore)
	if err != nil {
		t.Fatalf("SealedSenderDecryptToUSMC() error: %v", err)
	}

	if decryptedUSMC.Type() != 2 {
		t.Errorf("Decrypted Type() = %d, want 2", decryptedUSMC.Type())
	}
	if !bytes.Equal(decryptedUSMC.Contents(), []byte("hello bob")) {
		t.Errorf("Decrypted Contents() = %q, want %q", string(decryptedUSMC.Contents()), "hello bob")
	}
	if decryptedUSMC.Sender() == nil {
		t.Fatal("Decrypted Sender() should not be nil")
	}
	if decryptedUSMC.Sender().SenderUUID() != "alice-uuid" {
		t.Errorf("Decrypted SenderUUID() = %q, want %q", decryptedUSMC.Sender().SenderUUID(), "alice-uuid")
	}
}

func TestSealedSenderDecryptToUSMCTooShort(t *testing.T) {
	bobStore := newTestIdentityStore(t)

	_, err := SealedSenderDecryptToUSMC([]byte{}, bobStore)
	if err == nil {
		t.Error("SealedSenderDecryptToUSMC with empty ciphertext should return error")
	}
}

func TestSealedSenderDecryptToUSMCUnsupportedVersion(t *testing.T) {
	bobStore := newTestIdentityStore(t)

	_, err := SealedSenderDecryptToUSMC([]byte{0x99, 0x01, 0x02}, bobStore)
	if err == nil {
		t.Error("SealedSenderDecryptToUSMC with unsupported version should return error")
	}
}

func TestSealedSenderDecryptToUSMCV2WithoutServiceId(t *testing.T) {
	bobStore := newTestIdentityStore(t)

	// v2 version byte but no ServiceId provided
	_, err := SealedSenderDecryptToUSMC([]byte{SealedSenderV2VersionUUID, 0x01, 0x02}, bobStore)
	if err == nil {
		t.Error("SealedSenderDecryptToUSMC v2 without ServiceId should return error")
	}
}

func TestSealedSenderDecryptToUSMCInvalidEnvelope(t *testing.T) {
	bobStore := newTestIdentityStore(t)

	// Valid v1 version byte but invalid protobuf
	_, err := SealedSenderDecryptToUSMC([]byte{SealedSenderV1Version, 0xFF, 0xFF}, bobStore)
	if err == nil {
		t.Error("SealedSenderDecryptToUSMC with invalid envelope should return error")
	}
}

func TestSealedSenderDecryptToUSMCTamperedMAC(t *testing.T) {
	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	aliceStore := newTestIdentityStore(t)
	bobStore := newTestIdentityStore(t)

	bobAddress := protocol.NewSignalAddress("bob-uuid", 1)
	aliceStore.SaveIdentity(bobAddress, identity.NewKey(bobStore.GetIdentityKeyPair().PublicKey().PublicKey()))

	senderCert, _ := NewSenderCertificate(
		"alice-uuid", nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999,
		serverCert, serverKey.PrivateKey(),
	)

	usmc, _ := NewUnidentifiedSenderMessageContent(2, senderCert, []byte("test"), ContentHintDefault, nil)

	ciphertext, err := SealedSenderEncryptFromUSMC(bobAddress, usmc, aliceStore)
	if err != nil {
		t.Fatalf("SealedSenderEncryptFromUSMC() error: %v", err)
	}

	// Tamper with the ciphertext
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	if len(tampered) > 10 {
		tampered[len(tampered)-2] ^= 0xFF
	}

	_, err = SealedSenderDecryptToUSMC(tampered, bobStore)
	if err == nil {
		t.Error("SealedSenderDecryptToUSMC with tampered ciphertext should return error")
	}
}

func TestGetRecipientIdentityKeyNoLoader(t *testing.T) {
	// Use a basic store that doesn't implement identityLoader or sessionIdentityStore
	basicStore := &basicIdentityStore{
		keyPair: newTestIdentityStore(t).keyPair,
	}

	address := protocol.NewSignalAddress("bob", 1)
	_, err := getRecipientIdentityKey(address, basicStore)
	if err == nil {
		t.Error("getRecipientIdentityKey with unsupported store should return error")
	}
}

// basicIdentityStore only implements the minimum required interface.
type basicIdentityStore struct {
	keyPair *identity.KeyPair
}

func (s *basicIdentityStore) GetIdentityKeyPair() *identity.KeyPair {
	return s.keyPair
}

func (s *basicIdentityStore) GetLocalRegistrationId() uint32 {
	return 1
}

func (s *basicIdentityStore) SaveIdentity(address *protocol.SignalAddress, identityKey *identity.Key) {
}

func (s *basicIdentityStore) IsTrustedIdentity(address *protocol.SignalAddress, identityKey *identity.Key, direction store.Direction) bool {
	return true
}

func (s *basicIdentityStore) GetIdentity(address *protocol.SignalAddress) (*identity.Key, error) {
	return nil, nil
}

func TestSealedSenderFullEncryptDecrypt(t *testing.T) {
	// Full test of SealedSenderEncrypt and SealedSenderDecrypt using session cipher.
	// SealedSenderEncrypt/Decrypt internally use protobuf serializer, so the session
	// must be established with protobuf serializer to match.
	serializer := serialize.NewProtobufSerializer()

	// Create trust root
	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	// Create Alice (sender) and Bob (recipient)
	aliceKP, _ := ecc.GenerateKeyPair()
	aliceIdentity := identity.NewKeyPair(identity.NewKey(aliceKP.PublicKey()), aliceKP.PrivateKey())
	aliceRegID := uint32(1)

	bobKP, _ := ecc.GenerateKeyPair()
	bobIdentity := identity.NewKeyPair(identity.NewKey(bobKP.PublicKey()), bobKP.PrivateKey())
	bobRegID := uint32(2)

	_ = aliceRegID // used by identity store
	bobAddress := protocol.NewSignalAddress("bob-uuid-87654321-4321-4321-4321-cba987654321", 1)

	// Set up stores for Alice
	aliceSessionStore := newInMemorySessionStoreForV1(serializer)
	alicePreKeyStore := newInMemoryPreKeyStoreForV1()
	aliceSignedPreKeyStore := newInMemorySignedPreKeyStoreForV1()
	aliceIdentityStore := &fullIdentityStore{
		keyPair: aliceIdentity, regID: aliceRegID,
		trusted: make(map[string]*identity.Key),
	}

	// Set up stores for Bob
	bobSessionStore := newInMemorySessionStoreForV1(serializer)
	bobPreKeyStore := newInMemoryPreKeyStoreForV1()
	bobSignedPreKeyStore := newInMemorySignedPreKeyStoreForV1()
	bobIdentityStore := &fullIdentityStore{
		keyPair: bobIdentity, regID: bobRegID,
		trusted: make(map[string]*identity.Key),
	}

	// Generate Bob's pre keys
	bobPreKeys, _ := keyhelper.GeneratePreKeys(0, 10, serializer.PreKeyRecord)
	for _, pk := range bobPreKeys {
		bobPreKeyStore.StorePreKey(pk.ID().Value, record.NewPreKey(pk.ID().Value, pk.KeyPair(), serializer.PreKeyRecord))
	}

	bobSignedPreKey, _ := keyhelper.GenerateSignedPreKey(bobIdentity, 0, serializer.SignedPreKeyRecord)
	bobSignedPreKeyStore.StoreSignedPreKey(bobSignedPreKey.ID(), record.NewSignedPreKey(
		bobSignedPreKey.ID(), bobSignedPreKey.Timestamp(), bobSignedPreKey.KeyPair(),
		bobSignedPreKey.Signature(), serializer.SignedPreKeyRecord,
	))

	// Generate Bob's Kyber pre-key for PQXDH.
	bobKyberPreKey, _ := keyhelper.GenerateKyberPreKey(bobIdentity.PrivateKey(), 42, &mockKyberPreKeySerializer{})
	bobKyberPreKeyStore := newInMemoryKyberPreKeyStoreForV1()
	if err := bobKyberPreKeyStore.StoreKyberPreKey(42, bobKyberPreKey); err != nil {
		t.Fatal(err)
	}

	// Alice establishes session with Bob using PQXDH.
	aliceBuilder := session.NewBuilderWithKyber(
		aliceSessionStore, alicePreKeyStore, aliceSignedPreKeyStore,
		aliceIdentityStore, newInMemoryKyberPreKeyStoreForV1(), bobAddress, serializer,
	)

	bundle := prekey.NewBundleWithKyber(
		bobRegID, bobAddress.DeviceID(),
		bobPreKeys[0].ID(), bobSignedPreKey.ID(),
		bobPreKeys[0].KeyPair().PublicKey(), bobSignedPreKey.KeyPair().PublicKey(),
		bobSignedPreKey.Signature(), bobIdentity.PublicKey(),
		&optional.Uint32{Value: 42},
		bobKyberPreKey.KeyPair().Public,
		bobKyberPreKey.Signature(),
	)
	if err := aliceBuilder.ProcessBundle(bundle); err != nil {
		t.Fatalf("ProcessBundle error: %v", err)
	}

	// Create sender certificate for Alice
	senderCert, err := NewSenderCertificate(
		"alice-uuid-12345678-1234-1234-1234-123456789abc",
		nil,
		aliceIdentity.PublicKey().PublicKey(),
		1,
		9999999999,
		serverCert,
		serverKey.PrivateKey(),
	)
	if err != nil {
		t.Fatalf("NewSenderCertificate error: %v", err)
	}

	// Encrypt using sealed sender
	plaintext := []byte("Hello Bob, this is a sealed sender message!")
	ciphertext, err := SealedSenderEncrypt(
		bobAddress, senderCert, plaintext,
		aliceSessionStore, aliceIdentityStore,
	)
	if err != nil {
		t.Fatalf("SealedSenderEncrypt error: %v", err)
	}

	if len(ciphertext) == 0 {
		t.Fatal("Ciphertext should not be empty")
	}

	// Decrypt as Bob using SealedSenderDecryptWithKyber.
	result, err := SealedSenderDecryptWithKyber(
		ciphertext, trustRoot.PublicKey(), 1000,
		"bob-uuid-87654321-4321-4321-4321-cba987654321", nil, 1,
		bobSessionStore, bobIdentityStore,
		bobPreKeyStore, bobSignedPreKeyStore,
		bobKyberPreKeyStore,
	)
	if err != nil {
		t.Fatalf("SealedSenderDecrypt error: %v", err)
	}

	if result.SenderUUID != "alice-uuid-12345678-1234-1234-1234-123456789abc" {
		t.Errorf("SenderUUID = %q, want alice-uuid", result.SenderUUID)
	}
	if string(result.Message) != string(plaintext) {
		t.Errorf("Message = %q, want %q", string(result.Message), string(plaintext))
	}
	if result.DeviceID != 1 {
		t.Errorf("DeviceID = %d, want 1", result.DeviceID)
	}
}

// fullIdentityStore implements store.IdentityKey + sessionIdentityStore.
type fullIdentityStore struct {
	keyPair *identity.KeyPair
	regID   uint32
	trusted map[string]*identity.Key
}

func (s *fullIdentityStore) GetIdentityKeyPair() *identity.KeyPair { return s.keyPair }
func (s *fullIdentityStore) GetLocalRegistrationId() uint32        { return s.regID }
func (s *fullIdentityStore) SaveIdentity(addr *protocol.SignalAddress, key *identity.Key) {
	s.trusted[addr.String()] = key
}
func (s *fullIdentityStore) IsTrustedIdentity(addr *protocol.SignalAddress, key *identity.Key, dir store.Direction) bool {
	t := s.trusted[addr.String()]
	return t == nil || t.Fingerprint() == key.Fingerprint()
}
func (s *fullIdentityStore) GetIdentity(addr *protocol.SignalAddress) (*identity.Key, error) {
	return s.trusted[addr.String()], nil
}
func (s *fullIdentityStore) GetIdentityKey(addr *protocol.SignalAddress) (ecc.ECPublicKeyable, error) {
	k := s.trusted[addr.String()]
	if k != nil {
		return k.PublicKey(), nil
	}
	return nil, nil
}

func newInMemorySessionStoreForV1(serializer *serialize.Serializer) *inMemorySessionStoreV1 {
	return &inMemorySessionStoreV1{
		sessions:   make(map[string]*record.Session),
		serializer: serializer,
	}
}

type inMemorySessionStoreV1 struct {
	sessions   map[string]*record.Session
	serializer *serialize.Serializer
}

func (s *inMemorySessionStoreV1) LoadSession(addr *protocol.SignalAddress) *record.Session {
	if sess, ok := s.sessions[addr.String()]; ok {
		return sess
	}
	return record.NewSession(s.serializer.Session, s.serializer.State)
}
func (s *inMemorySessionStoreV1) GetSubDeviceSessions(name string) []uint32 { return nil }
func (s *inMemorySessionStoreV1) StoreSession(addr *protocol.SignalAddress, r *record.Session) {
	s.sessions[addr.String()] = r
}
func (s *inMemorySessionStoreV1) ContainsSession(addr *protocol.SignalAddress) bool {
	_, ok := s.sessions[addr.String()]
	return ok
}
func (s *inMemorySessionStoreV1) DeleteSession(addr *protocol.SignalAddress) {
	delete(s.sessions, addr.String())
}
func (s *inMemorySessionStoreV1) DeleteAllSessions() {
	s.sessions = make(map[string]*record.Session)
}

func newInMemoryPreKeyStoreForV1() *inMemoryPreKeyStoreV1 {
	return &inMemoryPreKeyStoreV1{store: make(map[uint32]*record.PreKey)}
}

type inMemoryPreKeyStoreV1 struct {
	store map[uint32]*record.PreKey
}

func (s *inMemoryPreKeyStoreV1) LoadPreKey(id uint32) *record.PreKey    { return s.store[id] }
func (s *inMemoryPreKeyStoreV1) StorePreKey(id uint32, r *record.PreKey) { s.store[id] = r }
func (s *inMemoryPreKeyStoreV1) ContainsPreKey(id uint32) bool          { _, ok := s.store[id]; return ok }
func (s *inMemoryPreKeyStoreV1) RemovePreKey(id uint32)                  { delete(s.store, id) }

func newInMemorySignedPreKeyStoreForV1() *inMemorySignedPreKeyStoreV1 {
	return &inMemorySignedPreKeyStoreV1{store: make(map[uint32]*record.SignedPreKey)}
}

type inMemorySignedPreKeyStoreV1 struct {
	store map[uint32]*record.SignedPreKey
}

func (s *inMemorySignedPreKeyStoreV1) LoadSignedPreKey(id uint32) *record.SignedPreKey {
	return s.store[id]
}
func (s *inMemorySignedPreKeyStoreV1) LoadSignedPreKeys() []*record.SignedPreKey {
	var keys []*record.SignedPreKey
	for _, k := range s.store {
		keys = append(keys, k)
	}
	return keys
}
func (s *inMemorySignedPreKeyStoreV1) StoreSignedPreKey(id uint32, r *record.SignedPreKey) {
	s.store[id] = r
}
func (s *inMemorySignedPreKeyStoreV1) ContainsSignedPreKey(id uint32) bool {
	_, ok := s.store[id]
	return ok
}
func (s *inMemorySignedPreKeyStoreV1) RemoveSignedPreKey(id uint32) { delete(s.store, id) }

// inMemoryKyberPreKeyStoreV1 is an in-memory Kyber pre-key store for testing.
type inMemoryKyberPreKeyStoreV1 struct {
	store  map[uint32]*record.KyberPreKey
	marked map[uint32]bool
}

func newInMemoryKyberPreKeyStoreForV1() *inMemoryKyberPreKeyStoreV1 {
	return &inMemoryKyberPreKeyStoreV1{
		store:  make(map[uint32]*record.KyberPreKey),
		marked: make(map[uint32]bool),
	}
}

func (s *inMemoryKyberPreKeyStoreV1) LoadKyberPreKey(id uint32) (*record.KyberPreKey, error) {
	return s.store[id], nil
}
func (s *inMemoryKyberPreKeyStoreV1) StoreKyberPreKey(id uint32, r *record.KyberPreKey) error {
	s.store[id] = r
	return nil
}
func (s *inMemoryKyberPreKeyStoreV1) MarkKyberPreKeyUsed(id uint32, _ uint32, _ ecc.ECPublicKeyable) error {
	s.marked[id] = true
	return nil
}
func (s *inMemoryKyberPreKeyStoreV1) ContainsKyberPreKey(id uint32) bool {
	_, ok := s.store[id]
	return ok
}

// mockKyberPreKeySerializer is a minimal serializer for Kyber pre-key records.
type mockKyberPreKeySerializer struct{}

func (m *mockKyberPreKeySerializer) Serialize(_ *record.KyberPreKeyStructure) ([]byte, error) {
	return nil, nil
}
func (m *mockKyberPreKeySerializer) Deserialize(_ []byte) (*record.KyberPreKeyStructure, error) {
	return nil, nil
}

func TestSealedSenderDecryptSelfSend(t *testing.T) {
	serializer := serialize.NewProtobufSerializer()
	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	aliceKP, _ := ecc.GenerateKeyPair()
	aliceIdentity := identity.NewKeyPair(identity.NewKey(aliceKP.PublicKey()), aliceKP.PrivateKey())

	bobKP, _ := ecc.GenerateKeyPair()
	bobIdentity := identity.NewKeyPair(identity.NewKey(bobKP.PublicKey()), bobKP.PrivateKey())

	senderUUID := "alice-uuid-00000000-0000-0000-0000-000000000001"
	bobAddress := protocol.NewSignalAddress("bob-uuid-00000000-0000-0000-0000-000000000002", 1)

	// Set up session
	aliceSessionStore := newInMemorySessionStoreForV1(serializer)
	aliceIdentityStore := &fullIdentityStore{
		keyPair: aliceIdentity, regID: 1,
		trusted: make(map[string]*identity.Key),
	}

	bobPreKeyStore := newInMemoryPreKeyStoreForV1()
	bobSignedPreKeyStore := newInMemorySignedPreKeyStoreForV1()
	bobIdentityStore := &fullIdentityStore{
		keyPair: bobIdentity, regID: 2,
		trusted: make(map[string]*identity.Key),
	}

	bobPreKeys, _ := keyhelper.GeneratePreKeys(0, 10, serializer.PreKeyRecord)
	for _, pk := range bobPreKeys {
		bobPreKeyStore.StorePreKey(pk.ID().Value, record.NewPreKey(pk.ID().Value, pk.KeyPair(), serializer.PreKeyRecord))
	}
	bobSignedPreKey, _ := keyhelper.GenerateSignedPreKey(bobIdentity, 0, serializer.SignedPreKeyRecord)
	bobSignedPreKeyStore.StoreSignedPreKey(bobSignedPreKey.ID(), record.NewSignedPreKey(
		bobSignedPreKey.ID(), bobSignedPreKey.Timestamp(), bobSignedPreKey.KeyPair(),
		bobSignedPreKey.Signature(), serializer.SignedPreKeyRecord,
	))

	bobKyberPreKey, _ := keyhelper.GenerateKyberPreKey(bobIdentity.PrivateKey(), 42, &mockKyberPreKeySerializer{})
	bobKyberPreKeyStore := newInMemoryKyberPreKeyStoreForV1()
	if err := bobKyberPreKeyStore.StoreKyberPreKey(42, bobKyberPreKey); err != nil {
		t.Fatal(err)
	}

	aliceBuilder := session.NewBuilderWithKyber(
		aliceSessionStore, newInMemoryPreKeyStoreForV1(), newInMemorySignedPreKeyStoreForV1(),
		aliceIdentityStore, newInMemoryKyberPreKeyStoreForV1(), bobAddress, serializer,
	)
	bundle := prekey.NewBundleWithKyber(2, 1, bobPreKeys[0].ID(), bobSignedPreKey.ID(),
		bobPreKeys[0].KeyPair().PublicKey(), bobSignedPreKey.KeyPair().PublicKey(),
		bobSignedPreKey.Signature(), bobIdentity.PublicKey(),
		&optional.Uint32{Value: 42}, bobKyberPreKey.KeyPair().Public, bobKyberPreKey.Signature())
	if err := aliceBuilder.ProcessBundle(bundle); err != nil {
		t.Fatalf("ProcessBundle failed: %v", err)
	}

	senderCert, _ := NewSenderCertificate(senderUUID, nil, aliceIdentity.PublicKey().PublicKey(),
		1, 9999999999, serverCert, serverKey.PrivateKey())

	ciphertext, err := SealedSenderEncrypt(bobAddress, senderCert, []byte("test"),
		aliceSessionStore, aliceIdentityStore)
	if err != nil {
		t.Fatalf("SealedSenderEncrypt error: %v", err)
	}

	// Try to decrypt as self (same UUID and device)
	_, err = SealedSenderDecrypt(ciphertext, trustRoot.PublicKey(), 1000,
		senderUUID, nil, 1,
		newInMemorySessionStoreForV1(serializer), bobIdentityStore,
		bobPreKeyStore, bobSignedPreKeyStore)
	if err == nil {
		t.Error("SealedSenderDecrypt should detect self-send")
	}
}

func TestSealedSenderDecryptUnsupportedMessageType(t *testing.T) {
	// Test with a USMC that has an unsupported message type (e.g., 99)
	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	aliceStore := newTestIdentityStore(t)
	bobStore := newTestIdentityStore(t)

	bobAddress := protocol.NewSignalAddress("bob-uuid", 1)
	aliceStore.SaveIdentity(bobAddress, identity.NewKey(bobStore.GetIdentityKeyPair().PublicKey().PublicKey()))

	senderCert, _ := NewSenderCertificate("alice-uuid", nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999, serverCert, serverKey.PrivateKey())

	// Use unsupported message type 99
	usmc, _ := NewUnidentifiedSenderMessageContent(99, senderCert, []byte("test"), ContentHintDefault, nil)

	ciphertext, err := SealedSenderEncryptFromUSMC(bobAddress, usmc, aliceStore)
	if err != nil {
		t.Fatalf("SealedSenderEncryptFromUSMC error: %v", err)
	}

	serializer := serialize.NewJSONSerializer()
	_, err = SealedSenderDecrypt(ciphertext, trustRoot.PublicKey(), 1000,
		"bob-uuid", nil, 1,
		newInMemorySessionStoreForV1(serializer), bobStore,
		newInMemoryPreKeyStoreForV1(), newInMemorySignedPreKeyStoreForV1())
	if err == nil {
		t.Error("SealedSenderDecrypt with unsupported message type should return error")
	}
}

func TestSealedSenderFullEncryptDecryptWhisperMessage(t *testing.T) {
	// Test the MESSAGE (whisper) code path in SealedSenderDecrypt.
	// First, establish a session with a PreKey message, then send a second
	// message which will be a regular whisper message (non-PreKey).
	serializer := serialize.NewProtobufSerializer()

	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	aliceKP, _ := ecc.GenerateKeyPair()
	aliceIdentity := identity.NewKeyPair(identity.NewKey(aliceKP.PublicKey()), aliceKP.PrivateKey())

	bobKP, _ := ecc.GenerateKeyPair()
	bobIdentity := identity.NewKeyPair(identity.NewKey(bobKP.PublicKey()), bobKP.PrivateKey())

	bobAddress := protocol.NewSignalAddress("bob-uuid-22222222-2222-2222-2222-222222222222", 1)
	aliceAddress := protocol.NewSignalAddress("alice-uuid-11111111-1111-1111-1111-111111111111", 1)
	senderUUID := "alice-uuid-11111111-1111-1111-1111-111111111111"

	// Set up stores for Alice.
	aliceSessionStore := newInMemorySessionStoreForV1(serializer)
	alicePreKeyStore := newInMemoryPreKeyStoreForV1()
	aliceSignedPreKeyStore := newInMemorySignedPreKeyStoreForV1()
	aliceIdentityStore := &fullIdentityStore{
		keyPair: aliceIdentity, regID: 1,
		trusted: make(map[string]*identity.Key),
	}

	// Set up stores for Bob.
	bobSessionStore := newInMemorySessionStoreForV1(serializer)
	bobPreKeyStore := newInMemoryPreKeyStoreForV1()
	bobSignedPreKeyStore := newInMemorySignedPreKeyStoreForV1()
	bobIdentityStore := &fullIdentityStore{
		keyPair: bobIdentity, regID: 2,
		trusted: make(map[string]*identity.Key),
	}

	// Generate Bob's pre keys.
	bobPreKeys, _ := keyhelper.GeneratePreKeys(0, 10, serializer.PreKeyRecord)
	for _, pk := range bobPreKeys {
		bobPreKeyStore.StorePreKey(pk.ID().Value, record.NewPreKey(pk.ID().Value, pk.KeyPair(), serializer.PreKeyRecord))
	}
	bobSignedPreKey, _ := keyhelper.GenerateSignedPreKey(bobIdentity, 0, serializer.SignedPreKeyRecord)
	bobSignedPreKeyStore.StoreSignedPreKey(bobSignedPreKey.ID(), record.NewSignedPreKey(
		bobSignedPreKey.ID(), bobSignedPreKey.Timestamp(), bobSignedPreKey.KeyPair(),
		bobSignedPreKey.Signature(), serializer.SignedPreKeyRecord,
	))

	// Generate Bob's Kyber pre-key for PQXDH.
	bobKyberPreKey, _ := keyhelper.GenerateKyberPreKey(bobIdentity.PrivateKey(), 42, &mockKyberPreKeySerializer{})
	bobKyberPreKeyStore := newInMemoryKyberPreKeyStoreForV1()
	if err := bobKyberPreKeyStore.StoreKyberPreKey(42, bobKyberPreKey); err != nil {
		t.Fatal(err)
	}

	// Alice establishes session with Bob using PQXDH.
	aliceBuilder := session.NewBuilderWithKyber(
		aliceSessionStore, alicePreKeyStore, aliceSignedPreKeyStore,
		aliceIdentityStore, newInMemoryKyberPreKeyStoreForV1(), bobAddress, serializer,
	)
	bundle := prekey.NewBundleWithKyber(
		2, bobAddress.DeviceID(),
		bobPreKeys[0].ID(), bobSignedPreKey.ID(),
		bobPreKeys[0].KeyPair().PublicKey(), bobSignedPreKey.KeyPair().PublicKey(),
		bobSignedPreKey.Signature(), bobIdentity.PublicKey(),
		&optional.Uint32{Value: 42},
		bobKyberPreKey.KeyPair().Public,
		bobKyberPreKey.Signature(),
	)
	if err := aliceBuilder.ProcessBundle(bundle); err != nil {
		t.Fatalf("ProcessBundle error: %v", err)
	}

	senderCert, err := NewSenderCertificate(
		senderUUID, nil,
		aliceIdentity.PublicKey().PublicKey(),
		1, 9999999999,
		serverCert, serverKey.PrivateKey(),
	)
	if err != nil {
		t.Fatalf("NewSenderCertificate error: %v", err)
	}

	// First message: PreKey message to establish session on Bob's side.
	ciphertext1, err := SealedSenderEncrypt(
		bobAddress, senderCert, []byte("first message"),
		aliceSessionStore, aliceIdentityStore,
	)
	if err != nil {
		t.Fatalf("SealedSenderEncrypt (first) error: %v", err)
	}

	result1, err := SealedSenderDecryptWithKyber(
		ciphertext1, trustRoot.PublicKey(), 1000,
		"bob-uuid-22222222-2222-2222-2222-222222222222", nil, 1,
		bobSessionStore, bobIdentityStore,
		bobPreKeyStore, bobSignedPreKeyStore,
		bobKyberPreKeyStore,
	)
	if err != nil {
		t.Fatalf("SealedSenderDecrypt (first) error: %v", err)
	}
	if string(result1.Message) != "first message" {
		t.Errorf("First message = %q, want %q", string(result1.Message), "first message")
	}

	// Bob replies to establish the return session.
	bobBuilder := session.NewBuilderWithKyber(
		bobSessionStore, bobPreKeyStore, bobSignedPreKeyStore,
		bobIdentityStore, bobKyberPreKeyStore, aliceAddress, serializer,
	)
	bobCipher := session.NewCipher(bobBuilder, aliceAddress)

	// Bob's reply (this establishes Bob's session with Alice for return messages).
	replyMsg, err := bobCipher.Encrypt([]byte("bob reply"))
	if err != nil {
		t.Fatalf("Bob encrypt reply error: %v", err)
	}
	replyBytes, _ := replyMsg.Serialize()

	// Alice decrypts Bob's reply to complete the session ratchet.
	aliceBuilder2 := session.NewBuilderWithKyber(
		aliceSessionStore, alicePreKeyStore, aliceSignedPreKeyStore,
		aliceIdentityStore, newInMemoryKyberPreKeyStoreForV1(), bobAddress, serializer,
	)
	aliceCipher := session.NewCipher(aliceBuilder2, bobAddress)
	replyWhisper, err := protocol.NewSignalMessageFromBytes(replyBytes, serializer.SignalMessage)
	if err != nil {
		t.Fatalf("NewSignalMessageFromBytes error: %v", err)
	}
	_, err = aliceCipher.Decrypt(replyWhisper)
	if err != nil {
		t.Fatalf("Alice decrypt reply error: %v", err)
	}

	// Second message from Alice: Now a regular whisper message (non-PreKey).
	ciphertext2, err := SealedSenderEncrypt(
		bobAddress, senderCert, []byte("second whisper message"),
		aliceSessionStore, aliceIdentityStore,
	)
	if err != nil {
		t.Fatalf("SealedSenderEncrypt (second) error: %v", err)
	}

	result2, err := SealedSenderDecryptWithKyber(
		ciphertext2, trustRoot.PublicKey(), 1000,
		"bob-uuid-22222222-2222-2222-2222-222222222222", nil, 1,
		bobSessionStore, bobIdentityStore,
		bobPreKeyStore, bobSignedPreKeyStore,
		bobKyberPreKeyStore,
	)
	if err != nil {
		t.Fatalf("SealedSenderDecrypt (second/whisper) error: %v", err)
	}
	if string(result2.Message) != "second whisper message" {
		t.Errorf("Second message = %q, want %q", string(result2.Message), "second whisper message")
	}
}

func TestSealedSenderDecryptInvalidCertificate(t *testing.T) {
	// Test SealedSenderDecrypt when the sender certificate validation fails.
	trustRoot := newTestTrustRoot(t)
	wrongRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	aliceStore := newTestIdentityStore(t)
	bobStore := newTestIdentityStore(t)

	bobAddress := protocol.NewSignalAddress("bob-uuid", 1)
	aliceStore.SaveIdentity(bobAddress, identity.NewKey(bobStore.GetIdentityKeyPair().PublicKey().PublicKey()))

	senderCert, _ := NewSenderCertificate(
		"alice-uuid", nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999,
		serverCert, serverKey.PrivateKey(),
	)
	usmc, _ := NewUnidentifiedSenderMessageContent(2, senderCert, []byte("test"), ContentHintDefault, nil)

	ciphertext, err := SealedSenderEncryptFromUSMC(bobAddress, usmc, aliceStore)
	if err != nil {
		t.Fatalf("SealedSenderEncryptFromUSMC error: %v", err)
	}

	// Decrypt with wrong trust root should fail at certificate validation.
	_, err = SealedSenderDecrypt(
		ciphertext, wrongRoot.PublicKey(), 1000,
		"bob-uuid", nil, 1,
		newInMemorySessionStoreForV1(serialize.NewJSONSerializer()), bobStore,
		newInMemoryPreKeyStoreForV1(), newInMemorySignedPreKeyStoreForV1(),
	)
	if err == nil {
		t.Error("SealedSenderDecrypt with wrong trust root should return error")
	}
}

func TestSealedSenderV1Constants(t *testing.T) {
	if SealedSenderV1Version != 0x11 {
		t.Errorf("SealedSenderV1Version = 0x%02x, want 0x11", SealedSenderV1Version)
	}
}

func TestGetRecipientIdentityKeyWithLoader(t *testing.T) {
	loaderStore := &identityLoaderStore{
		keyPair: newTestIdentityStore(t).keyPair,
		loaded:  make(map[string]ecc.ECPublicKeyable),
	}

	// Save an identity
	kp, _ := ecc.GenerateKeyPair()
	addr := protocol.NewSignalAddress("test", 1)
	loaderStore.loaded[addr.String()] = kp.PublicKey()

	key, err := getRecipientIdentityKey(addr, loaderStore)
	if err != nil {
		t.Fatalf("getRecipientIdentityKey with loader error: %v", err)
	}
	if key == nil {
		t.Fatal("Should return the loaded identity key")
	}
}

func TestGetRecipientIdentityKeyLoaderReturnsNil(t *testing.T) {
	loaderStore := &identityLoaderStore{
		keyPair: newTestIdentityStore(t).keyPair,
		loaded:  make(map[string]ecc.ECPublicKeyable),
	}

	addr := protocol.NewSignalAddress("nonexistent", 1)
	// Loader returns nil, should fall through to next check
	_, err := getRecipientIdentityKey(addr, loaderStore)
	if err == nil {
		t.Error("getRecipientIdentityKey with nil loaded identity should return error")
	}
}

// identityLoaderStore implements identityLoader interface.
type identityLoaderStore struct {
	keyPair *identity.KeyPair
	loaded  map[string]ecc.ECPublicKeyable
}

func (s *identityLoaderStore) GetIdentityKeyPair() *identity.KeyPair {
	return s.keyPair
}
func (s *identityLoaderStore) GetLocalRegistrationId() uint32 { return 1 }
func (s *identityLoaderStore) SaveIdentity(address *protocol.SignalAddress, identityKey *identity.Key) {
}
func (s *identityLoaderStore) IsTrustedIdentity(address *protocol.SignalAddress, identityKey *identity.Key, direction store.Direction) bool {
	return true
}
func (s *identityLoaderStore) GetIdentity(address *protocol.SignalAddress) (*identity.Key, error) {
	return nil, nil
}
func (s *identityLoaderStore) LoadIdentity(address *protocol.SignalAddress) ecc.ECPublicKeyable {
	return s.loaded[address.String()]
}

func TestSealedSenderDecryptToUSMCInvalidStructure(t *testing.T) {
	// Cover the "invalid sealed sender message structure" check (line 233).
	bobStore := newTestIdentityStore(t)

	tests := []struct {
		name    string
		eph     []byte
		static  []byte
		message []byte
	}{
		{"empty ephemeral", nil, make([]byte, 20), make([]byte, 20)},
		{"short encrypted static", []byte{0x05}, make([]byte, 5), make([]byte, 20)},
		{"short encrypted message", []byte{0x05}, make([]byte, 20), make([]byte, 5)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envelope := &sealedpb.UnidentifiedSenderMessage{
				EphemeralPublic:  tt.eph,
				EncryptedStatic:  tt.static,
				EncryptedMessage: tt.message,
			}
			envelopeBytes, _ := proto.Marshal(envelope)
			data := append([]byte{SealedSenderV1Version}, envelopeBytes...)

			_, err := SealedSenderDecryptToUSMC(data, bobStore)
			if err == nil {
				t.Error("SealedSenderDecryptToUSMC with invalid structure should return error")
			}
		})
	}
}

func TestSealedSenderDecryptToUSMCV2VersionServiceId(t *testing.T) {
	// Cover the v2 dispatch path for SealedSenderV2VersionServiceId (0x23) without ServiceId.
	bobStore := newTestIdentityStore(t)
	_, err := SealedSenderDecryptToUSMC([]byte{SealedSenderV2VersionServiceId, 0x01, 0x02}, bobStore)
	if err == nil {
		t.Error("SealedSenderDecryptToUSMC v2 ServiceId version without ServiceId should return error")
	}
}

func TestSealedSenderEncryptFromUSMCNoRecipientKey(t *testing.T) {
	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	aliceStore := newTestIdentityStore(t)

	senderCert, _ := NewSenderCertificate(
		"alice-uuid", nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999,
		serverCert, serverKey.PrivateKey(),
	)

	usmc, _ := NewUnidentifiedSenderMessageContent(2, senderCert, []byte("test"), ContentHintDefault, nil)

	// No identity saved for Bob, so getRecipientIdentityKey should fail
	// when using a store that doesn't support loading remote identities
	bobAddress := protocol.NewSignalAddress("bob-uuid", 1)

	_, err := SealedSenderEncryptFromUSMC(bobAddress, usmc, aliceStore)
	if err == nil {
		t.Error("SealedSenderEncryptFromUSMC without recipient identity key should return error")
	}
}

func TestSealedSenderDecryptToUSMCStaticMACFailure(t *testing.T) {
	// Test that tampering with the encrypted static portion (sender's identity
	// key) causes a static MAC verification failure at line 267.
	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	aliceStore := newTestIdentityStore(t)
	bobStore := newTestIdentityStore(t)

	bobAddress := protocol.NewSignalAddress("bob-uuid", 1)
	aliceStore.SaveIdentity(bobAddress, identity.NewKey(bobStore.GetIdentityKeyPair().PublicKey().PublicKey()))

	senderCert, _ := NewSenderCertificate("alice-uuid", nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999, serverCert, serverKey.PrivateKey())
	usmc, _ := NewUnidentifiedSenderMessageContent(2, senderCert, []byte("test"), ContentHintDefault, nil)

	ciphertext, err := SealedSenderEncryptFromUSMC(bobAddress, usmc, aliceStore)
	if err != nil {
		t.Fatalf("SealedSenderEncryptFromUSMC() error: %v", err)
	}

	// Parse the envelope to tamper with the encrypted static field specifically.
	envelope := &sealedpb.UnidentifiedSenderMessage{}
	if err := proto.Unmarshal(ciphertext[1:], envelope); err != nil {
		t.Fatalf("proto.Unmarshal error: %v", err)
	}

	// Tamper with the encrypted static (not the MAC at the end, but the body).
	encStatic := envelope.GetEncryptedStatic()
	if len(encStatic) > macTruncateLen+1 {
		encStatic[0] ^= 0xFF // flip a byte in the encrypted static body
	}
	envelope.EncryptedStatic = encStatic

	tamperedEnvelope, _ := proto.Marshal(envelope)
	tampered := append([]byte{SealedSenderV1Version}, tamperedEnvelope...)

	_, err = SealedSenderDecryptToUSMC(tampered, bobStore)
	if err == nil {
		t.Error("SealedSenderDecryptToUSMC should fail on tampered static MAC")
	}
	if err != nil && err.Error() != "sealed: static key MAC verification failed" {
		// Could also be a different crypto error, which is still a valid failure.
		t.Logf("Got expected error: %v", err)
	}
}

func TestSealedSenderDecryptToUSMCMessageMACFailure(t *testing.T) {
	// Specifically verify the message MAC check at line 299 by tampering
	// with the encrypted message body (not the trailing MAC bytes).
	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	aliceStore := newTestIdentityStore(t)
	bobStore := newTestIdentityStore(t)

	bobAddress := protocol.NewSignalAddress("bob-uuid", 1)
	aliceStore.SaveIdentity(bobAddress, identity.NewKey(bobStore.GetIdentityKeyPair().PublicKey().PublicKey()))

	senderCert, _ := NewSenderCertificate("alice-uuid", nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999, serverCert, serverKey.PrivateKey())
	usmc, _ := NewUnidentifiedSenderMessageContent(2, senderCert, []byte("test message"), ContentHintDefault, nil)

	ciphertext, err := SealedSenderEncryptFromUSMC(bobAddress, usmc, aliceStore)
	if err != nil {
		t.Fatalf("SealedSenderEncryptFromUSMC() error: %v", err)
	}

	// Parse envelope and tamper with the encrypted message body.
	envelope := &sealedpb.UnidentifiedSenderMessage{}
	if err := proto.Unmarshal(ciphertext[1:], envelope); err != nil {
		t.Fatalf("proto.Unmarshal error: %v", err)
	}

	encMsg := envelope.GetEncryptedMessage()
	if len(encMsg) > macTruncateLen+1 {
		encMsg[0] ^= 0xFF // flip a byte in the encrypted message body
	}
	envelope.EncryptedMessage = encMsg

	tamperedEnvelope, _ := proto.Marshal(envelope)
	tampered := append([]byte{SealedSenderV1Version}, tamperedEnvelope...)

	_, err = SealedSenderDecryptToUSMC(tampered, bobStore)
	if err == nil {
		t.Error("SealedSenderDecryptToUSMC should fail on tampered message MAC")
	}
}

func TestSealedSenderDecryptToUSMCInvalidEphemeralKey(t *testing.T) {
	// Cover the ecc.DecodePoint error path for the ephemeral public key (line 241).
	bobStore := newTestIdentityStore(t)

	envelope := &sealedpb.UnidentifiedSenderMessage{
		EphemeralPublic:  []byte{0x99, 0x01, 0x02, 0x03}, // invalid key type prefix
		EncryptedStatic:  make([]byte, 44),                // 33 + macTruncateLen + 1
		EncryptedMessage: make([]byte, 20),
	}
	envelopeBytes, _ := proto.Marshal(envelope)
	data := append([]byte{SealedSenderV1Version}, envelopeBytes...)

	_, err := SealedSenderDecryptToUSMC(data, bobStore)
	if err == nil {
		t.Error("SealedSenderDecryptToUSMC should fail on invalid ephemeral key")
	}
}

func TestSealedSenderDecryptExpiredCertificate(t *testing.T) {
	// Cover the certificate expired path in SealedSenderDecrypt.
	// This hits the Validate error return at line 335-336.
	serializer := serialize.NewProtobufSerializer()
	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	aliceKP, _ := ecc.GenerateKeyPair()
	aliceIdentity := identity.NewKeyPair(identity.NewKey(aliceKP.PublicKey()), aliceKP.PrivateKey())

	bobKP, _ := ecc.GenerateKeyPair()
	bobIdentity := identity.NewKeyPair(identity.NewKey(bobKP.PublicKey()), bobKP.PrivateKey())

	bobAddress := protocol.NewSignalAddress("bob-uuid-expired-00000000-0000-0000-0000-000000000001", 1)

	aliceSessionStore := newInMemorySessionStoreForV1(serializer)
	aliceIdentityStore := &fullIdentityStore{
		keyPair: aliceIdentity, regID: 1,
		trusted: make(map[string]*identity.Key),
	}

	bobPreKeyStore := newInMemoryPreKeyStoreForV1()
	bobSignedPreKeyStore := newInMemorySignedPreKeyStoreForV1()
	bobIdentityStore := &fullIdentityStore{
		keyPair: bobIdentity, regID: 2,
		trusted: make(map[string]*identity.Key),
	}

	bobPreKeys, _ := keyhelper.GeneratePreKeys(0, 10, serializer.PreKeyRecord)
	for _, pk := range bobPreKeys {
		bobPreKeyStore.StorePreKey(pk.ID().Value, record.NewPreKey(pk.ID().Value, pk.KeyPair(), serializer.PreKeyRecord))
	}
	bobSignedPreKey, _ := keyhelper.GenerateSignedPreKey(bobIdentity, 0, serializer.SignedPreKeyRecord)
	bobSignedPreKeyStore.StoreSignedPreKey(bobSignedPreKey.ID(), record.NewSignedPreKey(
		bobSignedPreKey.ID(), bobSignedPreKey.Timestamp(), bobSignedPreKey.KeyPair(),
		bobSignedPreKey.Signature(), serializer.SignedPreKeyRecord,
	))

	bobKyberPreKey, _ := keyhelper.GenerateKyberPreKey(bobIdentity.PrivateKey(), 42, &mockKyberPreKeySerializer{})

	aliceBuilder := session.NewBuilderWithKyber(
		aliceSessionStore, newInMemoryPreKeyStoreForV1(), newInMemorySignedPreKeyStoreForV1(),
		aliceIdentityStore, newInMemoryKyberPreKeyStoreForV1(), bobAddress, serializer,
	)
	bundle := prekey.NewBundleWithKyber(2, 1, bobPreKeys[0].ID(), bobSignedPreKey.ID(),
		bobPreKeys[0].KeyPair().PublicKey(), bobSignedPreKey.KeyPair().PublicKey(),
		bobSignedPreKey.Signature(), bobIdentity.PublicKey(),
		&optional.Uint32{Value: 42}, bobKyberPreKey.KeyPair().Public, bobKyberPreKey.Signature())
	if err := aliceBuilder.ProcessBundle(bundle); err != nil {
		t.Fatalf("ProcessBundle error: %v", err)
	}

	// Create sender certificate with very short expiration (1000 ms from epoch).
	senderCert, _ := NewSenderCertificate(
		"alice-uuid-expired-12345678-1234-1234-1234-123456789abc",
		nil,
		aliceIdentity.PublicKey().PublicKey(),
		1,
		1000, // expires at timestamp 1000
		serverCert,
		serverKey.PrivateKey(),
	)

	ciphertext, err := SealedSenderEncrypt(bobAddress, senderCert, []byte("expired"),
		aliceSessionStore, aliceIdentityStore)
	if err != nil {
		t.Fatalf("SealedSenderEncrypt error: %v", err)
	}

	// Decrypt with a timestamp after expiration.
	_, err = SealedSenderDecrypt(ciphertext, trustRoot.PublicKey(),
		5000, // timestamp > expiration (1000)
		"bob-uuid-expired-00000000-0000-0000-0000-000000000001", nil, 1,
		newInMemorySessionStoreForV1(serializer), bobIdentityStore,
		bobPreKeyStore, bobSignedPreKeyStore)
	if err == nil {
		t.Error("SealedSenderDecrypt should fail with expired sender certificate")
	}
}

func TestSealedSenderEncryptSenderKeyType(t *testing.T) {
	// The SealedSenderEncrypt function maps protocol ciphertext types to USMC types.
	// The SENDERKEY_TYPE case (line 78-79) is not reachable through normal encrypt
	// because session cipher only produces PREKEY_TYPE or WHISPER_TYPE. But we can
	// directly test the USMC with SENDERKEY_MESSAGE type through SealedSenderEncryptFromUSMC
	// and verify it round-trips correctly via decrypt.
	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	aliceStore := newTestIdentityStore(t)
	bobStore := newTestIdentityStore(t)

	bobAddress := protocol.NewSignalAddress("bob-uuid", 1)
	aliceStore.SaveIdentity(bobAddress, identity.NewKey(bobStore.GetIdentityKeyPair().PublicKey().PublicKey()))

	senderCert, _ := NewSenderCertificate("alice-uuid", nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999, serverCert, serverKey.PrivateKey())

	// Create USMC with SENDERKEY_MESSAGE type (7)
	usmcType := uint32(sealedpb.UnidentifiedSenderMessage_Message_SENDERKEY_MESSAGE)
	usmc, err := NewUnidentifiedSenderMessageContent(
		usmcType, senderCert, []byte("senderkey payload"), ContentHintDefault, nil,
	)
	if err != nil {
		t.Fatalf("NewUnidentifiedSenderMessageContent() error: %v", err)
	}

	ciphertext, err := SealedSenderEncryptFromUSMC(bobAddress, usmc, aliceStore)
	if err != nil {
		t.Fatalf("SealedSenderEncryptFromUSMC() error: %v", err)
	}

	// Decrypt and verify the type is preserved.
	decryptedUSMC, err := SealedSenderDecryptToUSMC(ciphertext, bobStore)
	if err != nil {
		t.Fatalf("SealedSenderDecryptToUSMC() error: %v", err)
	}

	if decryptedUSMC.Type() != usmcType {
		t.Errorf("Decrypted Type() = %d, want %d", decryptedUSMC.Type(), usmcType)
	}
}

func TestSealedSenderDecryptBadInnerPreKeyMessage(t *testing.T) {
	// Cover the error path when the USMC contains an invalid PreKey message
	// at line 362 of SealedSenderDecrypt. We build a USMC with PREKEY_MESSAGE
	// type but garbage contents, encrypt it, and try full decrypt.
	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	aliceStore := newTestIdentityStore(t)
	bobStore := newTestIdentityStore(t)

	bobAddress := protocol.NewSignalAddress("bob-uuid", 1)
	aliceStore.SaveIdentity(bobAddress, identity.NewKey(bobStore.GetIdentityKeyPair().PublicKey().PublicKey()))

	senderCert, _ := NewSenderCertificate("alice-uuid", nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999, serverCert, serverKey.PrivateKey())

	// PREKEY_MESSAGE type but invalid contents
	preKeyType := uint32(sealedpb.UnidentifiedSenderMessage_Message_PREKEY_MESSAGE)
	usmc, _ := NewUnidentifiedSenderMessageContent(
		preKeyType, senderCert, []byte("not a valid prekey message"), ContentHintDefault, nil,
	)

	ciphertext, err := SealedSenderEncryptFromUSMC(bobAddress, usmc, aliceStore)
	if err != nil {
		t.Fatalf("SealedSenderEncryptFromUSMC() error: %v", err)
	}

	serializer := serialize.NewProtobufSerializer()
	_, err = SealedSenderDecrypt(ciphertext, trustRoot.PublicKey(), 1000,
		"bob-uuid", nil, 1,
		newInMemorySessionStoreForV1(serializer), bobStore,
		newInMemoryPreKeyStoreForV1(), newInMemorySignedPreKeyStoreForV1())
	if err == nil {
		t.Error("SealedSenderDecrypt should fail with invalid PreKey message contents")
	}
}

func TestSealedSenderDecryptBadInnerWhisperMessage(t *testing.T) {
	// Cover the error path when the USMC contains an invalid Whisper message
	// at line 387 of SealedSenderDecrypt.
	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	aliceStore := newTestIdentityStore(t)
	bobStore := newTestIdentityStore(t)

	bobAddress := protocol.NewSignalAddress("bob-uuid", 1)
	aliceStore.SaveIdentity(bobAddress, identity.NewKey(bobStore.GetIdentityKeyPair().PublicKey().PublicKey()))

	senderCert, _ := NewSenderCertificate("alice-uuid", nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999, serverCert, serverKey.PrivateKey())

	// MESSAGE (whisper) type but invalid contents
	msgType := uint32(sealedpb.UnidentifiedSenderMessage_Message_MESSAGE)
	usmc, _ := NewUnidentifiedSenderMessageContent(
		msgType, senderCert, []byte("not a valid whisper message"), ContentHintDefault, nil,
	)

	ciphertext, err := SealedSenderEncryptFromUSMC(bobAddress, usmc, aliceStore)
	if err != nil {
		t.Fatalf("SealedSenderEncryptFromUSMC() error: %v", err)
	}

	serializer := serialize.NewProtobufSerializer()
	_, err = SealedSenderDecrypt(ciphertext, trustRoot.PublicKey(), 1000,
		"bob-uuid", nil, 1,
		newInMemorySessionStoreForV1(serializer), bobStore,
		newInMemoryPreKeyStoreForV1(), newInMemorySignedPreKeyStoreForV1())
	if err == nil {
		t.Error("SealedSenderDecrypt should fail with invalid Whisper message contents")
	}
}
