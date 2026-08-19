package sealed

import (
	"encoding/binary"
	"errors"
	"testing"

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

// inMemorySessionStore for v2 tests.
type inMemorySessionStore struct {
	sessions   map[string]*record.Session
	serializer *serialize.Serializer
}

func newInMemorySessionStore(serializer *serialize.Serializer) *inMemorySessionStore {
	return &inMemorySessionStore{
		sessions:   make(map[string]*record.Session),
		serializer: serializer,
	}
}

func (s *inMemorySessionStore) LoadSession(address *protocol.SignalAddress) (*record.Session, error) {
	if sess, ok := s.sessions[address.String()]; ok {
		return sess, nil
	}
	return record.NewSession(s.serializer.Session, s.serializer.State), nil
}

func (s *inMemorySessionStore) GetSubDeviceSessions(name string) ([]uint32, error) {
	return nil, nil
}

func (s *inMemorySessionStore) StoreSession(address *protocol.SignalAddress, r *record.Session) error {
	s.sessions[address.String()] = r
	return nil
}

func (s *inMemorySessionStore) ContainsSession(address *protocol.SignalAddress) (bool, error) {
	_, ok := s.sessions[address.String()]
	return ok, nil
}

func (s *inMemorySessionStore) DeleteSession(address *protocol.SignalAddress) error {
	delete(s.sessions, address.String())
	return nil
}

func (s *inMemorySessionStore) DeleteAllSessions() error {
	s.sessions = make(map[string]*record.Session)
	return nil
}

// inMemoryPreKeyStore for v2 tests.
type inMemoryPreKeyStore struct {
	store map[uint32]*record.PreKey
}

func newInMemoryPreKeyStore() *inMemoryPreKeyStore {
	return &inMemoryPreKeyStore{store: make(map[uint32]*record.PreKey)}
}

func (s *inMemoryPreKeyStore) LoadPreKey(id uint32) (*record.PreKey, error) {
	return s.store[id], nil
}
func (s *inMemoryPreKeyStore) StorePreKey(id uint32, r *record.PreKey) error {
	s.store[id] = r
	return nil
}
func (s *inMemoryPreKeyStore) ContainsPreKey(id uint32) (bool, error) {
	_, ok := s.store[id]
	return ok, nil
}
func (s *inMemoryPreKeyStore) RemovePreKey(id uint32) error {
	delete(s.store, id)
	return nil
}

// inMemorySignedPreKeyStore for v2 tests.
type inMemorySignedPreKeyStore struct {
	store map[uint32]*record.SignedPreKey
}

func newInMemorySignedPreKeyStore() *inMemorySignedPreKeyStore {
	return &inMemorySignedPreKeyStore{store: make(map[uint32]*record.SignedPreKey)}
}

func (s *inMemorySignedPreKeyStore) LoadSignedPreKey(id uint32) (*record.SignedPreKey, error) {
	return s.store[id], nil
}
func (s *inMemorySignedPreKeyStore) LoadSignedPreKeys() ([]*record.SignedPreKey, error) {
	var keys []*record.SignedPreKey
	for _, k := range s.store {
		keys = append(keys, k)
	}
	return keys, nil
}
func (s *inMemorySignedPreKeyStore) StoreSignedPreKey(id uint32, r *record.SignedPreKey) error {
	s.store[id] = r
	return nil
}
func (s *inMemorySignedPreKeyStore) ContainsSignedPreKey(id uint32) (bool, error) {
	_, ok := s.store[id]
	return ok, nil
}
func (s *inMemorySignedPreKeyStore) RemoveSignedPreKey(id uint32) error {
	delete(s.store, id)
	return nil
}

// v2TestIdentityStore extends testIdentityStore with session identity loading.
type v2TestIdentityStore struct {
	keyPair        *identity.KeyPair
	registrationID uint32
	trustedKeys    map[string]*identity.Key
}

func newV2TestIdentityStore(t *testing.T) *v2TestIdentityStore {
	t.Helper()
	kp, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	identityKey := identity.NewKey(kp.PublicKey())
	identityKeyPair := identity.NewKeyPair(identityKey, kp.PrivateKey())
	return &v2TestIdentityStore{
		keyPair:        identityKeyPair,
		registrationID: keyhelper.GenerateRegistrationID(),
		trustedKeys:    make(map[string]*identity.Key),
	}
}

func (s *v2TestIdentityStore) GetIdentityKeyPair() *identity.KeyPair {
	return s.keyPair
}

func (s *v2TestIdentityStore) GetLocalRegistrationId() uint32 {
	return s.registrationID
}

func (s *v2TestIdentityStore) SaveIdentity(address *protocol.SignalAddress, identityKey *identity.Key) (store.IdentityChange, error) {
	prev, existed := s.trustedKeys[address.String()]
	s.trustedKeys[address.String()] = identityKey
	if existed && prev != identityKey {
		return store.IdentityChangeReplacedExisting, nil
	}
	return store.IdentityChangeNewOrUnchanged, nil
}

func (s *v2TestIdentityStore) IsTrustedIdentity(address *protocol.SignalAddress, identityKey *identity.Key, direction store.Direction) (bool, error) {
	return true, nil
}

func (s *v2TestIdentityStore) GetIdentity(address *protocol.SignalAddress) (*identity.Key, error) {
	return s.trustedKeys[address.String()], nil
}

// GetIdentityKey satisfies the sessionIdentityStore interface.
func (s *v2TestIdentityStore) GetIdentityKey(address *protocol.SignalAddress) (ecc.ECPublicKeyable, error) {
	k := s.trustedKeys[address.String()]
	if k != nil {
		return k.PublicKey(), nil
	}
	return nil, nil
}

func TestSealedSenderV2Constants(t *testing.T) {
	if SealedSenderV2VersionUUID != 0x22 {
		t.Errorf("SealedSenderV2VersionUUID = 0x%02x, want 0x22", SealedSenderV2VersionUUID)
	}
	if SealedSenderV2VersionServiceId != 0x23 {
		t.Errorf("SealedSenderV2VersionServiceId = 0x%02x, want 0x23", SealedSenderV2VersionServiceId)
	}
}

func setupV2Session(t *testing.T) (
	aliceStore *v2TestIdentityStore,
	bobStore *v2TestIdentityStore,
	aliceAddress *protocol.SignalAddress,
	bobAddress *protocol.SignalAddress,
	bobSession *record.Session,
	serializer *serialize.Serializer,
) {
	t.Helper()
	serializer = serialize.NewJSONSerializer()

	aliceStore = newV2TestIdentityStore(t)
	bobStore = newV2TestIdentityStore(t)

	aliceAddress = protocol.NewSignalAddress("9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a", 1)
	bobAddress = protocol.NewSignalAddress("a1b2c3d4-e5f6-7890-abcd-ef0123456789", 1)

	// Generate Bob's pre keys
	bobPreKeys, err := keyhelper.GeneratePreKeys(0, 10, serializer.PreKeyRecord)
	if err != nil {
		t.Fatalf("GeneratePreKeys error: %v", err)
	}
	bobPreKeyStore := newInMemoryPreKeyStore()
	for _, pk := range bobPreKeys {
		if err := bobPreKeyStore.StorePreKey(pk.ID().Value, record.NewPreKey(pk.ID().Value, pk.KeyPair(), serializer.PreKeyRecord)); err != nil {
			t.Fatalf("setup: StorePreKey: %v", err)
		}
	}

	bobSignedPreKey, err := keyhelper.GenerateSignedPreKey(bobStore.keyPair, 0, serializer.SignedPreKeyRecord)
	if err != nil {
		t.Fatalf("GenerateSignedPreKey error: %v", err)
	}
	bobSignedPreKeyStore := newInMemorySignedPreKeyStore()
	if err := bobSignedPreKeyStore.StoreSignedPreKey(bobSignedPreKey.ID(), record.NewSignedPreKey(
		bobSignedPreKey.ID(), bobSignedPreKey.Timestamp(), bobSignedPreKey.KeyPair(),
		bobSignedPreKey.Signature(), serializer.SignedPreKeyRecord,
	)); err != nil {
		t.Fatalf("setup: StoreSignedPreKey: %v", err)
	}

	// Generate Bob's Kyber pre-key for PQXDH
	bobKyberPreKey, err := keyhelper.GenerateKyberPreKey(bobStore.keyPair.PrivateKey(), 42, &mockKyberPreKeySerializer{})
	if err != nil {
		t.Fatalf("GenerateKyberPreKey error: %v", err)
	}

	// Alice processes Bob's pre key bundle to establish a session
	aliceSessionStore := newInMemorySessionStore(serializer)
	aliceBuilder := session.NewBuilderWithKyber(
		aliceSessionStore, newInMemoryPreKeyStore(), newInMemorySignedPreKeyStore(),
		aliceStore, newInMemoryKyberPreKeyStoreForV1(), bobAddress, serializer,
	)

	bundle := prekey.NewBundleWithKyber(
		bobStore.registrationID, bobAddress.DeviceID(),
		bobPreKeys[0].ID(), bobSignedPreKey.ID(),
		bobPreKeys[0].KeyPair().PublicKey(), bobSignedPreKey.KeyPair().PublicKey(),
		bobSignedPreKey.Signature(), bobStore.keyPair.PublicKey(),
		&optional.Uint32{Value: 42},
		bobKyberPreKey.PublicKey(),
		bobKyberPreKey.Signature(),
	)
	if err := aliceBuilder.ProcessBundle(bundle); err != nil {
		t.Fatalf("ProcessBundle error: %v", err)
	}

	// Alice now has a session with Bob
	var loadErr error
	bobSession, loadErr = aliceSessionStore.LoadSession(bobAddress)
	if loadErr != nil {
		t.Fatalf("LoadSession error: %v", loadErr)
	}
	if bobSession == nil {
		t.Fatal("Alice should have a session with Bob")
	}

	// Save identities
	if _, err := aliceStore.SaveIdentity(bobAddress, identity.NewKey(bobStore.keyPair.PublicKey().PublicKey())); err != nil {
		t.Fatalf("setup: SaveIdentity: %v", err)
	}
	if _, err := bobStore.SaveIdentity(aliceAddress, identity.NewKey(aliceStore.keyPair.PublicKey().PublicKey())); err != nil {
		t.Fatalf("setup: SaveIdentity: %v", err)
	}

	return
}

func TestSealedSenderMultiRecipientEncryptAndV2Decrypt(t *testing.T) {
	aliceStore, bobStore, _, bobAddress, bobSession, _ := setupV2Session(t)

	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	senderCert, err := NewSenderCertificate(
		"9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a",
		nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999,
		serverCert, serverKey.PrivateKey(),
	)
	if err != nil {
		t.Fatalf("NewSenderCertificate error: %v", err)
	}

	usmc, err := NewUnidentifiedSenderMessageContent(
		2, senderCert, []byte("v2 encrypted content"), ContentHintDefault, nil,
	)
	if err != nil {
		t.Fatalf("NewUnidentifiedSenderMessageContent error: %v", err)
	}

	// Encrypt for Bob using v2 multi-recipient
	ciphertext, err := SealedSenderMultiRecipientEncrypt(
		[]*protocol.SignalAddress{bobAddress},
		[]*record.Session{bobSession},
		nil,
		usmc,
		aliceStore,
	)
	if err != nil {
		t.Fatalf("SealedSenderMultiRecipientEncrypt error: %v", err)
	}

	if len(ciphertext) == 0 {
		t.Fatal("Ciphertext should not be empty")
	}
	if ciphertext[0] != SealedSenderV2VersionServiceId {
		t.Errorf("Version byte = 0x%02x, want 0x%02x", ciphertext[0], SealedSenderV2VersionServiceId)
	}

	// Decrypt as Bob
	bobServiceId, err := protocol.ServiceIdFromString(protocol.ServiceIdKindACI, bobAddress.Name())
	if err != nil {
		t.Fatalf("ServiceIdFromString error: %v", err)
	}

	decryptedUSMC, err := SealedSenderV2DecryptToUSMC(ciphertext, bobServiceId, bobStore)
	if err != nil {
		t.Fatalf("SealedSenderV2DecryptToUSMC error: %v", err)
	}

	if decryptedUSMC.Type() != 2 {
		t.Errorf("Decrypted Type() = %d, want 2", decryptedUSMC.Type())
	}
	if string(decryptedUSMC.Contents()) != "v2 encrypted content" {
		t.Errorf("Decrypted Contents() = %q, want %q", string(decryptedUSMC.Contents()), "v2 encrypted content")
	}
}

func TestSealedSenderMultiRecipientEncryptMismatchedLengths(t *testing.T) {
	aliceStore := newV2TestIdentityStore(t)

	_, err := SealedSenderMultiRecipientEncrypt(
		[]*protocol.SignalAddress{protocol.NewSignalAddress("bob", 1)},
		nil, // no sessions
		nil,
		&UnidentifiedSenderMessageContent{},
		aliceStore,
	)
	if err == nil {
		t.Error("Should error when destinations and sessions have different lengths")
	}
}

func TestSealedSenderMultiRecipientEncryptNilUSMC(t *testing.T) {
	aliceStore := newV2TestIdentityStore(t)

	_, err := SealedSenderMultiRecipientEncrypt(
		nil, nil, nil, nil, aliceStore,
	)
	if err == nil {
		t.Error("Should error when usmc is nil")
	}
}

func TestSealedSenderMultiRecipientEncryptNilSession(t *testing.T) {
	aliceStore := newV2TestIdentityStore(t)
	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	senderCert, _ := NewSenderCertificate(
		"9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a", nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999, serverCert, serverKey.PrivateKey(),
	)
	usmc, _ := NewUnidentifiedSenderMessageContent(2, senderCert, []byte("test"), ContentHintDefault, nil)

	bobAddress := protocol.NewSignalAddress("a1b2c3d4-e5f6-7890-abcd-ef0123456789", 1)
	_, err := SealedSenderMultiRecipientEncrypt(
		[]*protocol.SignalAddress{bobAddress},
		[]*record.Session{nil},
		nil,
		usmc,
		aliceStore,
	)
	if err == nil {
		t.Error("Should error when session is nil")
	}
}

func TestSealedSenderMultiRecipientEncryptExcludedRecipient(t *testing.T) {
	aliceStore, _, _, bobAddress, bobSession, _ := setupV2Session(t)

	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	senderCert, _ := NewSenderCertificate(
		"9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a", nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999, serverCert, serverKey.PrivateKey(),
	)
	usmc, _ := NewUnidentifiedSenderMessageContent(2, senderCert, []byte("test"), ContentHintDefault, nil)

	// Exclude Bob
	bobServiceId, _ := protocol.ServiceIdFromString(protocol.ServiceIdKindACI, bobAddress.Name())

	ciphertext, err := SealedSenderMultiRecipientEncrypt(
		[]*protocol.SignalAddress{bobAddress},
		[]*record.Session{bobSession},
		[]protocol.ServiceId{bobServiceId},
		usmc,
		aliceStore,
	)
	if err != nil {
		t.Fatalf("SealedSenderMultiRecipientEncrypt error: %v", err)
	}

	// Bob is excluded, so decryption should fail
	_, err = SealedSenderV2DecryptToUSMC(ciphertext, bobServiceId, newV2TestIdentityStore(t))
	if err == nil {
		t.Error("Excluded recipient should not be able to decrypt")
	}
}

func TestSealedSenderV2DecryptToUSMCTooShort(t *testing.T) {
	bobStore := newV2TestIdentityStore(t)
	bobSid := protocol.NewACI([16]byte{1, 2, 3})

	_, err := SealedSenderV2DecryptToUSMC([]byte{}, bobSid, bobStore)
	if err == nil {
		t.Error("Should error on empty ciphertext")
	}
}

func TestSealedSenderV2DecryptToUSMCWrongVersion(t *testing.T) {
	bobStore := newV2TestIdentityStore(t)
	bobSid := protocol.NewACI([16]byte{1, 2, 3})

	_, err := SealedSenderV2DecryptToUSMC([]byte{0x99, 0x01, 0x02}, bobSid, bobStore)
	if err == nil {
		t.Error("Should error on unsupported version")
	}
}

func TestSealedSenderV2DecryptToUSMCRecipientNotFound(t *testing.T) {
	aliceStore, _, _, bobAddress, bobSession, _ := setupV2Session(t)

	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	senderCert, _ := NewSenderCertificate(
		"9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a", nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999, serverCert, serverKey.PrivateKey(),
	)
	usmc, _ := NewUnidentifiedSenderMessageContent(2, senderCert, []byte("test"), ContentHintDefault, nil)

	ciphertext, err := SealedSenderMultiRecipientEncrypt(
		[]*protocol.SignalAddress{bobAddress},
		[]*record.Session{bobSession},
		nil, usmc, aliceStore,
	)
	if err != nil {
		t.Fatalf("SealedSenderMultiRecipientEncrypt error: %v", err)
	}

	// Decrypt as someone who is NOT Bob
	otherSid := protocol.NewACI([16]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	otherStore := newV2TestIdentityStore(t)

	_, err = SealedSenderV2DecryptToUSMC(ciphertext, otherSid, otherStore)
	if err == nil {
		t.Error("Should error when recipient is not found in message")
	}
}

func TestV2ParseMessageTruncatedServiceId(t *testing.T) {
	// 1 recipient, but not enough bytes for service ID
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, 1) // 1 recipient
	data := buf[:n]
	data = append(data, make([]byte, 5)...) // only 5 bytes, need 17

	_, err := v2ParseMessage(data, SealedSenderV2VersionServiceId)
	if err == nil {
		t.Error("Should error on truncated service ID")
	}
}

func TestV2ParseMessageTruncatedDeviceCount(t *testing.T) {
	// 1 recipient with valid service ID but truncated device count
	var buf []byte
	varint := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(varint, 1) // 1 recipient
	buf = append(buf, varint[:n]...)
	buf = append(buf, make([]byte, v2ServiceIdSize)...) // service ID
	// No device count varint following

	_, err := v2ParseMessage(buf, SealedSenderV2VersionServiceId)
	if err == nil {
		t.Error("Should error on truncated device count")
	}
}

func TestV2ParseMessageTooManyDevices(t *testing.T) {
	var buf []byte
	varint := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(varint, 1) // 1 recipient
	buf = append(buf, varint[:n]...)
	buf = append(buf, make([]byte, v2ServiceIdSize)...) // service ID (all zeros = ACI)
	n = binary.PutUvarint(varint, 1001)                 // too many devices
	buf = append(buf, varint[:n]...)

	_, err := v2ParseMessage(buf, SealedSenderV2VersionServiceId)
	if err == nil {
		t.Error("Should error on too many devices")
	}
}

func TestV2ParseMessageTruncatedRegistrationId(t *testing.T) {
	var buf []byte
	varint := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(varint, 1) // 1 recipient
	buf = append(buf, varint[:n]...)
	buf = append(buf, make([]byte, v2ServiceIdSize)...) // service ID
	n = binary.PutUvarint(varint, 1)                    // 1 device
	buf = append(buf, varint[:n]...)
	n = binary.PutUvarint(varint, 1) // device ID = 1
	buf = append(buf, varint[:n]...)
	// Missing registration ID bytes

	_, err := v2ParseMessage(buf, SealedSenderV2VersionServiceId)
	if err == nil {
		t.Error("Should error on truncated registration ID")
	}
}

func TestV2ParseMessageTruncatedPerRecipientData(t *testing.T) {
	var buf []byte
	varint := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(varint, 1) // 1 recipient
	buf = append(buf, varint[:n]...)
	buf = append(buf, make([]byte, v2ServiceIdSize)...) // service ID
	n = binary.PutUvarint(varint, 1)                    // 1 device
	buf = append(buf, varint[:n]...)
	n = binary.PutUvarint(varint, 1) // device ID = 1
	buf = append(buf, varint[:n]...)
	buf = append(buf, 0x00, 0x01) // registration ID = 1
	// Missing C_i and AT_i

	_, err := v2ParseMessage(buf, SealedSenderV2VersionServiceId)
	if err == nil {
		t.Error("Should error on truncated per-recipient data")
	}
}

func TestV2ParseMessageTruncatedEphemeralKey(t *testing.T) {
	var buf []byte
	varint := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(varint, 1) // 1 recipient
	buf = append(buf, varint[:n]...)
	buf = append(buf, make([]byte, v2ServiceIdSize)...) // service ID
	n = binary.PutUvarint(varint, 1)                    // 1 device
	buf = append(buf, varint[:n]...)
	n = binary.PutUvarint(varint, 1) // device ID = 1
	buf = append(buf, varint[:n]...)
	buf = append(buf, 0x00, 0x01)                           // registration ID = 1
	buf = append(buf, make([]byte, v2EncryptedMKeySize)...) // C_i
	buf = append(buf, make([]byte, v2AuthTagSize)...)       // AT_i
	// Missing ephemeral key

	_, err := v2ParseMessage(buf, SealedSenderV2VersionServiceId)
	if err == nil {
		t.Error("Should error on truncated ephemeral key")
	}
}

func TestV2ParseMessageMissingPayload(t *testing.T) {
	var buf []byte
	varint := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(varint, 1) // 1 recipient
	buf = append(buf, varint[:n]...)
	buf = append(buf, make([]byte, v2ServiceIdSize)...)     // service ID (17 bytes)
	buf = append(buf, 0x01)                                 // device ID = 1 (single byte)
	buf = append(buf, 0x00, 0x01)                           // registration ID = 1, no has_more bit
	buf = append(buf, make([]byte, v2EncryptedMKeySize)...) // C_i
	buf = append(buf, make([]byte, v2AuthTagSize)...)       // AT_i
	buf = append(buf, make([]byte, 32)...)                  // ephemeral key
	// No payload

	_, err := v2ParseMessage(buf, SealedSenderV2VersionServiceId)
	if err == nil {
		t.Error("Should error on missing payload")
	}
}

func TestSealedSenderV2DecryptToUSMCInvalidRecipientFields(t *testing.T) {
	// Build a valid v2 message, then tamper with the recipient fields to trigger
	// validation errors inside SealedSenderV2DecryptToUSMC.
	aliceStore, bobStore, _, bobAddress, bobSession, _ := setupV2Session(t)

	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	senderCert, _ := NewSenderCertificate(
		"9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a", nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999, serverCert, serverKey.PrivateKey(),
	)
	usmc, _ := NewUnidentifiedSenderMessageContent(2, senderCert, []byte("test"), ContentHintDefault, nil)

	ciphertext, err := SealedSenderMultiRecipientEncrypt(
		[]*protocol.SignalAddress{bobAddress},
		[]*record.Session{bobSession},
		nil, usmc, aliceStore,
	)
	if err != nil {
		t.Fatalf("SealedSenderMultiRecipientEncrypt error: %v", err)
	}

	bobServiceId, _ := protocol.ServiceIdFromString(protocol.ServiceIdKindACI, bobAddress.Name())

	t.Run("invalid encrypted M key size", func(t *testing.T) {
		// Parse the v2 message to find and tamper with the recipient's encrypted M key.
		parsed, err := v2ParseMessage(ciphertext[1:], ciphertext[0])
		if err != nil {
			t.Fatalf("v2ParseMessage error: %v", err)
		}
		// Tamper: set EncryptedMKey to wrong size.
		recipient := parsed.Recipients[bobServiceId.String()]
		recipient.EncryptedMKey = make([]byte, 10) // wrong size

		// Re-build a tampered message manually.
		recipientOutputs := make([]v2RecipientOutput, 0)
		for sidStr, r := range parsed.Recipients {
			sid, _ := protocol.ServiceIdFromString(protocol.ServiceIdKindACI, sidStr)
			recipientOutputs = append(recipientOutputs, v2RecipientOutput{
				serviceId:  sid,
				deviceIDs:  r.DeviceIDs,
				regIDs:     r.RegistrationIDs,
				encryptedM: r.EncryptedMKey,
				authTag:    r.AuthTag,
			})
		}
		tampered, _ := v2BuildMessage(ciphertext[0], recipientOutputs, parsed.EphemeralPublic, parsed.EncryptedPayload)

		_, err = SealedSenderV2DecryptToUSMC(tampered, bobServiceId, bobStore)
		if err == nil {
			t.Error("Should error on invalid encrypted M key size")
		}
	})

	t.Run("invalid auth tag size", func(t *testing.T) {
		parsed, _ := v2ParseMessage(ciphertext[1:], ciphertext[0])
		recipient := parsed.Recipients[bobServiceId.String()]
		recipient.AuthTag = make([]byte, 5) // wrong size

		recipientOutputs := make([]v2RecipientOutput, 0)
		for sidStr, r := range parsed.Recipients {
			sid, _ := protocol.ServiceIdFromString(protocol.ServiceIdKindACI, sidStr)
			recipientOutputs = append(recipientOutputs, v2RecipientOutput{
				serviceId:  sid,
				deviceIDs:  r.DeviceIDs,
				regIDs:     r.RegistrationIDs,
				encryptedM: r.EncryptedMKey,
				authTag:    r.AuthTag,
			})
		}
		tampered, _ := v2BuildMessage(ciphertext[0], recipientOutputs, parsed.EphemeralPublic, parsed.EncryptedPayload)

		_, err := SealedSenderV2DecryptToUSMC(tampered, bobServiceId, bobStore)
		if err == nil {
			t.Error("Should error on invalid auth tag size")
		}
	})

	t.Run("invalid ephemeral key size", func(t *testing.T) {
		parsed, _ := v2ParseMessage(ciphertext[1:], ciphertext[0])

		recipientOutputs := make([]v2RecipientOutput, 0)
		for sidStr, r := range parsed.Recipients {
			sid, _ := protocol.ServiceIdFromString(protocol.ServiceIdKindACI, sidStr)
			recipientOutputs = append(recipientOutputs, v2RecipientOutput{
				serviceId:  sid,
				deviceIDs:  r.DeviceIDs,
				regIDs:     r.RegistrationIDs,
				encryptedM: r.EncryptedMKey,
				authTag:    r.AuthTag,
			})
		}
		// Build with short ephemeral key.
		tampered, _ := v2BuildMessage(ciphertext[0], recipientOutputs, make([]byte, 16), parsed.EncryptedPayload)

		_, err := SealedSenderV2DecryptToUSMC(tampered, bobServiceId, bobStore)
		if err == nil {
			t.Error("Should error on invalid ephemeral key size")
		}
	})
}

func TestV2ParseMessageInvalidDeviceIdVarint(t *testing.T) {
	// Cover the "failed to read device ID varint" error path (line 520).
	var buf []byte
	varint := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(varint, 1) // 1 recipient
	buf = append(buf, varint[:n]...)
	buf = append(buf, make([]byte, v2ServiceIdSize)...) // service ID
	n = binary.PutUvarint(varint, 1)                    // 1 device
	buf = append(buf, varint[:n]...)
	// Truncated/invalid device ID varint
	buf = append(buf, 0x80) // incomplete varint (high bit set, no following byte)

	_, err := v2ParseMessage(buf, SealedSenderV2VersionServiceId)
	if err == nil {
		t.Error("Should error on invalid device ID varint")
	}
}

func TestSealedSenderMultiRecipientEncryptNoRemoteIdentity(t *testing.T) {
	// Cover the "no remote identity key in session" error path (line 180).
	aliceStore := newV2TestIdentityStore(t)
	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	senderCert, _ := NewSenderCertificate(
		"9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a", nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999, serverCert, serverKey.PrivateKey(),
	)
	usmc, _ := NewUnidentifiedSenderMessageContent(2, senderCert, []byte("test"), ContentHintDefault, nil)

	// Create a fresh session with no remote identity key.
	serializer := serialize.NewJSONSerializer()
	emptySession := record.NewSession(serializer.Session, serializer.State)
	bobAddress := protocol.NewSignalAddress("a1b2c3d4-e5f6-7890-abcd-ef0123456789", 1)

	_, err := SealedSenderMultiRecipientEncrypt(
		[]*protocol.SignalAddress{bobAddress},
		[]*record.Session{emptySession},
		nil,
		usmc,
		aliceStore,
	)
	if err == nil {
		t.Error("Should error when session has no remote identity key")
	}
}

func TestV2ParseMessageErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty data", []byte{}},
		{"truncated varint", []byte{0x80}},
		{"too many recipients", func() []byte {
			buf := make([]byte, binary.MaxVarintLen64)
			n := binary.PutUvarint(buf, 10001)
			return buf[:n]
		}()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := v2ParseMessage(tt.data, SealedSenderV2VersionServiceId)
			if err == nil {
				t.Error("v2ParseMessage should return error for invalid data")
			}
		})
	}
}

func TestV2BuildMessage(t *testing.T) {
	recipients := []v2RecipientOutput{
		{
			serviceId:  protocol.NewACI([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}),
			deviceIDs:  []uint32{1},
			regIDs:     []uint16{100},
			encryptedM: make([]byte, 32),
			authTag:    make([]byte, 16),
		},
	}

	ephPub := make([]byte, 32)
	payload := []byte("test payload")

	msg, err := v2BuildMessage(SealedSenderV2VersionServiceId, recipients, ephPub, payload)
	if err != nil {
		t.Fatalf("v2BuildMessage error: %v", err)
	}

	if msg[0] != SealedSenderV2VersionServiceId {
		t.Errorf("Version byte = 0x%02x, want 0x%02x", msg[0], SealedSenderV2VersionServiceId)
	}
	if len(msg) == 0 {
		t.Fatal("Message should not be empty")
	}
}

func TestV2BuildMessageMultipleRecipients(t *testing.T) {
	recipients := []v2RecipientOutput{
		{
			serviceId:  protocol.NewACI([16]byte{1}),
			deviceIDs:  []uint32{1, 2},
			regIDs:     []uint16{100, 200},
			encryptedM: make([]byte, 32),
			authTag:    make([]byte, 16),
		},
		{
			serviceId:  protocol.NewACI([16]byte{2}),
			deviceIDs:  []uint32{1},
			regIDs:     []uint16{300},
			encryptedM: make([]byte, 32),
			authTag:    make([]byte, 16),
		},
	}

	ephPub := make([]byte, 32)
	payload := []byte("multi-recipient test")

	msg, err := v2BuildMessage(SealedSenderV2VersionServiceId, recipients, ephPub, payload)
	if err != nil {
		t.Fatalf("v2BuildMessage error: %v", err)
	}

	// Parse it back
	parsed, err := v2ParseMessage(msg[1:], SealedSenderV2VersionServiceId)
	if err != nil {
		t.Fatalf("v2ParseMessage error: %v", err)
	}

	if len(parsed.Recipients) != 2 {
		t.Errorf("Parsed recipients = %d, want 2", len(parsed.Recipients))
	}
	if len(parsed.EphemeralPublic) != 32 {
		t.Errorf("EphemeralPublic length = %d, want 32", len(parsed.EphemeralPublic))
	}
}

func TestSealedSenderV2DispatchFromV1Decrypt(t *testing.T) {
	// When SealedSenderDecryptToUSMC sees a v2 version byte AND a ServiceId is provided,
	// it should dispatch to V2.
	aliceStore, bobStore, _, bobAddress, bobSession, _ := setupV2Session(t)

	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	senderCert, _ := NewSenderCertificate(
		"9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a", nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999, serverCert, serverKey.PrivateKey(),
	)
	usmc, _ := NewUnidentifiedSenderMessageContent(2, senderCert, []byte("v2 via v1 api"), ContentHintDefault, nil)

	ciphertext, err := SealedSenderMultiRecipientEncrypt(
		[]*protocol.SignalAddress{bobAddress},
		[]*record.Session{bobSession},
		nil, usmc, aliceStore,
	)
	if err != nil {
		t.Fatalf("SealedSenderMultiRecipientEncrypt error: %v", err)
	}

	bobServiceId, _ := protocol.ServiceIdFromString(protocol.ServiceIdKindACI, bobAddress.Name())

	// Use the v1 entrypoint with a ServiceId to trigger v2 dispatch
	decryptedUSMC, err := SealedSenderDecryptToUSMC(ciphertext, bobStore, bobServiceId)
	if err != nil {
		t.Fatalf("SealedSenderDecryptToUSMC (v2 dispatch) error: %v", err)
	}

	if string(decryptedUSMC.Contents()) != "v2 via v1 api" {
		t.Errorf("Contents() = %q, want %q", string(decryptedUSMC.Contents()), "v2 via v1 api")
	}
}

func TestSealedSenderV2DecryptTamperedAuthTag(t *testing.T) {
	// Cover the sender authentication tag verification failure at line 465.
	// We encrypt a valid v2 message, then tamper with the per-recipient auth tag
	// directly in the binary format.
	aliceStore, bobStore, _, bobAddress, bobSession, _ := setupV2Session(t)

	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	senderCert, _ := NewSenderCertificate(
		"9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a", nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999, serverCert, serverKey.PrivateKey(),
	)
	usmc, _ := NewUnidentifiedSenderMessageContent(2, senderCert, []byte("auth tag test"), ContentHintDefault, nil)

	ciphertext, err := SealedSenderMultiRecipientEncrypt(
		[]*protocol.SignalAddress{bobAddress},
		[]*record.Session{bobSession},
		nil, usmc, aliceStore,
	)
	if err != nil {
		t.Fatalf("SealedSenderMultiRecipientEncrypt error: %v", err)
	}

	bobServiceId, _ := protocol.ServiceIdFromString(protocol.ServiceIdKindACI, bobAddress.Name())

	// The v2 binary format for 1 recipient with 1 device is:
	// version(1) | recipientCount varint(1) | serviceId(17) | deviceCount varint(1) |
	// deviceId varint(1) | regId(2) | C_i(32) | AT_i(16) | ephPub(32) | payload(...)
	//
	// Tamper with AT_i (auth tag): it starts after C_i.
	// Offset: 1(version) + 1(recipientCount) + 17(serviceId) + 1(deviceCount) +
	//         1(deviceId) + 2(regId) + 32(C_i) = 55
	// AT_i is bytes [55..71)
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	authTagOffset := 1 + 1 + v2ServiceIdSize + 1 + 1 + 2 + v2EncryptedMKeySize
	for i := authTagOffset; i < authTagOffset+v2AuthTagSize && i < len(tampered); i++ {
		tampered[i] ^= 0xFF
	}

	_, err = SealedSenderV2DecryptToUSMC(tampered, bobServiceId, bobStore)
	if err == nil {
		t.Error("SealedSenderV2DecryptToUSMC should fail with tampered auth tag")
	}
}

func TestSealedSenderV2DecryptTamperedEncryptedM(t *testing.T) {
	// Cover the ephemeral public key validation failure at line 415.
	// Tampering with C_i causes the recovered M to be wrong, which causes
	// the derived r to be wrong, which causes the ephemeral key check to fail.
	aliceStore, bobStore, _, bobAddress, bobSession, _ := setupV2Session(t)

	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	senderCert, _ := NewSenderCertificate(
		"9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a", nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999, serverCert, serverKey.PrivateKey(),
	)
	usmc, _ := NewUnidentifiedSenderMessageContent(2, senderCert, []byte("eph key test"), ContentHintDefault, nil)

	ciphertext, err := SealedSenderMultiRecipientEncrypt(
		[]*protocol.SignalAddress{bobAddress},
		[]*record.Session{bobSession},
		nil, usmc, aliceStore,
	)
	if err != nil {
		t.Fatalf("SealedSenderMultiRecipientEncrypt error: %v", err)
	}

	bobServiceId, _ := protocol.ServiceIdFromString(protocol.ServiceIdKindACI, bobAddress.Name())

	// Tamper with C_i (encrypted M key) directly in the binary.
	// C_i starts at offset: 1(version) + 1(recipientCount) + 17(serviceId) +
	//                        1(deviceCount) + 1(deviceId) + 2(regId) = 23
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	ciOffset := 1 + 1 + v2ServiceIdSize + 1 + 1 + 2
	for i := ciOffset; i < ciOffset+v2EncryptedMKeySize && i < len(tampered); i++ {
		tampered[i] ^= 0xFF
	}

	_, err = SealedSenderV2DecryptToUSMC(tampered, bobServiceId, bobStore)
	if err == nil {
		t.Error("SealedSenderV2DecryptToUSMC should fail with tampered encrypted M (ephemeral key mismatch)")
	}
}

func TestSealedSenderV2DecryptTamperedPayload(t *testing.T) {
	// Cover the AES-GCM-SIV decrypt failure at line 422.
	aliceStore, bobStore, _, bobAddress, bobSession, _ := setupV2Session(t)

	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	senderCert, _ := NewSenderCertificate(
		"9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a", nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999, serverCert, serverKey.PrivateKey(),
	)
	usmc, _ := NewUnidentifiedSenderMessageContent(2, senderCert, []byte("payload tamper test"), ContentHintDefault, nil)

	ciphertext, err := SealedSenderMultiRecipientEncrypt(
		[]*protocol.SignalAddress{bobAddress},
		[]*record.Session{bobSession},
		nil, usmc, aliceStore,
	)
	if err != nil {
		t.Fatalf("SealedSenderMultiRecipientEncrypt error: %v", err)
	}

	bobServiceId, _ := protocol.ServiceIdFromString(protocol.ServiceIdKindACI, bobAddress.Name())

	// Tamper with the encrypted payload portion at the end of the message.
	// The encrypted payload is after the last recipient data + ephemeral key.
	tamperedCt := make([]byte, len(ciphertext))
	copy(tamperedCt, ciphertext)
	// Flip bytes near the end (in the encrypted payload).
	if len(tamperedCt) > 10 {
		tamperedCt[len(tamperedCt)-5] ^= 0xFF
		tamperedCt[len(tamperedCt)-3] ^= 0xFF
	}

	_, err = SealedSenderV2DecryptToUSMC(tamperedCt, bobServiceId, bobStore)
	if err == nil {
		t.Error("SealedSenderV2DecryptToUSMC should fail with tampered payload")
	}
}

func TestSealedSenderMultiRecipientEncryptMultipleDevices(t *testing.T) {
	// Cover the path where multiple destinations share the same ServiceId
	// (multiple devices for one recipient). This exercises the grouping logic
	// at lines 188-199 and device iteration at lines 248-253.
	serializer := serialize.NewJSONSerializer()

	aliceStore := newV2TestIdentityStore(t)
	bobStore := newV2TestIdentityStore(t)

	bobUUID := "a1b2c3d4-e5f6-7890-abcd-ef0123456789"
	bobAddress1 := protocol.NewSignalAddress(bobUUID, 1)
	bobAddress2 := protocol.NewSignalAddress(bobUUID, 2)

	// Establish sessions with both Bob devices.
	bobPreKeys1, _ := keyhelper.GeneratePreKeys(0, 10, serializer.PreKeyRecord)
	bobPreKeyStore1 := newInMemoryPreKeyStore()
	for _, pk := range bobPreKeys1 {
		if err := bobPreKeyStore1.StorePreKey(pk.ID().Value, record.NewPreKey(pk.ID().Value, pk.KeyPair(), serializer.PreKeyRecord)); err != nil {
			t.Fatalf("setup: StorePreKey: %v", err)
		}
	}
	bobSignedPreKey1, _ := keyhelper.GenerateSignedPreKey(bobStore.keyPair, 0, serializer.SignedPreKeyRecord)
	bobSignedPreKeyStore1 := newInMemorySignedPreKeyStore()
	if err := bobSignedPreKeyStore1.StoreSignedPreKey(bobSignedPreKey1.ID(), record.NewSignedPreKey(
		bobSignedPreKey1.ID(), bobSignedPreKey1.Timestamp(), bobSignedPreKey1.KeyPair(),
		bobSignedPreKey1.Signature(), serializer.SignedPreKeyRecord,
	)); err != nil {
		t.Fatalf("setup: StoreSignedPreKey: %v", err)
	}

	// Generate Kyber pre-key for device 1
	bobKyberPreKey1, _ := keyhelper.GenerateKyberPreKey(bobStore.keyPair.PrivateKey(), 42, &mockKyberPreKeySerializer{})

	// Session for device 1
	aliceSessionStore := newInMemorySessionStore(serializer)
	aliceBuilder1 := session.NewBuilderWithKyber(
		aliceSessionStore, newInMemoryPreKeyStore(), newInMemorySignedPreKeyStore(),
		aliceStore, newInMemoryKyberPreKeyStoreForV1(), bobAddress1, serializer,
	)
	bundle1 := prekey.NewBundleWithKyber(
		bobStore.registrationID, bobAddress1.DeviceID(),
		bobPreKeys1[0].ID(), bobSignedPreKey1.ID(),
		bobPreKeys1[0].KeyPair().PublicKey(), bobSignedPreKey1.KeyPair().PublicKey(),
		bobSignedPreKey1.Signature(), bobStore.keyPair.PublicKey(),
		&optional.Uint32{Value: 42},
		bobKyberPreKey1.PublicKey(),
		bobKyberPreKey1.Signature(),
	)
	if err := aliceBuilder1.ProcessBundle(bundle1); err != nil {
		t.Fatalf("ProcessBundle (device 1) error: %v", err)
	}

	// Session for device 2 (using different prekeys)
	bobPreKeys2, _ := keyhelper.GeneratePreKeys(100, 10, serializer.PreKeyRecord)
	bobPreKeyStore2 := newInMemoryPreKeyStore()
	for _, pk := range bobPreKeys2 {
		if err := bobPreKeyStore2.StorePreKey(pk.ID().Value, record.NewPreKey(pk.ID().Value, pk.KeyPair(), serializer.PreKeyRecord)); err != nil {
			t.Fatalf("setup: StorePreKey: %v", err)
		}
	}
	bobSignedPreKey2, _ := keyhelper.GenerateSignedPreKey(bobStore.keyPair, 1, serializer.SignedPreKeyRecord)
	bobSignedPreKeyStore2 := newInMemorySignedPreKeyStore()
	if err := bobSignedPreKeyStore2.StoreSignedPreKey(bobSignedPreKey2.ID(), record.NewSignedPreKey(
		bobSignedPreKey2.ID(), bobSignedPreKey2.Timestamp(), bobSignedPreKey2.KeyPair(),
		bobSignedPreKey2.Signature(), serializer.SignedPreKeyRecord,
	)); err != nil {
		t.Fatalf("setup: StoreSignedPreKey: %v", err)
	}

	// Generate Kyber pre-key for device 2
	bobKyberPreKey2, _ := keyhelper.GenerateKyberPreKey(bobStore.keyPair.PrivateKey(), 43, &mockKyberPreKeySerializer{})

	aliceBuilder2 := session.NewBuilderWithKyber(
		aliceSessionStore, newInMemoryPreKeyStore(), newInMemorySignedPreKeyStore(),
		aliceStore, newInMemoryKyberPreKeyStoreForV1(), bobAddress2, serializer,
	)
	bundle2 := prekey.NewBundleWithKyber(
		bobStore.registrationID+1, bobAddress2.DeviceID(),
		bobPreKeys2[0].ID(), bobSignedPreKey2.ID(),
		bobPreKeys2[0].KeyPair().PublicKey(), bobSignedPreKey2.KeyPair().PublicKey(),
		bobSignedPreKey2.Signature(), bobStore.keyPair.PublicKey(),
		&optional.Uint32{Value: 43},
		bobKyberPreKey2.PublicKey(),
		bobKyberPreKey2.Signature(),
	)
	if err := aliceBuilder2.ProcessBundle(bundle2); err != nil {
		t.Fatalf("ProcessBundle (device 2) error: %v", err)
	}

	bobSession1, err := aliceSessionStore.LoadSession(bobAddress1)
	if err != nil {
		t.Fatalf("LoadSession (device 1) error: %v", err)
	}
	bobSession2, err := aliceSessionStore.LoadSession(bobAddress2)
	if err != nil {
		t.Fatalf("LoadSession (device 2) error: %v", err)
	}

	if _, err := aliceStore.SaveIdentity(bobAddress1, identity.NewKey(bobStore.keyPair.PublicKey().PublicKey())); err != nil {
		t.Fatalf("setup: SaveIdentity: %v", err)
	}

	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)
	senderCert, _ := NewSenderCertificate(
		"9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a", nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999, serverCert, serverKey.PrivateKey(),
	)
	usmc, _ := NewUnidentifiedSenderMessageContent(2, senderCert, []byte("multi-device"), ContentHintDefault, nil)

	// Encrypt for both devices of the same ServiceId.
	ciphertext, err := SealedSenderMultiRecipientEncrypt(
		[]*protocol.SignalAddress{bobAddress1, bobAddress2},
		[]*record.Session{bobSession1, bobSession2},
		nil, usmc, aliceStore,
	)
	if err != nil {
		t.Fatalf("SealedSenderMultiRecipientEncrypt error: %v", err)
	}

	// Verify it parses with one recipient entry with two devices.
	parsed, err := v2ParseMessage(ciphertext[1:], ciphertext[0])
	if err != nil {
		t.Fatalf("v2ParseMessage error: %v", err)
	}

	bobServiceId, _ := protocol.ServiceIdFromString(protocol.ServiceIdKindACI, bobUUID)
	recipient, ok := parsed.Recipients[bobServiceId.String()]
	if !ok {
		t.Fatal("Bob should be in the parsed recipients")
	}
	if len(recipient.DeviceIDs) != 2 {
		t.Errorf("DeviceIDs count = %d, want 2", len(recipient.DeviceIDs))
	}

	// Both devices should be able to decrypt (same identity key).
	decryptedUSMC, err := SealedSenderV2DecryptToUSMC(ciphertext, bobServiceId, bobStore)
	if err != nil {
		t.Fatalf("SealedSenderV2DecryptToUSMC error: %v", err)
	}
	if string(decryptedUSMC.Contents()) != "multi-device" {
		t.Errorf("Contents() = %q, want %q", string(decryptedUSMC.Contents()), "multi-device")
	}
}

func TestSealedSenderMultiRecipientEncryptInvalidServiceId(t *testing.T) {
	// Cover the "invalid service ID" error path at line 169.
	aliceStore := newV2TestIdentityStore(t)
	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	senderCert, _ := NewSenderCertificate(
		"9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a", nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999, serverCert, serverKey.PrivateKey(),
	)
	usmc, _ := NewUnidentifiedSenderMessageContent(2, senderCert, []byte("test"), ContentHintDefault, nil)

	serializer := serialize.NewJSONSerializer()
	emptySession := record.NewSession(serializer.Session, serializer.State)

	// Use an address with an invalid UUID.
	badAddress := protocol.NewSignalAddress("not-a-valid-uuid", 1)

	_, err := SealedSenderMultiRecipientEncrypt(
		[]*protocol.SignalAddress{badAddress},
		[]*record.Session{emptySession},
		nil, usmc, aliceStore,
	)
	if err == nil {
		t.Error("Should error when address name is not a valid UUID")
	}
}

func TestV2ParseMessageInvalidServiceIdBytes(t *testing.T) {
	// Cover the "invalid service ID" error at line 500 in v2ParseMessage.
	var buf []byte
	varint := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(varint, 1) // 1 recipient
	buf = append(buf, varint[:n]...)

	// ServiceId with invalid kind byte (0xFF instead of 0x01 ACI or 0x02 PNI).
	sid := make([]byte, v2ServiceIdSize)
	sid[0] = 0xFF // invalid kind
	buf = append(buf, sid...)

	n = binary.PutUvarint(varint, 1) // 1 device
	buf = append(buf, varint[:n]...)
	n = binary.PutUvarint(varint, 1) // device ID
	buf = append(buf, varint[:n]...)
	buf = append(buf, 0x00, 0x01)                           // reg ID
	buf = append(buf, make([]byte, v2EncryptedMKeySize)...) // C_i
	buf = append(buf, make([]byte, v2AuthTagSize)...)       // AT_i
	buf = append(buf, make([]byte, 32)...)                  // eph pub
	buf = append(buf, 0x01)                                 // payload

	_, err := v2ParseMessage(buf, SealedSenderV2VersionServiceId)
	if err == nil {
		t.Error("v2ParseMessage should error on invalid service ID kind")
	}
}

func TestKeyhelperNewPreKeyBundle(t *testing.T) {
	// Just verify our helper works
	kp, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair error: %v", err)
	}
	ikp, _ := keyhelper.GenerateIdentityKeyPair()

	bundle := prekey.NewBundle(
		1, 1, nil, 0,
		kp.PublicKey(), kp.PublicKey(),
		[64]byte{}, ikp.PublicKey(),
	)
	if bundle == nil {
		t.Fatal("NewPreKeyBundle returned nil")
	}
}

// --- PNI destination encrypt tests (#22) ---

// TestSealedSenderMultiRecipientEncryptPNIDestination verifies that encrypting
// to a PNI-prefixed address succeeds. Before the fix, the encrypt path called
// ServiceIdFromString(ServiceIdKindACI, ...) which rejected "PNI:<uuid>" names.
// After the fix it calls ServiceIdFromServiceIdString which auto-detects the kind.
func TestSealedSenderMultiRecipientEncryptPNIDestination(t *testing.T) {
	aliceStore, _, _, _, bobSession, _ := setupV2Session(t)

	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	senderCert, err := NewSenderCertificate(
		"9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a",
		nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999,
		serverCert, serverKey.PrivateKey(),
	)
	if err != nil {
		t.Fatalf("NewSenderCertificate error: %v", err)
	}

	usmc, err := NewUnidentifiedSenderMessageContent(
		2, senderCert, []byte("pni destination content"), ContentHintDefault, nil,
	)
	if err != nil {
		t.Fatalf("NewUnidentifiedSenderMessageContent error: %v", err)
	}

	// Use a PNI-prefixed address name. The session was established above and
	// carries the same remote identity key regardless of the address name prefix.
	pniAddress := protocol.NewSignalAddress("PNI:a1b2c3d4-e5f6-7890-abcd-ef0123456789", 1)
	if _, err := aliceStore.SaveIdentity(pniAddress, identity.NewKey(bobSession.SessionState().RemoteIdentityKey().PublicKey())); err != nil {
		t.Fatalf("setup: SaveIdentity: %v", err)
	}

	ciphertext, err := SealedSenderMultiRecipientEncrypt(
		[]*protocol.SignalAddress{pniAddress},
		[]*record.Session{bobSession},
		nil,
		usmc,
		aliceStore,
	)
	if err != nil {
		t.Fatalf("SealedSenderMultiRecipientEncrypt (PNI destination): %v", err)
	}
	if len(ciphertext) == 0 {
		t.Fatal("ciphertext should not be empty")
	}
}

// TestSealedSenderV2DecryptPNISender verifies that the Step 7.5 ServiceId
// validation in the v2 decrypt path accepts a PNI-keyed sender certificate.
// Before the fix, ServiceIdFromString(ServiceIdKindACI, "PNI:...") would reject
// PNI sender certificates. After the fix, ServiceIdFromServiceIdString detects
// the kind automatically.
func TestSealedSenderV2DecryptPNISender(t *testing.T) {
	aliceStore, bobStore, _, bobAddress, bobSession, _ := setupV2Session(t)

	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	// Alice sends with a PNI-prefixed UUID in the sender certificate.
	pniUUID := "PNI:9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a"
	senderCert, err := NewSenderCertificate(
		pniUUID,
		nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999,
		serverCert, serverKey.PrivateKey(),
	)
	if err != nil {
		t.Fatalf("NewSenderCertificate (PNI): %v", err)
	}

	usmc, err := NewUnidentifiedSenderMessageContent(
		2, senderCert, []byte("pni sender content"), ContentHintDefault, nil,
	)
	if err != nil {
		t.Fatalf("NewUnidentifiedSenderMessageContent error: %v", err)
	}

	ciphertext, err := SealedSenderMultiRecipientEncrypt(
		[]*protocol.SignalAddress{bobAddress},
		[]*record.Session{bobSession},
		nil,
		usmc,
		aliceStore,
	)
	if err != nil {
		t.Fatalf("SealedSenderMultiRecipientEncrypt error: %v", err)
	}

	bobServiceId, err := protocol.ServiceIdFromString(protocol.ServiceIdKindACI, bobAddress.Name())
	if err != nil {
		t.Fatalf("ServiceIdFromString error: %v", err)
	}

	decryptedUSMC, err := SealedSenderV2DecryptToUSMC(ciphertext, bobServiceId, bobStore)
	if err != nil {
		t.Fatalf("SealedSenderV2DecryptToUSMC (PNI sender): %v", err)
	}

	// The sender UUID in the decrypted USMC must be the PNI-prefixed string.
	if got := decryptedUSMC.Sender().SenderUUID(); got != pniUUID {
		t.Errorf("SenderUUID: got %q, want %q", got, pniUUID)
	}
	if string(decryptedUSMC.Contents()) != "pni sender content" {
		t.Errorf("Contents: got %q, want %q", string(decryptedUSMC.Contents()), "pni sender content")
	}
}

// TestParseHugeRecipientCount_NoPanic is a regression test for the OOM /
// makeslice panic that occurred when the recipientOrder slice was preallocated
// with the raw attacker-controlled wire varint instead of preallocCap.
//
// A crafted message with a recipient count of 1<<32 (= 4 294 967 296) would
// attempt to allocate >4 GB for the recipientOrder slice before the fix.
// After the fix the preallocation is bounded by v2MaxPreallocRecipients (6000)
// and the parser returns a *V2ParseError because the first per-recipient read
// immediately exhausts the empty data buffer.
func TestParseHugeRecipientCount_NoPanic(t *testing.T) {
	var buf [1 + binary.MaxVarintLen64]byte
	buf[0] = SealedSenderV2VersionUUID
	n := binary.PutUvarint(buf[1:], 1<<32)
	data := buf[:1+n]

	_, err := ParseSealedSenderV2SentMessage(data)
	if err == nil {
		t.Fatal("expected parse error for huge recipient count, got nil")
	}
	var parseErr *V2ParseError
	if !errors.As(err, &parseErr) {
		t.Errorf("expected *V2ParseError, got %T: %v", err, err)
	}
}
