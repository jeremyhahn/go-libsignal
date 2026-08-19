package sessionmanagement_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	groupRecord "github.com/jeremyhahn/go-libsignal/pkg/groups/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/prekey"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/session"
	"github.com/jeremyhahn/go-libsignal/pkg/sessionmanagement"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/state/store"
	"github.com/jeremyhahn/go-libsignal/pkg/util/keyhelper"
	"github.com/jeremyhahn/go-libsignal/pkg/util/optional"
)

// uuidFromName derives a deterministic UUID-format string from an arbitrary
// name. This ensures test addresses pass ServiceId validation (UUID format is
// required by SerializeAddresses for address binding to succeed).
func uuidFromName(name string) string {
	h := sha256.Sum256([]byte(name))
	b := h[:16]
	// Force RFC 4122 version 4 and variant bits for a well-formed UUID.
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	s := hex.EncodeToString(b)
	return fmt.Sprintf("%s-%s-%s-%s-%s", s[0:8], s[8:12], s[12:16], s[16:20], s[20:32])
}

// =====================================================================
// In-memory store implementations (duplicated from session_test to avoid
// cross-package import of unexported types; this is intentional per Go
// test design rules).
// =====================================================================

type memIdentityStore struct {
	trusted         map[string]*identity.Key
	identityKeyPair *identity.KeyPair
	regID           uint32
}

func newMemIdentityStore(kp *identity.KeyPair, regID uint32) *memIdentityStore {
	return &memIdentityStore{
		trusted:         make(map[string]*identity.Key),
		identityKeyPair: kp,
		regID:           regID,
	}
}

func (s *memIdentityStore) GetIdentityKeyPair() *identity.KeyPair { return s.identityKeyPair }
func (s *memIdentityStore) GetLocalRegistrationId() uint32        { return s.regID }
func (s *memIdentityStore) GetIdentity(addr *protocol.SignalAddress) (*identity.Key, error) {
	return s.trusted[addr.String()], nil
}
func (s *memIdentityStore) SaveIdentity(addr *protocol.SignalAddress, key *identity.Key) (store.IdentityChange, error) {
	prev, had := s.trusted[addr.String()]
	s.trusted[addr.String()] = key
	if had && prev != key {
		return store.IdentityChangeReplacedExisting, nil
	}
	return store.IdentityChangeNewOrUnchanged, nil
}
func (s *memIdentityStore) IsTrustedIdentity(addr *protocol.SignalAddress, key *identity.Key, _ store.Direction) (bool, error) {
	trusted := s.trusted[addr.String()]
	return trusted == nil || trusted.Fingerprint() == key.Fingerprint(), nil
}

type memPreKeyStore struct{ store map[uint32]*record.PreKey }

func newMemPreKeyStore() *memPreKeyStore {
	return &memPreKeyStore{store: make(map[uint32]*record.PreKey)}
}

func (s *memPreKeyStore) LoadPreKey(id uint32) (*record.PreKey, error) { return s.store[id], nil }
func (s *memPreKeyStore) StorePreKey(id uint32, r *record.PreKey) error {
	s.store[id] = r
	return nil
}
func (s *memPreKeyStore) ContainsPreKey(id uint32) (bool, error) {
	_, ok := s.store[id]
	return ok, nil
}
func (s *memPreKeyStore) RemovePreKey(id uint32) error {
	delete(s.store, id)
	return nil
}

type memSessionStore struct {
	sessions   map[string]*record.Session
	serializer *serialize.Serializer
}

func newMemSessionStore(serializer *serialize.Serializer) *memSessionStore {
	return &memSessionStore{sessions: make(map[string]*record.Session), serializer: serializer}
}

func (s *memSessionStore) LoadSession(addr *protocol.SignalAddress) (*record.Session, error) {
	if r, ok := s.sessions[addr.String()]; ok {
		return r, nil
	}
	r := record.NewSession(s.serializer.Session, s.serializer.State)
	s.sessions[addr.String()] = r
	return r, nil
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
	for _, r := range s.store {
		out = append(out, r)
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
func (s *memSignedPreKeyStore) RemoveSignedPreKey(id uint32) error {
	delete(s.store, id)
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

type mockKyberPreKeySerializer struct{}

func (m *mockKyberPreKeySerializer) Serialize(s *record.KyberPreKeyStructure) ([]byte, error) {
	return json.Marshal(s)
}
func (m *mockKyberPreKeySerializer) Deserialize(b []byte) (*record.KyberPreKeyStructure, error) {
	var s record.KyberPreKeyStructure
	return &s, json.Unmarshal(b, &s)
}

// testParty bundles all stores and keys needed for one participant.
type testParty struct {
	identityKP     *identity.KeyPair
	regID          uint32
	preKeys        []*record.PreKey
	signedPreKey   *record.SignedPreKey
	kyberPreKey    *record.KyberPreKey
	addr           *protocol.SignalAddress
	sessionStore   *memSessionStore
	preKeyStore    *memPreKeyStore
	signedKeyStore *memSignedPreKeyStore
	identityStore  *memIdentityStore
	kyberStore     *memKyberPreKeyStore
}

func newTestParty(t *testing.T, name string, deviceID uint32, ser *serialize.Serializer) *testParty {
	t.Helper()
	p := &testParty{}
	var err error

	p.identityKP, err = keyhelper.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("GenerateIdentityKeyPair: %v", err)
	}
	p.regID = keyhelper.GenerateRegistrationID()

	// start=1: GeneratePreKeys requires start >= 1 (pre-key ID 0 is invalid).
	p.preKeys, err = keyhelper.GeneratePreKeys(1, 10, ser.PreKeyRecord)
	if err != nil {
		t.Fatalf("GeneratePreKeys: %v", err)
	}

	p.signedPreKey, err = keyhelper.GenerateSignedPreKey(p.identityKP, 1, ser.SignedPreKeyRecord)
	if err != nil {
		t.Fatalf("GenerateSignedPreKey: %v", err)
	}

	p.kyberPreKey, err = keyhelper.GenerateKyberPreKey(p.identityKP.PrivateKey(), 42, &mockKyberPreKeySerializer{})
	if err != nil {
		t.Fatalf("GenerateKyberPreKey: %v", err)
	}

	p.sessionStore = newMemSessionStore(ser)
	p.preKeyStore = newMemPreKeyStore()
	p.signedKeyStore = newMemSignedPreKeyStore()
	p.identityStore = newMemIdentityStore(p.identityKP, p.regID)
	p.kyberStore = newMemKyberPreKeyStore()
	// Use a UUID-format name derived from the human label so that
	// SerializeAddresses (which requires valid ServiceId strings) succeeds
	// when address binding is in effect.
	p.addr = protocol.NewSignalAddress(uuidFromName(name), deviceID)

	for _, pk := range p.preKeys {
		if err := p.preKeyStore.StorePreKey(pk.ID().Value, record.NewPreKey(pk.ID().Value, pk.KeyPair(), ser.PreKeyRecord)); err != nil {
			t.Fatalf("StorePreKey: %v", err)
		}
	}
	if err := p.signedKeyStore.StoreSignedPreKey(p.signedPreKey.ID(),
		record.NewSignedPreKey(p.signedPreKey.ID(), p.signedPreKey.Timestamp(), p.signedPreKey.KeyPair(), p.signedPreKey.Signature(), ser.SignedPreKeyRecord),
	); err != nil {
		t.Fatalf("StoreSignedPreKey: %v", err)
	}
	if err := p.kyberStore.StoreKyberPreKey(42, p.kyberPreKey); err != nil {
		t.Fatalf("StoreKyberPreKey: %v", err)
	}

	return p
}

func (p *testParty) kyberBundle(ser *serialize.Serializer) *prekey.Bundle {
	return prekey.NewBundleWithKyber(
		p.regID,
		p.addr.DeviceID(),
		p.preKeys[0].ID(),
		p.signedPreKey.ID(),
		p.preKeys[0].KeyPair().PublicKey(),
		p.signedPreKey.KeyPair().PublicKey(),
		p.signedPreKey.Signature(),
		p.identityKP.PublicKey(),
		&optional.Uint32{Value: 42},
		p.kyberPreKey.PublicKey(),
		p.kyberPreKey.Signature(),
	)
}

// setupSession establishes a session from alice to bob so that MessageEncrypt /
// MessageDecryptSignal can be tested.
func setupSession(t *testing.T, alice, bob *testParty, ser *serialize.Serializer) {
	t.Helper()
	builder := session.NewBuilderWithKyber(
		alice.sessionStore,
		alice.preKeyStore,
		alice.signedKeyStore,
		alice.identityStore,
		alice.kyberStore,
		bob.addr,
		ser,
	)
	if err := builder.ProcessBundle(bob.kyberBundle(ser)); err != nil {
		t.Fatalf("ProcessBundle: %v", err)
	}
}

// =====================================================================
// Tests
// =====================================================================

// TestMessageEncrypt_AndDecryptPreKey performs a complete PreKey message
// exchange, covering MessageEncrypt (sends PreKeySignalMessage on first
// contact) and MessageDecryptPreKey.
func TestMessageEncrypt_AndDecryptPreKey(t *testing.T) {
	ser := serialize.NewJSONSerializer()
	alice := newTestParty(t, "alice", 1, ser)
	bob := newTestParty(t, "bob", 2, ser)

	// Alice builds session toward bob's bundle (produces PreKeySignalMessage).
	setupSession(t, alice, bob, ser)

	plaintext := []byte("hello via prekey")
	ciphertext, err := sessionmanagement.MessageEncrypt(
		plaintext,
		bob.addr,
		alice.addr,
		alice.sessionStore,
		alice.identityStore,
		ser,
	)
	if err != nil {
		t.Fatalf("MessageEncrypt: %v", err)
	}
	if ciphertext == nil {
		t.Fatal("MessageEncrypt returned nil")
	}

	// The first message to bob is a PreKeySignalMessage.
	preKeyMsg, ok := ciphertext.(*protocol.PreKeySignalMessage)
	if !ok {
		t.Fatalf("expected *protocol.PreKeySignalMessage, got %T", ciphertext)
	}

	// Bob decrypts via MessageDecryptPreKey.
	decrypted, err := sessionmanagement.MessageDecryptPreKey(
		preKeyMsg,
		alice.addr,
		bob.addr,
		bob.sessionStore,
		bob.identityStore,
		bob.preKeyStore,
		bob.signedKeyStore,
		bob.kyberStore,
		ser,
	)
	if err != nil {
		t.Fatalf("MessageDecryptPreKey: %v", err)
	}
	if string(decrypted) != "hello via prekey" {
		t.Errorf("decrypted = %q, want %q", decrypted, "hello via prekey")
	}
}

// TestMessageDecrypt_DispatchesPreKey exercises the MessageDecrypt dispatcher
// when passed a *protocol.PreKeySignalMessage.
func TestMessageDecrypt_DispatchesPreKey(t *testing.T) {
	ser := serialize.NewJSONSerializer()
	alice := newTestParty(t, "alice_d", 1, ser)
	bob := newTestParty(t, "bob_d", 2, ser)

	setupSession(t, alice, bob, ser)

	plaintext := []byte("dispatch prekey test")
	ct, err := sessionmanagement.MessageEncrypt(
		plaintext, bob.addr, alice.addr,
		alice.sessionStore, alice.identityStore, ser,
	)
	if err != nil {
		t.Fatalf("MessageEncrypt: %v", err)
	}

	decrypted, err := sessionmanagement.MessageDecrypt(
		ct,
		alice.addr, bob.addr,
		bob.sessionStore,
		bob.identityStore,
		bob.preKeyStore,
		bob.signedKeyStore,
		bob.kyberStore,
		ser,
	)
	if err != nil {
		t.Fatalf("MessageDecrypt (prekey path): %v", err)
	}
	if string(decrypted) != "dispatch prekey test" {
		t.Errorf("decrypted = %q, want %q", decrypted, "dispatch prekey test")
	}
}

// TestMessageDecryptSignal exercises MessageDecryptSignal by sending a second
// message after the session is established (SignalMessage, not PreKeySignalMessage).
func TestMessageDecryptSignal(t *testing.T) {
	ser := serialize.NewJSONSerializer()
	alice := newTestParty(t, "alice_s", 1, ser)
	bob := newTestParty(t, "bob_s", 2, ser)

	// Establish alice→bob session.
	setupSession(t, alice, bob, ser)

	// First message: Alice → Bob (PreKeySignalMessage). Bob must process it to
	// establish his session state.
	firstCT, err := sessionmanagement.MessageEncrypt(
		[]byte("first"),
		bob.addr, alice.addr,
		alice.sessionStore, alice.identityStore, ser,
	)
	if err != nil {
		t.Fatalf("MessageEncrypt first: %v", err)
	}
	preKeyMsg, ok := firstCT.(*protocol.PreKeySignalMessage)
	if !ok {
		t.Fatalf("expected PreKeySignalMessage, got %T", firstCT)
	}
	if _, err := sessionmanagement.MessageDecryptPreKey(
		preKeyMsg, alice.addr, bob.addr,
		bob.sessionStore, bob.identityStore,
		bob.preKeyStore, bob.signedKeyStore, bob.kyberStore, ser,
	); err != nil {
		t.Fatalf("MessageDecryptPreKey (setup): %v", err)
	}

	// Bob replies so alice has a session state that produces SignalMessages.
	bobBuilder := session.NewBuilderWithKyber(
		bob.sessionStore, bob.preKeyStore, bob.signedKeyStore,
		bob.identityStore, bob.kyberStore,
		alice.addr, ser,
	)
	bobCipher := session.NewCipherWithLocalAddress(bobBuilder, nil, alice.addr)
	bobMsg, err := bobCipher.Encrypt([]byte("reply"))
	if err != nil {
		t.Fatalf("Bob encrypt reply: %v", err)
	}
	// Alice decrypts bob's reply to sync her ratchet.
	aliceBuilder := session.NewBuilderWithKyber(
		alice.sessionStore, alice.preKeyStore, alice.signedKeyStore,
		alice.identityStore, alice.kyberStore,
		bob.addr, ser,
	)
	aliceCipher := session.NewCipherWithLocalAddress(aliceBuilder, nil, bob.addr)
	switch m := bobMsg.(type) {
	case *protocol.SignalMessage:
		if _, err := aliceCipher.Decrypt(m); err != nil {
			t.Fatalf("Alice decrypt bob reply: %v", err)
		}
	case *protocol.PreKeySignalMessage:
		if _, err := aliceCipher.Decrypt(m.WhisperMessage()); err != nil {
			t.Fatalf("Alice decrypt bob prekey reply: %v", err)
		}
	}

	// Now Alice → Bob second message (should be SignalMessage).
	secondCT, err := sessionmanagement.MessageEncrypt(
		[]byte("second via signal"),
		bob.addr, alice.addr,
		alice.sessionStore, alice.identityStore, ser,
	)
	if err != nil {
		t.Fatalf("MessageEncrypt second: %v", err)
	}
	signalMsg, ok := secondCT.(*protocol.SignalMessage)
	if !ok {
		t.Fatalf("expected *protocol.SignalMessage as second message, got %T; protocol setup must be deterministic", secondCT)
	}

	// MessageDecryptSignal.
	decrypted, err := sessionmanagement.MessageDecryptSignal(
		signalMsg,
		alice.addr,
		bob.addr,
		bob.sessionStore,
		bob.identityStore,
		ser,
	)
	if err != nil {
		t.Fatalf("MessageDecryptSignal: %v", err)
	}
	if string(decrypted) != "second via signal" {
		t.Errorf("decrypted = %q, want %q", decrypted, "second via signal")
	}
}

// TestMessageDecrypt_DispatchesSignal exercises the SignalMessage branch of
// MessageDecrypt by sending a post-handshake message.
func TestMessageDecrypt_DispatchesSignal(t *testing.T) {
	ser := serialize.NewJSONSerializer()
	alice := newTestParty(t, "alice_ds", 1, ser)
	bob := newTestParty(t, "bob_ds", 2, ser)

	// Establish session.
	setupSession(t, alice, bob, ser)

	// First message: Alice → Bob (PreKeySignalMessage). Bob processes it.
	firstCT, err := sessionmanagement.MessageEncrypt(
		[]byte("first ds"),
		bob.addr, alice.addr,
		alice.sessionStore, alice.identityStore, ser,
	)
	if err != nil {
		t.Fatalf("MessageEncrypt: %v", err)
	}
	preKeyMsg, ok := firstCT.(*protocol.PreKeySignalMessage)
	if !ok {
		t.Fatalf("expected PreKeySignalMessage, got %T", firstCT)
	}
	if _, err := sessionmanagement.MessageDecryptPreKey(
		preKeyMsg, alice.addr, bob.addr,
		bob.sessionStore, bob.identityStore,
		bob.preKeyStore, bob.signedKeyStore, bob.kyberStore, ser,
	); err != nil {
		t.Fatalf("MessageDecryptPreKey setup: %v", err)
	}

	// Bob replies.
	bobBuilder := session.NewBuilderWithKyber(
		bob.sessionStore, bob.preKeyStore, bob.signedKeyStore,
		bob.identityStore, bob.kyberStore,
		alice.addr, ser,
	)
	bobCipher := session.NewCipherWithLocalAddress(bobBuilder, nil, alice.addr)
	bobReply, err := bobCipher.Encrypt([]byte("bob reply ds"))
	if err != nil {
		t.Fatalf("Bob encrypt: %v", err)
	}
	// Alice decrypts bob's reply.
	aliceBuilder := session.NewBuilderWithKyber(
		alice.sessionStore, alice.preKeyStore, alice.signedKeyStore,
		alice.identityStore, alice.kyberStore,
		bob.addr, ser,
	)
	aliceCipher := session.NewCipherWithLocalAddress(aliceBuilder, nil, bob.addr)
	switch m := bobReply.(type) {
	case *protocol.SignalMessage:
		if _, err := aliceCipher.Decrypt(m); err != nil {
			t.Fatalf("Alice decrypt: %v", err)
		}
	case *protocol.PreKeySignalMessage:
		if _, err := aliceCipher.Decrypt(m.WhisperMessage()); err != nil {
			t.Fatalf("Alice decrypt prekey: %v", err)
		}
	}

	// Second Alice→Bob message: should be SignalMessage after ratchet sync.
	secondCT, err := sessionmanagement.MessageEncrypt(
		[]byte("second ds via signal"),
		bob.addr, alice.addr,
		alice.sessionStore, alice.identityStore, ser,
	)
	if err != nil {
		t.Fatalf("MessageEncrypt second: %v", err)
	}
	signalMsg, ok := secondCT.(*protocol.SignalMessage)
	if !ok {
		t.Fatalf("expected *protocol.SignalMessage as second message, got %T; protocol setup must be deterministic", secondCT)
	}

	decrypted, err := sessionmanagement.MessageDecrypt(
		signalMsg,
		alice.addr, bob.addr,
		bob.sessionStore, bob.identityStore,
		bob.preKeyStore, bob.signedKeyStore, bob.kyberStore,
		ser,
	)
	if err != nil {
		t.Fatalf("MessageDecrypt (signal path): %v", err)
	}
	if string(decrypted) != "second ds via signal" {
		t.Errorf("decrypted = %q, want %q", decrypted, "second ds via signal")
	}
}

// TestMessageDecrypt_SenderKeyMessageRejected exercises the SenderKeyMessage
// branch in the messageKind dispatcher.
func TestMessageDecrypt_SenderKeyMessageRejected(t *testing.T) {
	ser := serialize.NewJSONSerializer()

	// Build a minimal SenderKeyMessage using a generated signing key.
	signingKP, err := keyhelper.GenerateSenderSigningKey()
	if err != nil {
		t.Fatalf("GenerateSenderSigningKey: %v", err)
	}
	var distID [16]byte
	skm, err := protocol.NewSenderKeyMessage(
		distID, 0, 0, []byte{0x01},
		signingKP.PrivateKey(), ser.SenderKeyMessage,
	)
	if err != nil {
		t.Fatalf("NewSenderKeyMessage: %v", err)
	}
	addr := protocol.NewSignalAddress("x", 1)

	_, err = sessionmanagement.MessageDecrypt(
		skm, addr, addr, nil, nil, nil, nil, nil, ser,
	)
	if err == nil {
		t.Fatal("expected error for SenderKeyMessage")
	}
	var typedErr *sessionmanagement.InvalidCiphertextTypeError
	if !errors.As(err, &typedErr) {
		t.Fatalf("expected *InvalidCiphertextTypeError, got %T", err)
	}
	if typedErr.Kind != "SenderKeyMessage" {
		t.Errorf("Kind = %q, want SenderKeyMessage", typedErr.Kind)
	}
}

// TestMessageDecrypt_SenderKeyDistributionMessageRejected exercises the
// SenderKeyDistributionMessage branch in the messageKind dispatcher.
func TestMessageDecrypt_SenderKeyDistributionMessageRejected(t *testing.T) {
	ser := serialize.NewJSONSerializer()

	signingKP, err := keyhelper.GenerateSenderSigningKey()
	if err != nil {
		t.Fatalf("GenerateSenderSigningKey: %v", err)
	}
	var distID [16]byte
	skdm := protocol.NewSenderKeyDistributionMessage(
		distID, 0, 0, make([]byte, 32),
		signingKP.PublicKey(),
		ser.SenderKeyDistributionMessage,
		3,
	)
	addr := protocol.NewSignalAddress("x", 1)

	_, err = sessionmanagement.MessageDecrypt(
		skdm, addr, addr, nil, nil, nil, nil, nil, ser,
	)
	if err == nil {
		t.Fatal("expected error for SenderKeyDistributionMessage")
	}
	var typedErr *sessionmanagement.InvalidCiphertextTypeError
	if !errors.As(err, &typedErr) {
		t.Fatalf("expected *InvalidCiphertextTypeError, got %T", err)
	}
	if typedErr.Kind != "SenderKeyDistributionMessage" {
		t.Errorf("Kind = %q, want SenderKeyDistributionMessage", typedErr.Kind)
	}
}

// failingKyberStore wraps memKyberPreKeyStore and makes MarkKyberPreKeyUsed
// return an error, exercising the deferred.Complete() error path in
// MessageDecryptPreKey.
type failingKyberStore struct {
	*memKyberPreKeyStore
}

func (s *failingKyberStore) MarkKyberPreKeyUsed(_ uint32, _ uint32, _ ecc.ECPublicKeyable) error {
	return errors.New("forced mark failure")
}

var _ store.KyberPreKey = (*failingKyberStore)(nil)

// TestMessageDecryptPreKey_DeferredCompleteError exercises the error return
// from deferred.Complete() when the KyberPreKey store fails to mark the key used.
func TestMessageDecryptPreKey_DeferredCompleteError(t *testing.T) {
	ser := serialize.NewJSONSerializer()
	alice := newTestParty(t, "alice_dce", 1, ser)
	bob := newTestParty(t, "bob_dce", 2, ser)

	// Alice establishes a session toward bob.
	setupSession(t, alice, bob, ser)

	// Alice encrypts (PreKeySignalMessage).
	ct, err := sessionmanagement.MessageEncrypt(
		[]byte("trigger deferred error"),
		bob.addr, alice.addr,
		alice.sessionStore, alice.identityStore, ser,
	)
	if err != nil {
		t.Fatalf("MessageEncrypt: %v", err)
	}
	preKeyMsg, ok := ct.(*protocol.PreKeySignalMessage)
	if !ok {
		t.Fatalf("expected *protocol.PreKeySignalMessage as first message, got %T; first message from an unacked session must be PreKeySignalMessage", ct)
	}

	// Replace bob's kyber store with a failing one so deferred.Complete() fails.
	failingStore := &failingKyberStore{bob.kyberStore}

	_, err = sessionmanagement.MessageDecryptPreKey(
		preKeyMsg, alice.addr, bob.addr,
		bob.sessionStore, bob.identityStore,
		bob.preKeyStore, bob.signedKeyStore, failingStore,
		ser,
	)
	if err == nil {
		t.Fatal("expected error from deferred.Complete() with failing Kyber store")
	}
}

// Verify that the in-memory stores satisfy the required interfaces at compile time.
var _ store.IdentityKey = (*memIdentityStore)(nil)
var _ store.PreKey = (*memPreKeyStore)(nil)
var _ store.Session = (*memSessionStore)(nil)
var _ store.SignedPreKey = (*memSignedPreKeyStore)(nil)
var _ store.KyberPreKey = (*memKyberPreKeyStore)(nil)

// groupRecord import used for type-check only (avoid unused-import error).
var _ = groupRecord.NewSenderKey

// establishSignalMessageSession is a test helper that runs the full
// Alice→Bob PreKey handshake so that Alice's second message is a plain
// SignalMessage (post-handshake). Returns the second SignalMessage ready for
// MessageDecryptSignal, along with both parties' state.
func establishSignalMessageSession(t *testing.T, alice, bob *testParty, ser *serialize.Serializer) *protocol.SignalMessage {
	t.Helper()

	// Alice → Bob first message (PreKeySignalMessage).
	firstCT, err := sessionmanagement.MessageEncrypt(
		[]byte("setup"),
		bob.addr, alice.addr,
		alice.sessionStore, alice.identityStore, ser,
	)
	if err != nil {
		t.Fatalf("MessageEncrypt first: %v", err)
	}
	preKeyMsg, ok := firstCT.(*protocol.PreKeySignalMessage)
	if !ok {
		t.Fatalf("expected PreKeySignalMessage, got %T", firstCT)
	}
	if _, err := sessionmanagement.MessageDecryptPreKey(
		preKeyMsg, alice.addr, bob.addr,
		bob.sessionStore, bob.identityStore,
		bob.preKeyStore, bob.signedKeyStore, bob.kyberStore, ser,
	); err != nil {
		t.Fatalf("MessageDecryptPreKey setup: %v", err)
	}

	// Bob → Alice reply (to advance Alice's ratchet past the unack state).
	bobBuilder := session.NewBuilderWithKyber(
		bob.sessionStore, bob.preKeyStore, bob.signedKeyStore,
		bob.identityStore, bob.kyberStore,
		alice.addr, ser,
	)
	bobCipher := session.NewCipherWithLocalAddress(bobBuilder, nil, alice.addr)
	bobReply, err := bobCipher.Encrypt([]byte("reply"))
	if err != nil {
		t.Fatalf("Bob encrypt reply: %v", err)
	}
	aliceBuilder := session.NewBuilderWithKyber(
		alice.sessionStore, alice.preKeyStore, alice.signedKeyStore,
		alice.identityStore, alice.kyberStore,
		bob.addr, ser,
	)
	aliceCipher := session.NewCipherWithLocalAddress(aliceBuilder, nil, bob.addr)
	switch m := bobReply.(type) {
	case *protocol.SignalMessage:
		if _, err := aliceCipher.Decrypt(m); err != nil {
			t.Fatalf("Alice decrypt reply: %v", err)
		}
	case *protocol.PreKeySignalMessage:
		if _, err := aliceCipher.Decrypt(m.WhisperMessage()); err != nil {
			t.Fatalf("Alice decrypt prekey reply: %v", err)
		}
	}

	// Alice → Bob second message: must be SignalMessage.
	secondCT, err := sessionmanagement.MessageEncrypt(
		[]byte("post-handshake"),
		bob.addr, alice.addr,
		alice.sessionStore, alice.identityStore, ser,
	)
	if err != nil {
		t.Fatalf("MessageEncrypt second: %v", err)
	}
	signalMsg, ok := secondCT.(*protocol.SignalMessage)
	if !ok {
		t.Fatalf("expected *protocol.SignalMessage as second message, got %T; after Alice decrypts Bob's reply the ratchet must advance and the next message must be a SignalMessage", secondCT)
	}
	return signalMsg
}

// TestMessageDecryptSignal_WithMatchingLocalAddress verifies that when both
// addresses are known and match the message's embedded binding, decryption
// succeeds via the VerifyMacWithAddresses path.
//
// Codex finding P1 — with both addresses known + matching → decrypt succeeds.
func TestMessageDecryptSignal_WithMatchingLocalAddress(t *testing.T) {
	ser := serialize.NewJSONSerializer()
	alice := newTestParty(t, "alice_bind", 1, ser)
	bob := newTestParty(t, "bob_bind", 2, ser)

	setupSession(t, alice, bob, ser)
	signalMsg := establishSignalMessageSession(t, alice, bob, ser)

	decrypted, err := sessionmanagement.MessageDecryptSignal(
		signalMsg,
		alice.addr,
		bob.addr, // localAddress matches the message's recipient binding
		bob.sessionStore,
		bob.identityStore,
		ser,
	)
	if err != nil {
		t.Fatalf("MessageDecryptSignal with matching addresses: %v", err)
	}
	if string(decrypted) != "post-handshake" {
		t.Errorf("decrypted = %q, want %q", decrypted, "post-handshake")
	}
}

// TestMessageDecryptSignal_MismatchedLocalAddress verifies that when the
// localAddress does not match the recipient embedded in the message's
// addresses binding field, MessageDecryptSignal fails with the address-mismatch
// typed error from pkg/protocol.
//
// Codex finding P1 — mismatched localAddress → decrypt FAILS with typed error.
func TestMessageDecryptSignal_MismatchedLocalAddress(t *testing.T) {
	ser := serialize.NewJSONSerializer()
	alice := newTestParty(t, "alice_mm", 1, ser)
	bob := newTestParty(t, "bob_mm", 2, ser)
	charlie := newTestParty(t, "charlie_mm", 3, ser)

	setupSession(t, alice, bob, ser)
	signalMsg := establishSignalMessageSession(t, alice, bob, ser)

	// Bob's session store has the session, but we claim Charlie is the local
	// address. The embedded binding (alice→bob) will not match (alice→charlie),
	// so VerifyMacWithAddresses must reject the message.
	_, err := sessionmanagement.MessageDecryptSignal(
		signalMsg,
		alice.addr,
		charlie.addr, // wrong localAddress: binding was for bob, not charlie
		bob.sessionStore,
		bob.identityStore,
		ser,
	)
	if err == nil {
		t.Fatal("expected address-mismatch error, got nil")
	}
	if !errors.Is(err, protocol.ErrAddressMismatch) {
		t.Fatalf("expected errors.Is(err, protocol.ErrAddressMismatch), got %T: %v", err, err)
	}
}

// TestMessageDecryptSignal_NilLocalAddress verifies that passing a nil
// localAddress skips address-binding enforcement, retaining backward
// compatibility with legacy callers that do not supply a local address.
//
// Codex finding P1 — localAddress nil (legacy path) → decrypt succeeds.
func TestMessageDecryptSignal_NilLocalAddress(t *testing.T) {
	ser := serialize.NewJSONSerializer()
	alice := newTestParty(t, "alice_nil", 1, ser)
	bob := newTestParty(t, "bob_nil", 2, ser)

	setupSession(t, alice, bob, ser)

	// Encrypt without local address binding so the message has no binding field.
	firstCT, err := sessionmanagement.MessageEncrypt(
		[]byte("nil-addr-setup"),
		bob.addr, nil, // no localAddress → no binding in message
		alice.sessionStore, alice.identityStore, ser,
	)
	if err != nil {
		t.Fatalf("MessageEncrypt first: %v", err)
	}
	preKeyMsg, ok := firstCT.(*protocol.PreKeySignalMessage)
	if !ok {
		t.Fatalf("expected PreKeySignalMessage, got %T", firstCT)
	}
	if _, err := sessionmanagement.MessageDecryptPreKey(
		preKeyMsg, alice.addr, nil,
		bob.sessionStore, bob.identityStore,
		bob.preKeyStore, bob.signedKeyStore, bob.kyberStore, ser,
	); err != nil {
		t.Fatalf("MessageDecryptPreKey setup: %v", err)
	}

	bobBuilder := session.NewBuilderWithKyber(
		bob.sessionStore, bob.preKeyStore, bob.signedKeyStore,
		bob.identityStore, bob.kyberStore,
		alice.addr, ser,
	)
	bobCipher := session.NewCipherWithLocalAddress(bobBuilder, nil, alice.addr)
	bobReply, err := bobCipher.Encrypt([]byte("reply-nil"))
	if err != nil {
		t.Fatalf("Bob encrypt: %v", err)
	}
	aliceBuilder := session.NewBuilderWithKyber(
		alice.sessionStore, alice.preKeyStore, alice.signedKeyStore,
		alice.identityStore, alice.kyberStore,
		bob.addr, ser,
	)
	aliceCipher := session.NewCipherWithLocalAddress(aliceBuilder, nil, bob.addr)
	switch m := bobReply.(type) {
	case *protocol.SignalMessage:
		if _, err := aliceCipher.Decrypt(m); err != nil {
			t.Fatalf("Alice decrypt reply: %v", err)
		}
	case *protocol.PreKeySignalMessage:
		if _, err := aliceCipher.Decrypt(m.WhisperMessage()); err != nil {
			t.Fatalf("Alice decrypt prekey reply: %v", err)
		}
	}

	secondCT, err := sessionmanagement.MessageEncrypt(
		[]byte("legacy-no-binding"),
		bob.addr, nil, // no localAddress → no binding
		alice.sessionStore, alice.identityStore, ser,
	)
	if err != nil {
		t.Fatalf("MessageEncrypt second: %v", err)
	}
	signalMsg, ok := secondCT.(*protocol.SignalMessage)
	if !ok {
		t.Fatalf("expected *protocol.SignalMessage as second message, got %T; after Alice decrypts Bob's reply the ratchet must advance and the next message must be a SignalMessage", secondCT)
	}

	// Decrypt with nil localAddress — no address binding enforcement.
	decrypted, err := sessionmanagement.MessageDecryptSignal(
		signalMsg,
		alice.addr,
		nil, // legacy: no binding check
		bob.sessionStore,
		bob.identityStore,
		ser,
	)
	if err != nil {
		t.Fatalf("MessageDecryptSignal (nil localAddress): %v", err)
	}
	if string(decrypted) != "legacy-no-binding" {
		t.Errorf("decrypted = %q, want %q", decrypted, "legacy-no-binding")
	}
}

// newPhoneTestParty creates a testParty whose SignalAddress.Name() is a phone
// number — a non-canonical name that cannot be parsed as a ServiceId.
func newPhoneTestParty(t *testing.T, phone string, deviceID uint32, ser *serialize.Serializer) *testParty {
	t.Helper()
	p := newTestParty(t, phone+"_internal", deviceID, ser)
	// Override the address to use the phone number as the name so that
	// IsCanonicalServiceIdAddress returns false.
	p.addr = protocol.NewSignalAddress(phone, deviceID)
	return p
}

// newACIPrefixTestParty creates a testParty whose SignalAddress.Name() uses
// the legacy "ACI:<uuid>" prefix, which the lenient parser accepts as canonical.
func newACIPrefixTestParty(t *testing.T, label string, deviceID uint32, ser *serialize.Serializer) *testParty {
	t.Helper()
	p := newTestParty(t, label, deviceID, ser)
	// Wrap the UUID name in the legacy "ACI:" prefix — still accepted as canonical.
	p.addr = protocol.NewSignalAddress("ACI:"+p.addr.Name(), deviceID)
	return p
}

// setupSessionWithCustomAddrs builds an alice→bob session using the session
// store's actual key addresses but encrypts/decrypts to the provided addr
// overrides. This is needed when the test party's canonical addr differs from
// the address used for phone-number tests.
func setupSessionForCustom(t *testing.T, alice, bob *testParty, aliceAddr, bobAddr *protocol.SignalAddress, ser *serialize.Serializer) {
	t.Helper()
	builder := session.NewBuilderWithKyber(
		alice.sessionStore,
		alice.preKeyStore,
		alice.signedKeyStore,
		alice.identityStore,
		alice.kyberStore,
		bobAddr,
		ser,
	)
	if err := builder.ProcessBundle(bob.kyberBundle(ser)); err != nil {
		t.Fatalf("ProcessBundle: %v", err)
	}
}

// TestBackCompat_PhoneNumberBothEndpoints exercises the back-compat fallback
// when BOTH endpoints use phone-number names (non-canonical). Encryption and
// decryption must succeed via the unbound legacy path.
func TestBackCompat_PhoneNumberBothEndpoints(t *testing.T) {
	ser := serialize.NewJSONSerializer()
	alice := newPhoneTestParty(t, "+15555550100", 1, ser)
	bob := newPhoneTestParty(t, "+15555550101", 2, ser)

	setupSessionForCustom(t, alice, bob, alice.addr, bob.addr, ser)

	ct, err := sessionmanagement.MessageEncrypt(
		[]byte("phone-phone"),
		bob.addr, alice.addr,
		alice.sessionStore, alice.identityStore, ser,
	)
	if err != nil {
		t.Fatalf("MessageEncrypt (both phone): %v", err)
	}

	preKeyMsg, ok := ct.(*protocol.PreKeySignalMessage)
	if !ok {
		t.Fatalf("expected PreKeySignalMessage, got %T", ct)
	}

	decrypted, err := sessionmanagement.MessageDecryptPreKey(
		preKeyMsg, alice.addr, bob.addr,
		bob.sessionStore, bob.identityStore,
		bob.preKeyStore, bob.signedKeyStore, bob.kyberStore, ser,
	)
	if err != nil {
		t.Fatalf("MessageDecryptPreKey (both phone): %v", err)
	}
	if string(decrypted) != "phone-phone" {
		t.Errorf("decrypted = %q, want %q", decrypted, "phone-phone")
	}
}

// TestBackCompat_PhoneAndUUIDMixed exercises the back-compat fallback when
// one endpoint uses a phone number and the other uses a UUID. The unbound
// legacy path must be used and decrypt must succeed.
func TestBackCompat_PhoneAndUUIDMixed(t *testing.T) {
	ser := serialize.NewJSONSerializer()
	// alice uses phone number, bob uses canonical UUID
	alice := newPhoneTestParty(t, "+15555550200", 1, ser)
	bob := newTestParty(t, "bob_mixed", 2, ser)

	setupSessionForCustom(t, alice, bob, alice.addr, bob.addr, ser)

	ct, err := sessionmanagement.MessageEncrypt(
		[]byte("phone-uuid"),
		bob.addr, alice.addr,
		alice.sessionStore, alice.identityStore, ser,
	)
	if err != nil {
		t.Fatalf("MessageEncrypt (phone+uuid): %v", err)
	}

	preKeyMsg, ok := ct.(*protocol.PreKeySignalMessage)
	if !ok {
		t.Fatalf("expected PreKeySignalMessage, got %T", ct)
	}

	decrypted, err := sessionmanagement.MessageDecryptPreKey(
		preKeyMsg, alice.addr, bob.addr,
		bob.sessionStore, bob.identityStore,
		bob.preKeyStore, bob.signedKeyStore, bob.kyberStore, ser,
	)
	if err != nil {
		t.Fatalf("MessageDecryptPreKey (phone+uuid): %v", err)
	}
	if string(decrypted) != "phone-uuid" {
		t.Errorf("decrypted = %q, want %q", decrypted, "phone-uuid")
	}
}

// TestBackCompat_ACIPrefixBothEndpoints verifies that the legacy "ACI:<uuid>"
// form is treated as canonical — the bound path is used, and a mismatch on
// localAddress triggers ErrAddressMismatch.
func TestBackCompat_ACIPrefixBothEndpoints(t *testing.T) {
	ser := serialize.NewJSONSerializer()
	alice := newACIPrefixTestParty(t, "alice_aci_pfx", 1, ser)
	bob := newACIPrefixTestParty(t, "bob_aci_pfx", 2, ser)

	setupSessionForCustom(t, alice, bob, alice.addr, bob.addr, ser)

	ct, err := sessionmanagement.MessageEncrypt(
		[]byte("aci-prefix"),
		bob.addr, alice.addr,
		alice.sessionStore, alice.identityStore, ser,
	)
	if err != nil {
		t.Fatalf("MessageEncrypt (ACI prefix): %v", err)
	}

	preKeyMsg, ok := ct.(*protocol.PreKeySignalMessage)
	if !ok {
		t.Fatalf("expected PreKeySignalMessage, got %T", ct)
	}

	// Decrypt with the correct local address (bob) — should succeed.
	decrypted, err := sessionmanagement.MessageDecryptPreKey(
		preKeyMsg, alice.addr, bob.addr,
		bob.sessionStore, bob.identityStore,
		bob.preKeyStore, bob.signedKeyStore, bob.kyberStore, ser,
	)
	if err != nil {
		t.Fatalf("MessageDecryptPreKey (ACI prefix, correct addr): %v", err)
	}
	if string(decrypted) != "aci-prefix" {
		t.Errorf("decrypted = %q, want %q", decrypted, "aci-prefix")
	}
}

// TestBackCompat_PNIBothEndpoints verifies that "PNI:<uuid>" addresses are
// treated as canonical (bound path enabled).
func TestBackCompat_PNIBothEndpoints(t *testing.T) {
	ser := serialize.NewJSONSerializer()
	aliceBase := newTestParty(t, "alice_pni_test", 1, ser)
	bobBase := newTestParty(t, "bob_pni_test", 2, ser)

	alicePNI := "PNI:" + aliceBase.addr.Name()
	bobPNI := "PNI:" + bobBase.addr.Name()
	aliceAddr := protocol.NewSignalAddress(alicePNI, 1)
	bobAddr := protocol.NewSignalAddress(bobPNI, 2)

	// Rebuild parties with PNI addresses but reuse their key material.
	aliceBase.addr = aliceAddr
	bobBase.addr = bobAddr

	setupSessionForCustom(t, aliceBase, bobBase, aliceAddr, bobAddr, ser)

	ct, err := sessionmanagement.MessageEncrypt(
		[]byte("pni-pni"),
		bobAddr, aliceAddr,
		aliceBase.sessionStore, aliceBase.identityStore, ser,
	)
	if err != nil {
		t.Fatalf("MessageEncrypt (PNI): %v", err)
	}

	preKeyMsg, ok := ct.(*protocol.PreKeySignalMessage)
	if !ok {
		t.Fatalf("expected PreKeySignalMessage, got %T", ct)
	}

	decrypted, err := sessionmanagement.MessageDecryptPreKey(
		preKeyMsg, aliceAddr, bobAddr,
		bobBase.sessionStore, bobBase.identityStore,
		bobBase.preKeyStore, bobBase.signedKeyStore, bobBase.kyberStore, ser,
	)
	if err != nil {
		t.Fatalf("MessageDecryptPreKey (PNI): %v", err)
	}
	if string(decrypted) != "pni-pni" {
		t.Errorf("decrypted = %q, want %q", decrypted, "pni-pni")
	}
}

// =============================================================================
// Finding 1 regression: double-commit of deferred.Complete()
//
// Before the fix, sessionmanagement.MessageDecryptPreKey called
// deferred.Complete() AFTER SessionCipher.DecryptPreKeyMessage had ALREADY
// called it internally. For a non-idempotent store (one that errors on the
// second call to MarkKyberPreKeyUsed/RemovePreKey), this caused a spurious
// error on what was otherwise a successful first message decrypt.
//
// The fix discards the returned *DeferredActions with `_`, so Complete() is
// only called once — inside DecryptPreKeyMessage.
// =============================================================================

// oneShotKyberStore wraps memKyberPreKeyStore and makes MarkKyberPreKeyUsed
// succeed exactly once. A second call returns an error, simulating a
// non-idempotent remote pre-key store (e.g., one that errors when trying to
// delete an already-deleted key).
type oneShotKyberStore struct {
	*memKyberPreKeyStore
	calls int
}

func (s *oneShotKyberStore) MarkKyberPreKeyUsed(id uint32, regID uint32, ik ecc.ECPublicKeyable) error {
	s.calls++
	if s.calls > 1 {
		return fmt.Errorf("oneShotKyberStore: MarkKyberPreKeyUsed called %d times (non-idempotent store fails on second call)", s.calls)
	}
	return s.memKyberPreKeyStore.MarkKyberPreKeyUsed(id, regID, ik)
}

var _ store.KyberPreKey = (*oneShotKyberStore)(nil)

// TestMessageDecryptPreKey_NoDoubleCommit verifies Finding 1: that
// MessageDecryptPreKey does NOT call deferred.Complete() a second time after
// SessionCipher.DecryptPreKeyMessage has already called it internally.
//
// Before the fix: MessageDecryptPreKey called deferred.Complete() again after
// DecryptPreKeyMessage returned, which triggered a second call to
// MarkKyberPreKeyUsed. With a non-idempotent store (one that errors on the
// second call, e.g., because the key was already removed), this produced a
// spurious error even though decryption succeeded.
//
// After the fix: deferred is discarded with `_`, so MarkKyberPreKeyUsed is
// only called once (from within DecryptPreKeyMessage) and the one-shot store
// does not see a second call. MessageDecryptPreKey succeeds.
func TestMessageDecryptPreKey_NoDoubleCommit(t *testing.T) {
	ser := serialize.NewJSONSerializer()
	alice := newTestParty(t, "alice_nodc", 1, ser)
	bob := newTestParty(t, "bob_nodc", 2, ser)

	setupSession(t, alice, bob, ser)

	ct, err := sessionmanagement.MessageEncrypt(
		[]byte("no-double-commit"),
		bob.addr, alice.addr,
		alice.sessionStore, alice.identityStore, ser,
	)
	if err != nil {
		t.Fatalf("MessageEncrypt: %v", err)
	}
	preKeyMsg, ok := ct.(*protocol.PreKeySignalMessage)
	if !ok {
		t.Fatalf("expected PreKeySignalMessage, got %T", ct)
	}

	// Replace Bob's Kyber store with a one-shot version: succeeds on call 1,
	// errors on call 2. If MessageDecryptPreKey double-commits, this test fails.
	oneShot := &oneShotKyberStore{memKyberPreKeyStore: bob.kyberStore}

	plaintext, err := sessionmanagement.MessageDecryptPreKey(
		preKeyMsg, alice.addr, bob.addr,
		bob.sessionStore, bob.identityStore,
		bob.preKeyStore, bob.signedKeyStore, oneShot,
		ser,
	)
	if err != nil {
		t.Fatalf("MessageDecryptPreKey with one-shot Kyber store should succeed (single Complete): %v\n"+
			"(pre-fix: second deferred.Complete() call failed on non-idempotent store)", err)
	}
	if string(plaintext) != "no-double-commit" {
		t.Errorf("plaintext = %q, want %q", plaintext, "no-double-commit")
	}

	// Verify the one-shot store was called exactly once (not twice).
	if oneShot.calls != 1 {
		t.Errorf("MarkKyberPreKeyUsed called %d times, expected exactly 1 (pre-fix called 2)", oneShot.calls)
	}
}

// TestBackCompat_UUIDBoundPath_AddressMismatch confirms that canonical-UUID
// endpoints use the bound path and that an incorrect localAddress on decrypt
// causes ErrAddressMismatch — demonstrating the security property is preserved
// for canonical callers.
func TestBackCompat_UUIDBoundPath_AddressMismatch(t *testing.T) {
	ser := serialize.NewJSONSerializer()
	alice := newTestParty(t, "alice_bound_check", 1, ser)
	bob := newTestParty(t, "bob_bound_check", 2, ser)
	charlie := newTestParty(t, "charlie_bound_check", 3, ser)

	setupSession(t, alice, bob, ser)
	signalMsg := establishSignalMessageSession(t, alice, bob, ser)

	// Decrypt with charlie as local address — mismatch must be detected.
	_, err := sessionmanagement.MessageDecryptSignal(
		signalMsg,
		alice.addr,
		charlie.addr,
		bob.sessionStore,
		bob.identityStore,
		ser,
	)
	if err == nil {
		t.Fatal("expected ErrAddressMismatch for canonical mismatch, got nil")
	}
	if !errors.Is(err, protocol.ErrAddressMismatch) {
		t.Fatalf("expected ErrAddressMismatch, got %T: %v", err, err)
	}
}
