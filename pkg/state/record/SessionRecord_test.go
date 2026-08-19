package record_test

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/kdf"
	"github.com/jeremyhahn/go-libsignal/pkg/kem"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/chain"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/message"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/root"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/util/bytehelper"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
	"github.com/jeremyhahn/go-libsignal/pkg/util/optional"
)

func newSerializer() *serialize.Serializer {
	return serialize.NewJSONSerializer()
}

func genKP(t *testing.T) *ecc.ECKeyPair {
	t.Helper()
	kp, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func genIDKeyPair(t *testing.T) *identity.KeyPair {
	t.Helper()
	kp := genKP(t)
	return identity.NewKeyPair(identity.NewKey(kp.PublicKey()), kp.PrivateKey())
}

func makeChainKey(t *testing.T) *chain.Key {
	t.Helper()
	return chain.NewKey(kdf.DeriveSecrets, make([]byte, 32), 0)
}

func makeRootKey(t *testing.T) *root.Key {
	t.Helper()
	return root.NewKey(kdf.DeriveSecrets, make([]byte, 32))
}

// ================== PreKeyRecord ==================

func TestNewPreKey(t *testing.T) {
	s := newSerializer()
	kp := genKP(t)

	pk := record.NewPreKey(1, kp, s.PreKeyRecord)

	if pk.ID().Value != 1 {
		t.Fatal("ID mismatch")
	}
	if pk.KeyPair() != kp {
		t.Fatal("keypair mismatch")
	}
}

func TestPreKeySerializeDeserialize(t *testing.T) {
	s := newSerializer()
	kp := genKP(t)

	pk := record.NewPreKey(5, kp, s.PreKeyRecord)

	b, err := pk.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	pk2, err := record.NewPreKeyFromBytes(b, s.PreKeyRecord)
	if err != nil {
		t.Fatal(err)
	}

	if pk2.ID().Value != 5 {
		t.Fatal("ID mismatch after roundtrip")
	}
	if pk2.KeyPair() == nil {
		t.Fatal("keypair should not be nil after roundtrip")
	}
}

func TestNewPreKeyFromStruct(t *testing.T) {
	s := newSerializer()
	kp := genKP(t)

	privKey := kp.PrivateKey().Serialize()
	structure := &record.PreKeyStructure{
		ID:         10,
		PublicKey:  kp.PublicKey().Serialize(),
		PrivateKey: mustGuard(t, privKey[:]),
	}

	pk, err := record.NewPreKeyFromStruct(structure, s.PreKeyRecord)
	if err != nil {
		t.Fatal(err)
	}
	if pk.ID().Value != 10 {
		t.Fatal("ID mismatch")
	}
}

func TestNewPreKeyFromBytesInvalid(t *testing.T) {
	s := newSerializer()
	_, err := record.NewPreKeyFromBytes([]byte("not json"), s.PreKeyRecord)
	if err == nil {
		t.Fatal("expected error for invalid data")
	}
}

// ================== SignedPreKeyRecord ==================

func TestNewSignedPreKey(t *testing.T) {
	s := newSerializer()
	kp := genKP(t)
	sig := [64]byte{0x01}

	spk := record.NewSignedPreKey(1, 1000, kp, sig, s.SignedPreKeyRecord)

	if spk.ID() != 1 {
		t.Fatal("ID mismatch")
	}
	if spk.Timestamp() != 1000 {
		t.Fatal("timestamp mismatch")
	}
	if spk.KeyPair() != kp {
		t.Fatal("keypair mismatch")
	}
	if spk.Signature() != sig {
		t.Fatal("signature mismatch")
	}
}

func TestSignedPreKeySerializeDeserialize(t *testing.T) {
	s := newSerializer()
	kp := genKP(t)
	sig := [64]byte{0xaa, 0xbb}

	spk := record.NewSignedPreKey(2, 2000, kp, sig, s.SignedPreKeyRecord)

	b, err := spk.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	spk2, err := record.NewSignedPreKeyFromBytes(b, s.SignedPreKeyRecord)
	if err != nil {
		t.Fatal(err)
	}

	if spk2.ID() != 2 {
		t.Fatal("ID mismatch after roundtrip")
	}
	if spk2.Timestamp() != 2000 {
		t.Fatal("timestamp mismatch after roundtrip")
	}
}

func TestNewSignedPreKeyFromStruct(t *testing.T) {
	s := newSerializer()
	kp := genKP(t)

	spkPrivKey := kp.PrivateKey().Serialize()
	structure := &record.SignedPreKeyStructure{
		ID:         3,
		PublicKey:  kp.PublicKey().Serialize(),
		PrivateKey: mustGuard(t, spkPrivKey[:]),
		Signature:  make([]byte, 64),
		Timestamp:  3000,
	}

	spk, err := record.NewSignedPreKeyFromStruct(structure, s.SignedPreKeyRecord)
	if err != nil {
		t.Fatal(err)
	}
	if spk.ID() != 3 {
		t.Fatal("ID mismatch")
	}
}

func TestNewSignedPreKeyFromBytesInvalid(t *testing.T) {
	s := newSerializer()
	_, err := record.NewSignedPreKeyFromBytes([]byte("not json"), s.SignedPreKeyRecord)
	if err == nil {
		t.Fatal("expected error for invalid data")
	}
}

// ================== PendingPreKeyState ==================

func TestNewPendingPreKey(t *testing.T) {
	kp := genKP(t)
	preKeyID := optional.NewOptionalUint32(5)

	structure := &record.PendingPreKeyStructure{
		PreKeyID:       preKeyID,
		SignedPreKeyID: 20,
		BaseKey:        kp.PublicKey().Serialize(),
	}

	ppk, err := record.NewPendingPreKeyFromStruct(structure)
	if err != nil {
		t.Fatal(err)
	}

	if ppk.KyberPreKeyID() != nil {
		t.Fatal("kyber prekey ID should be nil when not set")
	}
	if ppk.KyberCiphertext() != nil {
		t.Fatal("kyber ciphertext should be nil when not set")
	}
}

func TestPendingPreKeyFromStructNil(t *testing.T) {
	ppk, err := record.NewPendingPreKeyFromStruct(nil)
	if err != nil {
		t.Fatal(err)
	}
	if ppk != nil {
		t.Fatal("expected nil for nil structure")
	}
}

func TestPendingPreKeyKyberFields(t *testing.T) {
	kp := genKP(t)

	structure := &record.PendingPreKeyStructure{
		PreKeyID:        optional.NewOptionalUint32(1),
		SignedPreKeyID:  10,
		BaseKey:         kp.PublicKey().Serialize(),
		KyberPreKeyID:   optional.NewOptionalUint32(42),
		KyberCiphertext: []byte("kyber-ct"),
	}

	ppk, err := record.NewPendingPreKeyFromStruct(structure)
	if err != nil {
		t.Fatal(err)
	}

	if ppk.KyberPreKeyID() == nil || ppk.KyberPreKeyID().Value != 42 {
		t.Fatal("kyber prekey ID mismatch")
	}
	if string(ppk.KyberCiphertext()) != "kyber-ct" {
		t.Fatal("kyber ciphertext mismatch")
	}
}

// ================== UnacknowledgedPreKey ==================

func TestNewUnackPreKeyMessageItems(t *testing.T) {
	kp := genKP(t)
	preKeyID := optional.NewOptionalUint32(3)

	items := record.NewUnackPreKeyMessageItems(preKeyID, 15, kp.PublicKey())

	if items.PreKeyID().Value != 3 {
		t.Fatal("prekey ID mismatch")
	}
	if items.SignedPreKeyID() != 15 {
		t.Fatal("signed prekey ID mismatch")
	}
	if items.BaseKey() == nil {
		t.Fatal("base key should not be nil")
	}
}

func TestNewUnackPreKeyMessageItemsFromStruct(t *testing.T) {
	kp := genKP(t)

	structure := &record.UnackPreKeyMessageItemsStructure{
		PreKeyID:       optional.NewOptionalUint32(7),
		SignedPreKeyID: 25,
		BaseKey:        kp.PublicKey().Serialize(),
	}

	items, err := record.NewUnackPreKeyMessageItemsFromStruct(structure)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if items.PreKeyID().Value != 7 {
		t.Fatal("prekey ID mismatch")
	}
	if items.SignedPreKeyID() != 25 {
		t.Fatal("signed prekey ID mismatch")
	}
}

func TestUnackPreKeyMessageItemsKyberFields(t *testing.T) {
	kp := genKP(t)

	structure := &record.UnackPreKeyMessageItemsStructure{
		PreKeyID:        optional.NewOptionalUint32(1),
		SignedPreKeyID:  10,
		BaseKey:         kp.PublicKey().Serialize(),
		KyberPreKeyID:   optional.NewOptionalUint32(99),
		KyberCiphertext: []byte("ct-data"),
	}

	items, err := record.NewUnackPreKeyMessageItemsFromStruct(structure)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if items.KyberPreKeyID() == nil || items.KyberPreKeyID().Value != 99 {
		t.Fatal("kyber prekey ID mismatch")
	}
	if string(items.KyberCiphertext()) != "ct-data" {
		t.Fatal("kyber ciphertext mismatch")
	}
}

func TestNewUnackPreKeyMessageItemsFromStruct_InvalidBaseKey(t *testing.T) {
	structure := &record.UnackPreKeyMessageItemsStructure{
		PreKeyID:       optional.NewOptionalUint32(1),
		SignedPreKeyID: 10,
		BaseKey:        []byte{0xFF}, // invalid key data
	}

	_, err := record.NewUnackPreKeyMessageItemsFromStruct(structure)
	if err == nil {
		t.Fatal("expected error for invalid base key")
	}
}

// ================== ChainState ==================

func TestNewReceiverChainPair(t *testing.T) {
	kp := genKP(t)
	ck := makeChainKey(t)
	ch := record.NewChain(kp, ck, []*message.Keys{})
	pair := record.NewReceiverChainPair(ch, 5)

	if pair.ReceiverChain != ch {
		t.Fatal("receiver chain mismatch")
	}
	if pair.Index != 5 {
		t.Fatal("index mismatch")
	}
}

func TestNewChain(t *testing.T) {
	kp := genKP(t)
	ck := makeChainKey(t)
	mk := message.NewKeys([]byte("cipher"), []byte("mac"), []byte("iv"), 0)
	ch := record.NewChain(kp, ck, []*message.Keys{mk})

	if ch.SenderRatchetKey() != kp {
		t.Fatal("sender ratchet key mismatch")
	}
	if ch.ChainKey() != ck {
		t.Fatal("chain key mismatch")
	}
	if len(ch.MessageKeys()) != 1 {
		t.Fatal("message keys count mismatch")
	}
}

func TestChainSetSenderRatchetKey(t *testing.T) {
	kp1 := genKP(t)
	kp2 := genKP(t)
	ck := makeChainKey(t)
	ch := record.NewChain(kp1, ck, []*message.Keys{})

	ch.SetSenderRatchetKey(kp2)
	if ch.SenderRatchetKey() != kp2 {
		t.Fatal("sender ratchet key not updated")
	}
}

func TestChainSetChainKey(t *testing.T) {
	kp := genKP(t)
	ck1 := makeChainKey(t)
	ck2 := chain.NewKey(kdf.DeriveSecrets, make([]byte, 32), 5)
	ch := record.NewChain(kp, ck1, []*message.Keys{})

	ch.SetChainKey(ck2)
	if ch.ChainKey() != ck2 {
		t.Fatal("chain key not updated")
	}
}

func TestChainMessageKeysOperations(t *testing.T) {
	kp := genKP(t)
	ck := makeChainKey(t)
	mk1 := message.NewKeys([]byte("c1"), []byte("m1"), []byte("i1"), 0)
	mk2 := message.NewKeys([]byte("c2"), []byte("m2"), []byte("i2"), 1)

	ch := record.NewChain(kp, ck, []*message.Keys{mk1})

	// AddMessageKeys
	ch.AddMessageKeys(mk2)
	if len(ch.MessageKeys()) != 2 {
		t.Fatal("expected 2 message keys after add")
	}

	// SetMessageKeys
	mk3 := message.NewKeys([]byte("c3"), []byte("m3"), []byte("i3"), 2)
	ch.SetMessageKeys([]*message.Keys{mk3})
	if len(ch.MessageKeys()) != 1 {
		t.Fatal("expected 1 message key after set")
	}

	// PopFirstMessageKeys
	popped := ch.PopFirstMessageKeys()
	if popped != mk3 {
		t.Fatal("popped key mismatch")
	}
	if len(ch.MessageKeys()) != 0 {
		t.Fatal("expected 0 message keys after pop")
	}
}

func TestNewChainFromStructure(t *testing.T) {
	kp := genKP(t)
	privKey := kp.PrivateKey().Serialize()

	structure := &record.ChainStructure{
		SenderRatchetKeyPublic:  kp.PublicKey().Serialize(),
		SenderRatchetKeyPrivate: mustGuard(t, privKey[:]),
		ChainKey:                &chain.KeyStructure{Key: make([]byte, 32), Index: 3},
		MessageKeys: []*message.KeysStructure{
			{CipherKey: []byte("c"), MacKey: []byte("m"), IV: []byte("i"), Index: 0},
		},
	}

	ch, err := record.NewChainFromStructure(structure)
	if err != nil {
		t.Fatal(err)
	}
	if ch == nil {
		t.Fatal("chain should not be nil")
	}
	if ch.SenderRatchetKey() == nil {
		t.Fatal("sender ratchet key should not be nil")
	}
	if ch.ChainKey() == nil {
		t.Fatal("chain key should not be nil")
	}
	if len(ch.MessageKeys()) != 1 {
		t.Fatal("message keys count mismatch")
	}
}

func TestNewChainFromStructureNil(t *testing.T) {
	ch, err := record.NewChainFromStructure(nil)
	if err != nil {
		t.Fatal(err)
	}
	if ch != nil {
		t.Fatal("expected nil chain for nil structure")
	}
}

func TestNewChainFromStructureNoPrivateKey(t *testing.T) {
	kp := genKP(t)

	structure := &record.ChainStructure{
		SenderRatchetKeyPublic:  kp.PublicKey().Serialize(),
		SenderRatchetKeyPrivate: secret.Secret{},
		ChainKey:                &chain.KeyStructure{Key: make([]byte, 32), Index: 0},
	}

	ch, err := record.NewChainFromStructure(structure)
	if err != nil {
		t.Fatal(err)
	}
	if ch == nil {
		t.Fatal("chain should not be nil even without private key")
	}
}

// ================== KyberPreKeyRecord ==================

type kyberPreKeySerializer struct{}

func (k *kyberPreKeySerializer) Serialize(preKey *record.KyberPreKeyStructure) ([]byte, error) {
	return json.Marshal(preKey)
}

func (k *kyberPreKeySerializer) Deserialize(serialized []byte) (*record.KyberPreKeyStructure, error) {
	var s record.KyberPreKeyStructure
	err := json.Unmarshal(serialized, &s)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func TestNewKyberPreKey(t *testing.T) {
	pubKey := kem.NewPublicKey(kem.KeyTypeKyber1024, make([]byte, 1568))
	kp := mustGuardedKyberKeyPair(t, pubKey, make([]byte, 3168))
	sig := []byte("test-signature")

	kpk := record.NewKyberPreKey(42, 5000, kp, sig, &kyberPreKeySerializer{})

	if kpk.ID() != 42 {
		t.Fatal("ID mismatch")
	}
	if kpk.Timestamp() != 5000 {
		t.Fatal("timestamp mismatch")
	}
	if kpk.PublicKey() != kp.Public {
		t.Fatal("public key mismatch")
	}
	retSig := kpk.Signature()
	if !bytes.Equal(retSig, sig) {
		t.Fatal("signature mismatch")
	}
}

func TestKyberPreKeySerialize(t *testing.T) {
	pubKey := kem.NewPublicKey(kem.KeyTypeKyber1024, make([]byte, 1568))
	kp := mustGuardedKyberKeyPair(t, pubKey, make([]byte, 3168))

	kpk := record.NewKyberPreKey(10, 1000, kp, []byte("sig"), &kyberPreKeySerializer{})

	b, err := kpk.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 {
		t.Fatal("serialized bytes should not be empty")
	}
}

func TestNewKyberPreKeyFromStructure(t *testing.T) {
	pubKey := kem.NewPublicKey(kem.KeyTypeKyber1024, make([]byte, 1568))
	secKey, err := kem.NewSecretKey(kem.KeyTypeKyber1024, make([]byte, 3168))
	if err != nil {
		t.Fatalf("NewSecretKey() error: %v", err)
	}

	structure := record.KyberPreKeyStructure{
		ID:         7,
		PublicKey:  pubKey.Serialize(),
		PrivateKey: mustGuard(t, secKey.Data()),
		Signature:  []byte("sig-data"),
		Timestamp:  2000,
	}

	kpk, err := record.NewKyberPreKeyFromStructure(structure, &kyberPreKeySerializer{})
	if err != nil {
		t.Fatal(err)
	}
	if kpk.ID() != 7 {
		t.Fatal("ID mismatch")
	}
	if kpk.Timestamp() != 2000 {
		t.Fatal("timestamp mismatch")
	}
	if kpk.PublicKey() == nil {
		t.Fatal("public key should not be nil")
	}
	if !bytes.Equal(kpk.Signature(), []byte("sig-data")) {
		t.Fatal("signature mismatch")
	}
}

func TestNewKyberPreKeyFromStructureInvalidPublicKey(t *testing.T) {
	structure := record.KyberPreKeyStructure{
		ID:        1,
		PublicKey: []byte{0xFF},
		Timestamp: 100,
	}

	_, err := record.NewKyberPreKeyFromStructure(structure, &kyberPreKeySerializer{})
	if err == nil {
		t.Fatal("expected error for invalid public key")
	}
}

// ================== SessionRecord ==================

func TestNewSession(t *testing.T) {
	s := newSerializer()
	sess := record.NewSession(s.Session, s.State)

	if !sess.IsFresh() {
		t.Fatal("new session should be fresh")
	}
	if sess.SessionState() == nil {
		t.Fatal("session state should not be nil")
	}
	if len(sess.PreviousSessionStates()) != 0 {
		t.Fatal("previous states should be empty")
	}
}

func TestSessionSetState(t *testing.T) {
	s := newSerializer()
	sess := record.NewSession(s.Session, s.State)

	newState := record.NewState(s.State)
	sess.SetState(newState)

	if sess.SessionState() != newState {
		t.Fatal("set state failed")
	}
}

func TestSessionArchiveCurrentState(t *testing.T) {
	s := newSerializer()
	sess := record.NewSession(s.Session, s.State)

	originalState := sess.SessionState()
	sess.ArchiveCurrentState()

	if len(sess.PreviousSessionStates()) != 1 {
		t.Fatal("expected 1 previous state after archive")
	}
	if sess.PreviousSessionStates()[0] != originalState {
		t.Fatal("archived state mismatch")
	}
}

func TestSessionPromoteState(t *testing.T) {
	s := newSerializer()
	sess := record.NewSession(s.Session, s.State)

	state1 := sess.SessionState()
	state2 := record.NewState(s.State)
	sess.PromoteState(state2)

	if sess.SessionState() != state2 {
		t.Fatal("promoted state mismatch")
	}
	if sess.PreviousSessionStates()[0] != state1 {
		t.Fatal("previous state mismatch")
	}
}

func TestSessionArchiveMaxLength(t *testing.T) {
	s := newSerializer()
	sess := record.NewSession(s.Session, s.State)

	for i := 0; i < 50; i++ {
		sess.ArchiveCurrentState()
	}

	if len(sess.PreviousSessionStates()) > 40 {
		t.Fatalf("expected at most 40 previous states, got %d",
			len(sess.PreviousSessionStates()))
	}
}

func TestSessionFromState(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	sess := record.NewSessionFromState(state, s.Session)

	if sess.IsFresh() {
		t.Fatal("session from state should not be fresh")
	}
	if sess.SessionState() != state {
		t.Fatal("state mismatch")
	}
}

func TestSessionHasSessionState(t *testing.T) {
	s := newSerializer()
	sess := record.NewSession(s.Session, s.State)

	state := sess.SessionState()
	state.SetVersion(3)
	kp := genKP(t)
	state.SetSenderBaseKey(kp.PublicKey().Serialize())

	// HasSessionState returns true when BOTH version AND base key match
	// (using constant-time comparison). This matches Rust promote_matching_session.
	// SetSenderBaseKey now correctly parses the 33-byte type-prefixed form via
	// ecc.DecodePoint, so state.SenderBaseKey() equals kp.PublicKey().Serialize().
	baseKey := state.SenderBaseKey()
	result := sess.HasSessionState(3, baseKey)
	if !result {
		t.Fatal("expected true when both version and base key match")
	}

	// When version differs, should return false even with matching base key.
	result = sess.HasSessionState(2, baseKey)
	if result {
		t.Fatal("expected false when version differs")
	}
}

func TestSessionHasSessionStateNilBaseKey(t *testing.T) {
	s := newSerializer()
	sess := record.NewSession(s.Session, s.State)
	state := sess.SessionState()
	state.SetVersion(3)

	// Version matches but sender base key is nil -- should return false.
	result := sess.HasSessionState(3, []byte{0x01})
	if result {
		t.Fatal("expected false when sender base key is nil")
	}
}

func TestSessionHasSessionStatePreviousStates(t *testing.T) {
	s := newSerializer()
	sess := record.NewSession(s.Session, s.State)

	// Set up current state
	kp1 := genKP(t)
	sess.SessionState().SetVersion(3)
	sess.SessionState().SetSenderBaseKey(kp1.PublicKey().Serialize())

	// SetSenderBaseKey now correctly decodes the 33-byte type-prefixed EC key via
	// ecc.DecodePoint, so SenderBaseKey() returns the original Serialize() bytes.
	oldBaseKey := sess.SessionState().SenderBaseKey()

	// Archive and set up new current state
	sess.ArchiveCurrentState()
	kp2 := genKP(t)
	sess.SessionState().SetVersion(3)
	sess.SessionState().SetSenderBaseKey(kp2.PublicKey().Serialize())
	newBaseKey := sess.SessionState().SenderBaseKey()

	// S-C1: HasSessionState should find the old state in previous states
	// AND promote it to the current session (matching Rust promote_matching_session).
	result := sess.HasSessionState(3, oldBaseKey)
	if !result {
		t.Fatal("expected true for matching version and base key in previous states")
	}

	// Verify the old state was promoted to current.
	currentBaseKey := sess.SessionState().SenderBaseKey()
	if subtle.ConstantTimeCompare(currentBaseKey, oldBaseKey) != 1 {
		t.Fatal("S-C1: expected old state to be promoted to current session")
	}

	// Verify the previously-current state was moved to previous states.
	prev := sess.PreviousSessionStates()
	if len(prev) == 0 {
		t.Fatal("expected previous states to contain the displaced current state")
	}
	if subtle.ConstantTimeCompare(prev[0].SenderBaseKey(), newBaseKey) != 1 {
		t.Fatal("expected displaced current state to be first in previous states")
	}

	// Should NOT find it with wrong version.
	result = sess.HasSessionState(2, oldBaseKey)
	if result {
		t.Fatal("expected false when version differs in previous states")
	}
}

func TestSessionHasSessionStateNotFound(t *testing.T) {
	s := newSerializer()
	sess := record.NewSession(s.Session, s.State)

	kp := genKP(t)
	sess.SessionState().SetVersion(3)
	sess.SessionState().SetSenderBaseKey(kp.PublicKey().Serialize())

	// Non-matching base key with matching version should return false.
	kp2 := genKP(t)
	result := sess.HasSessionState(3, kp2.PublicKey().Serialize())
	if result {
		t.Fatal("expected false for non-matching base key")
	}

	// Non-matching version with matching base key should also return false.
	result = sess.HasSessionState(2, kp.PublicKey().Serialize())
	if result {
		t.Fatal("expected false for non-matching version")
	}
}

func makeFullStateStructure(t *testing.T) *record.StateStructure {
	t.Helper()
	kp := genKP(t)
	pubKeyBytes := kp.PublicKey().Serialize()
	privKeyArr := kp.PrivateKey().Serialize()

	return &record.StateStructure{
		SessionVersion:       3,
		LocalIdentityPublic:  pubKeyBytes,
		RemoteIdentityPublic: pubKeyBytes,
		SenderBaseKey:        pubKeyBytes,
		RootKey:              mustGuard(t, make([]byte, 32)),
		PendingPreKey: &record.PendingPreKeyStructure{
			PreKeyID:       optional.NewOptionalUint32(1),
			SignedPreKeyID: 1,
			BaseKey:        pubKeyBytes,
		},
		SenderChain: &record.ChainStructure{
			SenderRatchetKeyPublic:  pubKeyBytes,
			SenderRatchetKeyPrivate: mustGuard(t, privKeyArr[:]),
			ChainKey:                &chain.KeyStructure{Key: make([]byte, 32), Index: 0},
		},
	}
}

func makeFullState(t *testing.T) *record.State {
	t.Helper()
	s := newSerializer()
	structure := makeFullStateStructure(t)
	state, err := record.NewStateFromStructure(structure, s.State)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func TestSessionFromStructure(t *testing.T) {
	s := newSerializer()
	state1 := makeFullStateStructure(t)
	state2 := makeFullStateStructure(t)
	state2.SessionVersion = 2

	structure := &record.SessionStructure{
		SessionState:   state1,
		PreviousStates: []*record.StateStructure{state2},
	}

	sess, err := record.NewSessionFromStructure(structure, s.Session, s.State)
	if err != nil {
		t.Fatal(err)
	}

	if sess.SessionState().Version() != 3 {
		t.Fatal("session version mismatch")
	}
	if len(sess.PreviousSessionStates()) != 1 {
		t.Fatal("previous states count mismatch")
	}
}

func TestSessionFromBytes(t *testing.T) {
	s := newSerializer()
	state1 := makeFullStateStructure(t)

	structure := &record.SessionStructure{
		SessionState:   state1,
		PreviousStates: []*record.StateStructure{},
	}

	b, err := s.Session.Serialize(structure)
	if err != nil {
		t.Fatal(err)
	}

	sess, err := record.NewSessionFromBytes(b, s.Session, s.State)
	if err != nil {
		t.Fatal(err)
	}

	if sess.SessionState().Version() != 3 {
		t.Fatal("session version mismatch after bytes roundtrip")
	}
	if sess.IsFresh() {
		t.Fatal("session from bytes should not be fresh")
	}
}

func TestSessionFromBytesInvalid(t *testing.T) {
	s := newSerializer()
	_, err := record.NewSessionFromBytes([]byte("not json"), s.Session, s.State)
	if err == nil {
		t.Fatal("expected error for invalid bytes")
	}
}

func TestSessionSerializeRoundTrip(t *testing.T) {
	s := newSerializer()
	state := makeFullState(t)
	sess := record.NewSessionFromState(state, s.Session)

	b, err := sess.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	sess2, err := record.NewSessionFromBytes(b, s.Session, s.State)
	if err != nil {
		t.Fatal(err)
	}

	if sess2.SessionState().Version() != state.Version() {
		t.Fatal("version mismatch after session serialize roundtrip")
	}
}

// ================== SessionState ==================

func TestNewState(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	if state == nil {
		t.Fatal("state should not be nil")
	}
	// A new state has stored version 0, which maps to version 2
	// (pre-versioning session behavior, matching Rust).
	if state.Version() != 2 {
		t.Fatal("version should be 2 (pre-versioning default)")
	}
}

func TestStateSettersAndGetters(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	state.SetVersion(3)
	if state.Version() != 3 {
		t.Fatal("version mismatch")
	}

	state.SetPreviousCounter(10)
	if state.PreviousCounter() != 10 {
		t.Fatal("previous counter mismatch")
	}

	state.SetLocalRegistrationID(1111)
	if state.LocalRegistrationID() != 1111 {
		t.Fatal("local registration ID mismatch")
	}

	state.SetRemoteRegistrationID(2222)
	if state.RemoteRegistrationID() != 2222 {
		t.Fatal("remote registration ID mismatch")
	}

	localIdentity := genIDKeyPair(t)
	state.SetLocalIdentityKey(localIdentity.PublicKey())
	if state.LocalIdentityKey() != localIdentity.PublicKey() {
		t.Fatal("local identity key mismatch")
	}

	remoteIdentity := genIDKeyPair(t)
	state.SetRemoteIdentityKey(remoteIdentity.PublicKey())
	if state.RemoteIdentityKey() != remoteIdentity.PublicKey() {
		t.Fatal("remote identity key mismatch")
	}
}

func TestStateSenderBaseKey(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	if state.SenderBaseKey() != nil {
		t.Fatal("sender base key should be nil initially")
	}

	kp := genKP(t)
	state.SetSenderBaseKey(kp.PublicKey().Serialize())
	if state.SenderBaseKey() == nil {
		t.Fatal("sender base key should not be nil after set")
	}
}

func TestStateRootKey(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	rk := makeRootKey(t)
	if err := state.SetRootKey(rk); err != nil {
		t.Fatalf("SetRootKey failed: %v", err)
	}

	got := state.RootKey()
	if got == nil {
		t.Fatal("root key should not be nil after set")
	}
	if !bytes.Equal(got.(*root.Key).Bytes(), rk.Bytes()) {
		t.Fatal("root key bytes mismatch")
	}
}

func TestStateHasSenderChain(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	if state.HasSenderChain() {
		t.Fatal("should not have sender chain initially")
	}
}

func TestStateSenderChainOperations(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	kp := genKP(t)
	ck := makeChainKey(t)

	state.SetSenderChain(kp, ck)

	if !state.HasSenderChain() {
		t.Fatal("should have sender chain after set")
	}

	srk := state.SenderRatchetKey()
	if srk == nil {
		t.Fatal("sender ratchet key should not be nil")
	}

	srkp := state.SenderRatchetKeyPair()
	if srkp == nil {
		t.Fatal("sender ratchet key pair should not be nil")
	}
	if srkp != kp {
		t.Fatal("sender ratchet key pair mismatch")
	}

	sck := state.SenderChainKey()
	if sck == nil {
		t.Fatal("sender chain key should not be nil")
	}

	ck2 := chain.NewKey(kdf.DeriveSecrets, make([]byte, 32), 5)
	state.SetSenderChainKey(ck2)
	sck2 := state.SenderChainKey()
	if sck2 == nil {
		t.Fatal("sender chain key should not be nil after update")
	}
}

func TestStateReceiverChainOperations(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	kp := genKP(t)
	ck := makeChainKey(t)

	if state.HasReceiverChain(kp.PublicKey()) {
		t.Fatal("should not have receiver chain initially")
	}

	state.AddReceiverChain(kp.PublicKey(), ck)

	if !state.HasReceiverChain(kp.PublicKey()) {
		t.Fatal("should have receiver chain after add")
	}

	rck := state.ReceiverChainKey(kp.PublicKey())
	if rck == nil {
		t.Fatal("receiver chain key should not be nil")
	}

	ck2 := chain.NewKey(kdf.DeriveSecrets, make([]byte, 32), 3)
	if err := state.SetReceiverChainKey(kp.PublicKey(), ck2); err != nil {
		t.Fatal(err)
	}
}

func TestStateReceiverChainMaxLength(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	for i := 0; i < 7; i++ {
		kp := genKP(t)
		ck := makeChainKey(t)
		state.AddReceiverChain(kp.PublicKey(), ck)
	}
	// Verifies it doesn't panic when exceeding maxReceiverChains
}

func TestStateMessageKeysOperations(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	kp := genKP(t)
	ck := makeChainKey(t)
	state.AddReceiverChain(kp.PublicKey(), ck)

	if state.HasMessageKeys(kp.PublicKey(), 0) {
		t.Fatal("should not have message keys initially")
	}

	mk := message.NewKeys([]byte("cipher"), []byte("mac"), []byte("iv00"), 0)
	if err := state.SetMessageKeys(kp.PublicKey(), mk); err != nil {
		t.Fatal(err)
	}

	if !state.HasMessageKeys(kp.PublicKey(), 0) {
		t.Fatal("should have message keys after set")
	}

	removed := state.RemoveMessageKeys(kp.PublicKey(), 0)
	if removed == nil {
		t.Fatal("removed message keys should not be nil")
	}
	if removed.Index() != 0 {
		t.Fatal("removed message key index mismatch")
	}

	if state.HasMessageKeys(kp.PublicKey(), 0) {
		t.Fatal("should not have message keys after removal")
	}
}

func TestStateHasPendingKeyExchange(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	if state.HasPendingKeyExchange() {
		t.Fatal("should not have pending key exchange initially")
	}

	baseKey := genKP(t)
	ratchetKey := genKP(t)
	identityKey := genIDKeyPair(t)

	state.SetPendingKeyExchange(5, baseKey, ratchetKey, identityKey)

	if !state.HasPendingKeyExchange() {
		t.Fatal("should have pending key exchange after set")
	}
	if state.PendingKeyExchangeSequence() != 5 {
		t.Fatal("pending key exchange sequence mismatch")
	}
	if state.PendingKeyExchangeBaseKeyPair() != baseKey {
		t.Fatal("pending key exchange base key mismatch")
	}
	if state.PendingKeyExchangeRatchetKeyPair() != ratchetKey {
		t.Fatal("pending key exchange ratchet key mismatch")
	}
	if state.PendingKeyExchangeIdentityKeyPair() != identityKey {
		t.Fatal("pending key exchange identity key mismatch")
	}
}

func TestStateUnacknowledgedPreKeyMessage(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	if state.HasUnacknowledgedPreKeyMessage() {
		t.Fatal("should not have unacknowledged prekey initially")
	}

	kp := genKP(t)
	preKeyID := optional.NewOptionalUint32(1)
	state.SetUnacknowledgedPreKeyMessage(preKeyID, 10, kp.PublicKey())

	if !state.HasUnacknowledgedPreKeyMessage() {
		t.Fatal("should have unacknowledged prekey after set")
	}

	items, err := state.UnackPreKeyMessageItems()
	if err != nil {
		t.Fatal(err)
	}
	if items.PreKeyID().Value != 1 {
		t.Fatal("prekey ID mismatch")
	}
	if items.SignedPreKeyID() != 10 {
		t.Fatal("signed prekey ID mismatch")
	}

	state.ClearUnackPreKeyMessage()
	if state.HasUnacknowledgedPreKeyMessage() {
		t.Fatal("should not have unacknowledged prekey after clear")
	}
}

func TestStateUnacknowledgedPreKeyMessageWithKyber(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	kp := genKP(t)
	preKeyID := optional.NewOptionalUint32(1)
	kyberPreKeyID := optional.NewOptionalUint32(42)
	kyberCiphertext := []byte("kyber-ct")

	state.SetUnacknowledgedPreKeyMessageWithKyber(preKeyID, 10, kp.PublicKey(), kyberPreKeyID, kyberCiphertext)

	items, err := state.UnackPreKeyMessageItems()
	if err != nil {
		t.Fatal(err)
	}
	if items.KyberPreKeyID() == nil || items.KyberPreKeyID().Value != 42 {
		t.Fatal("kyber prekey ID mismatch")
	}
	if string(items.KyberCiphertext()) != "kyber-ct" {
		t.Fatal("kyber ciphertext mismatch")
	}
}

func TestStateFromStructure(t *testing.T) {
	s := newSerializer()
	structure := makeFullStateStructure(t)
	structure.LocalRegistrationID = 1111
	structure.RemoteRegistrationID = 2222

	state, err := record.NewStateFromStructure(structure, s.State)
	if err != nil {
		t.Fatal(err)
	}

	if state.Version() != 3 {
		t.Fatal("version mismatch")
	}
	if state.LocalRegistrationID() != 1111 {
		t.Fatal("local registration ID mismatch")
	}
}

func TestStateFromStructureWithReceiverChains(t *testing.T) {
	s := newSerializer()
	structure := makeFullStateStructure(t)

	kp := genKP(t)
	structure.ReceiverChains = []*record.ChainStructure{
		{
			SenderRatchetKeyPublic: kp.PublicKey().Serialize(),
			ChainKey:               &chain.KeyStructure{Key: make([]byte, 32), Index: 0},
		},
	}

	state, err := record.NewStateFromStructure(structure, s.State)
	if err != nil {
		t.Fatal(err)
	}

	if !state.HasReceiverChain(kp.PublicKey()) {
		t.Fatal("should have receiver chain from structure")
	}
}

func TestStateFromStructureWithPendingKeyExchange(t *testing.T) {
	s := newSerializer()
	structure := makeFullStateStructure(t)

	kp := genKP(t)
	privKey := kp.PrivateKey().Serialize()
	getSlice := bytehelper.ArrayToSlice

	structure.PendingKeyExchange = &record.PendingKeyExchangeStructure{
		Sequence:                7,
		LocalBaseKeyPublic:      getSlice(kp.PublicKey().PublicKey()),
		LocalBaseKeyPrivate:     mustGuard(t, getSlice(privKey)),
		LocalRatchetKeyPublic:   getSlice(kp.PublicKey().PublicKey()),
		LocalRatchetKeyPrivate:  mustGuard(t, getSlice(privKey)),
		LocalIdentityKeyPublic:  getSlice(kp.PublicKey().PublicKey()),
		LocalIdentityKeyPrivate: mustGuard(t, getSlice(privKey)),
	}

	state, err := record.NewStateFromStructure(structure, s.State)
	if err != nil {
		t.Fatal(err)
	}

	if !state.HasPendingKeyExchange() {
		t.Fatal("should have pending key exchange from structure")
	}
	if state.PendingKeyExchangeSequence() != 7 {
		t.Fatal("pending key exchange sequence mismatch")
	}
}

func TestStateFromBytes(t *testing.T) {
	s := newSerializer()
	structure := makeFullStateStructure(t)

	b, err := s.State.Serialize(structure)
	if err != nil {
		t.Fatal(err)
	}

	state, err := record.NewStateFromBytes(b, s.State)
	if err != nil {
		t.Fatal(err)
	}

	if state.Version() != 3 {
		t.Fatal("version mismatch after bytes roundtrip")
	}
}

func TestStateFromBytesInvalid(t *testing.T) {
	s := newSerializer()
	_, err := record.NewStateFromBytes([]byte("not json"), s.State)
	if err == nil {
		t.Fatal("expected error for invalid bytes")
	}
}

func TestStateSerializeRoundTrip(t *testing.T) {
	state := makeFullState(t)
	s := newSerializer()

	state.SetVersion(3)
	state.SetLocalRegistrationID(1111)
	state.SetRemoteRegistrationID(2222)
	state.SetPreviousCounter(5)

	b, err := state.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	state2, err := record.NewStateFromBytes(b, s.State)
	if err != nil {
		t.Fatal(err)
	}

	if state2.Version() != 3 {
		t.Fatal("version mismatch after serialize roundtrip")
	}
	if state2.LocalRegistrationID() != 1111 {
		t.Fatal("local reg ID mismatch after serialize roundtrip")
	}
	if state2.RemoteRegistrationID() != 2222 {
		t.Fatal("remote reg ID mismatch after serialize roundtrip")
	}
}

func TestStateSerializeWithPendingKeyExchange(t *testing.T) {
	state := makeFullState(t)

	baseKey := genKP(t)
	ratchetKey := genKP(t)
	identityKey := genIDKeyPair(t)
	state.SetPendingKeyExchange(10, baseKey, ratchetKey, identityKey)

	s := newSerializer()
	b, err := state.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	state2, err := record.NewStateFromBytes(b, s.State)
	if err != nil {
		t.Fatal(err)
	}

	if !state2.HasPendingKeyExchange() {
		t.Fatal("should have pending key exchange after roundtrip")
	}
	if state2.PendingKeyExchangeSequence() != 10 {
		t.Fatal("pending key exchange sequence mismatch after roundtrip")
	}
}

// ================== PendingKeyExchangeState ==================

func TestNewPendingKeyExchangeFromStructNil(t *testing.T) {
	result, err := record.NewPendingKeyExchangeFromStruct(nil)
	if err != nil {
		t.Fatalf("unexpected error for nil structure: %v", err)
	}
	if result != nil {
		t.Fatal("expected nil for nil structure")
	}
}

func TestNewPendingKeyExchange(t *testing.T) {
	baseKey := genKP(t)
	ratchetKey := genKP(t)
	identityKey := genIDKeyPair(t)

	pke := record.NewPendingKeyExchange(10, baseKey, ratchetKey, identityKey)
	if pke == nil {
		t.Fatal("pending key exchange should not be nil")
	}
}

func TestNewPendingKeyExchangeFromStruct(t *testing.T) {
	kp := genKP(t)
	privKey := kp.PrivateKey().Serialize()
	getSlice := bytehelper.ArrayToSlice

	structure := &record.PendingKeyExchangeStructure{
		Sequence:                42,
		LocalBaseKeyPublic:      getSlice(kp.PublicKey().PublicKey()),
		LocalBaseKeyPrivate:     mustGuard(t, getSlice(privKey)),
		LocalRatchetKeyPublic:   getSlice(kp.PublicKey().PublicKey()),
		LocalRatchetKeyPrivate:  mustGuard(t, getSlice(privKey)),
		LocalIdentityKeyPublic:  getSlice(kp.PublicKey().PublicKey()),
		LocalIdentityKeyPrivate: mustGuard(t, getSlice(privKey)),
	}

	pke, err := record.NewPendingKeyExchangeFromStruct(structure)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pke == nil {
		t.Fatal("pending key exchange should not be nil")
	}
}

// ================== DR-W1: Archive clears pending pre-key ==================

func TestArchiveCurrentStateClearsPendingPreKey(t *testing.T) {
	s := newSerializer()
	sess := record.NewSession(s.Session, s.State)

	// Set up a pending pre-key on the current state.
	kp := genKP(t)
	preKeyID := optional.NewOptionalUint32(42)
	sess.SessionState().SetUnacknowledgedPreKeyMessage(preKeyID, 10, kp.PublicKey())
	if !sess.SessionState().HasUnacknowledgedPreKeyMessage() {
		t.Fatal("should have pending pre-key before archive")
	}

	sess.ArchiveCurrentState()

	// The archived state (now in previousStates) should have its pending pre-key cleared.
	if len(sess.PreviousSessionStates()) != 1 {
		t.Fatal("expected 1 previous state after archive")
	}
	archivedState := sess.PreviousSessionStates()[0]
	if archivedState.HasUnacknowledgedPreKeyMessage() {
		t.Fatal("archived state should not have pending pre-key (DR-W1)")
	}
}

func TestPromoteStateClearsPendingPreKeyOnArchived(t *testing.T) {
	s := newSerializer()
	sess := record.NewSession(s.Session, s.State)

	// Set up a pending pre-key on the current state.
	kp := genKP(t)
	preKeyID := optional.NewOptionalUint32(7)
	sess.SessionState().SetUnacknowledgedPreKeyMessage(preKeyID, 5, kp.PublicKey())

	// Promote a new state; the old current (with pending pre-key) goes to previous.
	newState := record.NewState(s.State)
	sess.PromoteState(newState)

	// The archived state should have its pending pre-key cleared.
	archivedState := sess.PreviousSessionStates()[0]
	if archivedState.HasUnacknowledgedPreKeyMessage() {
		t.Fatal("promoted-to-previous state should not have pending pre-key (DR-W1)")
	}
}

// ================== DR-W2: SessionWithSelf ==================

func TestSessionWithSelfTrue(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	// Set local and remote identity to the same key.
	idKP := genIDKeyPair(t)
	state.SetLocalIdentityKey(idKP.PublicKey())
	state.SetRemoteIdentityKey(idKP.PublicKey())

	if !state.SessionWithSelf() {
		t.Fatal("expected SessionWithSelf to return true for same identity")
	}
}

func TestSessionWithSelfFalse(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	// Set local and remote identity to different keys.
	localID := genIDKeyPair(t)
	remoteID := genIDKeyPair(t)
	state.SetLocalIdentityKey(localID.PublicKey())
	state.SetRemoteIdentityKey(remoteID.PublicKey())

	if state.SessionWithSelf() {
		t.Fatal("expected SessionWithSelf to return false for different identities")
	}
}

func TestSessionWithSelfNilKeys(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	// Neither key set -- should return false without panicking.
	if state.SessionWithSelf() {
		t.Fatal("expected SessionWithSelf to return false when keys are nil")
	}
}

// ================== DR-W5: PromoteOldSession removes duplicate ==================

func TestPromoteOldSessionRemovesDuplicate(t *testing.T) {
	s := newSerializer()
	sess := record.NewSession(s.Session, s.State)

	// Build 3 previous states by archiving. Use versions > 2 to avoid
	// collisions with the version 0 -> 2 mapping for pre-versioning sessions.
	for i := 0; i < 3; i++ {
		sess.SessionState().SetVersion(i + 10)
		sess.ArchiveCurrentState()
	}
	// Current state has version 0 (maps to 2). Previous states: [v12, v11, v10]
	if len(sess.PreviousSessionStates()) != 3 {
		t.Fatalf("expected 3 previous states, got %d", len(sess.PreviousSessionStates()))
	}

	// Promote the state at index 1 (v11).
	stateToPromote := sess.PreviousSessionStates()[1]
	sess.PromoteOldSession(1, stateToPromote)

	// After promotion:
	// - Current should be the promoted state (v11)
	// - Previous should contain the old current + remaining previous states
	//   but NOT the promoted state again.
	if sess.SessionState().Version() != stateToPromote.Version() {
		t.Fatalf("expected promoted state version %d, got %d",
			stateToPromote.Version(), sess.SessionState().Version())
	}

	// Count how many times the promoted version appears in previous states.
	promotedVersion := stateToPromote.Version()
	count := 0
	for _, ps := range sess.PreviousSessionStates() {
		if ps.Version() == promotedVersion {
			count++
		}
	}
	if count != 0 {
		t.Fatalf("promoted state should not appear in previousStates, found %d times (DR-W5)", count)
	}
}
