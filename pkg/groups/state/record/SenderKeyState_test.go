package record

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/groups/ratchet"
)

// jsonSenderKeyStateSerializer is a test serializer for SenderKeyState.
type jsonSenderKeyStateSerializer struct{}

func (s *jsonSenderKeyStateSerializer) Serialize(state *SenderKeyStateStructure) ([]byte, error) {
	return json.Marshal(state)
}

func (s *jsonSenderKeyStateSerializer) Deserialize(serialized []byte) (*SenderKeyStateStructure, error) {
	var structure SenderKeyStateStructure
	err := json.Unmarshal(serialized, &structure)
	if err != nil {
		return nil, err
	}
	return &structure, nil
}

func newTestStateSerializer() SenderKeyStateSerializer {
	return &jsonSenderKeyStateSerializer{}
}

func newTestKeyPair(t *testing.T) *ecc.ECKeyPair {
	t.Helper()
	kp, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	return kp
}

func TestNewSenderKeyState(t *testing.T) {
	keyPair := newTestKeyPair(t)
	chainKey := make([]byte, 32)
	for i := range chainKey {
		chainKey[i] = byte(i)
	}
	serializer := newTestStateSerializer()

	state := NewSenderKeyState(3, 42, 0, chainKey, keyPair, serializer)
	if state.KeyID() != 42 {
		t.Errorf("KeyID() = %d, want 42", state.KeyID())
	}
	if state.SenderChainKey() == nil {
		t.Fatal("SenderChainKey() should not be nil")
	}
	if state.SenderChainKey().Iteration() != 0 {
		t.Errorf("SenderChainKey().Iteration() = %d, want 0", state.SenderChainKey().Iteration())
	}
	if state.SigningKey() == nil {
		t.Fatal("SigningKey() should not be nil")
	}
}

func TestNewSenderKeyStateFromPublicKey(t *testing.T) {
	keyPair := newTestKeyPair(t)
	chainKey := make([]byte, 32)
	serializer := newTestStateSerializer()

	state := NewSenderKeyStateFromPublicKey(3, 10, 5, chainKey, keyPair.PublicKey(), serializer)
	if state.KeyID() != 10 {
		t.Errorf("KeyID() = %d, want 10", state.KeyID())
	}
	if state.SenderChainKey().Iteration() != 5 {
		t.Errorf("SenderChainKey().Iteration() = %d, want 5", state.SenderChainKey().Iteration())
	}
	if state.SigningKey().PublicKey() == nil {
		t.Error("SigningKey().PublicKey() should not be nil")
	}
	// Private key should be nil when created from public key only
	if state.SigningKey().PrivateKey() != nil {
		t.Error("SigningKey().PrivateKey() should be nil when created from public key")
	}
}

func TestSenderKeyStateSetSenderChainKey(t *testing.T) {
	keyPair := newTestKeyPair(t)
	chainKey := make([]byte, 32)
	serializer := newTestStateSerializer()
	state := NewSenderKeyState(3, 1, 0, chainKey, keyPair, serializer)

	newChainKey := ratchet.NewSenderChainKey(10, []byte{0xFF, 0xFE, 0xFD})
	state.SetSenderChainKey(newChainKey)

	if state.SenderChainKey().Iteration() != 10 {
		t.Errorf("After SetSenderChainKey, Iteration() = %d, want 10", state.SenderChainKey().Iteration())
	}
}

func TestSenderKeyStateAddAndHasSenderMessageKey(t *testing.T) {
	keyPair := newTestKeyPair(t)
	chainKey := make([]byte, 32)
	serializer := newTestStateSerializer()
	state := NewSenderKeyState(3, 1, 0, chainKey, keyPair, serializer)

	seed := make([]byte, 32)
	msgKey, err := ratchet.NewSenderMessageKey(7, seed)
	if err != nil {
		t.Fatalf("NewSenderMessageKey() error: %v", err)
	}

	if state.HasSenderMessageKey(7) {
		t.Error("HasSenderMessageKey(7) should be false before adding")
	}

	state.AddSenderMessageKey(msgKey)

	if !state.HasSenderMessageKey(7) {
		t.Error("HasSenderMessageKey(7) should be true after adding")
	}
	if state.HasSenderMessageKey(8) {
		t.Error("HasSenderMessageKey(8) should be false")
	}
}

func TestSenderKeyStateRemoveSenderMessageKey(t *testing.T) {
	keyPair := newTestKeyPair(t)
	chainKey := make([]byte, 32)
	serializer := newTestStateSerializer()
	state := NewSenderKeyState(3, 1, 0, chainKey, keyPair, serializer)

	seed := make([]byte, 32)
	msgKey, err := ratchet.NewSenderMessageKey(3, seed)
	if err != nil {
		t.Fatalf("NewSenderMessageKey() error: %v", err)
	}

	state.AddSenderMessageKey(msgKey)

	removed := state.RemoveSenderMessageKey(3)
	if removed == nil {
		t.Fatal("RemoveSenderMessageKey(3) should not return nil")
	}
	if removed.Iteration() != 3 {
		t.Errorf("Removed key iteration = %d, want 3", removed.Iteration())
	}

	if state.HasSenderMessageKey(3) {
		t.Error("HasSenderMessageKey(3) should be false after removal")
	}
}

func TestSenderKeyStateRemoveNonExistentKey(t *testing.T) {
	keyPair := newTestKeyPair(t)
	chainKey := make([]byte, 32)
	serializer := newTestStateSerializer()
	state := NewSenderKeyState(3, 1, 0, chainKey, keyPair, serializer)

	removed := state.RemoveSenderMessageKey(999)
	if removed != nil {
		t.Error("RemoveSenderMessageKey for non-existent key should return nil")
	}
}

func TestSenderKeyStateAddExceedsMax(t *testing.T) {
	keyPair := newTestKeyPair(t)
	chainKey := make([]byte, 32)
	serializer := newTestStateSerializer()
	state := NewSenderKeyState(3, 1, 0, chainKey, keyPair, serializer)

	// Add more than maxMessageKeys to trigger trimming
	seed := make([]byte, 32)
	for i := 0; i < maxMessageKeys+10; i++ {
		msgKey, err := ratchet.NewSenderMessageKey(uint32(i), seed)
		if err != nil {
			t.Fatalf("NewSenderMessageKey(%d) error: %v", i, err)
		}
		state.AddSenderMessageKey(msgKey)
	}

	// First keys should have been trimmed
	if state.HasSenderMessageKey(0) {
		t.Error("Key at iteration 0 should have been trimmed")
	}
	// Last key should still exist
	if !state.HasSenderMessageKey(uint32(maxMessageKeys + 9)) {
		t.Error("Last added key should still exist")
	}
}

func TestSenderKeyStateSerialize(t *testing.T) {
	keyPair := newTestKeyPair(t)
	chainKey := make([]byte, 32)
	for i := range chainKey {
		chainKey[i] = byte(i)
	}
	serializer := newTestStateSerializer()
	state := NewSenderKeyState(3, 42, 5, chainKey, keyPair, serializer)

	data, err := state.Serialize()
	if err != nil {
		t.Fatalf("Serialize() error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("Serialize() returned empty bytes")
	}
}

func TestNewSenderKeyStateFromStructure(t *testing.T) {
	keyPair := newTestKeyPair(t)
	chainKey := make([]byte, 32)
	for i := range chainKey {
		chainKey[i] = byte(i)
	}
	serializer := newTestStateSerializer()

	privArr := keyPair.PrivateKey().Serialize()
	structure := &SenderKeyStateStructure{
		Keys:  []*ratchet.SenderMessageKeyStructure{},
		KeyID: 55,
		SenderChainKey: &ratchet.SenderChainKeyStructure{
			Iteration: 3,
			ChainKey:  chainKey,
		},
		SigningKeyPrivate: privArr[:],
		SigningKeyPublic:  keyPair.PublicKey().Serialize(),
	}

	state, err := NewSenderKeyStateFromStructure(structure, serializer)
	if err != nil {
		t.Fatalf("NewSenderKeyStateFromStructure() error: %v", err)
	}
	if state.KeyID() != 55 {
		t.Errorf("KeyID() = %d, want 55", state.KeyID())
	}
	if state.SenderChainKey().Iteration() != 3 {
		t.Errorf("SenderChainKey().Iteration() = %d, want 3", state.SenderChainKey().Iteration())
	}
}

func TestNewSenderKeyStateFromStructureWithKeys(t *testing.T) {
	keyPair := newTestKeyPair(t)
	chainKey := make([]byte, 32)
	serializer := newTestStateSerializer()

	msgKeyStruct := &ratchet.SenderMessageKeyStructure{
		Iteration: 7,
		IV:        make([]byte, 16),
		CipherKey: make([]byte, 32),
		Seed:      make([]byte, 32),
	}

	privArr2 := keyPair.PrivateKey().Serialize()
	structure := &SenderKeyStateStructure{
		Keys:  []*ratchet.SenderMessageKeyStructure{msgKeyStruct},
		KeyID: 10,
		SenderChainKey: &ratchet.SenderChainKeyStructure{
			Iteration: 0,
			ChainKey:  chainKey,
		},
		SigningKeyPrivate: privArr2[:],
		SigningKeyPublic:  keyPair.PublicKey().Serialize(),
	}

	state, err := NewSenderKeyStateFromStructure(structure, serializer)
	if err != nil {
		t.Fatalf("NewSenderKeyStateFromStructure() error: %v", err)
	}
	if !state.HasSenderMessageKey(7) {
		t.Error("HasSenderMessageKey(7) should be true after reconstruction from structure")
	}
}

func TestNewSenderKeyStateFromBytes(t *testing.T) {
	keyPair := newTestKeyPair(t)
	chainKey := make([]byte, 32)
	for i := range chainKey {
		chainKey[i] = byte(i)
	}
	serializer := newTestStateSerializer()

	original := NewSenderKeyState(3, 42, 5, chainKey, keyPair, serializer)
	data, err := original.Serialize()
	if err != nil {
		t.Fatalf("Serialize() error: %v", err)
	}

	restored, err := NewSenderKeyStateFromBytes(data, serializer)
	if err != nil {
		t.Fatalf("NewSenderKeyStateFromBytes() error: %v", err)
	}
	if restored.KeyID() != 42 {
		t.Errorf("Restored KeyID() = %d, want 42", restored.KeyID())
	}
	if restored.SenderChainKey().Iteration() != 5 {
		t.Errorf("Restored SenderChainKey().Iteration() = %d, want 5", restored.SenderChainKey().Iteration())
	}
}

func TestNewSenderKeyStateFromBytesInvalid(t *testing.T) {
	serializer := newTestStateSerializer()
	_, err := NewSenderKeyStateFromBytes([]byte("invalid json"), serializer)
	if err == nil {
		t.Error("NewSenderKeyStateFromBytes with invalid data should return error")
	}
}

func TestSenderKeyStateStructure(t *testing.T) {
	keyPair := newTestKeyPair(t)
	chainKey := make([]byte, 32)
	for i := range chainKey {
		chainKey[i] = byte(i)
	}
	serializer := newTestStateSerializer()

	state := NewSenderKeyState(3, 42, 5, chainKey, keyPair, serializer)

	// Add a message key
	seed := make([]byte, 32)
	msgKey, err := ratchet.NewSenderMessageKey(1, seed)
	if err != nil {
		t.Fatalf("NewSenderMessageKey() error: %v", err)
	}
	state.AddSenderMessageKey(msgKey)

	// Serialize and restore
	data, err := state.Serialize()
	if err != nil {
		t.Fatalf("Serialize() error: %v", err)
	}

	restored, err := NewSenderKeyStateFromBytes(data, serializer)
	if err != nil {
		t.Fatalf("NewSenderKeyStateFromBytes() error: %v", err)
	}
	if !restored.HasSenderMessageKey(1) {
		t.Error("Restored state should have message key at iteration 1")
	}
	if !bytes.Equal(restored.SenderChainKey().Seed(), chainKey) {
		t.Error("Restored chain key seed should match original")
	}
}
