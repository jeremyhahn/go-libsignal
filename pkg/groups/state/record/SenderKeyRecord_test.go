package record

import (
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/groups/ratchet"
)

// jsonSenderKeyRecordSerializer is a test serializer for SenderKey records.
type jsonSenderKeyRecordSerializer struct{}

func (s *jsonSenderKeyRecordSerializer) Serialize(record *SenderKeyStructure) ([]byte, error) {
	return json.Marshal(record)
}

func (s *jsonSenderKeyRecordSerializer) Deserialize(serialized []byte) (*SenderKeyStructure, error) {
	var structure SenderKeyStructure
	err := json.Unmarshal(serialized, &structure)
	if err != nil {
		return nil, err
	}
	return &structure, nil
}

func newTestRecordSerializer() SenderKeySerializer {
	return &jsonSenderKeyRecordSerializer{}
}

func TestNewSenderKey(t *testing.T) {
	recSerializer := newTestRecordSerializer()
	stateSerializer := newTestStateSerializer()

	record := NewSenderKey(recSerializer, stateSerializer)
	if record == nil {
		t.Fatal("NewSenderKey() returned nil")
	}
	if !record.IsEmpty() {
		t.Error("New record should be empty")
	}
}

func TestSenderKeyIsEmpty(t *testing.T) {
	recSerializer := newTestRecordSerializer()
	stateSerializer := newTestStateSerializer()

	record := NewSenderKey(recSerializer, stateSerializer)

	tests := []struct {
		name     string
		setup    func()
		expected bool
	}{
		{
			name:     "empty record",
			setup:    func() {},
			expected: true,
		},
		{
			name: "after SetSenderKeyState",
			setup: func() {
				kp := newTestKeyPair(t)
				record.SetSenderKeyState(3, 1, 0, make([]byte, 32), kp)
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset for each test
			record = NewSenderKey(recSerializer, stateSerializer)
			tt.setup()
			if record.IsEmpty() != tt.expected {
				t.Errorf("IsEmpty() = %v, want %v", record.IsEmpty(), tt.expected)
			}
		})
	}
}

func TestSenderKeySenderKeyState(t *testing.T) {
	recSerializer := newTestRecordSerializer()
	stateSerializer := newTestStateSerializer()

	t.Run("empty record returns error", func(t *testing.T) {
		record := NewSenderKey(recSerializer, stateSerializer)
		_, err := record.SenderKeyState()
		if err == nil {
			t.Error("SenderKeyState() on empty record should return error")
		}
	})

	t.Run("non-empty record returns first state", func(t *testing.T) {
		record := NewSenderKey(recSerializer, stateSerializer)
		kp := newTestKeyPair(t)
		record.SetSenderKeyState(3, 42, 0, make([]byte, 32), kp)

		state, err := record.SenderKeyState()
		if err != nil {
			t.Fatalf("SenderKeyState() error: %v", err)
		}
		if state.KeyID() != 42 {
			t.Errorf("KeyID() = %d, want 42", state.KeyID())
		}
	})
}

func TestSenderKeyGetSenderKeyStateByID(t *testing.T) {
	recSerializer := newTestRecordSerializer()
	stateSerializer := newTestStateSerializer()
	record := NewSenderKey(recSerializer, stateSerializer)

	kp := newTestKeyPair(t)
	record.SetSenderKeyState(3, 10, 0, make([]byte, 32), kp)

	t.Run("existing ID", func(t *testing.T) {
		state, err := record.GetSenderKeyStateByID(10)
		if err != nil {
			t.Fatalf("GetSenderKeyStateByID(10) error: %v", err)
		}
		if state.KeyID() != 10 {
			t.Errorf("KeyID() = %d, want 10", state.KeyID())
		}
	})

	t.Run("non-existing ID", func(t *testing.T) {
		_, err := record.GetSenderKeyStateByID(999)
		if err == nil {
			t.Error("GetSenderKeyStateByID(999) should return error for non-existing ID")
		}
	})
}

func TestSenderKeyAddSenderKeyState(t *testing.T) {
	recSerializer := newTestRecordSerializer()
	stateSerializer := newTestStateSerializer()
	record := NewSenderKey(recSerializer, stateSerializer)

	kp1 := newTestKeyPair(t)
	kp2 := newTestKeyPair(t)

	record.AddSenderKeyState(3, 1, 0, make([]byte, 32), kp1.PublicKey())
	record.AddSenderKeyState(3, 2, 0, make([]byte, 32), kp2.PublicKey())

	if record.IsEmpty() {
		t.Error("Record should not be empty after adding states")
	}

	state1, err := record.GetSenderKeyStateByID(1)
	if err != nil {
		t.Fatalf("GetSenderKeyStateByID(1) error: %v", err)
	}
	if state1.KeyID() != 1 {
		t.Errorf("state1 KeyID() = %d, want 1", state1.KeyID())
	}

	state2, err := record.GetSenderKeyStateByID(2)
	if err != nil {
		t.Fatalf("GetSenderKeyStateByID(2) error: %v", err)
	}
	if state2.KeyID() != 2 {
		t.Errorf("state2 KeyID() = %d, want 2", state2.KeyID())
	}
}

func TestSenderKeySetSenderKeyState(t *testing.T) {
	recSerializer := newTestRecordSerializer()
	stateSerializer := newTestStateSerializer()
	record := NewSenderKey(recSerializer, stateSerializer)

	kp1 := newTestKeyPair(t)
	kp2 := newTestKeyPair(t)

	// Set first state
	record.SetSenderKeyState(3, 1, 0, make([]byte, 32), kp1)
	state, _ := record.SenderKeyState()
	if state.KeyID() != 1 {
		t.Errorf("KeyID() = %d, want 1", state.KeyID())
	}

	// Set replaces all existing states
	record.SetSenderKeyState(3, 2, 5, make([]byte, 32), kp2)
	state, _ = record.SenderKeyState()
	if state.KeyID() != 2 {
		t.Errorf("After replacement, KeyID() = %d, want 2", state.KeyID())
	}

	// Previous state should no longer exist
	_, err := record.GetSenderKeyStateByID(1)
	if err == nil {
		t.Error("GetSenderKeyStateByID(1) should return error after SetSenderKeyState replaced it")
	}
}

func TestSenderKeyAddExceedsMax(t *testing.T) {
	recSerializer := newTestRecordSerializer()
	stateSerializer := newTestStateSerializer()
	record := NewSenderKey(recSerializer, stateSerializer)

	// Add more than maxSenderKeyStates states to trigger trimming
	for i := 0; i < maxSenderKeyStates+5; i++ {
		kp := newTestKeyPair(t)
		record.AddSenderKeyState(3, uint32(i), 0, make([]byte, 32), kp.PublicKey())
	}

	// First states should have been trimmed
	_, err := record.GetSenderKeyStateByID(0)
	if err == nil {
		t.Error("State at ID 0 should have been trimmed")
	}

	// Last state should exist
	_, err = record.GetSenderKeyStateByID(uint32(maxSenderKeyStates + 4))
	if err != nil {
		t.Errorf("Last added state should exist, got error: %v", err)
	}
}

func TestSenderKeySerialize(t *testing.T) {
	recSerializer := newTestRecordSerializer()
	stateSerializer := newTestStateSerializer()
	record := NewSenderKey(recSerializer, stateSerializer)

	kp := newTestKeyPair(t)
	record.SetSenderKeyState(3, 42, 0, make([]byte, 32), kp)

	data, err := record.Serialize()
	if err != nil {
		t.Fatalf("Serialize() error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("Serialize() returned empty bytes")
	}
}

func TestNewSenderKeyFromBytes(t *testing.T) {
	recSerializer := newTestRecordSerializer()
	stateSerializer := newTestStateSerializer()
	record := NewSenderKey(recSerializer, stateSerializer)

	kp := newTestKeyPair(t)
	record.SetSenderKeyState(3, 42, 5, make([]byte, 32), kp)

	data, err := record.Serialize()
	if err != nil {
		t.Fatalf("Serialize() error: %v", err)
	}

	restored, err := NewSenderKeyFromBytes(data, recSerializer, stateSerializer)
	if err != nil {
		t.Fatalf("NewSenderKeyFromBytes() error: %v", err)
	}

	state, err := restored.SenderKeyState()
	if err != nil {
		t.Fatalf("Restored SenderKeyState() error: %v", err)
	}
	if state.KeyID() != 42 {
		t.Errorf("Restored KeyID() = %d, want 42", state.KeyID())
	}
}

func TestNewSenderKeyFromBytesInvalid(t *testing.T) {
	recSerializer := newTestRecordSerializer()
	stateSerializer := newTestStateSerializer()

	_, err := NewSenderKeyFromBytes([]byte("invalid json"), recSerializer, stateSerializer)
	if err == nil {
		t.Error("NewSenderKeyFromBytes with invalid data should return error")
	}
}

func TestNewSenderKeyFromStruct(t *testing.T) {
	kp := newTestKeyPair(t)
	recSerializer := newTestRecordSerializer()
	stateSerializer := newTestStateSerializer()

	privKey := kp.PrivateKey().Serialize()
	structure := &SenderKeyStructure{
		SenderKeyStates: []*SenderKeyStateStructure{
			{
				Keys:  nil,
				KeyID: 100,
				SenderChainKey: &ratchet.SenderChainKeyStructure{
					Iteration: 0,
					ChainKey:  make([]byte, 32),
				},
				SigningKeyPrivate: privKey[:],
				SigningKeyPublic:  kp.PublicKey().Serialize(),
			},
		},
	}

	record, err := NewSenderKeyFromStruct(structure, recSerializer, stateSerializer)
	if err != nil {
		t.Fatalf("NewSenderKeyFromStruct() error: %v", err)
	}

	state, err := record.SenderKeyState()
	if err != nil {
		t.Fatalf("SenderKeyState() error: %v", err)
	}
	if state.KeyID() != 100 {
		t.Errorf("KeyID() = %d, want 100", state.KeyID())
	}
}

func TestNewSenderKeyFromStructInvalidKey(t *testing.T) {
	stateSerializer := newTestStateSerializer()
	recSerializer := newTestRecordSerializer()

	structure := &SenderKeyStructure{
		SenderKeyStates: []*SenderKeyStateStructure{
			{
				Keys:  nil,
				KeyID: 1,
				SenderChainKey: &ratchet.SenderChainKeyStructure{
					Iteration: 0,
					ChainKey:  make([]byte, 32),
				},
				SigningKeyPrivate: make([]byte, 32),
				SigningKeyPublic:  []byte{0xFF}, // Invalid key type
			},
		},
	}

	_, err := NewSenderKeyFromStruct(structure, recSerializer, stateSerializer)
	if err == nil {
		t.Error("NewSenderKeyFromStruct with invalid public key should return error")
	}
}

// Import the ratchet package's structure type alias
func TestSenderKeyRoundTrip(t *testing.T) {
	recSerializer := newTestRecordSerializer()
	stateSerializer := newTestStateSerializer()

	// Build record with multiple states
	record := NewSenderKey(recSerializer, stateSerializer)
	kp := newTestKeyPair(t)
	record.SetSenderKeyState(3, 42, 5, make([]byte, 32), kp)

	// Serialize
	data, err := record.Serialize()
	if err != nil {
		t.Fatalf("Serialize() error: %v", err)
	}

	// Restore
	restored, err := NewSenderKeyFromBytes(data, recSerializer, stateSerializer)
	if err != nil {
		t.Fatalf("NewSenderKeyFromBytes() error: %v", err)
	}

	// Verify state preserved
	state, err := restored.SenderKeyState()
	if err != nil {
		t.Fatalf("Restored SenderKeyState() error: %v", err)
	}
	if state.KeyID() != 42 {
		t.Errorf("Restored KeyID() = %d, want 42", state.KeyID())
	}
	if state.SenderChainKey().Iteration() != 5 {
		t.Errorf("Restored Iteration() = %d, want 5", state.SenderChainKey().Iteration())
	}
}

// Ensure imports are used.
var (
	_ = ecc.DjbType
	_ = ratchet.KdfInfo
)
