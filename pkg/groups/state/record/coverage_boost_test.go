package record

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/groups/ratchet"
)

// TestSenderKeyStateMessageVersion_NonZero verifies that MessageVersion returns
// the stored version when it is non-zero.
func TestSenderKeyStateMessageVersion_NonZero(t *testing.T) {
	keyPair := newTestKeyPair(t)
	chainKey := make([]byte, 32)
	serializer := newTestStateSerializer()

	state := NewSenderKeyState(4, 1, 0, chainKey, keyPair, serializer)
	if state.MessageVersion() != 4 {
		t.Errorf("MessageVersion() = %d, want 4", state.MessageVersion())
	}
}

// TestSenderKeyStateMessageVersion_ZeroDefaultsToThree verifies that
// MessageVersion returns 3 when the stored version is 0 (legacy behavior
// matching the Rust reference).
func TestSenderKeyStateMessageVersion_ZeroDefaultsToThree(t *testing.T) {
	keyPair := newTestKeyPair(t)
	chainKey := make([]byte, 32)
	serializer := newTestStateSerializer()

	// Create with messageVersion=0; getter must default to 3.
	state := &SenderKeyState{
		keys:           make([]*ratchet.SenderMessageKey, 0),
		keyID:          1,
		messageVersion: 0,
		senderChainKey: ratchet.NewSenderChainKey(0, chainKey),
		signingKeyPair: keyPair,
		serializer:     serializer,
	}
	if state.MessageVersion() != 3 {
		t.Errorf("MessageVersion() = %d, want 3 for stored version 0", state.MessageVersion())
	}
}

// TestSenderKeyRecordErrorMessages verifies Error() and Is() on the typed errors.
func TestSenderKeyRecordErrorMessages(t *testing.T) {
	t.Run("ErrNoSenderKeys message", func(t *testing.T) {
		err := ErrNoSenderKeys
		if err.Error() != "record: no sender keys" {
			t.Errorf("Error() = %q, want %q", err.Error(), "record: no sender keys")
		}
	})

	t.Run("ErrNoSenderKeyForID message", func(t *testing.T) {
		err := ErrNoSenderKeyForID
		if err.Error() != "record: no sender key for ID" {
			t.Errorf("Error() = %q, want %q", err.Error(), "record: no sender key for ID")
		}
	})

	t.Run("default error kind message", func(t *testing.T) {
		err := &SenderKeyRecordError{kind: senderKeyRecordErrorKind(999)}
		if err.Error() != "record: unknown sender key error" {
			t.Errorf("Error() = %q, want %q", err.Error(), "record: unknown sender key error")
		}
	})
}

// TestSenderKeyRecordErrorIs verifies errors.Is matching by kind.
func TestSenderKeyRecordErrorIs(t *testing.T) {
	t.Run("same kind matches", func(t *testing.T) {
		err := &SenderKeyRecordError{kind: errNoSenderKeys}
		if !errors.Is(err, ErrNoSenderKeys) {
			t.Error("errors.Is should match ErrNoSenderKeys")
		}
	})

	t.Run("different kind does not match", func(t *testing.T) {
		if errors.Is(ErrNoSenderKeys, ErrNoSenderKeyForID) {
			t.Error("ErrNoSenderKeys should not match ErrNoSenderKeyForID")
		}
	})

	t.Run("non-SenderKeyRecordError target does not match", func(t *testing.T) {
		err := ErrNoSenderKeys
		if errors.Is(err, errors.New("other")) {
			t.Error("SenderKeyRecordError should not match an unrelated error type")
		}
	})
}

// TestAddSenderKeyState_ReinsertExisting verifies that adding a state with the
// same (chain_id, signing_key) re-uses the existing state rather than creating
// a new one (matching Rust deduplication behavior).
func TestAddSenderKeyState_ReinsertExisting(t *testing.T) {
	recSerializer := newTestRecordSerializer()
	stateSerializer := newTestStateSerializer()
	record := NewSenderKey(recSerializer, stateSerializer)

	kp := newTestKeyPair(t)
	chainKey := make([]byte, 32)

	// Add the state initially.
	record.AddSenderKeyState(3, 1, 0, chainKey, kp.PublicKey())

	// Retrieve it and set a message key so we can verify the existing state is reused.
	state1, err := record.GetSenderKeyStateByID(1)
	if err != nil {
		t.Fatalf("GetSenderKeyStateByID(1) error: %v", err)
	}
	seed := make([]byte, 32)
	msgKey, err := ratchet.NewSenderMessageKey(7, seed)
	if err != nil {
		t.Fatalf("NewSenderMessageKey error: %v", err)
	}
	state1.AddSenderMessageKey(msgKey)

	// Re-add with the same (id, signing_key). Should reuse existing state.
	record.AddSenderKeyState(3, 1, 5, chainKey, kp.PublicKey())

	// The re-inserted state should preserve the original state's message key.
	state2, err := record.GetSenderKeyStateByID(1)
	if err != nil {
		t.Fatalf("GetSenderKeyStateByID(1) after re-add error: %v", err)
	}
	if !state2.HasSenderMessageKey(7) {
		t.Error("Re-inserted state should preserve existing message key (reuse existing state)")
	}
}

// TestAddSenderKeyState_DifferentSigningKey verifies that adding a state with
// the same chain_id but a different signing key replaces the old state.
func TestAddSenderKeyState_DifferentSigningKey(t *testing.T) {
	recSerializer := newTestRecordSerializer()
	stateSerializer := newTestStateSerializer()
	record := NewSenderKey(recSerializer, stateSerializer)

	kp1 := newTestKeyPair(t)
	kp2 := newTestKeyPair(t)
	chainKey := make([]byte, 32)

	record.AddSenderKeyState(3, 1, 0, chainKey, kp1.PublicKey())

	// Add with the same chain_id but a different signing key.
	record.AddSenderKeyState(3, 1, 0, chainKey, kp2.PublicKey())

	// The state should still be found (the new one replaced the old).
	state, err := record.GetSenderKeyStateByID(1)
	if err != nil {
		t.Fatalf("GetSenderKeyStateByID(1) error: %v", err)
	}
	// The key should be from kp2.
	if string(state.SigningKey().PublicKey().Serialize()) != string(kp2.PublicKey().Serialize()) {
		t.Error("State should use the new signing key after replacement")
	}
}


// TestSenderKeyStateFromPublicKey_SetsKeyID verifies the full constructor sets
// all fields when creating from a public key only.
func TestSenderKeyStateFromPublicKey_MessageVersionPreserved(t *testing.T) {
	kp := newTestKeyPair(t)
	chainKey := make([]byte, 32)
	serializer := newTestStateSerializer()

	state := NewSenderKeyStateFromPublicKey(4, 77, 10, chainKey, kp.PublicKey(), serializer)
	if state.MessageVersion() != 4 {
		t.Errorf("MessageVersion() = %d, want 4", state.MessageVersion())
	}
	if state.KeyID() != 77 {
		t.Errorf("KeyID() = %d, want 77", state.KeyID())
	}
	if state.SenderChainKey().Iteration() != 10 {
		t.Errorf("Iteration() = %d, want 10", state.SenderChainKey().Iteration())
	}
}

// TestNewSenderKeyStateFromStructure_InvalidPublicKey exercises the
// ecc.DecodePoint error path.
func TestNewSenderKeyStateFromStructure_InvalidPublicKey(t *testing.T) {
	keyPair := newTestKeyPair(t)
	serializer := newTestStateSerializer()

	privArr := keyPair.PrivateKey().Serialize()
	structure := &SenderKeyStateStructure{
		Keys:  nil,
		KeyID: 1,
		SenderChainKey: &ratchet.SenderChainKeyStructure{
			Iteration: 0,
			ChainKey:  make([]byte, 32),
		},
		SigningKeyPrivate: privArr[:],
		SigningKeyPublic:  []byte{0xFF, 0x01, 0x02}, // invalid key type prefix
	}

	_, err := NewSenderKeyStateFromStructure(structure, serializer)
	if err == nil {
		t.Error("NewSenderKeyStateFromStructure with invalid public key should return error")
	}
}

// TestErrNoSenderKeysFromSenderKeyState exercises the ErrNoSenderKeys error
// returned by SenderKeyState() on an empty record.
func TestErrNoSenderKeysFromSenderKeyState(t *testing.T) {
	recSerializer := newTestRecordSerializer()
	stateSerializer := newTestStateSerializer()
	record := NewSenderKey(recSerializer, stateSerializer)

	_, err := record.SenderKeyState()
	if !errors.Is(err, ErrNoSenderKeys) {
		t.Errorf("SenderKeyState() on empty record should return ErrNoSenderKeys, got %v", err)
	}
}

// TestErrNoSenderKeyForIDFromGetByID exercises the ErrNoSenderKeyForID error.
func TestErrNoSenderKeyForIDFromGetByID(t *testing.T) {
	recSerializer := newTestRecordSerializer()
	stateSerializer := newTestStateSerializer()
	record := NewSenderKey(recSerializer, stateSerializer)

	kp := newTestKeyPair(t)
	record.SetSenderKeyState(3, 1, 0, make([]byte, 32), kp)

	_, err := record.GetSenderKeyStateByID(999)
	if !errors.Is(err, ErrNoSenderKeyForID) {
		t.Errorf("GetSenderKeyStateByID on missing ID should return ErrNoSenderKeyForID, got %v", err)
	}
}

// TestSenderKeyStateMessageVersion_AllVersions tests the MessageVersion branch
// for the boundary between 0 (defaults to 3) and non-zero versions.
func TestSenderKeyStateMessageVersion_AllVersions(t *testing.T) {
	kp := newTestKeyPair(t)
	chainKey := make([]byte, 32)
	serializer := newTestStateSerializer()

	tests := []struct {
		stored   uint32
		expected uint32
	}{
		{0, 3},
		{1, 1},
		{3, 3},
		{4, 4},
		{5, 5},
	}

	for _, tt := range tests {
		state := NewSenderKeyState(tt.stored, 1, 0, chainKey, kp, serializer)
		got := state.MessageVersion()
		if got != tt.expected {
			t.Errorf("stored=%d: MessageVersion() = %d, want %d", tt.stored, got, tt.expected)
		}
	}
}

// Ensure ecc import is used.
var _ = ecc.DjbType
