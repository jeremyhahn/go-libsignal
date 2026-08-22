//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 10 tests in this file exercise X25519. FIPS 140-3 does not approve that,
// but the X3DH key agreement specification (section 2.1) requires it, so the
// fips140only build tag drops this file from the FIPS gate. `make test` and
// `make coverage` still run it.

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

// TestAddSenderKeyState_ReinsertBecomesmost_recent verifies that re-adding a
// state with the same (chain_id, signing_key) moves it to the front of the
// deque, matching Rust's
// when_second_state_with_same_public_key_and_chain_id_added_then_it_becomes_the_most_recent
// (rust/protocol/src/sender_keys.rs:571-590).
func TestAddSenderKeyState_ReinsertBecomesMostRecent(t *testing.T) {
	recSerializer := newTestRecordSerializer()
	stateSerializer := newTestStateSerializer()
	record := NewSenderKey(recSerializer, stateSerializer)

	kp1 := newTestKeyPair(t)
	kp2 := newTestKeyPair(t)
	chainKey := make([]byte, 32)

	// Add two distinct states: order becomes [2, 1] (newest first).
	record.AddSenderKeyState(3, 1, 0, chainKey, kp1.PublicKey())
	record.AddSenderKeyState(3, 2, 0, chainKey, kp2.PublicKey())

	// SenderKeyState() returns front = state 2.
	front, err := record.SenderKeyState()
	if err != nil {
		t.Fatalf("SenderKeyState() error: %v", err)
	}
	if front.KeyID() != 2 {
		t.Fatalf("before re-add: front KeyID = %d, want 2", front.KeyID())
	}

	// Re-add state 1 (same key, same chain_id). It must be promoted to front.
	record.AddSenderKeyState(3, 1, 0, chainKey, kp1.PublicKey())

	front, err = record.SenderKeyState()
	if err != nil {
		t.Fatalf("SenderKeyState() after re-add error: %v", err)
	}
	if front.KeyID() != 1 {
		t.Errorf("after re-add: front KeyID = %d, want 1 (promoted to front)", front.KeyID())
	}
	// State 2 must still be accessible (second position).
	_, err = record.GetSenderKeyStateByID(2)
	if err != nil {
		t.Errorf("state 2 should still exist after re-add of state 1: %v", err)
	}
}

// TestAddSenderKeyState_ExceedsMaxOldestEjected verifies FIFO eviction when
// MAX_SENDER_KEY_STATES is exceeded, matching Rust's
// when_exceed_maximum_states_then_oldest_is_ejected
// (rust/protocol/src/sender_keys.rs:496-535).
func TestAddSenderKeyState_ExceedsMaxOldestEjected(t *testing.T) {
	if maxSenderKeyStates != 5 {
		t.Fatalf("test written expecting maxSenderKeyStates=5, got %d", maxSenderKeyStates)
	}

	recSerializer := newTestRecordSerializer()
	stateSerializer := newTestStateSerializer()
	record := NewSenderKey(recSerializer, stateSerializer)

	kps := make([]*ecc.ECKeyPair, 6)
	for i := range kps {
		kps[i] = newTestKeyPair(t)
	}
	chainKey := make([]byte, 32)

	// Add 5 states (IDs 1-5). After each add the newest is at front.
	for i := 0; i < 5; i++ {
		record.AddSenderKeyState(3, uint32(i+1), 0, chainKey, kps[i].PublicKey())
	}

	// Front must be state 5 (most recently added).
	front, err := record.SenderKeyState()
	if err != nil {
		t.Fatalf("SenderKeyState() error: %v", err)
	}
	if front.KeyID() != 5 {
		t.Fatalf("front before eviction: KeyID = %d, want 5", front.KeyID())
	}
	// State 1 is the oldest (tail).
	_, err = record.GetSenderKeyStateByID(1)
	if err != nil {
		t.Fatalf("state 1 should exist before eviction: %v", err)
	}

	// Add state 6 — state 1 (oldest) must be evicted.
	record.AddSenderKeyState(3, 6, 0, chainKey, kps[5].PublicKey())

	if _, err = record.GetSenderKeyStateByID(1); err == nil {
		t.Error("state 1 (oldest) must be evicted after exceeding maxSenderKeyStates")
	}
	// State 6 is now at front.
	front, err = record.SenderKeyState()
	if err != nil {
		t.Fatalf("SenderKeyState() after eviction error: %v", err)
	}
	if front.KeyID() != 6 {
		t.Errorf("front after eviction: KeyID = %d, want 6", front.KeyID())
	}
	// States 2-5 must still be present.
	for _, id := range []uint32{2, 3, 4, 5} {
		if _, err = record.GetSenderKeyStateByID(id); err != nil {
			t.Errorf("state %d should still exist after eviction: %v", id, err)
		}
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
			ChainKey:  mustGuard(t, make([]byte, 32)),
		},
		SigningKeyPrivate: mustGuard(t, privArr[:]),
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
