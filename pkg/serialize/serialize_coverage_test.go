package serialize

import (
	"strings"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/util/optional"
)

// TestMessageDeserializeError_Error_WithDetail verifies MessageDeserializeError with detail.
func TestMessageDeserializeError_Error_WithDetail(t *testing.T) {
	e := &MessageDeserializeError{
		MessageType: "SignalMessage",
		Detail:      "too short: only 3 bytes",
	}

	msg := e.Error()
	if !strings.Contains(msg, "SignalMessage") {
		t.Errorf("Error() = %q, expected 'SignalMessage'", msg)
	}
	if !strings.Contains(msg, "too short: only 3 bytes") {
		t.Errorf("Error() = %q, expected detail", msg)
	}
}

// TestMessageDeserializeError_Error_WithoutDetail verifies MessageDeserializeError without detail.
func TestMessageDeserializeError_Error_WithoutDetail(t *testing.T) {
	e := &MessageDeserializeError{
		MessageType: "PreKeySignalMessage",
	}

	msg := e.Error()
	if !strings.Contains(msg, "PreKeySignalMessage") {
		t.Errorf("Error() = %q, expected 'PreKeySignalMessage'", msg)
	}
	if !strings.Contains(msg, "too short") {
		t.Errorf("Error() = %q, expected 'too short'", msg)
	}
}

// TestFieldLengthError_Error verifies FieldLengthError message format.
func TestFieldLengthError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *FieldLengthError
		contains []string
	}{
		{
			name: "ratchet key",
			err: &FieldLengthError{
				MessageType: "SignalMessage",
				Field:       "ratchet key",
				Expected:    33,
				Actual:      10,
			},
			contains: []string{"SignalMessage", "ratchet key", "10", "33"},
		},
		{
			name: "identity key",
			err: &FieldLengthError{
				MessageType: "PreKeySignalMessage",
				Field:       "identity key",
				Expected:    33,
				Actual:      5,
			},
			contains: []string{"PreKeySignalMessage", "identity key", "5", "33"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.err.Error()
			if msg == "" {
				t.Fatal("Error() returned empty string")
			}
			for _, sub := range tc.contains {
				if !strings.Contains(msg, sub) {
					t.Errorf("Error() = %q, expected substring %q", msg, sub)
				}
			}
		})
	}
}

// TestBoundsExceededError_Error verifies BoundsExceededError message format.
func TestBoundsExceededError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *BoundsExceededError
		contains []string
	}{
		{
			name: "session count",
			err: &BoundsExceededError{
				MessageType: "SessionRecord",
				Field:       "previous sessions",
				Max:         40,
				Actual:      50,
			},
			contains: []string{"SessionRecord", "previous sessions", "40", "50"},
		},
		{
			name: "message keys",
			err: &BoundsExceededError{
				MessageType: "ChainState",
				Field:       "message keys",
				Max:         2000,
				Actual:      3000,
			},
			contains: []string{"ChainState", "message keys", "2000", "3000"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.err.Error()
			if msg == "" {
				t.Fatal("Error() returned empty string")
			}
			for _, sub := range tc.contains {
				if !strings.Contains(msg, sub) {
					t.Errorf("Error() = %q, expected substring %q", msg, sub)
				}
			}
		})
	}
}

// TestMessageDeserializeError_ImplementsError verifies interface compliance.
func TestMessageDeserializeError_ImplementsError(t *testing.T) {
	var _ error = (*MessageDeserializeError)(nil)
	var _ error = (*FieldLengthError)(nil)
	var _ error = (*BoundsExceededError)(nil)
}

// TestFieldLengthError_Distinct verifies that distinct field/message combinations
// produce distinct error messages.
func TestFieldLengthError_Distinct(t *testing.T) {
	e1 := &FieldLengthError{MessageType: "A", Field: "x", Expected: 10, Actual: 5}
	e2 := &FieldLengthError{MessageType: "B", Field: "y", Expected: 20, Actual: 15}

	if e1.Error() == e2.Error() {
		t.Error("distinct FieldLengthErrors should produce different messages")
	}
}

// TestBoundsExceededError_Distinct verifies distinct bounds errors produce distinct messages.
func TestBoundsExceededError_Distinct(t *testing.T) {
	e1 := &BoundsExceededError{MessageType: "X", Field: "chains", Max: 5, Actual: 10}
	e2 := &BoundsExceededError{MessageType: "Y", Field: "keys", Max: 100, Actual: 200}

	if e1.Error() == e2.Error() {
		t.Error("distinct BoundsExceededErrors should produce different messages")
	}
}

// TestProtobufStateSerializer_WithKyberPendingPreKey covers the Kyber pending prekey
// branch in stateStructureToProto and protoToStateStructure.
func TestProtobufStateSerializer_WithKyberPendingPreKey(t *testing.T) {
	s := &ProtobufStateSerializer{}
	original := &record.StateStructure{
		SessionVersion: 4,
		PendingPreKey: &record.PendingPreKeyStructure{
			PreKeyID:        optional.NewOptionalUint32(10),
			SignedPreKeyID:  20,
			BaseKey:         []byte{0x05, 0x01},
			KyberPreKeyID:   optional.NewOptionalUint32(99),
			KyberCiphertext: []byte{0xDE, 0xAD, 0xBE, 0xEF},
		},
	}

	serialized, err := s.Serialize(original)
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	deserialized, err := s.Deserialize(serialized)
	if err != nil {
		t.Fatalf("Deserialize failed: %v", err)
	}

	if deserialized.PendingPreKey == nil {
		t.Fatal("PendingPreKey should not be nil")
	}
	if deserialized.PendingPreKey.KyberPreKeyID == nil {
		t.Fatal("KyberPreKeyID should not be nil")
	}
	if deserialized.PendingPreKey.KyberPreKeyID.Value != 99 {
		t.Errorf("KyberPreKeyID = %d, want 99", deserialized.PendingPreKey.KyberPreKeyID.Value)
	}
	if string(deserialized.PendingPreKey.KyberCiphertext) != string([]byte{0xDE, 0xAD, 0xBE, 0xEF}) {
		t.Error("KyberCiphertext mismatch")
	}
}

// TestProtobufStateSerializer_WithPqRatchetState covers the PqRatchetState branch
// in stateStructureToProto.
func TestProtobufStateSerializer_WithPqRatchetState(t *testing.T) {
	s := &ProtobufStateSerializer{}
	pqState := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	original := &record.StateStructure{
		SessionVersion: 4,
		PqRatchetState: pqState,
	}

	serialized, err := s.Serialize(original)
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	deserialized, err := s.Deserialize(serialized)
	if err != nil {
		t.Fatalf("Deserialize failed: %v", err)
	}

	if len(deserialized.PqRatchetState) != len(pqState) {
		t.Errorf("PqRatchetState length = %d, want %d", len(deserialized.PqRatchetState), len(pqState))
	}
	for i, b := range deserialized.PqRatchetState {
		if b != pqState[i] {
			t.Errorf("PqRatchetState[%d] = %d, want %d", i, b, pqState[i])
			break
		}
	}
}
