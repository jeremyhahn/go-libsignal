package protocol

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
)

// jsonSignalMessageSerializer is a minimal JSON serializer for testing.
type jsonSignalMessageSerializer struct{}

func (j *jsonSignalMessageSerializer) Serialize(msg *SignalMessageStructure) ([]byte, error) {
	return json.Marshal(msg)
}

func (j *jsonSignalMessageSerializer) Deserialize(data []byte) (*SignalMessageStructure, error) {
	var msg SignalMessageStructure
	err := json.Unmarshal(data, &msg)
	if err != nil {
		return nil, err
	}
	return &msg, nil
}

func newTestKeyPair(t *testing.T) *ecc.ECKeyPair {
	t.Helper()
	kp, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	return kp
}

func newTestIdentityKey(t *testing.T) *identity.Key {
	t.Helper()
	kp := newTestKeyPair(t)
	return identity.NewKey(kp.PublicKey())
}

func TestNewSignalMessageFromStruct(t *testing.T) {
	serializer := &jsonSignalMessageSerializer{}
	ratchetKey := newTestKeyPair(t)

	t.Run("valid message", func(t *testing.T) {
		structure := &SignalMessageStructure{
			Version:    CurrentVersion,
			Counter:    1,
			RatchetKey: ratchetKey.PublicKey().Serialize(),
			CipherText: []byte("test ciphertext"),
		}

		msg, err := NewSignalMessageFromStruct(structure, serializer)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if msg.MessageVersion() != CurrentVersion {
			t.Fatalf("expected version %d, got %d", CurrentVersion, msg.MessageVersion())
		}
		if msg.Counter() != 1 {
			t.Fatalf("expected counter 1, got %d", msg.Counter())
		}
		if msg.Type() != WHISPER_TYPE {
			t.Fatalf("expected type %d, got %d", WHISPER_TYPE, msg.Type())
		}
	})

	t.Run("legacy version accepted via constructor", func(t *testing.T) {
		// NewSignalMessageFromStruct is the constructor path and does not
		// enforce version bounds (matching Rust's new() behavior).
		// Version validation is in NewSignalMessageFromBytes (deserialization).
		structure := &SignalMessageStructure{
			Version:    UnsupportedVersion,
			RatchetKey: ratchetKey.PublicKey().Serialize(),
			CipherText: []byte("data"),
		}
		msg, err := NewSignalMessageFromStruct(structure, serializer)
		if err != nil {
			t.Fatalf("constructor should accept any version, got: %v", err)
		}
		if msg.MessageVersion() != UnsupportedVersion {
			t.Fatalf("expected version %d, got %d", UnsupportedVersion, msg.MessageVersion())
		}
	})

	t.Run("future version accepted via constructor", func(t *testing.T) {
		structure := &SignalMessageStructure{
			Version:    CurrentVersion + 10,
			RatchetKey: ratchetKey.PublicKey().Serialize(),
			CipherText: []byte("data"),
		}
		msg, err := NewSignalMessageFromStruct(structure, serializer)
		if err != nil {
			t.Fatalf("constructor should accept any version, got: %v", err)
		}
		if msg.MessageVersion() != CurrentVersion+10 {
			t.Fatalf("expected version %d, got %d", CurrentVersion+10, msg.MessageVersion())
		}
	})

	t.Run("missing ciphertext", func(t *testing.T) {
		structure := &SignalMessageStructure{
			Version:    CurrentVersion,
			RatchetKey: ratchetKey.PublicKey().Serialize(),
		}
		_, err := NewSignalMessageFromStruct(structure, serializer)
		if err == nil {
			t.Fatal("expected error for missing ciphertext")
		}
	})

	t.Run("missing ratchet key", func(t *testing.T) {
		structure := &SignalMessageStructure{
			Version:    CurrentVersion,
			CipherText: []byte("data"),
		}
		_, err := NewSignalMessageFromStruct(structure, serializer)
		if err == nil {
			t.Fatal("expected error for missing ratchet key")
		}
	})
}

func TestSignalMessageSerializeDeserialize(t *testing.T) {
	serializer := &jsonSignalMessageSerializer{}
	ratchetKey := newTestKeyPair(t)

	structure := &SignalMessageStructure{
		Version:         CurrentVersion,
		Counter:         5,
		PreviousCounter: 3,
		RatchetKey:      ratchetKey.PublicKey().Serialize(),
		CipherText:      []byte("hello world"),
		Mac:             []byte{0x01, 0x02, 0x03},
	}

	msg, err := NewSignalMessageFromStruct(structure, serializer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Serialize
	serialized, err := msg.Serialize()
	if err != nil {
		t.Fatalf("unexpected serialize error: %v", err)
	}

	// Deserialize
	msg2, err := NewSignalMessageFromBytes(serialized, serializer)
	if err != nil {
		t.Fatalf("unexpected deserialize error: %v", err)
	}

	if msg2.Counter() != 5 {
		t.Fatalf("expected counter 5, got %d", msg2.Counter())
	}
	if msg2.MessageVersion() != CurrentVersion {
		t.Fatal("version mismatch after roundtrip")
	}
}

func TestSignalMessageBody(t *testing.T) {
	serializer := &jsonSignalMessageSerializer{}
	ratchetKey := newTestKeyPair(t)
	body := []byte("test body content")

	structure := &SignalMessageStructure{
		Version:    CurrentVersion,
		RatchetKey: ratchetKey.PublicKey().Serialize(),
		CipherText: body,
	}

	msg, err := NewSignalMessageFromStruct(structure, serializer)
	if err != nil {
		t.Fatal(err)
	}
	if string(msg.Body()) != string(body) {
		t.Fatal("body mismatch")
	}
}

func TestSignalMessageStructure(t *testing.T) {
	serializer := &jsonSignalMessageSerializer{}
	ratchetKey := newTestKeyPair(t)

	original := &SignalMessageStructure{
		Version:         CurrentVersion,
		Counter:         10,
		PreviousCounter: 8,
		RatchetKey:      ratchetKey.PublicKey().Serialize(),
		CipherText:      []byte("cipher"),
		Mac:             []byte{0xaa, 0xbb},
	}

	msg, err := NewSignalMessageFromStruct(original, serializer)
	if err != nil {
		t.Fatal(err)
	}

	// Structure() should return a copy
	s := msg.Structure()
	if s.Counter != 10 {
		t.Fatal("counter mismatch")
	}
	if s.PreviousCounter != 8 {
		t.Fatal("previous counter mismatch")
	}
}

func TestSignalMessageSenderRatchetKey(t *testing.T) {
	serializer := &jsonSignalMessageSerializer{}
	ratchetKey := newTestKeyPair(t)

	structure := &SignalMessageStructure{
		Version:    CurrentVersion,
		RatchetKey: ratchetKey.PublicKey().Serialize(),
		CipherText: []byte("data"),
	}

	msg, err := NewSignalMessageFromStruct(structure, serializer)
	if err != nil {
		t.Fatal(err)
	}

	if msg.SenderRatchetKey() == nil {
		t.Fatal("sender ratchet key should not be nil")
	}
	if msg.SenderRatchetKey().PublicKey() != ratchetKey.PublicKey().PublicKey() {
		t.Fatal("sender ratchet key mismatch")
	}
}

func TestNewSignalMessage(t *testing.T) {
	serializer := &jsonSignalMessageSerializer{}
	ratchetKey := newTestKeyPair(t)
	senderIdentity := newTestIdentityKey(t)
	receiverIdentity := newTestIdentityKey(t)

	macKey := make([]byte, 32)
	for i := range macKey {
		macKey[i] = byte(i)
	}

	msg, err := NewSignalMessage(
		CurrentVersion, 1, 0, macKey,
		ratchetKey.PublicKey(), []byte("ciphertext"),
		senderIdentity, receiverIdentity, serializer,
		nil, // pqRatchetMsg
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if msg.Counter() != 1 {
		t.Fatal("counter mismatch")
	}
	if msg.MessageVersion() != CurrentVersion {
		t.Fatal("version mismatch")
	}
	if msg.Structure().Mac == nil {
		t.Fatal("mac should not be nil")
	}
}

func TestSignalMessageVerifyMac(t *testing.T) {
	serializer := &jsonSignalMessageSerializer{}
	ratchetKey := newTestKeyPair(t)
	senderIdentity := newTestIdentityKey(t)
	receiverIdentity := newTestIdentityKey(t)

	macKey := make([]byte, 32)
	for i := range macKey {
		macKey[i] = byte(i)
	}

	msg, err := NewSignalMessage(
		CurrentVersion, 1, 0, macKey,
		ratchetKey.PublicKey(), []byte("ciphertext"),
		senderIdentity, receiverIdentity, serializer,
		nil, // pqRatchetMsg
	)
	if err != nil {
		t.Fatal(err)
	}

	// Valid MAC verification
	err = msg.VerifyMac(CurrentVersion, senderIdentity, receiverIdentity, macKey)
	if err != nil {
		t.Fatalf("expected valid MAC, got error: %v", err)
	}

	// Invalid MAC: wrong key
	wrongKey := make([]byte, 32)
	wrongKey[0] = 0xFF
	err = msg.VerifyMac(CurrentVersion, senderIdentity, receiverIdentity, wrongKey)
	if err == nil {
		t.Fatal("expected error for bad MAC")
	}
}

func TestNewSignalMessageFromBytesInvalidJSON(t *testing.T) {
	serializer := &jsonSignalMessageSerializer{}
	_, err := NewSignalMessageFromBytes([]byte("not json"), serializer)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// failingSignalMessageSerializer always returns an error on Serialize.
type failingSignalMessageSerializer struct{}

func (f *failingSignalMessageSerializer) Serialize(_ *SignalMessageStructure) ([]byte, error) {
	return nil, errors.New("serialize failed")
}

func (f *failingSignalMessageSerializer) Deserialize(_ []byte) (*SignalMessageStructure, error) {
	return nil, errors.New("deserialize failed")
}

func TestNewSignalMessageSerializeError(t *testing.T) {
	serializer := &failingSignalMessageSerializer{}
	ratchetKey := newTestKeyPair(t)
	senderIdentity := newTestIdentityKey(t)
	receiverIdentity := newTestIdentityKey(t)
	macKey := make([]byte, 32)

	_, err := NewSignalMessage(
		CurrentVersion, 1, 0, macKey,
		ratchetKey.PublicKey(), []byte("ciphertext"),
		senderIdentity, receiverIdentity, serializer,
		nil, // pqRatchetMsg
	)
	if err == nil {
		t.Fatal("expected error when serializer fails")
	}
}

func TestSignalMessageVerifyMacSerializeError(t *testing.T) {
	// Create a valid message first with a working serializer, then replace
	// the serializer with a failing one before calling VerifyMac.
	goodSerializer := &jsonSignalMessageSerializer{}
	ratchetKey := newTestKeyPair(t)
	senderIdentity := newTestIdentityKey(t)
	receiverIdentity := newTestIdentityKey(t)
	macKey := make([]byte, 32)

	msg, err := NewSignalMessage(
		CurrentVersion, 1, 0, macKey,
		ratchetKey.PublicKey(), []byte("ciphertext"),
		senderIdentity, receiverIdentity, goodSerializer,
		nil, // pqRatchetMsg
	)
	if err != nil {
		t.Fatal(err)
	}

	// Replace serializer with a failing one
	msg.serializer = &failingSignalMessageSerializer{}

	err = msg.VerifyMac(CurrentVersion, senderIdentity, receiverIdentity, macKey)
	if err == nil {
		t.Fatal("expected error when serializer fails during VerifyMac")
	}
}

func TestNewSignalMessageWithInvalidRatchetKey(t *testing.T) {
	serializer := &jsonSignalMessageSerializer{}

	structure := &SignalMessageStructure{
		Version:    CurrentVersion,
		RatchetKey: []byte{0xFF, 0xFF}, // invalid ECC point
		CipherText: []byte("data"),
	}
	_, err := NewSignalMessageFromStruct(structure, serializer)
	if err == nil {
		t.Fatal("expected error for invalid ratchet key bytes")
	}
}

func TestSignalMessageVerifyMacWithSwappedIdentities(t *testing.T) {
	serializer := &jsonSignalMessageSerializer{}
	ratchetKey := newTestKeyPair(t)
	senderIdentity := newTestIdentityKey(t)
	receiverIdentity := newTestIdentityKey(t)

	macKey := make([]byte, 32)
	for i := range macKey {
		macKey[i] = byte(i)
	}

	msg, err := NewSignalMessage(
		CurrentVersion, 1, 0, macKey,
		ratchetKey.PublicKey(), []byte("ciphertext"),
		senderIdentity, receiverIdentity, serializer,
		nil, // pqRatchetMsg
	)
	if err != nil {
		t.Fatal(err)
	}

	// Swapped identity keys should fail MAC verification
	err = msg.VerifyMac(CurrentVersion, receiverIdentity, senderIdentity, macKey)
	if err == nil {
		t.Fatal("expected error for swapped identity keys")
	}
}

func TestSignalMessageVersionValidation(t *testing.T) {
	serializer := &jsonSignalMessageSerializer{}
	ratchetKey := newTestKeyPair(t)

	validStructure := func(version int) *SignalMessageStructure {
		return &SignalMessageStructure{
			Version:    version,
			Counter:    1,
			RatchetKey: ratchetKey.PublicKey().Serialize(),
			CipherText: []byte("test ciphertext"),
		}
	}

	t.Run("CurrentVersion equals 4", func(t *testing.T) {
		if CurrentVersion != 4 {
			t.Fatalf("expected CurrentVersion == 4, got %d", CurrentVersion)
		}
	})

	t.Run("PreKyberVersion equals 3", func(t *testing.T) {
		if PreKyberVersion != 3 {
			t.Fatalf("expected PreKyberVersion == 3, got %d", PreKyberVersion)
		}
	})

	// Helper to serialize a structure then deserialize via the bytes path
	// which enforces version validation (matching Rust's try_from).
	deserializeViaBytes := func(s *SignalMessageStructure) (*SignalMessage, error) {
		serialized, err := serializer.Serialize(s)
		if err != nil {
			return nil, err
		}
		return NewSignalMessageFromBytes(serialized, serializer)
	}

	t.Run("version 0 rejected on deserialization", func(t *testing.T) {
		_, err := deserializeViaBytes(validStructure(0))
		if err == nil {
			t.Fatal("expected error for version 0")
		}
		if !errors.Is(err, ErrLegacyVersion) {
			t.Fatalf("expected ErrLegacyVersion, got %v", err)
		}
	})

	t.Run("version 1 rejected on deserialization", func(t *testing.T) {
		_, err := deserializeViaBytes(validStructure(1))
		if err == nil {
			t.Fatal("expected error for version 1")
		}
		if !errors.Is(err, ErrLegacyVersion) {
			t.Fatalf("expected ErrLegacyVersion, got %v", err)
		}
	})

	t.Run("version 2 rejected on deserialization", func(t *testing.T) {
		_, err := deserializeViaBytes(validStructure(2))
		if err == nil {
			t.Fatal("expected error for version 2")
		}
		if !errors.Is(err, ErrLegacyVersion) {
			t.Fatalf("expected ErrLegacyVersion, got %v", err)
		}
	})

	t.Run("version 0 accepted via constructor", func(t *testing.T) {
		// Constructor path does not enforce version bounds (matches Rust new())
		msg, err := NewSignalMessageFromStruct(validStructure(0), serializer)
		if err != nil {
			t.Fatalf("constructor should accept any version, got error: %v", err)
		}
		if msg.MessageVersion() != 0 {
			t.Fatalf("expected version 0, got %d", msg.MessageVersion())
		}
	})

	t.Run("version 3 accepted", func(t *testing.T) {
		msg, err := deserializeViaBytes(validStructure(3))
		if err != nil {
			t.Fatalf("version 3 should be accepted, got error: %v", err)
		}
		if msg.MessageVersion() != 3 {
			t.Fatalf("expected version 3, got %d", msg.MessageVersion())
		}
	})

	t.Run("version 4 accepted", func(t *testing.T) {
		msg, err := deserializeViaBytes(validStructure(4))
		if err != nil {
			t.Fatalf("version 4 should be accepted, got error: %v", err)
		}
		if msg.MessageVersion() != 4 {
			t.Fatalf("expected version 4, got %d", msg.MessageVersion())
		}
	})

	t.Run("version 5 rejected as future on deserialization", func(t *testing.T) {
		_, err := deserializeViaBytes(validStructure(5))
		if err == nil {
			t.Fatal("expected error for version 5")
		}
		if !errors.Is(err, ErrUnrecognizedVersion) {
			t.Fatalf("expected ErrUnrecognizedVersion, got %v", err)
		}
	})

	t.Run("version 100 rejected as future on deserialization", func(t *testing.T) {
		_, err := deserializeViaBytes(validStructure(100))
		if err == nil {
			t.Fatal("expected error for version 100")
		}
		if !errors.Is(err, ErrUnrecognizedVersion) {
			t.Fatalf("expected ErrUnrecognizedVersion, got %v", err)
		}
	})
}

func TestSignalMessageVerifyMacVersion2(t *testing.T) {
	// Version < 3 skips the identity key prefix in MAC calculation.
	// This exercises the version < 3 branch in getMac.
	serializer := &jsonSignalMessageSerializer{}
	ratchetKey := newTestKeyPair(t)
	senderIdentity := newTestIdentityKey(t)
	receiverIdentity := newTestIdentityKey(t)

	macKey := make([]byte, 32)
	for i := range macKey {
		macKey[i] = byte(i + 10)
	}

	// Create a v3 message but verify with version 2 (to exercise version < 3 path in getMac)
	msg, err := NewSignalMessage(
		CurrentVersion, 5, 2, macKey,
		ratchetKey.PublicKey(), []byte("cipher-v2-test"),
		senderIdentity, receiverIdentity, serializer,
		nil, // pqRatchetMsg
	)
	if err != nil {
		t.Fatal(err)
	}

	// Verify with a different version - should fail since MAC was computed with v3
	err = msg.VerifyMac(2, senderIdentity, receiverIdentity, macKey)
	if err == nil {
		t.Fatal("expected error: MAC mismatch when version changes")
	}
}
