package protocol

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/util/optional"
)

type jsonPreKeySignalMessageSerializer struct{}

func (j *jsonPreKeySignalMessageSerializer) Serialize(msg *PreKeySignalMessageStructure) ([]byte, error) {
	return json.Marshal(msg)
}

func (j *jsonPreKeySignalMessageSerializer) Deserialize(data []byte) (*PreKeySignalMessageStructure, error) {
	var msg PreKeySignalMessageStructure
	err := json.Unmarshal(data, &msg)
	if err != nil {
		return nil, err
	}
	return &msg, nil
}

func makeSignalMessageBytes(t *testing.T) []byte {
	t.Helper()
	serializer := &jsonSignalMessageSerializer{}
	ratchetKey := newTestKeyPair(t)
	structure := &SignalMessageStructure{
		Version:    CurrentVersion,
		Counter:    1,
		RatchetKey: ratchetKey.PublicKey().Serialize(),
		CipherText: []byte("test"),
	}
	msg, err := NewSignalMessageFromStruct(structure, serializer)
	if err != nil {
		t.Fatal(err)
	}
	bytes, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return bytes
}

func TestNewPreKeySignalMessageFromStruct(t *testing.T) {
	preKeySerializer := &jsonPreKeySignalMessageSerializer{}
	msgSerializer := &jsonSignalMessageSerializer{}

	baseKey := newTestKeyPair(t)
	identityKeyPair := newTestKeyPair(t)
	identityKey := identity.NewKey(identityKeyPair.PublicKey())

	msgBytes := makeSignalMessageBytes(t)

	t.Run("valid v4 message with kyber", func(t *testing.T) {
		structure := &PreKeySignalMessageStructure{
			Version:         CurrentVersion,
			RegistrationID:  12345,
			PreKeyID:        optional.NewOptionalUint32(1),
			SignedPreKeyID:  2,
			BaseKey:         baseKey.PublicKey().Serialize(),
			IdentityKey:     identityKey.Serialize(),
			Message:         msgBytes,
			KyberPreKeyID:   optional.NewOptionalUint32(42),
			KyberCiphertext: []byte("kyber-ct"),
		}

		msg, err := NewPreKeySignalMessageFromStruct(structure, preKeySerializer, msgSerializer)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if msg.MessageVersion() != CurrentVersion {
			t.Fatal("version mismatch")
		}
		if msg.RegistrationID() != 12345 {
			t.Fatal("registration ID mismatch")
		}
		if msg.PreKeyID().Value != 1 {
			t.Fatal("prekey ID mismatch")
		}
		if msg.SignedPreKeyID() != 2 {
			t.Fatal("signed prekey ID mismatch")
		}
		if msg.Type() != PREKEY_TYPE {
			t.Fatal("type mismatch")
		}
		if msg.BaseKey() == nil {
			t.Fatal("base key should not be nil")
		}
		if msg.IdentityKey() == nil {
			t.Fatal("identity key should not be nil")
		}
		if msg.WhisperMessage() == nil {
			t.Fatal("whisper message should not be nil")
		}
	})

	t.Run("valid v3 message without kyber", func(t *testing.T) {
		structure := &PreKeySignalMessageStructure{
			Version:        PreKyberVersion,
			RegistrationID: 12345,
			PreKeyID:       optional.NewOptionalUint32(1),
			SignedPreKeyID: 2,
			BaseKey:        baseKey.PublicKey().Serialize(),
			IdentityKey:    identityKey.Serialize(),
			Message:        msgBytes,
		}

		msg, err := NewPreKeySignalMessageFromStruct(structure, preKeySerializer, msgSerializer)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if msg.MessageVersion() != PreKyberVersion {
			t.Fatal("version mismatch")
		}
	})

	t.Run("legacy version", func(t *testing.T) {
		structure := &PreKeySignalMessageStructure{
			Version:     UnsupportedVersion,
			BaseKey:     baseKey.PublicKey().Serialize(),
			IdentityKey: identityKey.Serialize(),
			Message:     msgBytes,
		}
		_, err := NewPreKeySignalMessageFromStruct(structure, preKeySerializer, msgSerializer)
		if err == nil {
			t.Fatal("expected error for legacy version")
		}
	})

	t.Run("future version", func(t *testing.T) {
		structure := &PreKeySignalMessageStructure{
			Version:     CurrentVersion + 10,
			BaseKey:     baseKey.PublicKey().Serialize(),
			IdentityKey: identityKey.Serialize(),
			Message:     msgBytes,
		}
		_, err := NewPreKeySignalMessageFromStruct(structure, preKeySerializer, msgSerializer)
		if err == nil {
			t.Fatal("expected error for future version")
		}
	})

	t.Run("missing base key", func(t *testing.T) {
		structure := &PreKeySignalMessageStructure{
			Version:     PreKyberVersion,
			IdentityKey: identityKey.Serialize(),
			Message:     msgBytes,
		}
		_, err := NewPreKeySignalMessageFromStruct(structure, preKeySerializer, msgSerializer)
		if err == nil {
			t.Fatal("expected error for missing base key")
		}
	})

	t.Run("missing identity key", func(t *testing.T) {
		structure := &PreKeySignalMessageStructure{
			Version: PreKyberVersion,
			BaseKey: baseKey.PublicKey().Serialize(),
			Message: msgBytes,
		}
		_, err := NewPreKeySignalMessageFromStruct(structure, preKeySerializer, msgSerializer)
		if err == nil {
			t.Fatal("expected error for missing identity key")
		}
	})

	t.Run("missing message", func(t *testing.T) {
		structure := &PreKeySignalMessageStructure{
			Version:     PreKyberVersion,
			BaseKey:     baseKey.PublicKey().Serialize(),
			IdentityKey: identityKey.Serialize(),
		}
		_, err := NewPreKeySignalMessageFromStruct(structure, preKeySerializer, msgSerializer)
		if err == nil {
			t.Fatal("expected error for missing message")
		}
	})
}

func TestPreKeySignalMessageSerializeDeserialize(t *testing.T) {
	preKeySerializer := &jsonPreKeySignalMessageSerializer{}
	msgSerializer := &jsonSignalMessageSerializer{}

	baseKey := newTestKeyPair(t)
	identityKeyPair := newTestKeyPair(t)
	identityKey := identity.NewKey(identityKeyPair.PublicKey())
	msgBytes := makeSignalMessageBytes(t)

	structure := &PreKeySignalMessageStructure{
		Version:        PreKyberVersion,
		RegistrationID: 9999,
		PreKeyID:       optional.NewOptionalUint32(5),
		SignedPreKeyID: 10,
		BaseKey:        baseKey.PublicKey().Serialize(),
		IdentityKey:    identityKey.Serialize(),
		Message:        msgBytes,
	}

	msg, err := NewPreKeySignalMessageFromStruct(structure, preKeySerializer, msgSerializer)
	if err != nil {
		t.Fatal(err)
	}

	serialized, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	msg2, err := NewPreKeySignalMessageFromBytes(serialized, preKeySerializer, msgSerializer)
	if err != nil {
		t.Fatal(err)
	}

	if msg2.RegistrationID() != 9999 {
		t.Fatal("registration ID mismatch after roundtrip")
	}
	if msg2.SignedPreKeyID() != 10 {
		t.Fatal("signed prekey ID mismatch after roundtrip")
	}
}

func TestPreKeySignalMessageFromBytesInvalidJSON(t *testing.T) {
	preKeySerializer := &jsonPreKeySignalMessageSerializer{}
	msgSerializer := &jsonSignalMessageSerializer{}

	_, err := NewPreKeySignalMessageFromBytes([]byte("not json"), preKeySerializer, msgSerializer)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestNewPreKeySignalMessage(t *testing.T) {
	preKeySerializer := &jsonPreKeySignalMessageSerializer{}
	msgSerializer := &jsonSignalMessageSerializer{}

	ratchetKey := newTestKeyPair(t)
	baseKey := newTestKeyPair(t)
	senderIdentity := newTestIdentityKey(t)
	receiverIdentity := newTestIdentityKey(t)

	macKey := make([]byte, 32)
	signalMsg, err := NewSignalMessage(
		PreKyberVersion, 0, 0, macKey,
		ratchetKey.PublicKey(), []byte("cipher"),
		senderIdentity, receiverIdentity, msgSerializer,
		nil,      // pqRatchetMsg
		nil, nil, // localAddress, remoteAddress (no binding)
	)
	if err != nil {
		t.Fatal(err)
	}

	preKeyMsg, err := NewPreKeySignalMessage(
		PreKyberVersion, 12345,
		optional.NewOptionalUint32(1), 2,
		baseKey.PublicKey(), senderIdentity,
		signalMsg, preKeySerializer, msgSerializer,
	)
	if err != nil {
		t.Fatal(err)
	}

	if preKeyMsg.RegistrationID() != 12345 {
		t.Fatal("registration ID mismatch")
	}
	if preKeyMsg.KyberPreKeyID() != nil {
		t.Fatal("kyber prekey ID should be nil")
	}
	if preKeyMsg.KyberCiphertext() != nil {
		t.Fatal("kyber ciphertext should be nil")
	}
}

func TestNewPreKeySignalMessageFromStructInvalidBaseKey(t *testing.T) {
	preKeySerializer := &jsonPreKeySignalMessageSerializer{}
	msgSerializer := &jsonSignalMessageSerializer{}
	identityKeyPair := newTestKeyPair(t)
	identityKey := identity.NewKey(identityKeyPair.PublicKey())
	msgBytes := makeSignalMessageBytes(t)

	structure := &PreKeySignalMessageStructure{
		Version:     PreKyberVersion,
		BaseKey:     []byte{0xFF, 0xFF}, // invalid ECC key
		IdentityKey: identityKey.Serialize(),
		Message:     msgBytes,
	}
	_, err := NewPreKeySignalMessageFromStruct(structure, preKeySerializer, msgSerializer)
	if err == nil {
		t.Fatal("expected error for invalid base key")
	}
}

func TestNewPreKeySignalMessageFromStructInvalidIdentityKey(t *testing.T) {
	preKeySerializer := &jsonPreKeySignalMessageSerializer{}
	msgSerializer := &jsonSignalMessageSerializer{}
	baseKey := newTestKeyPair(t)
	msgBytes := makeSignalMessageBytes(t)

	structure := &PreKeySignalMessageStructure{
		Version:     PreKyberVersion,
		BaseKey:     baseKey.PublicKey().Serialize(),
		IdentityKey: []byte{0xFF, 0xFF}, // invalid identity key
		Message:     msgBytes,
	}
	_, err := NewPreKeySignalMessageFromStruct(structure, preKeySerializer, msgSerializer)
	if err == nil {
		t.Fatal("expected error for invalid identity key")
	}
}

func TestNewPreKeySignalMessageFromStructInvalidMessage(t *testing.T) {
	preKeySerializer := &jsonPreKeySignalMessageSerializer{}
	msgSerializer := &jsonSignalMessageSerializer{}
	baseKey := newTestKeyPair(t)
	identityKeyPair := newTestKeyPair(t)
	identityKey := identity.NewKey(identityKeyPair.PublicKey())

	structure := &PreKeySignalMessageStructure{
		Version:     PreKyberVersion,
		BaseKey:     baseKey.PublicKey().Serialize(),
		IdentityKey: identityKey.Serialize(),
		Message:     []byte("not valid json"), // invalid signal message bytes
	}
	_, err := NewPreKeySignalMessageFromStruct(structure, preKeySerializer, msgSerializer)
	if err == nil {
		t.Fatal("expected error for invalid message bytes")
	}
}

func TestNewPreKeySignalMessageWithKyberSerializeError(t *testing.T) {
	preKeySerializer := &jsonPreKeySignalMessageSerializer{}
	// Use a failing signal message serializer so that message.Serialize() fails.
	failingMsgSerializer := &failingSignalMessageSerializer{}

	ratchetKey := newTestKeyPair(t)
	baseKey := newTestKeyPair(t)
	senderIdentity := newTestIdentityKey(t)
	receiverIdentity := newTestIdentityKey(t)

	// First create a SignalMessage with a working serializer
	goodMsgSerializer := &jsonSignalMessageSerializer{}
	macKey := make([]byte, 32)
	signalMsg, err := NewSignalMessage(
		PreKyberVersion, 0, 0, macKey,
		ratchetKey.PublicKey(), []byte("cipher"),
		senderIdentity, receiverIdentity, goodMsgSerializer,
		nil,      // pqRatchetMsg
		nil, nil, // localAddress, remoteAddress (no binding)
	)
	if err != nil {
		t.Fatal(err)
	}

	// Replace the serializer with the failing one
	signalMsg.serializer = failingMsgSerializer

	_, err = NewPreKeySignalMessageWithKyber(
		PreKyberVersion, 12345,
		optional.NewOptionalUint32(1), 2,
		baseKey.PublicKey(), senderIdentity,
		signalMsg, preKeySerializer, failingMsgSerializer,
		nil, nil,
	)
	if err == nil {
		t.Fatal("expected error when signal message serializer fails")
	}
}

func TestNewPreKeySignalMessageWithKyber(t *testing.T) {
	preKeySerializer := &jsonPreKeySignalMessageSerializer{}
	msgSerializer := &jsonSignalMessageSerializer{}

	ratchetKey := newTestKeyPair(t)
	baseKey := newTestKeyPair(t)
	senderIdentity := newTestIdentityKey(t)
	receiverIdentity := newTestIdentityKey(t)

	macKey := make([]byte, 32)
	signalMsg, err := NewSignalMessage(
		CurrentVersion, 0, 0, macKey,
		ratchetKey.PublicKey(), []byte("cipher"),
		senderIdentity, receiverIdentity, msgSerializer,
		nil,      // pqRatchetMsg
		nil, nil, // localAddress, remoteAddress (no binding)
	)
	if err != nil {
		t.Fatal(err)
	}

	kyberPreKeyID := optional.NewOptionalUint32(42)
	kyberCiphertext := []byte("kyber-ciphertext-data")

	preKeyMsg, err := NewPreKeySignalMessageWithKyber(
		CurrentVersion, 12345,
		optional.NewOptionalUint32(1), 2,
		baseKey.PublicKey(), senderIdentity,
		signalMsg, preKeySerializer, msgSerializer,
		kyberPreKeyID, kyberCiphertext,
	)
	if err != nil {
		t.Fatal(err)
	}

	if preKeyMsg.KyberPreKeyID() == nil || preKeyMsg.KyberPreKeyID().Value != 42 {
		t.Fatal("kyber prekey ID mismatch")
	}
	if string(preKeyMsg.KyberCiphertext()) != "kyber-ciphertext-data" {
		t.Fatal("kyber ciphertext mismatch")
	}
}

func TestPreKeySignalMessageVersionValidation(t *testing.T) {
	preKeySerializer := &jsonPreKeySignalMessageSerializer{}
	msgSerializer := &jsonSignalMessageSerializer{}

	baseKey := newTestKeyPair(t)
	identityKeyPair := newTestKeyPair(t)
	identityKey := identity.NewKey(identityKeyPair.PublicKey())
	msgBytes := makeSignalMessageBytes(t)

	makeStructure := func(version int, withKyber bool) *PreKeySignalMessageStructure {
		s := &PreKeySignalMessageStructure{
			Version:        version,
			RegistrationID: 12345,
			PreKeyID:       optional.NewOptionalUint32(1),
			SignedPreKeyID: 2,
			BaseKey:        baseKey.PublicKey().Serialize(),
			IdentityKey:    identityKey.Serialize(),
			Message:        msgBytes,
		}
		if withKyber {
			s.KyberPreKeyID = optional.NewOptionalUint32(42)
			s.KyberCiphertext = []byte("kyber-ciphertext-data")
		}
		return s
	}

	t.Run("version 0 rejected", func(t *testing.T) {
		_, err := NewPreKeySignalMessageFromStruct(makeStructure(0, false), preKeySerializer, msgSerializer)
		if err == nil {
			t.Fatal("expected error for version 0")
		}
		if !errors.Is(err, ErrLegacyVersion) {
			t.Fatalf("expected ErrLegacyVersion, got %v", err)
		}
	})

	t.Run("version 1 rejected", func(t *testing.T) {
		_, err := NewPreKeySignalMessageFromStruct(makeStructure(1, false), preKeySerializer, msgSerializer)
		if err == nil {
			t.Fatal("expected error for version 1")
		}
		if !errors.Is(err, ErrLegacyVersion) {
			t.Fatalf("expected ErrLegacyVersion, got %v", err)
		}
	})

	t.Run("version 2 rejected", func(t *testing.T) {
		_, err := NewPreKeySignalMessageFromStruct(makeStructure(2, false), preKeySerializer, msgSerializer)
		if err == nil {
			t.Fatal("expected error for version 2")
		}
		if !errors.Is(err, ErrLegacyVersion) {
			t.Fatalf("expected ErrLegacyVersion, got %v", err)
		}
	})

	t.Run("version 3 accepted without kyber", func(t *testing.T) {
		msg, err := NewPreKeySignalMessageFromStruct(makeStructure(3, false), preKeySerializer, msgSerializer)
		if err != nil {
			t.Fatalf("version 3 without kyber should be accepted, got error: %v", err)
		}
		if msg.MessageVersion() != 3 {
			t.Fatalf("expected version 3, got %d", msg.MessageVersion())
		}
	})

	t.Run("version 3 accepted with kyber", func(t *testing.T) {
		msg, err := NewPreKeySignalMessageFromStruct(makeStructure(3, true), preKeySerializer, msgSerializer)
		if err != nil {
			t.Fatalf("version 3 with kyber should be accepted, got error: %v", err)
		}
		if msg.MessageVersion() != 3 {
			t.Fatalf("expected version 3, got %d", msg.MessageVersion())
		}
	})

	t.Run("version 4 accepted with kyber", func(t *testing.T) {
		msg, err := NewPreKeySignalMessageFromStruct(makeStructure(4, true), preKeySerializer, msgSerializer)
		if err != nil {
			t.Fatalf("version 4 with kyber should be accepted, got error: %v", err)
		}
		if msg.MessageVersion() != 4 {
			t.Fatalf("expected version 4, got %d", msg.MessageVersion())
		}
	})

	t.Run("version 4 accepted without kyber via constructor", func(t *testing.T) {
		// NewPreKeySignalMessageFromStruct is the constructor path (like Rust's new()).
		// Kyber enforcement is only applied on deserialization (NewPreKeySignalMessageFromBytes),
		// matching Rust's try_from behavior.
		msg, err := NewPreKeySignalMessageFromStruct(makeStructure(4, false), preKeySerializer, msgSerializer)
		if err != nil {
			t.Fatalf("version 4 without kyber should be accepted via constructor, got error: %v", err)
		}
		if msg.MessageVersion() != 4 {
			t.Fatalf("expected version 4, got %d", msg.MessageVersion())
		}
	})

	t.Run("version 4 rejected without kyber via deserialization", func(t *testing.T) {
		// Kyber enforcement on deserialization path, matching Rust's try_from.
		s := makeStructure(4, false)
		serialized, err := preKeySerializer.Serialize(s)
		if err != nil {
			t.Fatalf("serialize error: %v", err)
		}
		_, err = NewPreKeySignalMessageFromBytes(serialized, preKeySerializer, msgSerializer)
		if err == nil {
			t.Fatal("expected error for version 4 without kyber on deserialization")
		}
		if !errors.Is(err, ErrMissingKyberPayload) {
			t.Fatalf("expected ErrMissingKyberPayload, got %v", err)
		}
	})

	t.Run("version 4 rejected with partial kyber - only id via deserialization", func(t *testing.T) {
		s := makeStructure(4, false)
		s.KyberPreKeyID = optional.NewOptionalUint32(42)
		serialized, err := preKeySerializer.Serialize(s)
		if err != nil {
			t.Fatalf("serialize error: %v", err)
		}
		_, err = NewPreKeySignalMessageFromBytes(serialized, preKeySerializer, msgSerializer)
		if err == nil {
			t.Fatal("expected error for version 4 with only kyber ID on deserialization")
		}
		if !errors.Is(err, ErrMissingKyberPayload) {
			t.Fatalf("expected ErrMissingKyberPayload, got %v", err)
		}
	})

	t.Run("version 4 rejected with partial kyber - only ciphertext via deserialization", func(t *testing.T) {
		s := makeStructure(4, false)
		s.KyberCiphertext = []byte("kyber-ct")
		serialized, err := preKeySerializer.Serialize(s)
		if err != nil {
			t.Fatalf("serialize error: %v", err)
		}
		_, err = NewPreKeySignalMessageFromBytes(serialized, preKeySerializer, msgSerializer)
		if err == nil {
			t.Fatal("expected error for version 4 with only kyber ciphertext on deserialization")
		}
		if !errors.Is(err, ErrMissingKyberPayload) {
			t.Fatalf("expected ErrMissingKyberPayload, got %v", err)
		}
	})

	t.Run("version 5 rejected as future", func(t *testing.T) {
		_, err := NewPreKeySignalMessageFromStruct(makeStructure(5, true), preKeySerializer, msgSerializer)
		if err == nil {
			t.Fatal("expected error for version 5")
		}
		if !errors.Is(err, ErrUnrecognizedVersion) {
			t.Fatalf("expected ErrUnrecognizedVersion, got %v", err)
		}
	})

	t.Run("version 100 rejected as future", func(t *testing.T) {
		_, err := NewPreKeySignalMessageFromStruct(makeStructure(100, true), preKeySerializer, msgSerializer)
		if err == nil {
			t.Fatal("expected error for version 100")
		}
		if !errors.Is(err, ErrUnrecognizedVersion) {
			t.Fatalf("expected ErrUnrecognizedVersion, got %v", err)
		}
	})
}

func TestPreKeySignalMessageAsymmetricKyberPayload(t *testing.T) {
	preKeySerializer := &jsonPreKeySignalMessageSerializer{}
	msgSerializer := &jsonSignalMessageSerializer{}

	ratchetKey := newTestKeyPair(t)
	baseKey := newTestKeyPair(t)
	senderIdentity := newTestIdentityKey(t)
	receiverIdentity := newTestIdentityKey(t)

	macKey := make([]byte, 32)
	signalMsg, err := NewSignalMessage(
		CurrentVersion, 0, 0, macKey,
		ratchetKey.PublicKey(), []byte("cipher"),
		senderIdentity, receiverIdentity, msgSerializer,
		nil,      // pqRatchetMsg
		nil, nil, // localAddress, remoteAddress (no binding)
	)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("kyber ID without ciphertext rejected", func(t *testing.T) {
		_, err := NewPreKeySignalMessageWithKyber(
			CurrentVersion, 12345,
			optional.NewOptionalUint32(1), 2,
			baseKey.PublicKey(), senderIdentity,
			signalMsg, preKeySerializer, msgSerializer,
			optional.NewOptionalUint32(42), nil, // ID present, CT absent
		)
		if err == nil {
			t.Fatal("expected error for asymmetric Kyber payload (ID without CT)")
		}
		if !errors.Is(err, ErrIncompleteMessage) {
			t.Fatalf("expected ErrIncompleteMessage, got %v", err)
		}
	})

	t.Run("kyber ciphertext without ID accepted", func(t *testing.T) {
		// When KyberPreKeyID is nil (not set), but KyberCiphertext is set,
		// this is still asymmetric and should be rejected.
		_, err := NewPreKeySignalMessageWithKyber(
			CurrentVersion, 12345,
			optional.NewOptionalUint32(1), 2,
			baseKey.PublicKey(), senderIdentity,
			signalMsg, preKeySerializer, msgSerializer,
			nil, []byte("kyber-ct"), // CT present, ID absent
		)
		if err == nil {
			t.Fatal("expected error for asymmetric Kyber payload (CT without ID)")
		}
		if !errors.Is(err, ErrIncompleteMessage) {
			t.Fatalf("expected ErrIncompleteMessage, got %v", err)
		}
	})

	t.Run("both kyber fields nil accepted", func(t *testing.T) {
		_, err := NewPreKeySignalMessageWithKyber(
			CurrentVersion, 12345,
			optional.NewOptionalUint32(1), 2,
			baseKey.PublicKey(), senderIdentity,
			signalMsg, preKeySerializer, msgSerializer,
			nil, nil, // Both absent
		)
		if err != nil {
			t.Fatalf("expected success when both Kyber fields absent, got: %v", err)
		}
	})

	t.Run("both kyber fields present accepted", func(t *testing.T) {
		_, err := NewPreKeySignalMessageWithKyber(
			CurrentVersion, 12345,
			optional.NewOptionalUint32(1), 2,
			baseKey.PublicKey(), senderIdentity,
			signalMsg, preKeySerializer, msgSerializer,
			optional.NewOptionalUint32(42), []byte("kyber-ct"),
		)
		if err != nil {
			t.Fatalf("expected success when both Kyber fields present, got: %v", err)
		}
	})
}

func TestPreKeySignalMessageKyberPayloadEnforcement(t *testing.T) {
	preKeySerializer := &jsonPreKeySignalMessageSerializer{}
	msgSerializer := &jsonSignalMessageSerializer{}

	ratchetKey := newTestKeyPair(t)
	baseKey := newTestKeyPair(t)
	senderIdentity := newTestIdentityKey(t)
	receiverIdentity := newTestIdentityKey(t)

	macKey := make([]byte, 32)
	signalMsg, err := NewSignalMessage(
		CurrentVersion, 0, 0, macKey,
		ratchetKey.PublicKey(), []byte("cipher"),
		senderIdentity, receiverIdentity, msgSerializer,
		nil,      // pqRatchetMsg
		nil, nil, // localAddress, remoteAddress (no binding)
	)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("v4 NewPreKeySignalMessage without kyber accepted via constructor", func(t *testing.T) {
		// The constructor path (NewPreKeySignalMessage) does not enforce Kyber,
		// matching Rust's PreKeySignalMessage::new() which allows creating v4
		// messages without Kyber payload. Enforcement is on deserialization only.
		msg, err := NewPreKeySignalMessage(
			CurrentVersion, 12345,
			optional.NewOptionalUint32(1), 2,
			baseKey.PublicKey(), senderIdentity,
			signalMsg, preKeySerializer, msgSerializer,
		)
		if err != nil {
			t.Fatalf("v4 without kyber should be accepted via constructor, got error: %v", err)
		}
		if msg.MessageVersion() != CurrentVersion {
			t.Fatalf("expected version %d, got %d", CurrentVersion, msg.MessageVersion())
		}
	})

	t.Run("v4 NewPreKeySignalMessageWithKyber accepted", func(t *testing.T) {
		msg, err := NewPreKeySignalMessageWithKyber(
			CurrentVersion, 12345,
			optional.NewOptionalUint32(1), 2,
			baseKey.PublicKey(), senderIdentity,
			signalMsg, preKeySerializer, msgSerializer,
			optional.NewOptionalUint32(42), []byte("kyber-ct"),
		)
		if err != nil {
			t.Fatalf("expected success for v4 with kyber, got error: %v", err)
		}
		if msg.KyberPreKeyID() == nil || msg.KyberPreKeyID().Value != 42 {
			t.Fatal("kyber pre-key ID mismatch")
		}
	})
}
