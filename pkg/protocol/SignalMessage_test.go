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
		nil,      // pqRatchetMsg
		nil, nil, // localAddress, remoteAddress (no binding)
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
		nil,      // pqRatchetMsg
		nil, nil, // localAddress, remoteAddress (no binding)
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
		nil,      // pqRatchetMsg
		nil, nil, // localAddress, remoteAddress (no binding)
	)
	if err == nil {
		t.Fatal("expected error when serializer fails")
	}
}

// TestSignalMessageVerifyMac_NoLongerCallsSerializer verifies that VerifyMac
// uses the retained wire bytes (serializedBytes) rather than re-serializing
// the struct. Replacing the serializer with a failing one after construction
// must NOT cause VerifyMac to return an error — the serializer is simply not
// consulted. This is the regression test for the byte-malleability fix:
// previously VerifyMac called Serialize() and would error when the serializer
// failed; now it uses the pre-stored bytes unconditionally.
func TestSignalMessageVerifyMac_NoLongerCallsSerializer(t *testing.T) {
	goodSerializer := &jsonSignalMessageSerializer{}
	ratchetKey := newTestKeyPair(t)
	senderIdentity := newTestIdentityKey(t)
	receiverIdentity := newTestIdentityKey(t)
	macKey := make([]byte, 32)

	msg, err := NewSignalMessage(
		CurrentVersion, 1, 0, macKey,
		ratchetKey.PublicKey(), []byte("ciphertext"),
		senderIdentity, receiverIdentity, goodSerializer,
		nil,      // pqRatchetMsg
		nil, nil, // localAddress, remoteAddress (no binding)
	)
	if err != nil {
		t.Fatal(err)
	}

	// Replace serializer with a failing one. With the old re-serialization code
	// VerifyMac would have called Serialize() here and returned a serializer
	// error. With the fix, VerifyMac uses the retained pre-MAC bytes and does
	// not touch the serializer at all, so verification must succeed.
	msg.serializer = &failingSignalMessageSerializer{}

	if err := msg.VerifyMac(CurrentVersion, senderIdentity, receiverIdentity, macKey); err != nil {
		t.Fatalf("VerifyMac must not call Serialize; got unexpected error: %v", err)
	}
}

// TestSignalMessageVerifyMac_NilSerializedBytes verifies that VerifyMac returns
// a bad-mac error when the message has no stored serializedBytes (e.g., a
// message created directly via NewSignalMessageFromStruct without going through
// NewSignalMessage or NewSignalMessageFromBytes). This is a safety net: callers
// that bypass the standard constructors cannot silently skip MAC verification.
func TestSignalMessageVerifyMac_NilSerializedBytes(t *testing.T) {
	serializer := &jsonSignalMessageSerializer{}
	ratchetKey := newTestKeyPair(t)
	senderIdentity := newTestIdentityKey(t)
	receiverIdentity := newTestIdentityKey(t)
	macKey := make([]byte, 32)

	structure := &SignalMessageStructure{
		Version:    CurrentVersion,
		Counter:    1,
		RatchetKey: ratchetKey.PublicKey().Serialize(),
		CipherText: []byte("test"),
		Mac:        make([]byte, 8),
	}
	// NewSignalMessageFromStruct does NOT set serializedBytes.
	msg, err := NewSignalMessageFromStruct(structure, serializer)
	if err != nil {
		t.Fatal(err)
	}

	err = msg.VerifyMac(CurrentVersion, senderIdentity, receiverIdentity, macKey)
	if err == nil {
		t.Fatal("expected bad-mac error when serializedBytes is nil")
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
		nil,      // pqRatchetMsg
		nil, nil, // localAddress, remoteAddress (no binding)
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

// TestSignalMessageVerifyMacAlwaysIncludesIdentityKeys verifies that getMac
// unconditionally includes sender and receiver identity keys in the HMAC input,
// matching Rust's SignalMessage::get_mac which always writes both keys
// (rust/protocol/src/protocol.rs:230-246). The legacy v2 branch that omitted
// identity keys has been removed; all supported versions (>= PreKyberVersion)
// include identity keys.
func TestSignalMessageVerifyMacAlwaysIncludesIdentityKeys(t *testing.T) {
	serializer := &jsonSignalMessageSerializer{}
	ratchetKey := newTestKeyPair(t)
	senderIdentity := newTestIdentityKey(t)
	receiverIdentity := newTestIdentityKey(t)

	macKey := make([]byte, 32)
	for i := range macKey {
		macKey[i] = byte(i + 10)
	}

	msg, err := NewSignalMessage(
		CurrentVersion, 5, 2, macKey,
		ratchetKey.PublicKey(), []byte("cipher-identity-test"),
		senderIdentity, receiverIdentity, serializer,
		nil,      // pqRatchetMsg
		nil, nil, // localAddress, remoteAddress (no binding)
	)
	if err != nil {
		t.Fatal(err)
	}

	// Correct identity keys → MAC verifies.
	if err := msg.VerifyMac(CurrentVersion, senderIdentity, receiverIdentity, macKey); err != nil {
		t.Fatalf("expected MAC to verify with correct identity keys, got: %v", err)
	}

	// Wrong receiver identity key → MAC mismatch.
	wrongIdentity := newTestIdentityKey(t)
	if err := msg.VerifyMac(CurrentVersion, senderIdentity, wrongIdentity, macKey); err == nil {
		t.Fatal("expected MAC mismatch with wrong receiver identity key")
	}
}

// TestNewSignalMessage_AddressBinding_ValidAddresses verifies that supplying two
// valid ServiceId-format addresses (UUID names, device IDs 1-127) embeds the
// address-binding field (proto field 6) in the resulting message.
//
// Codex finding P2 — valid addresses → binding present.
func TestNewSignalMessage_AddressBinding_ValidAddresses(t *testing.T) {
	serializer := &jsonSignalMessageSerializer{}
	ratchetKey := newTestKeyPair(t)
	senderID := newTestIdentityKey(t)
	receiverID := newTestIdentityKey(t)
	macKey := make([]byte, 32)

	sender := NewSignalAddress("11111111-1111-1111-1111-111111111111", 1)
	recipient := NewSignalAddress("22222222-2222-2222-2222-222222222222", 2)

	msg, err := NewSignalMessage(
		CurrentVersion, 1, 0, macKey,
		ratchetKey.PublicKey(), []byte("payload"),
		senderID, receiverID, serializer,
		nil, sender, recipient,
	)
	if err != nil {
		t.Fatalf("NewSignalMessage with valid addresses: unexpected error: %v", err)
	}
	if len(msg.Addresses()) != 36 {
		t.Fatalf("expected 36-byte address-binding field, got %d bytes", len(msg.Addresses()))
	}
}

// TestNewSignalMessage_AddressBinding_DeviceIDZero verifies that supplying
// a sender address with device ID 0 (not serializable as a binding address)
// omits the binding field and produces a valid unbound message, matching
// Rust's opportunistic serialize_addresses (protocol.rs:91-92, 250-256) which
// returns None rather than erroring.
func TestNewSignalMessage_AddressBinding_DeviceIDZero(t *testing.T) {
	serializer := &jsonSignalMessageSerializer{}
	ratchetKey := newTestKeyPair(t)
	senderID := newTestIdentityKey(t)
	receiverID := newTestIdentityKey(t)
	macKey := make([]byte, 32)

	// device ID 0 is invalid for SerializeAddresses → binding omitted.
	sender := NewSignalAddress("11111111-1111-1111-1111-111111111111", 0)
	recipient := NewSignalAddress("22222222-2222-2222-2222-222222222222", 1)

	msg, err := NewSignalMessage(
		CurrentVersion, 1, 0, macKey,
		ratchetKey.PublicKey(), []byte("payload"),
		senderID, receiverID, serializer,
		nil, sender, recipient,
	)
	if err != nil {
		t.Fatalf("expected unbound message for device ID 0, got error: %v", err)
	}
	if got := msg.Addresses(); got != nil {
		t.Fatalf("expected omitted (nil) binding field, got %d bytes", len(got))
	}
}

// TestNewSignalMessage_AddressBinding_DeviceIDTooLarge verifies that supplying
// a recipient address with device ID > 127 omits the binding field rather than
// erroring (Rust opportunistic binding, protocol.rs:91-92, 250-256).
func TestNewSignalMessage_AddressBinding_DeviceIDTooLarge(t *testing.T) {
	serializer := &jsonSignalMessageSerializer{}
	ratchetKey := newTestKeyPair(t)
	senderID := newTestIdentityKey(t)
	receiverID := newTestIdentityKey(t)
	macKey := make([]byte, 32)

	sender := NewSignalAddress("11111111-1111-1111-1111-111111111111", 1)
	// device ID 128 exceeds the valid range [1, 127].
	recipient := NewSignalAddress("22222222-2222-2222-2222-222222222222", 128)

	msg, err := NewSignalMessage(
		CurrentVersion, 1, 0, macKey,
		ratchetKey.PublicKey(), []byte("payload"),
		senderID, receiverID, serializer,
		nil, sender, recipient,
	)
	if err != nil {
		t.Fatalf("expected unbound message for device ID 128, got error: %v", err)
	}
	if got := msg.Addresses(); got != nil {
		t.Fatalf("expected omitted (nil) binding field, got %d bytes", len(got))
	}
}

// TestNewSignalMessage_AddressBinding_BothNil verifies that the legacy
// unbound path (both addresses nil) produces a message without the
// addresses field and returns no error.
//
// Codex finding P2 — both addresses nil → binding absent, no error (legacy path).
func TestNewSignalMessage_AddressBinding_BothNil(t *testing.T) {
	serializer := &jsonSignalMessageSerializer{}
	ratchetKey := newTestKeyPair(t)
	senderID := newTestIdentityKey(t)
	receiverID := newTestIdentityKey(t)
	macKey := make([]byte, 32)

	msg, err := NewSignalMessage(
		CurrentVersion, 1, 0, macKey,
		ratchetKey.PublicKey(), []byte("payload"),
		senderID, receiverID, serializer,
		nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("NewSignalMessage with nil addresses: unexpected error: %v", err)
	}
	if len(msg.Addresses()) != 0 {
		t.Fatalf("expected empty addresses field for unbound legacy path, got %d bytes", len(msg.Addresses()))
	}
}

// isError is a package-internal helper that checks whether err is an *Error
// with the given kind. Used to assert specific error kinds in tests without
// exporting the errorKind type.
func isError(err error, kind errorKind) bool {
	e, ok := err.(*Error)
	return ok && e.kind == kind
}
