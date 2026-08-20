//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 6 tests in this file exercise X25519. FIPS 140-3 does not approve that,
// but the X3DH key agreement specification (section 2.1) requires it, so the
// fips140only build tag drops this file from the FIPS gate. `make test` and
// `make coverage` still run it.

package protocol

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/proto/servicepb"
	"google.golang.org/protobuf/proto"
)

func TestNewDecryptionErrorMessage(t *testing.T) {
	ratchetKey := newTestKeyPair(t)

	t.Run("with ratchet key", func(t *testing.T) {
		msg, err := NewDecryptionErrorMessage(12345, 1, ratchetKey.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		if msg.Timestamp() != 12345 {
			t.Fatal("timestamp mismatch")
		}
		if msg.DeviceID() != 1 {
			t.Fatal("device ID mismatch")
		}
		if msg.RatchetKey() == nil {
			t.Fatal("ratchet key should not be nil")
		}
	})

	t.Run("without ratchet key", func(t *testing.T) {
		msg, err := NewDecryptionErrorMessage(67890, 2, nil)
		if err != nil {
			t.Fatal(err)
		}
		if msg.Timestamp() != 67890 {
			t.Fatal("timestamp mismatch")
		}
		if msg.DeviceID() != 2 {
			t.Fatal("device ID mismatch")
		}
		if msg.RatchetKey() != nil {
			t.Fatal("ratchet key should be nil")
		}
	})
}

func TestDecryptionErrorMessageSerializeDeserialize(t *testing.T) {
	ratchetKey := newTestKeyPair(t)

	t.Run("roundtrip with ratchet key", func(t *testing.T) {
		msg, err := NewDecryptionErrorMessage(11111, 3, ratchetKey.PublicKey())
		if err != nil {
			t.Fatal(err)
		}

		serialized, err := msg.Serialize()
		if err != nil {
			t.Fatal(err)
		}

		msg2, err := DeserializeDecryptionErrorMessage(serialized)
		if err != nil {
			t.Fatal(err)
		}

		if msg2.Timestamp() != 11111 {
			t.Fatal("timestamp mismatch after roundtrip")
		}
		if msg2.DeviceID() != 3 {
			t.Fatal("device ID mismatch after roundtrip")
		}
		if msg2.RatchetKey() == nil {
			t.Fatal("ratchet key should not be nil after roundtrip")
		}
	})

	t.Run("roundtrip without ratchet key", func(t *testing.T) {
		msg, err := NewDecryptionErrorMessage(22222, 4, nil)
		if err != nil {
			t.Fatal(err)
		}

		serialized, err := msg.Serialize()
		if err != nil {
			t.Fatal(err)
		}

		msg2, err := DeserializeDecryptionErrorMessage(serialized)
		if err != nil {
			t.Fatal(err)
		}

		if msg2.Timestamp() != 22222 {
			t.Fatal("timestamp mismatch")
		}
		if msg2.RatchetKey() != nil {
			t.Fatal("ratchet key should be nil")
		}
	})
}

func TestDeserializeDecryptionErrorMessageEmpty(t *testing.T) {
	_, err := DeserializeDecryptionErrorMessage([]byte{})
	if err == nil {
		t.Fatal("expected error for empty data")
	}
}

func TestDeserializeDecryptionErrorMessageInvalid(t *testing.T) {
	// Invalid protobuf should not crash, though protobuf is lenient
	_, err := DeserializeDecryptionErrorMessage([]byte{0xFF, 0xFF, 0xFF})
	// We just verify it doesn't panic - the error may or may not be nil
	// depending on protobuf parsing leniency
	_ = err
}

func TestDecryptionErrorMessageSerializeCached(t *testing.T) {
	msg, err := NewDecryptionErrorMessage(33333, 5, nil)
	if err != nil {
		t.Fatal(err)
	}

	// First call returns cached serialized bytes
	s1, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	// Second call should return same bytes
	s2, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	if len(s1) != len(s2) {
		t.Fatal("cached serialize should return same bytes")
	}
}

func TestDecryptionErrorMessageWithInvalidRatchetKeyDeserialization(t *testing.T) {
	// Create a DecryptionErrorMessage with a valid ratchet key, serialize it,
	// then verify that deserialization reconstructs the key correctly.
	kp, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	msg, err := NewDecryptionErrorMessage(44444, 6, kp.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	serialized, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	msg2, err := DeserializeDecryptionErrorMessage(serialized)
	if err != nil {
		t.Fatal(err)
	}

	originalKey := kp.PublicKey().PublicKey()
	parsedKey := msg2.RatchetKey().PublicKey()
	if originalKey != parsedKey {
		t.Fatal("ratchet key public key mismatch after roundtrip")
	}
}

func TestDecryptionErrorMessageSerializeUncached(t *testing.T) {
	// Directly create a DecryptionErrorMessage without calling NewDecryptionErrorMessage
	// so that serialized is nil, exercising the non-cached Serialize() path.
	msg := &DecryptionErrorMessage{
		timestamp: 55555,
		deviceID:  7,
	}

	data, err := msg.Serialize()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty serialized bytes")
	}

	// Verify roundtrip
	msg2, err := DeserializeDecryptionErrorMessage(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg2.Timestamp() != 55555 {
		t.Fatalf("expected timestamp 55555, got %d", msg2.Timestamp())
	}
	if msg2.DeviceID() != 7 {
		t.Fatalf("expected device ID 7, got %d", msg2.DeviceID())
	}
}

func TestDecryptionErrorMessageSerializeUncachedWithRatchetKey(t *testing.T) {
	kp := newTestKeyPair(t)
	msg := &DecryptionErrorMessage{
		ratchetKey: kp.PublicKey(),
		timestamp:  66666,
		deviceID:   8,
	}

	data, err := msg.Serialize()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg2, err := DeserializeDecryptionErrorMessage(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg2.RatchetKey() == nil {
		t.Fatal("ratchet key should not be nil")
	}
}

func TestDeserializeDecryptionErrorMessageBadRatchetKey(t *testing.T) {
	// Craft a protobuf with an invalid ratchet key to exercise the DecodePoint error path.
	// We use raw protobuf encoding: field 1 (ratchet_key) = varint tag 0x0a, len, invalid bytes.
	invalidProto := []byte{
		0x0a, 0x02, 0xFF, 0xFF, // field 1 (ratchet_key): 2 bytes of invalid key data
		0x10, 0x01, // field 2 (timestamp): 1
		0x18, 0x02, // field 3 (device_id): 2
	}
	_, err := DeserializeDecryptionErrorMessage(invalidProto)
	if err == nil {
		t.Fatal("expected error for invalid ratchet key")
	}
}

// buildContentBody builds a serialized Content proto with the given DEM bytes in the
// decryption_error_message field and appends the PlaintextContent padding byte.
func buildContentBody(t *testing.T, demBytes []byte) []byte {
	t.Helper()
	content := &servicepb.Content{
		DecryptionErrorMessage: demBytes,
	}
	encoded, err := proto.Marshal(content)
	if err != nil {
		t.Fatalf("failed to marshal Content proto: %v", err)
	}
	return append(encoded, plaintextPaddingByte)
}

func TestExtractDecryptionErrorMessageFromSerializedContent(t *testing.T) {
	t.Run("valid body with DEM", func(t *testing.T) {
		kp, err := ecc.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}

		dem, err := NewDecryptionErrorMessage(99999, 3, kp.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		demBytes, err := dem.Serialize()
		if err != nil {
			t.Fatal(err)
		}

		body := buildContentBody(t, demBytes)

		got, err := ExtractDecryptionErrorMessageFromSerializedContent(body)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Timestamp() != 99999 {
			t.Fatalf("expected timestamp 99999, got %d", got.Timestamp())
		}
		if got.DeviceID() != 3 {
			t.Fatalf("expected device ID 3, got %d", got.DeviceID())
		}
		if got.RatchetKey() == nil {
			t.Fatal("expected non-nil ratchet key")
		}
	})

	t.Run("valid body without DEM field returns ErrMissingDecryptionErrorMessage", func(t *testing.T) {
		// A Content proto with no decryption_error_message set.
		content := &servicepb.Content{
			DataMessage: []byte{0x01, 0x02},
		}
		encoded, err := proto.Marshal(content)
		if err != nil {
			t.Fatal(err)
		}
		body := append(encoded, plaintextPaddingByte)

		_, err = ExtractDecryptionErrorMessageFromSerializedContent(body)
		if err == nil {
			t.Fatal("expected error for Content with no decryption error message")
		}
		if !errors.Is(err, ErrMissingDecryptionErrorMessage) {
			t.Fatalf("expected ErrMissingDecryptionErrorMessage, got %T: %v", err, err)
		}
	})

	t.Run("malformed body returns ErrInvalidContentProto", func(t *testing.T) {
		// Random garbage with padding byte appended — not a valid proto.
		body := []byte{0xFF, 0xFE, 0xFD, plaintextPaddingByte}
		_, err := ExtractDecryptionErrorMessageFromSerializedContent(body)
		if err == nil {
			t.Fatal("expected error for malformed body")
		}
		if !errors.Is(err, ErrInvalidContentProto) {
			t.Fatalf("expected ErrInvalidContentProto, got %T: %v", err, err)
		}
	})

	t.Run("empty body returns ErrInvalidContentProto", func(t *testing.T) {
		_, err := ExtractDecryptionErrorMessageFromSerializedContent([]byte{})
		if err == nil {
			t.Fatal("expected error for empty body")
		}
		if !errors.Is(err, ErrInvalidContentProto) {
			t.Fatalf("expected ErrInvalidContentProto, got %T: %v", err, err)
		}
	})

	t.Run("body missing padding byte returns ErrInvalidContentProto", func(t *testing.T) {
		// Valid Content proto but without the trailing 0x80 byte.
		content := &servicepb.Content{}
		encoded, err := proto.Marshal(content)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ExtractDecryptionErrorMessageFromSerializedContent(encoded)
		if err == nil {
			t.Fatal("expected error for body without padding byte")
		}
		if !errors.Is(err, ErrInvalidContentProto) {
			t.Fatalf("expected ErrInvalidContentProto, got %T: %v", err, err)
		}
	})

	t.Run("DEM field present but contains invalid bytes returns ErrDecryptionErrorMessageDeserialize", func(t *testing.T) {
		// Craft a Content proto where decryption_error_message contains bytes that
		// will cause DeserializeDecryptionErrorMessage to fail (invalid ratchet key bytes).
		invalidDEM := []byte{
			0x0a, 0x02, 0xFF, 0xFF, // field 1 (ratchet_key): 2 bytes of invalid key data
			0x10, 0x01, // field 2 (timestamp): 1
			0x18, 0x02, // field 3 (device_id): 2
		}
		body := buildContentBody(t, invalidDEM)

		_, err := ExtractDecryptionErrorMessageFromSerializedContent(body)
		if err == nil {
			t.Fatal("expected error for invalid DEM bytes")
		}
		if !errors.Is(err, ErrDecryptionErrorMessageDeserialize) {
			t.Fatalf("expected ErrDecryptionErrorMessageDeserialize, got %T: %v", err, err)
		}
	})

	t.Run("only padding byte in body returns ErrInvalidContentProto or ErrMissingDecryptionErrorMessage", func(t *testing.T) {
		// A body of exactly one byte (the padding byte) — the Content proto is empty.
		body := []byte{plaintextPaddingByte}
		_, err := ExtractDecryptionErrorMessageFromSerializedContent(body)
		if err == nil {
			t.Fatal("expected error for body with only padding byte")
		}
		// Empty Content proto decodes fine but has no DEM.
		if !errors.Is(err, ErrMissingDecryptionErrorMessage) && !errors.Is(err, ErrInvalidContentProto) {
			t.Fatalf("expected ErrMissingDecryptionErrorMessage or ErrInvalidContentProto, got %T: %v", err, err)
		}
	})
}

// buildWhisperMessageBytes creates a serialized SignalMessage (WHISPER_TYPE) using the
// JSON test serializer. The returned bytes satisfy NewSignalMessageFromBytes.
func buildWhisperMessageBytes(t *testing.T) ([]byte, ecc.ECPublicKeyable) {
	t.Helper()
	serializer := &jsonSignalMessageSerializer{}
	ratchetKey := newTestKeyPair(t)
	structure := &SignalMessageStructure{
		Version:    CurrentVersion,
		Counter:    0,
		RatchetKey: ratchetKey.PublicKey().Serialize(),
		CipherText: []byte("enc"),
	}
	msg, err := NewSignalMessageFromStruct(structure, serializer)
	if err != nil {
		t.Fatal(err)
	}
	b, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return b, ratchetKey.PublicKey()
}

// TestDecryptionErrorMessageForOriginal_Whisper mirrors the Rust test
// test_decryption_error_message_for_plaintext at protocol.rs:1280-1356 for the
// Whisper case: ForOriginal extracts the sender ratchet key from a SignalMessage.
func TestDecryptionErrorMessageForOriginal_Whisper(t *testing.T) {
	msgSerializer := &jsonSignalMessageSerializer{}
	preKeySerializer := &jsonPreKeySignalMessageSerializer{}

	whisperBytes, expectedKey := buildWhisperMessageBytes(t)

	dem, err := DecryptionErrorMessageForOriginal(
		whisperBytes, WHISPER_TYPE, 12345, 1,
		msgSerializer, preKeySerializer,
	)
	if err != nil {
		t.Fatalf("ForOriginal(Whisper): %v", err)
	}
	if dem.Timestamp() != 12345 {
		t.Fatalf("timestamp: got %d, want 12345", dem.Timestamp())
	}
	if dem.DeviceID() != 1 {
		t.Fatalf("device ID: got %d, want 1", dem.DeviceID())
	}
	if dem.RatchetKey() == nil {
		t.Fatal("expected ratchet key for Whisper message")
	}
	if dem.RatchetKey().PublicKey() != expectedKey.PublicKey() {
		t.Fatal("ratchet key mismatch")
	}
}

// TestDecryptionErrorMessageForOriginal_SenderKey verifies that a SenderKey origin
// produces a nil ratchet key (SenderKey messages carry no ratchet key).
func TestDecryptionErrorMessageForOriginal_SenderKey(t *testing.T) {
	msgSerializer := &jsonSignalMessageSerializer{}
	preKeySerializer := &jsonPreKeySignalMessageSerializer{}

	// Arbitrary bytes; SenderKey branch does not parse originalBytes.
	dem, err := DecryptionErrorMessageForOriginal(
		[]byte("ignored"), SENDERKEY_TYPE, 99999, 7,
		msgSerializer, preKeySerializer,
	)
	if err != nil {
		t.Fatalf("ForOriginal(SenderKey): %v", err)
	}
	if dem.RatchetKey() != nil {
		t.Fatal("expected nil ratchet key for SenderKey message")
	}
	if dem.Timestamp() != 99999 {
		t.Fatalf("timestamp: got %d, want 99999", dem.Timestamp())
	}
}

// TestDecryptionErrorMessageForOriginal_Plaintext verifies that PLAINTEXT_TYPE
// is rejected with ErrInvalidArgumentPlaintext, matching the Rust InvalidArgument
// error at protocol.rs:898-900.
func TestDecryptionErrorMessageForOriginal_Plaintext(t *testing.T) {
	msgSerializer := &jsonSignalMessageSerializer{}
	preKeySerializer := &jsonPreKeySignalMessageSerializer{}

	_, err := DecryptionErrorMessageForOriginal(
		[]byte("anything"), PLAINTEXT_TYPE, 1, 1,
		msgSerializer, preKeySerializer,
	)
	if err == nil {
		t.Fatal("expected error for PLAINTEXT_TYPE, got nil")
	}
	if !errors.Is(err, ErrInvalidArgumentPlaintext) {
		t.Fatalf("expected ErrInvalidArgumentPlaintext, got %T: %v", err, err)
	}
}

// TestDecryptionErrorMessageForOriginal_UnknownType verifies that an unrecognized
// message type produces an error.
func TestDecryptionErrorMessageForOriginal_UnknownType(t *testing.T) {
	msgSerializer := &jsonSignalMessageSerializer{}
	preKeySerializer := &jsonPreKeySignalMessageSerializer{}

	_, err := DecryptionErrorMessageForOriginal(
		[]byte("x"), 99, 1, 1,
		msgSerializer, preKeySerializer,
	)
	if err == nil {
		t.Fatal("expected error for unknown message type, got nil")
	}
}
