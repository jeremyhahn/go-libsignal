package protocol

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
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
