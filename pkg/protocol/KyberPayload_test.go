package protocol

import (
	"bytes"
	"testing"
)

func TestNewKyberPayload(t *testing.T) {
	t.Run("constructor copies ciphertext", func(t *testing.T) {
		ct := []byte{0x01, 0x02, 0x03, 0x04}
		kp := NewKyberPayload(KyberPreKeyID(7), ct)

		// Mutating the original slice must not affect the payload.
		ct[0] = 0xFF
		if kp.Ciphertext()[0] == 0xFF {
			t.Fatal("KyberPayload did not defensively copy ciphertext on construction")
		}
	})

	t.Run("PreKeyID accessor", func(t *testing.T) {
		kp := NewKyberPayload(KyberPreKeyID(42), []byte{0xAA, 0xBB})
		if kp.PreKeyID() != KyberPreKeyID(42) {
			t.Fatalf("expected PreKeyID 42, got %d", kp.PreKeyID())
		}
	})

	t.Run("Ciphertext accessor returns copy", func(t *testing.T) {
		original := []byte{0x10, 0x20, 0x30}
		kp := NewKyberPayload(KyberPreKeyID(1), original)

		got := kp.Ciphertext()
		if !bytes.Equal(got, original) {
			t.Fatalf("expected ciphertext %v, got %v", original, got)
		}

		// Mutating the returned slice must not affect subsequent calls.
		got[0] = 0xFF
		second := kp.Ciphertext()
		if second[0] == 0xFF {
			t.Fatal("Ciphertext() did not return an independent copy")
		}
	})

	t.Run("zero-length ciphertext is allowed", func(t *testing.T) {
		kp := NewKyberPayload(KyberPreKeyID(0), []byte{})
		if kp.PreKeyID() != KyberPreKeyID(0) {
			t.Fatal("PreKeyID should be 0")
		}
		if len(kp.Ciphertext()) != 0 {
			t.Fatal("expected empty ciphertext")
		}
	})

	t.Run("nil ciphertext treated as empty", func(t *testing.T) {
		kp := NewKyberPayload(KyberPreKeyID(5), nil)
		if kp.Ciphertext() == nil {
			t.Fatal("Ciphertext() should return a non-nil slice for nil input")
		}
		if len(kp.Ciphertext()) != 0 {
			t.Fatal("expected zero-length ciphertext for nil input")
		}
	})

	t.Run("large pre-key ID boundary", func(t *testing.T) {
		const maxID = ^KyberPreKeyID(0) // all bits set
		kp := NewKyberPayload(maxID, []byte{0xDE, 0xAD})
		if kp.PreKeyID() != maxID {
			t.Fatalf("expected max KyberPreKeyID, got %d", kp.PreKeyID())
		}
	})
}
