package protocol

import (
	"testing"
)

func TestNewPlaintextContent(t *testing.T) {
	body := []byte("hello world")
	pc := NewPlaintextContent(body)

	if pc.Type() != PLAINTEXT_TYPE {
		t.Fatalf("expected type %d, got %d", PLAINTEXT_TYPE, pc.Type())
	}

	returnedBody := pc.Body()
	if string(returnedBody) != "hello world" {
		t.Fatalf("expected body 'hello world', got %q", string(returnedBody))
	}
}

func TestPlaintextContentSerialize(t *testing.T) {
	body := []byte("test data")
	pc := NewPlaintextContent(body)

	serialized, err := pc.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	// First byte should be version byte
	expectedVersion := byte((CurrentVersion << 4) | CurrentVersion)
	if serialized[0] != expectedVersion {
		t.Fatalf("expected version byte %x, got %x", expectedVersion, serialized[0])
	}

	// Remaining bytes should be the body
	if string(serialized[1:]) != "test data" {
		t.Fatal("serialized body mismatch")
	}
}

func TestNewPlaintextContentFromBytes(t *testing.T) {
	t.Run("valid bytes", func(t *testing.T) {
		original := NewPlaintextContent([]byte("message"))
		serialized, _ := original.Serialize()

		parsed, err := NewPlaintextContentFromBytes(serialized)
		if err != nil {
			t.Fatal(err)
		}

		if string(parsed.Body()) != "message" {
			t.Fatal("body mismatch after roundtrip")
		}
	})

	t.Run("empty bytes", func(t *testing.T) {
		_, err := NewPlaintextContentFromBytes([]byte{})
		if err == nil {
			t.Fatal("expected error for empty bytes")
		}
	})
}

func TestPlaintextContentEmptyBody(t *testing.T) {
	pc := NewPlaintextContent([]byte{})

	body := pc.Body()
	if len(body) != 0 {
		t.Fatalf("expected empty body, got %d bytes", len(body))
	}
}

func TestPlaintextContentBodyNilSafety(t *testing.T) {
	// Create a PlaintextContent with zero-length serialized
	pc := &PlaintextContent{serialized: nil}
	body := pc.Body()
	if body != nil {
		t.Fatal("expected nil body for nil serialized")
	}
}
