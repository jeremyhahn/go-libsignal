//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 1 test in this file exercises X25519. FIPS 140-3 does not approve that,
// but the X3DH key agreement specification (section 2.1) requires it, so the
// fips140only build tag drops this file from the FIPS gate. `make test` and
// `make coverage` still run it.

package protocol

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
)

func TestNewPlaintextContent(t *testing.T) {
	body := []byte("hello world")
	pc := NewPlaintextContent(body)

	if pc.Type() != PLAINTEXT_TYPE {
		t.Fatalf("expected type %d, got %d", PLAINTEXT_TYPE, pc.Type())
	}

	// Body() mirrors Rust: returns serialized[1:] which includes the trailing
	// 0x80 padding-boundary byte. Callers strip it themselves.
	returnedBody := pc.Body()
	want := append([]byte("hello world"), plaintextPaddingByte)
	if string(returnedBody) != string(want) {
		t.Fatalf("expected body %q (with trailing padding byte), got %q", string(want), string(returnedBody))
	}
}

func TestPlaintextContentSerialize(t *testing.T) {
	body := []byte("test data")
	pc := NewPlaintextContent(body)

	serialized, err := pc.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	// First byte is the canonical 0xC0 identifier (Rust
	// PLAINTEXT_CONTEXT_IDENTIFIER_BYTE).
	if serialized[0] != plaintextContextIdentifierByte {
		t.Fatalf("expected identifier byte %#x, got %#x", plaintextContextIdentifierByte, serialized[0])
	}

	// Last byte is the canonical 0x80 padding-boundary byte (Rust
	// PADDING_BOUNDARY_BYTE).
	if serialized[len(serialized)-1] != plaintextPaddingByte {
		t.Fatalf("expected padding byte %#x at end, got %#x", plaintextPaddingByte, serialized[len(serialized)-1])
	}

	// Bytes between the framing match the body.
	if string(serialized[1:len(serialized)-1]) != "test data" {
		t.Fatal("serialized body mismatch between identifier and padding bytes")
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

		// Roundtripped Body() includes the 0x80 padding byte.
		want := append([]byte("message"), plaintextPaddingByte)
		if string(parsed.Body()) != string(want) {
			t.Fatal("body mismatch after roundtrip")
		}
	})

	t.Run("empty bytes", func(t *testing.T) {
		_, err := NewPlaintextContentFromBytes([]byte{})
		if err == nil {
			t.Fatal("expected error for empty bytes")
		}
	})

	t.Run("wrong identifier byte rejected", func(t *testing.T) {
		// Pre-fix Go produced 0x44 here. Rust requires 0xC0 and rejects anything else.
		bad := []byte{0x44, 0x01, 0x02, plaintextPaddingByte}
		_, err := NewPlaintextContentFromBytes(bad)
		if err == nil {
			t.Fatal("expected error for wrong identifier byte")
		}
		if !errors.Is(err, ErrUnrecognizedVersion) {
			t.Fatalf("expected ErrUnrecognizedVersion, got %T: %v", err, err)
		}
	})
}

func TestPlaintextContentEmptyBody(t *testing.T) {
	pc := NewPlaintextContent([]byte{})

	// Body() returns the trailing 0x80 even when the inner body is empty.
	body := pc.Body()
	if len(body) != 1 || body[0] != plaintextPaddingByte {
		t.Fatalf("expected single padding byte, got %v", body)
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

// TestPlaintextContentFromDEM verifies the Rust From<DecryptionErrorMessage>
// for PlaintextContent conversion at rust/protocol/src/protocol.rs:837-851.
func TestPlaintextContentFromDEM(t *testing.T) {
	kp, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	dem, err := NewDecryptionErrorMessage(12345, 1, kp.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	pc, err := PlaintextContentFromDEM(dem)
	if err != nil {
		t.Fatalf("PlaintextContentFromDEM: %v", err)
	}

	if pc.Type() != PLAINTEXT_TYPE {
		t.Fatalf("expected PLAINTEXT_TYPE, got %d", pc.Type())
	}

	serialized, err := pc.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	// First byte must be the PlaintextContent identifier (0xC0).
	if serialized[0] != plaintextContextIdentifierByte {
		t.Fatalf("expected 0xC0 identifier, got 0x%02x", serialized[0])
	}
	// Last byte must be the padding boundary (0x80).
	if serialized[len(serialized)-1] != plaintextPaddingByte {
		t.Fatalf("expected 0x80 padding, got 0x%02x", serialized[len(serialized)-1])
	}

	// Body() feeds directly into ExtractDecryptionErrorMessageFromSerializedContent.
	got, err := ExtractDecryptionErrorMessageFromSerializedContent(pc.Body())
	if err != nil {
		t.Fatalf("round-trip extract failed: %v", err)
	}
	if got.Timestamp() != 12345 {
		t.Fatalf("timestamp mismatch: got %d, want 12345", got.Timestamp())
	}
	if got.DeviceID() != 1 {
		t.Fatalf("device ID mismatch: got %d, want 1", got.DeviceID())
	}
	if got.RatchetKey() == nil {
		t.Fatal("expected non-nil ratchet key after round-trip")
	}
}

// TestPlaintextContentFromDEM_NoRatchetKey verifies that a DEM with no ratchet
// key (SenderKey origin) is also wrapped correctly.
func TestPlaintextContentFromDEM_NoRatchetKey(t *testing.T) {
	dem, err := NewDecryptionErrorMessage(99999, 2, nil)
	if err != nil {
		t.Fatal(err)
	}

	pc, err := PlaintextContentFromDEM(dem)
	if err != nil {
		t.Fatalf("PlaintextContentFromDEM: %v", err)
	}

	got, err := ExtractDecryptionErrorMessageFromSerializedContent(pc.Body())
	if err != nil {
		t.Fatalf("round-trip extract failed: %v", err)
	}
	if got.Timestamp() != 99999 {
		t.Fatalf("timestamp mismatch: got %d, want 99999", got.Timestamp())
	}
	if got.RatchetKey() != nil {
		t.Fatal("expected nil ratchet key after round-trip")
	}
}
