//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 4 tests in this file exercise X25519. FIPS 140-3 does not approve that,
// but the X3DH key agreement specification (section 2.1) requires it, so the
// fips140only build tag drops this file from the FIPS gate. `make test` and
// `make coverage` still run it.

package protocol

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
)

type jsonSenderKeyMessageSerializer struct{}

func (j *jsonSenderKeyMessageSerializer) Serialize(msg *SenderKeyMessageStructure) ([]byte, error) {
	return json.Marshal(msg)
}

func (j *jsonSenderKeyMessageSerializer) Deserialize(data []byte) (*SenderKeyMessageStructure, error) {
	var msg SenderKeyMessageStructure
	err := json.Unmarshal(data, &msg)
	if err != nil {
		return nil, err
	}
	return &msg, nil
}

func TestNewSenderKeyMessageFromStruct(t *testing.T) {
	serializer := &jsonSenderKeyMessageSerializer{}

	t.Run("valid message", func(t *testing.T) {
		structure := &SenderKeyMessageStructure{
			ID:         1,
			Iteration:  10,
			CipherText: []byte("encrypted"),
			Version:    SenderKeyCurrentVersion,
			Signature:  []byte("signature"),
		}

		msg, err := NewSenderKeyMessageFromStruct(structure, serializer)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if msg.KeyID() != 1 {
			t.Fatal("key ID mismatch")
		}
		if msg.Iteration() != 10 {
			t.Fatal("iteration mismatch")
		}
		if string(msg.Ciphertext()) != "encrypted" {
			t.Fatal("ciphertext mismatch")
		}
		if msg.Version() != SenderKeyCurrentVersion {
			t.Fatal("version mismatch")
		}
		if msg.Type() != SENDERKEY_TYPE {
			t.Fatal("type mismatch")
		}
	})

	t.Run("legacy version", func(t *testing.T) {
		structure := &SenderKeyMessageStructure{
			Version:    UnsupportedVersion,
			CipherText: []byte("data"),
		}
		_, err := NewSenderKeyMessageFromStruct(structure, serializer)
		if err == nil {
			t.Fatal("expected error for legacy version")
		}
	})

	t.Run("future version", func(t *testing.T) {
		structure := &SenderKeyMessageStructure{
			Version:    SenderKeyCurrentVersion + 10,
			CipherText: []byte("data"),
		}
		_, err := NewSenderKeyMessageFromStruct(structure, serializer)
		if err == nil {
			t.Fatal("expected error for future version")
		}
	})

	t.Run("missing ciphertext", func(t *testing.T) {
		structure := &SenderKeyMessageStructure{
			Version: SenderKeyCurrentVersion,
		}
		_, err := NewSenderKeyMessageFromStruct(structure, serializer)
		if err == nil {
			t.Fatal("expected error for missing ciphertext")
		}
	})
}

func TestNewSenderKeyMessage(t *testing.T) {
	serializer := &jsonSenderKeyMessageSerializer{}

	t.Run("valid creation with signing key", func(t *testing.T) {
		signingKey, err := ecc.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}

		msg, err := NewSenderKeyMessage([16]byte{}, 1, 10, []byte("cipher"), signingKey.PrivateKey(), serializer)
		if err != nil {
			t.Fatal(err)
		}

		if msg.KeyID() != 1 {
			t.Fatal("key ID mismatch")
		}
		if msg.Iteration() != 10 {
			t.Fatal("iteration mismatch")
		}
		if msg.Version() != SenderKeyCurrentVersion {
			t.Fatal("version mismatch")
		}

		sig := msg.Signature()
		if sig == [64]byte{} {
			t.Fatal("signature should not be empty")
		}
	})

	t.Run("nil signing key", func(t *testing.T) {
		_, err := NewSenderKeyMessage([16]byte{}, 1, 10, []byte("cipher"), nil, serializer)
		if err == nil {
			t.Fatal("expected error for nil signing key")
		}
	})
}

func TestSenderKeyMessageSerialize(t *testing.T) {
	serializer := &jsonSenderKeyMessageSerializer{}
	signingKey, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	msg, err := NewSenderKeyMessage([16]byte{}, 5, 20, []byte("data"), signingKey.PrivateKey(), serializer)
	if err != nil {
		t.Fatal(err)
	}

	// Serialize (without signature)
	serialized, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if len(serialized) == 0 {
		t.Fatal("serialized bytes should not be empty")
	}

	// SignedSerialize (with signature)
	signed, err := msg.SignedSerialize()
	if err != nil {
		t.Fatal(err)
	}
	if len(signed) == 0 {
		t.Fatal("signed serialized bytes should not be empty")
	}
}

// failingSenderKeyMessageSerializer always returns an error on Serialize.
type failingSenderKeyMessageSerializer struct{}

func (f *failingSenderKeyMessageSerializer) Serialize(_ *SenderKeyMessageStructure) ([]byte, error) {
	return nil, errors.New("serialize failed")
}

func (f *failingSenderKeyMessageSerializer) Deserialize(_ []byte) (*SenderKeyMessageStructure, error) {
	return nil, errors.New("deserialize failed")
}

func TestNewSenderKeyMessageSerializeError(t *testing.T) {
	serializer := &failingSenderKeyMessageSerializer{}
	signingKey, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	_, err = NewSenderKeyMessage([16]byte{}, 1, 10, []byte("cipher"), signingKey.PrivateKey(), serializer)
	if err == nil {
		t.Fatal("expected error when serializer fails")
	}
}

// TestNewSenderKeyMessageWithVersion_StoresVersionParameter verifies that the
// version parameter supplied to NewSenderKeyMessageWithVersion is stored in the
// struct's version field so the wire byte high nibble encodes it correctly.
// Rust reference: protocol.rs:551 encodes message_version in the high nibble;
// the struct stores SENDERKEY_MESSAGE_CURRENT_VERSION (protocol.rs:558), but Go
// exposes version via Version() which must reflect the caller-supplied value.
// Latent while only v3 exists; critical once a v4 is introduced.
func TestNewSenderKeyMessageWithVersion_StoresVersionParameter(t *testing.T) {
	serializer := &jsonSenderKeyMessageSerializer{}
	signingKey, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	msg, err := NewSenderKeyMessageWithVersion(
		SenderKeyCurrentVersion, [16]byte{}, 1, 0, []byte("cipher"),
		signingKey.PrivateKey(), serializer,
	)
	if err != nil {
		t.Fatalf("NewSenderKeyMessageWithVersion error: %v", err)
	}
	if msg.Version() != SenderKeyCurrentVersion {
		t.Errorf("Version() = %d, want %d", msg.Version(), SenderKeyCurrentVersion)
	}
}

// TestNewSenderKeyMessageWithVersion_NilKey verifies that a nil signing key
// returns an error.
func TestNewSenderKeyMessageWithVersion_NilKey(t *testing.T) {
	serializer := &jsonSenderKeyMessageSerializer{}

	_, err := NewSenderKeyMessageWithVersion(
		SenderKeyCurrentVersion, [16]byte{}, 1, 0, []byte("cipher"), nil, serializer,
	)
	if err == nil {
		t.Fatal("expected error for nil signing key")
	}
}

func TestSenderKeyMessageFromBytes(t *testing.T) {
	serializer := &jsonSenderKeyMessageSerializer{}

	t.Run("valid roundtrip", func(t *testing.T) {
		structure := &SenderKeyMessageStructure{
			ID:         3,
			Iteration:  15,
			CipherText: []byte("ciphertext"),
			Version:    SenderKeyCurrentVersion,
		}
		bytes, err := json.Marshal(structure)
		if err != nil {
			t.Fatal(err)
		}

		msg, err := NewSenderKeyMessageFromBytes(bytes, serializer)
		if err != nil {
			t.Fatal(err)
		}
		if msg.KeyID() != 3 {
			t.Fatal("key ID mismatch")
		}
	})

	t.Run("invalid bytes", func(t *testing.T) {
		_, err := NewSenderKeyMessageFromBytes([]byte("not json"), serializer)
		if err == nil {
			t.Fatal("expected error for invalid bytes")
		}
	})
}
