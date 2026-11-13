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
	"testing"
)

type jsonSenderKeyDistributionMessageSerializer struct{}

func (j *jsonSenderKeyDistributionMessageSerializer) Serialize(msg *SenderKeyDistributionMessageStructure) ([]byte, error) {
	return json.Marshal(msg)
}

func (j *jsonSenderKeyDistributionMessageSerializer) Deserialize(data []byte) (*SenderKeyDistributionMessageStructure, error) {
	var msg SenderKeyDistributionMessageStructure
	err := json.Unmarshal(data, &msg)
	if err != nil {
		return nil, err
	}
	return &msg, nil
}

// validChainKey returns a 32-byte chain key for test use, matching the
// Rust reference requirement that chain_key.len() == 32.
func validChainKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func TestNewSenderKeyDistributionMessageFromStruct(t *testing.T) {
	serializer := &jsonSenderKeyDistributionMessageSerializer{}
	signingKey := newTestKeyPair(t)

	t.Run("valid message", func(t *testing.T) {
		chainKey := validChainKey()
		structure := &SenderKeyDistributionMessageStructure{
			ID:         1,
			Iteration:  5,
			ChainKey:   chainKey,
			SigningKey: signingKey.PublicKey().Serialize(),
			Version:    SenderKeyCurrentVersion,
		}

		msg, err := NewSenderKeyDistributionMessageFromStruct(structure, serializer)
		if err != nil {
			t.Fatal(err)
		}
		defer msg.Release()
		if msg.ID() != 1 {
			t.Fatal("id mismatch")
		}
		if msg.Iteration() != 5 {
			t.Fatal("iteration mismatch")
		}
		if len(msg.ChainKey()) != 32 {
			t.Fatalf("chain key length mismatch: got %d, want 32", len(msg.ChainKey()))
		}
		if msg.SignatureKey() == nil {
			t.Fatal("signature key should not be nil")
		}
		if msg.Type() != SENDERKEY_DISTRIBUTION_TYPE {
			t.Fatal("type mismatch")
		}
	})

	t.Run("legacy version", func(t *testing.T) {
		structure := &SenderKeyDistributionMessageStructure{
			Version:    UnsupportedVersion,
			ChainKey:   validChainKey(),
			SigningKey: signingKey.PublicKey().Serialize(),
		}
		_, err := NewSenderKeyDistributionMessageFromStruct(structure, serializer)
		if err == nil {
			t.Fatal("expected error for legacy version")
		}
	})

	t.Run("future version", func(t *testing.T) {
		structure := &SenderKeyDistributionMessageStructure{
			Version:    SenderKeyCurrentVersion + 10,
			ChainKey:   validChainKey(),
			SigningKey: signingKey.PublicKey().Serialize(),
		}
		_, err := NewSenderKeyDistributionMessageFromStruct(structure, serializer)
		if err == nil {
			t.Fatal("expected error for future version")
		}
	})

	t.Run("missing signing key", func(t *testing.T) {
		structure := &SenderKeyDistributionMessageStructure{
			Version:  SenderKeyCurrentVersion,
			ChainKey: validChainKey(),
		}
		_, err := NewSenderKeyDistributionMessageFromStruct(structure, serializer)
		if err == nil {
			t.Fatal("expected error for missing signing key")
		}
	})

	t.Run("missing chain key", func(t *testing.T) {
		structure := &SenderKeyDistributionMessageStructure{
			Version:    SenderKeyCurrentVersion,
			SigningKey: signingKey.PublicKey().Serialize(),
		}
		_, err := NewSenderKeyDistributionMessageFromStruct(structure, serializer)
		if err == nil {
			t.Fatal("expected error for missing chain key")
		}
	})

	t.Run("invalid chain key length", func(t *testing.T) {
		structure := &SenderKeyDistributionMessageStructure{
			Version:    SenderKeyCurrentVersion,
			ChainKey:   []byte("too-short"),
			SigningKey: signingKey.PublicKey().Serialize(),
		}
		_, err := NewSenderKeyDistributionMessageFromStruct(structure, serializer)
		if err == nil {
			t.Fatal("expected error for invalid chain key length")
		}
	})

	t.Run("invalid signing key length", func(t *testing.T) {
		structure := &SenderKeyDistributionMessageStructure{
			Version:    SenderKeyCurrentVersion,
			ChainKey:   validChainKey(),
			SigningKey: []byte("too-short"), // not 33 bytes
		}
		_, err := NewSenderKeyDistributionMessageFromStruct(structure, serializer)
		if err == nil {
			t.Fatal("expected error for invalid signing key length")
		}
	})
}

func TestNewSenderKeyDistributionMessage(t *testing.T) {
	serializer := &jsonSenderKeyDistributionMessageSerializer{}
	signingKey := newTestKeyPair(t)
	chainKey := validChainKey()

	msg := NewSenderKeyDistributionMessage([16]byte{}, 1, 10, chainKey, signingKey.PublicKey(), serializer, SenderKeyCurrentVersion)
	defer msg.Release()
	if msg.ID() != 1 {
		t.Fatal("id mismatch")
	}
	if msg.Iteration() != 10 {
		t.Fatal("iteration mismatch")
	}
	if len(msg.ChainKey()) != 32 {
		t.Fatalf("chain key length mismatch: got %d, want 32", len(msg.ChainKey()))
	}
}

func TestSenderKeyDistributionMessageVersion(t *testing.T) {
	serializer := &jsonSenderKeyDistributionMessageSerializer{}
	signingKey := newTestKeyPair(t)
	chainKey := validChainKey()

	t.Run("uses provided version", func(t *testing.T) {
		msg := NewSenderKeyDistributionMessage([16]byte{}, 1, 10, chainKey, signingKey.PublicKey(), serializer, SenderKeyCurrentVersion)
		defer msg.Release()
		if msg.Version() != SenderKeyCurrentVersion {
			t.Fatalf("expected version %d, got %d", SenderKeyCurrentVersion, msg.Version())
		}
	})

	t.Run("preserves non-current version", func(t *testing.T) {
		// Verify that a custom version is preserved rather than overwritten
		customVersion := uint32(2)
		msg := NewSenderKeyDistributionMessage([16]byte{}, 1, 10, chainKey, signingKey.PublicKey(), serializer, customVersion)
		defer msg.Release()
		if msg.Version() != customVersion {
			t.Fatalf("expected version %d, got %d", customVersion, msg.Version())
		}
	})
}

func TestSenderKeyDistributionMessageSerialize(t *testing.T) {
	serializer := &jsonSenderKeyDistributionMessageSerializer{}
	signingKey := newTestKeyPair(t)
	chainKey := validChainKey()

	msg := NewSenderKeyDistributionMessage([16]byte{}, 1, 10, chainKey, signingKey.PublicKey(), serializer, SenderKeyCurrentVersion)
	defer msg.Release()

	serialized, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	msg2, err := NewSenderKeyDistributionMessageFromBytes(serialized, serializer)
	if err != nil {
		t.Fatal(err)
	}
	defer msg2.Release()

	if msg2.ID() != 1 {
		t.Fatal("id mismatch after roundtrip")
	}
	if msg2.Iteration() != 10 {
		t.Fatal("iteration mismatch after roundtrip")
	}
}

func TestSenderKeyDistributionMessageFromBytesInvalid(t *testing.T) {
	serializer := &jsonSenderKeyDistributionMessageSerializer{}
	_, err := NewSenderKeyDistributionMessageFromBytes([]byte("invalid"), serializer)
	if err == nil {
		t.Fatal("expected error for invalid bytes")
	}
}

func TestNewSenderKeyDistributionMessageFromStructInvalidSigningKey(t *testing.T) {
	serializer := &jsonSenderKeyDistributionMessageSerializer{}

	// 33 bytes but invalid ECC key content (wrong type prefix).
	badSigningKey := make([]byte, 33)
	badSigningKey[0] = 0xFF
	structure := &SenderKeyDistributionMessageStructure{
		Version:    SenderKeyCurrentVersion,
		ChainKey:   validChainKey(),
		SigningKey: badSigningKey,
	}
	_, err := NewSenderKeyDistributionMessageFromStruct(structure, serializer)
	if err == nil {
		t.Fatal("expected error for invalid signing key bytes")
	}
}
