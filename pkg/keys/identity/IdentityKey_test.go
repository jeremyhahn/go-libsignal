package identity

import (
	"strings"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
)

func TestNewKey(t *testing.T) {
	var pubBytes [32]byte
	pubBytes[0] = 0xAA
	pub := ecc.NewDjbECPublicKey(pubBytes)
	key := NewKey(pub)
	if key == nil {
		t.Fatal("expected non-nil Key")
	}
	if key.PublicKey() != pub {
		t.Fatal("PublicKey mismatch")
	}
}

func TestNewKey_Serialize(t *testing.T) {
	var pubBytes [32]byte
	pubBytes[0] = 0x01
	pub := ecc.NewDjbECPublicKey(pubBytes)
	key := NewKey(pub)
	serialized := key.Serialize()
	// Should be DjbType prepended to pubBytes
	if len(serialized) != 33 {
		t.Fatalf("expected 33 bytes, got %d", len(serialized))
	}
	if serialized[0] != ecc.DjbType {
		t.Fatalf("first byte should be DjbType, got 0x%02x", serialized[0])
	}
}

func TestNewKey_Fingerprint(t *testing.T) {
	pub := ecc.NewDjbECPublicKey([32]byte{})
	key := NewKey(pub)
	fp := key.Fingerprint()
	if fp == "" {
		t.Fatal("fingerprint should not be empty")
	}
	// Fingerprint is hex-encoded, so length = 33 * 2 = 66
	if len(fp) != 66 {
		t.Fatalf("expected fingerprint length 66, got %d", len(fp))
	}
	// All lowercase hex
	if fp != strings.ToLower(fp) {
		t.Fatal("fingerprint should be lowercase hex")
	}
}

func TestNewKeyFromBytes(t *testing.T) {
	var pubBytes [32]byte
	pubBytes[5] = 0xFF
	key := NewKeyFromBytes(pubBytes, 0)
	pub := key.PublicKey().PublicKey()
	if pub != pubBytes {
		t.Fatal("PublicKey bytes mismatch")
	}
}

func TestNewKeyFromBytes_ZeroOffset(t *testing.T) {
	var pubBytes [32]byte
	key := NewKeyFromBytes(pubBytes, 0)
	if key.PublicKey() == nil {
		t.Fatal("PublicKey should not be nil")
	}
}

func TestNewKeyPair(t *testing.T) {
	pub := ecc.NewDjbECPublicKey([32]byte{1})
	priv := ecc.NewDjbECPrivateKey([32]byte{2})
	identityKey := NewKey(pub)
	kp := NewKeyPair(identityKey, priv)

	if kp.PublicKey() != identityKey {
		t.Fatal("PublicKey mismatch")
	}
	if kp.PrivateKey() != priv {
		t.Fatal("PrivateKey mismatch")
	}
}

func TestNewKeyPair_PrivateKeyType(t *testing.T) {
	pub := ecc.NewDjbECPublicKey([32]byte{})
	priv := ecc.NewDjbECPrivateKey([32]byte{})
	identityKey := NewKey(pub)
	kp := NewKeyPair(identityKey, priv)

	if kp.PrivateKey().Type() != ecc.DjbType {
		t.Fatalf("expected DjbType, got %d", kp.PrivateKey().Type())
	}
}

func TestKey_Fingerprint_DifferentKeys(t *testing.T) {
	k1 := NewKey(ecc.NewDjbECPublicKey([32]byte{1}))
	k2 := NewKey(ecc.NewDjbECPublicKey([32]byte{2}))
	if k1.Fingerprint() == k2.Fingerprint() {
		t.Fatal("different keys should have different fingerprints")
	}
}
