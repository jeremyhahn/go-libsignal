//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 1 test in this file exercises X25519. FIPS 140-3 does not approve that,
// but the X3DH key agreement specification (section 2.1) requires it, so the
// fips140only build tag drops this file from the FIPS gate. `make test` and
// `make coverage` still run it.

package identity

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
)

// TestKeyPairSerializeRoundTrip verifies that Serialize → NewKeyPairFromBytes
// produces a KeyPair with byte-identical public and private key material.
//
// We use ecc.GenerateKeyPair so that the private key is already Curve25519-clamped
// (NewDjbECPrivateKey applies clamping at construction; raw unclamped bytes will
// not round-trip unchanged).
//
// Rust reference: test_serialize_identity_key_pair in
// rust/protocol/src/identity_key.rs
func TestKeyPairSerializeRoundTrip(t *testing.T) {
	kp, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() failed: %v", err)
	}

	original := NewKeyPair(NewKey(kp.PublicKey()), kp.PrivateKey())

	serialized, err := original.Serialize()
	if err != nil {
		t.Fatalf("Serialize() failed: %v", err)
	}
	if len(serialized) == 0 {
		t.Fatal("Serialize() returned empty bytes")
	}

	restored, err := NewKeyPairFromBytes(serialized)
	if err != nil {
		t.Fatalf("NewKeyPairFromBytes() failed: %v", err)
	}

	// Public key must round-trip byte-for-byte.
	wantPub := original.PublicKey().Serialize()
	gotPub := restored.PublicKey().Serialize()
	if !bytes.Equal(gotPub, wantPub) {
		t.Errorf("public key mismatch: got %x, want %x", gotPub, wantPub)
	}

	// Private key must round-trip byte-for-byte (already clamped from GenerateKeyPair).
	wantPriv := original.PrivateKey().Serialize()
	gotPriv := restored.PrivateKey().Serialize()
	if gotPriv != wantPriv {
		t.Errorf("private key mismatch: got %x, want %x", gotPriv, wantPriv)
	}
}

// TestKeyPairSerialize_PublicKeyHasTypePrefix verifies that the serialized
// public_key field inside the protobuf is 33 bytes with the DjbType prefix.
//
// Rust reference: IdentityKeyPair::serialize stores public_key as
// self.identity_key.serialize() which prepends the 0x05 type byte.
func TestKeyPairSerialize_PublicKeyHasTypePrefix(t *testing.T) {
	var pubBytes [32]byte
	pubBytes[1] = 0x01
	pub := ecc.NewDjbECPublicKey(pubBytes)
	priv := ecc.NewDjbECPrivateKey([32]byte{0x02})
	kp := NewKeyPair(NewKey(pub), priv)

	serialized, err := kp.Serialize()
	if err != nil {
		t.Fatalf("Serialize() failed: %v", err)
	}

	// Deserialize and confirm the 0x05 prefix round-trips correctly.
	restored, err := NewKeyPairFromBytes(serialized)
	if err != nil {
		t.Fatalf("NewKeyPairFromBytes() failed: %v", err)
	}

	wantSerialized := pub.Serialize() // 33 bytes: 0x05 || pubBytes
	gotSerialized := restored.PublicKey().Serialize()
	if !bytes.Equal(gotSerialized, wantSerialized) {
		t.Errorf("serialized public key mismatch: got %x, want %x", gotSerialized, wantSerialized)
	}
}

// TestNewKeyPairFromBytes_CorruptProto verifies that garbage bytes produce
// ErrInvalidIdentityKeyPairProto.
func TestNewKeyPairFromBytes_CorruptProto(t *testing.T) {
	corrupt := []byte{0xFF, 0xFE, 0xFD, 0x00, 0x01}
	_, err := NewKeyPairFromBytes(corrupt)
	if err == nil {
		t.Fatal("expected error for corrupt protobuf, got nil")
	}
	var target *ErrInvalidIdentityKeyPairProtoType
	if !errors.As(err, &target) && !errors.Is(err, ErrInvalidIdentityKeyPairProto) {
		t.Errorf("expected ErrInvalidIdentityKeyPairProto, got %T: %v", err, err)
	}
}

// TestNewKeyPairFromBytes_BadPublicKey verifies that a protobuf with an
// invalid public key (wrong type prefix) produces ErrInvalidIdentityKeyPairPublicKeyType.
func TestNewKeyPairFromBytes_BadPublicKey(t *testing.T) {
	// Build a well-formed proto but use an unknown key type byte (0x01).
	badPub := make([]byte, 33)
	badPub[0] = 0x01 // not DjbType (0x05)

	goodPriv := make([]byte, 32)
	goodPriv[0] = 0x42

	// Hand-encode the proto fields:
	// field 1 (public_key) tag=0x0a, field 2 (private_key) tag=0x12
	var buf []byte
	buf = append(buf, 0x0a, byte(len(badPub)))
	buf = append(buf, badPub...)
	buf = append(buf, 0x12, byte(len(goodPriv)))
	buf = append(buf, goodPriv...)

	_, err := NewKeyPairFromBytes(buf)
	if err == nil {
		t.Fatal("expected error for bad public key type, got nil")
	}
	var target *ErrInvalidIdentityKeyPairPublicKeyType
	if !errors.As(err, &target) {
		t.Errorf("expected ErrInvalidIdentityKeyPairPublicKeyType, got %T: %v", err, err)
	}
}

// TestNewKeyPairFromBytes_BadPrivateKeyLength verifies that a protobuf with a
// private key that is not 32 bytes produces ErrInvalidIdentityKeyPairPrivateKeyType.
func TestNewKeyPairFromBytes_BadPrivateKeyLength(t *testing.T) {
	goodPub := make([]byte, 33)
	goodPub[0] = 0x05 // DjbType
	// remaining 32 bytes are zero — valid public key encoding

	shortPriv := []byte{0x01, 0x02} // only 2 bytes, not 32

	var buf []byte
	buf = append(buf, 0x0a, byte(len(goodPub)))
	buf = append(buf, goodPub...)
	buf = append(buf, 0x12, byte(len(shortPriv)))
	buf = append(buf, shortPriv...)

	_, err := NewKeyPairFromBytes(buf)
	if err == nil {
		t.Fatal("expected error for short private key, got nil")
	}
	var target *ErrInvalidIdentityKeyPairPrivateKeyType
	if !errors.As(err, &target) {
		t.Errorf("expected ErrInvalidIdentityKeyPairPrivateKeyType, got %T: %v", err, err)
	}
}

// TestNewKeyPairFromBytes_EmptyInput verifies that empty bytes produce an error.
func TestNewKeyPairFromBytes_EmptyInput(t *testing.T) {
	_, err := NewKeyPairFromBytes([]byte{})
	if err == nil {
		t.Fatal("expected error for empty input, got nil")
	}
}
