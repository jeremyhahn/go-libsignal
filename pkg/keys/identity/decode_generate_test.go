//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 3 tests in this file exercise X25519. FIPS 140-3 does not approve that,
// but the X3DH key agreement specification (section 2.1) requires it, so the
// fips140only build tag drops this file from the FIPS gate. `make test` and
// `make coverage` still run it.

package identity

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
)

// TestDecode_Valid verifies that Decode parses a DjbType-prefixed (0x05)
// Curve25519 public key and round-trips byte-for-byte. Rust reference:
// IdentityKey::decode in rust/protocol/src/identity_key.rs:50.
func TestDecode_Valid(t *testing.T) {
	kp, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	serialized := kp.PublicKey().Serialize() // [0x05][32 bytes]

	key, err := Decode(serialized)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil Key")
	}
	if !bytes.Equal(key.Serialize(), serialized) {
		t.Fatalf("round-trip mismatch: got %x want %x", key.Serialize(), serialized)
	}
}

// TestDecode_TooShort verifies that Decode surfaces the underlying
// ecc.DecodePoint error on malformed (truncated) input instead of panicking.
func TestDecode_TooShort(t *testing.T) {
	// A single type byte with no key material cannot decode.
	if _, err := Decode([]byte{0x05}); err == nil {
		t.Fatal("expected error for truncated input")
	}
}

// TestDecode_Empty verifies Decode rejects an empty slice with an error.
func TestDecode_Empty(t *testing.T) {
	if _, err := Decode(nil); err == nil {
		t.Fatal("expected error for empty input")
	}
}

// TestGenerateKeyPair_Success verifies GenerateKeyPair produces a usable
// key pair whose public/private halves are non-nil and serialize correctly.
// Rust reference: IdentityKeyPair::generate in
// rust/protocol/src/identity_key.rs:99.
func TestGenerateKeyPair_Success(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if kp.PublicKey() == nil || kp.PrivateKey() == nil {
		t.Fatal("expected non-nil public and private keys")
	}
	pub := kp.PublicKey().Serialize()
	if len(pub) != 33 || pub[0] != 0x05 {
		t.Fatalf("unexpected public key serialization: %x", pub)
	}
}

// TestGenerateKeyPair_Unique verifies two consecutive calls produce distinct
// key material (the CSPRNG is actually being used).
func TestGenerateKeyPair_Unique(t *testing.T) {
	a, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair a: %v", err)
	}
	b, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair b: %v", err)
	}
	if bytes.Equal(a.PublicKey().Serialize(), b.PublicKey().Serialize()) {
		t.Fatal("expected distinct key pairs from two GenerateKeyPair calls")
	}
}
