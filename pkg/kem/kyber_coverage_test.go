package kem

import (
	"testing"
)

// TestKyber1024KEMGenerateKeyPairConsistency verifies that generated key pairs
// have the correct key type and non-empty data, and that the public key can be
// round-tripped through serialization.
func TestKyber1024KEMGenerateKeyPairConsistency(t *testing.T) {
	k := NewKyber1024KEM()
	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	// The public key should be serializable (type prefix + data).
	serialized := kp.Public.Serialize()
	if len(serialized) < 2 {
		t.Fatal("serialized public key is too short")
	}
	if KeyType(serialized[0]) != KeyTypeKyber1024 {
		t.Errorf("serialized type byte = 0x%02x, want 0x%02x", serialized[0], KeyTypeKyber1024)
	}

	// Deserialize and verify round-trip.
	pk2, err := DeserializePublicKey(serialized)
	if err != nil {
		t.Fatalf("DeserializePublicKey: %v", err)
	}
	if pk2.Type() != KeyTypeKyber1024 {
		t.Errorf("deserialized key type = 0x%02x, want 0x%02x", pk2.Type(), KeyTypeKyber1024)
	}
}

// TestKyber1024KEMEncapsulateDecapsulateFull exercises the full encapsulate/decapsulate
// cycle with verification that the shared secret has expected length and is non-zero.
func TestKyber1024KEMEncapsulateDecapsulateFull(t *testing.T) {
	k := NewKyber1024KEM()
	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	ss, ct, err := k.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}

	// SharedSecret is a [32]byte array.
	if len(ss) != 32 {
		t.Errorf("shared secret length = %d, want 32", len(ss))
	}

	// Ciphertext should have correct type.
	if ct.Type() != KeyTypeKyber1024 {
		t.Errorf("ciphertext type = 0x%02x, want 0x%02x", ct.Type(), KeyTypeKyber1024)
	}

	// Ciphertext should be non-empty.
	if len(ct.Data()) == 0 {
		t.Error("ciphertext data should not be empty")
	}

	// Decapsulate should produce matching shared secret.
	ss2, err := k.Decapsulate(kp.Secret, ct)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	if *ss != *ss2 {
		t.Error("shared secrets should match")
	}

	// Shared secret should not be all zeros.
	allZero := true
	for _, b := range ss[:] {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("shared secret should not be all zeros")
	}
}

// TestKyber1024KEMCiphertextSerializeRoundTrip verifies that ciphertexts can be
// serialized and deserialized for transmission.
func TestKyber1024KEMCiphertextSerializeRoundTrip(t *testing.T) {
	k := NewKyber1024KEM()
	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	_, ct, err := k.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}

	serialized := ct.Serialize()
	restored, err := DeserializeCiphertext(serialized)
	if err != nil {
		t.Fatalf("DeserializeCiphertext: %v", err)
	}

	if restored.Type() != ct.Type() {
		t.Error("type mismatch after ciphertext round-trip")
	}

	// Decapsulate with the restored ciphertext should still work.
	ss1, err := k.Decapsulate(kp.Secret, ct)
	if err != nil {
		t.Fatalf("Decapsulate original: %v", err)
	}
	ss2, err := k.Decapsulate(kp.Secret, restored)
	if err != nil {
		t.Fatalf("Decapsulate restored: %v", err)
	}
	if *ss1 != *ss2 {
		t.Error("decapsulated secrets should match after ciphertext round-trip")
	}
}

// TestDeserializePublicKeyNilInput ensures nil input is handled.
func TestDeserializePublicKeyNilInput(t *testing.T) {
	_, err := DeserializePublicKey(nil)
	if err == nil {
		t.Fatal("expected error for nil input")
	}
}

// TestDeserializeCiphertextNilInput ensures nil input is handled.
func TestDeserializeCiphertextNilInput(t *testing.T) {
	_, err := DeserializeCiphertext(nil)
	if err == nil {
		t.Fatal("expected error for nil input")
	}
}
