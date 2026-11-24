package ecc

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret/secrettest"
)

// TestGuardPrivateKey covers the serialize-and-guard conversion with fixed key bytes, so it runs in the FIPS gate.
func TestGuardPrivateKey(t *testing.T) {
	var raw [32]byte
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	key, err := NewGuardedECPrivateKey(raw)
	if err != nil {
		t.Fatalf("NewGuardedECPrivateKey: %v", err)
	}
	defer key.Destroy()

	// Read back through the key itself: NewGuardedECPrivateKey clamps its
	// input, so the stored bytes are not the raw ones fed in.
	expected := key.Serialize()

	guarded, err := GuardPrivateKey(key)
	if err != nil {
		t.Fatalf("GuardPrivateKey: %v", err)
	}
	defer guarded.Destroy()

	if !secrettest.Matches(t, &guarded, expected[:]) {
		t.Error("guarded key does not match the serialized private key")
	}
}

// TestGuardPrivateKeyAbsent covers the nil case: an absent private key yields
// the zero Secret rather than an error, matching the zero-means-absent
// convention of the persisted-state structures.
func TestGuardPrivateKeyAbsent(t *testing.T) {
	guarded, err := GuardPrivateKey(nil)
	if err != nil {
		t.Fatalf("GuardPrivateKey(nil): %v", err)
	}
	if !guarded.IsZero() {
		t.Error("an absent private key must yield the zero Secret")
	}
	guarded.Destroy() // must not panic
}
