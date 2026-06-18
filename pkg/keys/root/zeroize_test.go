package root

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/kdf"
)

// TestKeyZeroize verifies that Zeroize destroys the guarded memory holding
// the root key, preventing sensitive material from lingering in memory.
func TestKeyZeroize(t *testing.T) {
	key := NewKey(kdf.DeriveSecrets, []byte("root-zeroize-test-key-32bytes---!"))

	if key.key.IsDestroyed() {
		t.Fatal("key should not be destroyed before Zeroize")
	}

	key.Zeroize()

	if !key.key.IsDestroyed() {
		t.Fatal("Zeroize should destroy the guarded key memory")
	}
}

// TestKeyZeroizeIdempotent verifies that calling Zeroize multiple times
// does not panic. The method must be safe to call after the first destruction.
func TestKeyZeroizeIdempotent(t *testing.T) {
	key := NewKey(kdf.DeriveSecrets, []byte("idempotent-root-key"))
	key.Zeroize()
	// Second call must not panic.
	key.Zeroize()
}
