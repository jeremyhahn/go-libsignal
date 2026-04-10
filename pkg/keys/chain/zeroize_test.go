package chain

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/kdf"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// TestKeyZeroize verifies that Zeroize destroys the guarded memory holding
// the chain key, preventing sensitive material from lingering in memory.
func TestKeyZeroize(t *testing.T) {
	key := NewKey(kdf.DeriveSecrets, []byte("zeroize-test-key-32bytes-length!"), 0)

	// Key should be alive before Zeroize.
	if key.key.IsDestroyed() {
		t.Fatal("key should not be destroyed before Zeroize")
	}

	key.Zeroize()

	// Key should be destroyed after Zeroize.
	if !key.key.IsDestroyed() {
		t.Fatal("Zeroize should destroy the guarded key memory")
	}
}

// TestKeyZeroizeIdempotent verifies that calling Zeroize multiple times
// does not panic. The method must be safe to call after first destruction.
func TestKeyZeroizeIdempotent(t *testing.T) {
	key := NewKey(kdf.DeriveSecrets, []byte("idempotent-zeroize"), 1)
	key.Zeroize()
	// Second call must not panic.
	key.Zeroize()
}

// TestSetKey_WhenPreviousKeyNil exercises the branch in SetKey where the
// existing internal key is nil (the nil-guard: if c.key != nil).
// This is reached when a Key is constructed with a nil internal secret.
func TestSetKey_WhenPreviousKeyNil(t *testing.T) {
	// Construct a Key struct directly with nil internal key to hit
	// the c.key == nil branch in SetKey.
	key := &Key{
		kdf:   kdf.DeriveSecrets,
		key:   nil,
		index: 0,
	}

	// SetKey must not panic when c.key is nil.
	key.SetKey([]byte("new-material"))

	if string(key.Key()) != "new-material" {
		t.Fatal("SetKey did not set the new key material")
	}
}

// TestMessageKeysWithSeed_KDFError exercises the error path in MessageKeysWithSeed
// where deriveMessageKeysFromSeed returns an error. The error must be propagated
// and the seed copy must be zeroized.
func TestMessageKeysWithSeed_KDFError(t *testing.T) {
	// Build a Key with an error-returning KDF.
	errorKDF := func(inputKeyMaterial, salt, info []byte, outputLength int) ([]byte, error) {
		return nil, errors.New("simulated KDF failure")
	}

	// Create a Key with valid secret but an error KDF.
	material := []byte("test-chain-key-32-bytes-fill---!")
	guardedKey, err := secret.New(material)
	if err != nil {
		t.Fatalf("failed to create guarded key for test: %v", err)
	}

	key := &Key{
		kdf:   errorKDF,
		key:   guardedKey,
		index: 0,
	}

	_, err = key.MessageKeysWithSeed()
	if err == nil {
		t.Fatal("expected error from KDF failure in MessageKeysWithSeed")
	}
}
