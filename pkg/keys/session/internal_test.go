package session

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// errSimulatedAllocFailure is the sentinel error returned by the injected
// allocator in tests that verify locked-memory allocation failure paths.
var errSimulatedAllocFailure = errors.New("simulated locked-memory allocation failure")

// failAfterN returns a secret allocator that succeeds for the first n calls
// and then injects a failure, restoring the original allocator afterward.
func failAfterN(n int, restore func()) func([]byte) (*secret.Secret, error) {
	count := 0
	return func(data []byte) (*secret.Secret, error) {
		count++
		if count > n {
			restore()
			return nil, errSimulatedAllocFailure
		}
		return secret.New(data)
	}
}

// TestNewDerivedSecrets_RootKeyAllocFailure verifies that NewDerivedSecrets
// panics when the root key allocation fails.
func TestNewDerivedSecrets_RootKeyAllocFailure(t *testing.T) {
	original := secretAlloc
	secretAlloc = func(data []byte) (*secret.Secret, error) {
		secretAlloc = original
		return nil, errSimulatedAllocFailure
	}

	defer func() {
		secretAlloc = original
		r := recover()
		if r == nil {
			t.Fatal("expected panic on root key allocation failure")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("expected string panic, got %T: %v", r, r)
		}
		if msg == "" {
			t.Fatal("expected non-empty panic message")
		}
	}()

	km := make([]byte, 64)
	NewDerivedSecrets(km)
}

// TestNewDerivedSecrets_ChainKeyAllocFailure verifies that NewDerivedSecrets
// panics when the chain key allocation fails (after root key succeeds).
func TestNewDerivedSecrets_ChainKeyAllocFailure(t *testing.T) {
	original := secretAlloc
	secretAlloc = failAfterN(1, func() { secretAlloc = original })

	defer func() {
		secretAlloc = original
		r := recover()
		if r == nil {
			t.Fatal("expected panic on chain key allocation failure")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("expected string panic, got %T: %v", r, r)
		}
		if msg == "" {
			t.Fatal("expected non-empty panic message")
		}
	}()

	km := make([]byte, 64)
	NewDerivedSecrets(km)
}

// TestNewDerivedSecrets_PQRKeyAllocFailure verifies that NewDerivedSecrets
// panics when the PQR key allocation fails (after root and chain key succeed).
func TestNewDerivedSecrets_PQRKeyAllocFailure(t *testing.T) {
	original := secretAlloc
	secretAlloc = failAfterN(2, func() { secretAlloc = original })

	defer func() {
		secretAlloc = original
		r := recover()
		if r == nil {
			t.Fatal("expected panic on PQR key allocation failure")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("expected string panic, got %T: %v", r, r)
		}
		if msg == "" {
			t.Fatal("expected non-empty panic message")
		}
	}()

	km := make([]byte, 96)
	NewDerivedSecrets(km)
}
