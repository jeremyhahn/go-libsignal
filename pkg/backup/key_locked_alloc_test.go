package backup

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/accountkeys"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// failEmptyAllocAfter makes the n-th (0-based) locked allocation fail and
// restores the real allocator when the test ends.
func failEmptyAllocAfter(t *testing.T, n int) {
	t.Helper()
	orig := secretEmptyAlloc
	calls := 0
	secretEmptyAlloc = func(size int) (*secret.Secret, error) {
		defer func() { calls++ }()
		if calls == n {
			return nil, errors.New("injected alloc failure")
		}
		return orig(size)
	}
	t.Cleanup(func() { secretEmptyAlloc = orig })
}

func TestDeriveBackupKey_LockedAllocFailure(t *testing.T) {
	failEmptyAllocAfter(t, 0)
	_, err := DeriveBackupKey(accountkeys.AccountEntropyPool(fakeAccountEntropyPool))
	var se *ErrSecuringSecret
	if !errors.As(err, &se) {
		t.Fatalf("want *ErrSecuringSecret, got %v", err)
	}
}

func TestDeriveMessageBackupKey_LockedAllocFailure(t *testing.T) {
	bk, err := DeriveBackupKey(accountkeys.AccountEntropyPool(fakeAccountEntropyPool))
	if err != nil {
		t.Fatalf("DeriveBackupKey: %v", err)
	}
	defer bk.Zeroize()
	id, err := bk.DeriveBackupID(fakeACI())
	if err != nil {
		t.Fatalf("DeriveBackupID: %v", err)
	}

	// Allocations in order: intermediate, HMAC key, AES key.
	for n, op := range []string{"HKDF output", "HMAC key", "AES key"} {
		t.Run(op, func(t *testing.T) {
			failEmptyAllocAfter(t, n)
			mk, err := DeriveMessageBackupKey(bk, id, nil)
			var se *ErrSecuringSecret
			if !errors.As(err, &se) || se.Operation != op {
				t.Fatalf("want ErrSecuringSecret{%q}, got %v", op, err)
			}
			if mk != nil {
				t.Fatalf("want nil key on failure")
			}
		})
	}
}
