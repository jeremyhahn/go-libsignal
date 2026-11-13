package svr

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// TestNewOPRFBackup4_VersionAllocFailure covers the failed version
// allocation, which runs after kAuth exists: the call must fail cleanly
// (kAuth is destroyed by its defer) and a later call must still succeed.
func TestNewOPRFBackup4_VersionAllocFailure(t *testing.T) {
	orig := versionRandAlloc
	versionRandAlloc = func(int) (*secret.Secret, error) {
		return nil, errors.New("injected alloc failure")
	}
	backup, err := NewOPRFBackup4([]uint64{1, 2}, testPassword("pass"), 10)
	versionRandAlloc = orig
	if err == nil {
		t.Fatal("want an error when the version allocation fails")
	}
	if backup != nil {
		t.Fatal("want nil backup on failure")
	}

	backup, err = NewOPRFBackup4([]uint64{1, 2}, testPassword("pass"), 10)
	if err != nil {
		t.Fatalf("NewOPRFBackup4 after restore: %v", err)
	}
	backup.Zeroize()
}
