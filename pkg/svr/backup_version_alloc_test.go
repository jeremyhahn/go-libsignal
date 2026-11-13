package svr

import (
	"errors"
	"testing"

	"github.com/gtank/ristretto255"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// TestNewOPRFBackup4_VersionAllocFailure covers the failed version
// allocation, which runs after kAuth exists: the call must fail cleanly,
// the kAuth it built must be destroyed, and a later call must still
// succeed.
func TestNewOPRFBackup4_VersionAllocFailure(t *testing.T) {
	origVersion, origAuth := versionRandAlloc, authSecretAlloc
	defer func() { versionRandAlloc, authSecretAlloc = origVersion, origAuth }()

	var kAuths []*secret.Secret
	authSecretAlloc = func(input *[64]byte, ap *ristretto255.Element) *secret.Secret {
		s := origAuth(input, ap)
		kAuths = append(kAuths, s)
		return s
	}
	versionRandAlloc = func(int) (*secret.Secret, error) {
		return nil, errors.New("injected alloc failure")
	}

	backup, err := NewOPRFBackup4([]uint64{1, 2}, testPassword("pass"), 10)
	if err == nil {
		t.Fatal("want an error when the version allocation fails")
	}
	if backup != nil {
		t.Fatal("want nil backup on failure")
	}
	if len(kAuths) != 1 {
		t.Fatalf("want kAuth built once before the failure, got %d", len(kAuths))
	}
	if !kAuths[0].IsDestroyed() {
		t.Fatal("kAuth was not destroyed on the version allocation failure")
	}

	versionRandAlloc = origVersion
	backup, err = NewOPRFBackup4([]uint64{1, 2}, testPassword("pass"), 10)
	if err != nil {
		t.Fatalf("NewOPRFBackup4 after restore: %v", err)
	}
	backup.Zeroize()
}
