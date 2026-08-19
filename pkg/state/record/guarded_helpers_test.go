package record_test

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/kem"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// mustGuard moves a copy of the given bytes into guarded memory, for building
// the persisted-state structures the tests exercise. It returns the zero
// Secret for empty input, matching the convention of those structures.
func mustGuard(t *testing.T, data []byte) secret.Secret {
	t.Helper()
	guarded, err := secret.NewValue(append([]byte(nil), data...))
	if err != nil {
		t.Fatalf("secret.NewValue: %v", err)
	}
	return guarded
}

// mustGuardedKyberKeyPair builds a Kyber pre-key key pair whose secret half is
// in guarded memory, which is the only form record.NewKyberPreKey accepts. The
// secretData slice is zeroized as part of the move into guarded memory.
func mustGuardedKyberKeyPair(t *testing.T, public *kem.PublicKey, secretData []byte) *kem.GuardedKeyPair {
	t.Helper()
	guarded, err := kem.NewGuardedSecretKey(public.Type(), secretData)
	if err != nil {
		t.Fatalf("kem.NewGuardedSecretKey: %v", err)
	}
	return &kem.GuardedKeyPair{Public: public, Secret: guarded}
}
