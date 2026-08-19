package serialize

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// mustGuard moves a copy of the given bytes into guarded memory, for building
// the persisted-state structures the serializer tests exercise.
func mustGuard(t *testing.T, data []byte) secret.Secret {
	t.Helper()
	guarded, err := secret.NewValue(append([]byte(nil), data...))
	if err != nil {
		t.Fatalf("secret.NewValue: %v", err)
	}
	return guarded
}
