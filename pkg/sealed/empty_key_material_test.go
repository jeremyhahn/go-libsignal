package sealed

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// TestDeriveFromSecret_EmptyKeyMaterial checks that the HKDF helpers
// refuse a nil or zero secret, which WithBytes borrows as nil.
func TestDeriveFromSecret_EmptyKeyMaterial(t *testing.T) {
	empty, err := secret.New([]byte{})
	if err != nil {
		t.Fatalf("secret.New: %v", err)
	}
	for name, s := range map[string]*secret.Secret{"nil": nil, "zero": {}, "empty": empty} {
		if out, err := deriveFromSecret(s, []byte("info"), 32); !errors.Is(err, ErrEmptyKeyMaterial) || out != nil {
			t.Errorf("deriveFromSecret(%s): want ErrEmptyKeyMaterial, got %x, %v", name, out, err)
		}
		if out, err := deriveSaltedFromSecret(s, []byte("salt"), 32); !errors.Is(err, ErrEmptyKeyMaterial) || out != nil {
			t.Errorf("deriveSaltedFromSecret(%s): want ErrEmptyKeyMaterial, got %x, %v", name, out, err)
		}
	}

	live, err := secret.New(make([]byte, 32))
	if err != nil {
		t.Fatalf("secret.New: %v", err)
	}
	defer live.Destroy()
	if _, err := deriveFromSecret(live, []byte("info"), 32); err != nil {
		t.Fatalf("deriveFromSecret(live): %v", err)
	}
	if _, err := deriveSaltedFromSecret(live, []byte("salt"), 32); err != nil {
		t.Fatalf("deriveSaltedFromSecret(live): %v", err)
	}
}
