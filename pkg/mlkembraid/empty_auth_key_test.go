package mlkembraid

import (
	"errors"
	"testing"
)

// TestAuthenticator_EmptyKeysRefused checks that an authenticator whose
// root or MAC key holds no material (borrowed as nil) neither runs
// KDF_AUTH nor computes a MAC under an empty key.
func TestAuthenticator_EmptyKeysRefused(t *testing.T) {
	var invalid *ErrInvalidInput

	a := &Authenticator{}
	if err := a.Update(1, []byte("update-key")); !errors.As(err, &invalid) || invalid.Field != "rootKey" {
		t.Fatalf("Update with no root key: want ErrInvalidInput{rootKey}, got %v", err)
	}
	if mac, err := a.macWith([]byte("label"), 1, []byte("data")); !errors.As(err, &invalid) || invalid.Field != "macKey" || mac != nil {
		t.Fatalf("macWith with no MAC key: want ErrInvalidInput{macKey}, got %x, %v", mac, err)
	}

	live, err := NewAuthenticator(1, []byte("shared-secret"))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	defer live.Zeroize()
	if _, err := live.macWith([]byte("label"), 1, []byte("data")); err != nil {
		t.Fatalf("macWith on a live authenticator: %v", err)
	}
}
