package sealed

import (
	"errors"

	"github.com/jeremyhahn/go-libsignal/pkg/kdf"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// ErrEmptyKeyMaterial is returned when a borrowed secret that keys a KDF
// holds no material. Deriving from it would give predictable keys.
var ErrEmptyKeyMaterial = errors.New("sealed: key material is empty")

// deriveFromSecret runs HKDF with no salt over the secret's material, inside
// its WithBytes borrow, and returns n output bytes owned by the caller.
func deriveFromSecret(s *secret.Secret, info []byte, n int) ([]byte, error) {
	var out []byte
	err := s.WithBytes(func(ikm []byte) error {
		// WithBytes borrows a nil or zero Secret as nil; refuse it.
		if len(ikm) == 0 {
			return ErrEmptyKeyMaterial
		}
		var deriveErr error
		out, deriveErr = kdf.DeriveSecrets(ikm, nil, info, n)
		return deriveErr
	})
	return out, err
}

// deriveSaltedFromSecret runs HKDF with the given salt and no info over the
// secret's material, inside its WithBytes borrow, and returns n output bytes
// owned by the caller.
func deriveSaltedFromSecret(s *secret.Secret, salt []byte, n int) ([]byte, error) {
	var out []byte
	err := s.WithBytes(func(ikm []byte) error {
		// WithBytes borrows a nil or zero Secret as nil; refuse it.
		if len(ikm) == 0 {
			return ErrEmptyKeyMaterial
		}
		var deriveErr error
		out, deriveErr = kdf.DeriveSecrets(ikm, salt, nil, n)
		return deriveErr
	})
	return out, err
}

// copyFromSecret copies the secret's material into dst, inside its WithBytes
// borrow. A destroyed secret copies nothing; the caller wipes dst.
func copyFromSecret(dst []byte, s *secret.Secret) {
	_ = s.WithBytes(func(b []byte) error {
		copy(dst, b)
		return nil
	})
}
