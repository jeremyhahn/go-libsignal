package sealed

import (
	"errors"

	"github.com/jeremyhahn/go-libsignal/pkg/kdf"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// ErrEmptyKeyMaterial is returned when a borrowed secret that keys a KDF
// holds no material. Deriving from it would give predictable keys.
var ErrEmptyKeyMaterial = errors.New("sealed: key material is empty")

// ErrKeyMaterialLength is returned when a borrowed secret does not hold
// exactly the number of bytes its caller needs.
var ErrKeyMaterialLength = errors.New("sealed: key material has the wrong length")

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

// beforeCopyBorrow runs just before copyFromSecret borrows its source. It
// is a no-op in production; tests set it to destroy the source and so model
// an enclave wiped (for example by a shutdown WipeAll) before the borrow.
var beforeCopyBorrow = func(*secret.Secret) {}

// copyFromSecret copies the secret's material into dst, inside its WithBytes
// borrow. It fails if the borrow fails (for example because the secret was
// destroyed) or if the secret does not hold exactly len(dst) bytes. On
// failure dst is wiped and must not be used: an all-zero private key clamps
// to a valid, predictable X25519 scalar.
func copyFromSecret(dst []byte, s *secret.Secret) error {
	beforeCopyBorrow(s)
	err := s.WithBytes(func(b []byte) error {
		if len(b) != len(dst) {
			return ErrKeyMaterialLength
		}
		copy(dst, b)
		return nil
	})
	if err != nil {
		crypto.Zeroize(dst)
		return err
	}
	return nil
}
