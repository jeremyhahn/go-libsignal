package record

import (
	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/util/bytehelper"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// guardedPrivateKey builds a GuardedECPrivateKey from the 32-byte key held in
// s, inside a WithBytes borrow. SliceToArray copies the view into an array,
// which NewGuardedECPrivateKey wipes after moving it into guarded memory.
// SliceToArray zero-pads, so a missing or short key is refused here rather
// than turned into a zero-padded key.
func guardedPrivateKey(s *secret.Secret) (*ecc.GuardedECPrivateKey, error) {
	var key *ecc.GuardedECPrivateKey
	err := s.WithBytes(func(b []byte) error {
		if len(b) != 32 {
			return &PrivateKeyLengthError{Got: len(b), Want: 32}
		}
		var kErr error
		key, kErr = ecc.NewGuardedECPrivateKey(bytehelper.SliceToArray(b))
		return kErr
	})
	return key, err
}

// secretLen reports the length of the material held in s, read inside a
// WithBytes borrow. A nil or empty secret reports 0; a destroyed secret is
// an error, so a wiped field is never mistaken for an absent one.
func secretLen(s *secret.Secret) (int, error) {
	n := 0
	if err := s.WithBytes(func(b []byte) error {
		n = len(b)
		return nil
	}); err != nil {
		return 0, err
	}
	return n, nil
}

// copySecret copies the material of s out inside a WithBytes borrow. A nil
// or empty secret yields nil, nil (the field is absent); a destroyed secret
// is an error, never a nil copy. The caller should wipe the copy.
func copySecret(s *secret.Secret) ([]byte, error) {
	var out []byte
	if err := s.WithBytes(func(b []byte) error {
		if len(b) > 0 {
			out = append([]byte(nil), b...)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}
