package record

import (
	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/util/bytehelper"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// guardedPrivateKey builds a GuardedECPrivateKey from the 32-byte key held in
// s, inside a WithBytes borrow. SliceToArray copies the view into an array,
// which NewGuardedECPrivateKey wipes after moving it into guarded memory.
func guardedPrivateKey(s *secret.Secret) (*ecc.GuardedECPrivateKey, error) {
	var key *ecc.GuardedECPrivateKey
	err := s.WithBytes(func(b []byte) error {
		var kErr error
		key, kErr = ecc.NewGuardedECPrivateKey(bytehelper.SliceToArray(b))
		return kErr
	})
	return key, err
}

// secretLen reports the length of the material held in s, read inside a
// WithBytes borrow. A nil, empty or destroyed secret reports 0.
func secretLen(s *secret.Secret) int {
	n := 0
	if err := s.WithBytes(func(b []byte) error {
		n = len(b)
		return nil
	}); err != nil {
		return 0
	}
	return n
}

// copySecret copies the material of s out inside a WithBytes borrow. A nil,
// empty or destroyed secret yields nil. The caller should wipe the copy.
func copySecret(s *secret.Secret) []byte {
	var out []byte
	if err := s.WithBytes(func(b []byte) error {
		if b != nil {
			out = append([]byte(nil), b...)
		}
		return nil
	}); err != nil {
		return nil
	}
	return out
}
