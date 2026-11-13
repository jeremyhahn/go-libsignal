package spqr

import "github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"

// copySecret copies the material of s out inside a WithBytes borrow, for a
// value that must leave the borrow (a proto field, a returned message key).
// A nil, empty or destroyed secret yields nil. The caller should wipe the
// copy after use.
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
