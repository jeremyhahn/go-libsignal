package spqr

import "github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"

// copySecret returns a copy of s's bytes, or nil if s is nil, empty or destroyed; the caller wipes it.
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
