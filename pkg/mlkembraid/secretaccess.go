package mlkembraid

import "github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"

// copySecret copies the material of s out inside a WithBytes borrow, for a
// value that must leave the borrow. A nil, empty or destroyed secret yields
// nil. The caller should wipe the copy after use.
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

// withBytes2 borrows a and b through WithBytes and calls fn with both views.
// The views are valid only during fn.
func withBytes2(a, b *secret.Secret, fn func(av, bv []byte) error) error {
	return a.WithBytes(func(av []byte) error {
		return b.WithBytes(func(bv []byte) error {
			return fn(av, bv)
		})
	})
}

// withBytes3 borrows a, b and c through WithBytes and calls fn with the
// three views. The views are valid only during fn.
func withBytes3(a, b, c *secret.Secret, fn func(av, bv, cv []byte) error) error {
	return a.WithBytes(func(av []byte) error {
		return withBytes2(b, c, func(bv, cv []byte) error {
			return fn(av, bv, cv)
		})
	})
}
