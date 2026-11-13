package mlkembraid

import "github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"

// copySecret copies the material of s out inside a WithBytes borrow, for a
// value that must leave the borrow. A nil s is an absent field and yields
// (nil, nil). A destroyed or empty secret is an error, never a nil copy, so
// a failed borrow cannot pass for an absent field. The caller should wipe
// the copy after use.
func copySecret(s *secret.Secret) ([]byte, error) {
	if s == nil {
		return nil, nil
	}
	var out []byte
	if err := s.WithBytes(func(b []byte) error {
		if len(b) == 0 {
			return &ErrInvalidInput{Field: "secret", Reason: "empty secret"}
		}
		out = append([]byte(nil), b...)
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
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
