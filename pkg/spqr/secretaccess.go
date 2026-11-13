package spqr

import (
	"fmt"

	"github.com/jeremyhahn/go-libsignal/internal/testseam"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// beforeCopyBorrow runs just before copySecret borrows its source. It is a
// test seam for a source destroyed between lookup and borrow; production
// code leaves it a no-op.
var beforeCopyBorrow = func(s *secret.Secret) {
	if hook := testseam.SPQRBeforeCopyBorrow; hook != nil {
		hook(s)
	}
}

// copySecret copies the material of s out inside a WithBytes borrow, for a
// value that must leave the borrow (a proto field, a returned message key).
// The borrowed material must be exactly want bytes long. A nil, empty,
// destroyed or wrong-length secret is an error, never a nil or zero copy:
// callers that mean "absent" must decide that before calling. The caller
// should wipe the copy after use.
func copySecret(s *secret.Secret, field string, want int) ([]byte, error) {
	if s == nil {
		return nil, &ErrInvalidInput{Field: field, Reason: "secret is nil"}
	}
	beforeCopyBorrow(s)
	var out []byte
	err := s.WithBytes(func(b []byte) error {
		if len(b) != want {
			return &ErrInvalidInput{Field: field, Reason: fmt.Sprintf("want %d bytes, got %d", want, len(b))}
		}
		out = append(make([]byte, 0, want), b...)
		return nil
	})
	if err != nil {
		crypto.Zeroize(out)
		return nil, err
	}
	return out, nil
}
