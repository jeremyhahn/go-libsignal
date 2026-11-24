package secret

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/jeremyhahn/go-enclave"
)

// Secret holds key material in go-enclave locked, guard-paged memory zeroized on destroy; zero-length input yields the empty zero Secret.
type Secret struct {
	enc enclave.ByteAccess
}

// New moves data into a Secret, zeroizing data; it returns ErrNilInput for nil or ErrSecretAlloc if allocation fails.
func New(data []byte) (*Secret, error) {
	if data == nil {
		return nil, &Error{kind: errNilInput}
	}
	if len(data) == 0 {
		return &Secret{}, nil
	}
	enc, err := newLocked(data)
	if err != nil {
		return nil, newAllocError(err)
	}
	return &Secret{enc: enc}, nil
}

// NewRandom returns a read-only Secret of size random bytes drawn into locked memory, or ErrSecretAlloc; under a budget it briefly needs two reservations.
func NewRandom(size int) (out *Secret, retErr error) {
	if size == 0 {
		return &Secret{}, nil
	}
	// Draw the randomness into a writable locked region, then move it into a
	// frozen enclave. go-enclave has no post-fill freeze, and the move keeps the
	// material locked the whole way — it never lands on the ordinary heap.
	scratch, err := newLockedSized(size)
	if err != nil {
		return nil, newAllocError(err)
	}
	// A failed scratch release is reported, and the fresh secret is not
	// handed out alongside an error.
	defer func() {
		if destroyErr := scratch.Destroy(); destroyErr != nil {
			if out != nil {
				out.Destroy()
				out = nil
			}
			retErr = errors.Join(retErr, destroyErr)
		}
	}()

	var s *Secret
	if err := scratch.WithBytes(func(b []byte) error {
		if _, readErr := io.ReadFull(rand.Reader, b); readErr != nil {
			return readErr
		}
		frozen, frozenErr := newLocked(b)
		if frozenErr != nil {
			return frozenErr
		}
		s = &Secret{enc: frozen}
		return nil
	}); err != nil {
		return nil, newAllocError(err)
	}
	return s, nil
}

// NewEmpty returns a zeroed, writable Secret of size bytes to fill inside WithBytes, or ErrSecretAlloc.
func NewEmpty(size int) (*Secret, error) {
	if size == 0 {
		return &Secret{}, nil
	}
	enc, err := newLockedSized(size)
	if err != nil {
		return nil, newAllocError(err)
	}
	return &Secret{enc: enc}, nil
}

// WithBytes calls fn with a view of the locked memory, valid only during fn; fn must not keep it or call the Secret. It returns ErrSecretDestroyed or ErrNilInput.
func (s *Secret) WithBytes(fn func([]byte) error) error {
	if fn == nil {
		return &Error{kind: errNilInput}
	}
	if s == nil || s.enc == nil {
		return fn(nil)
	}
	called := false
	err := s.enc.WithBytes(func(b []byte) error {
		called = true
		return fn(b)
	})
	if !called && errors.Is(err, enclave.ErrEnclaveDestroyed) {
		return &Error{kind: errSecretDestroyed}
	}
	return err
}

// Size returns the size of the secret in bytes.
// Returns 0 if the secret has been destroyed or holds no material.
func (s *Secret) Size() int {
	if s == nil || s.enc == nil {
		return 0
	}
	return s.enc.Size()
}

// Destroy zeroizes and frees the memory; it is idempotent and nil-safe, and panics if the enclave release fails.
func (s *Secret) Destroy() {
	if s == nil || s.enc == nil {
		return
	}
	if err := s.enc.Destroy(); err != nil {
		panic(fmt.Errorf("secret: destroy failed: %w", err))
	}
}

// IsDestroyed reports whether the secret holds no live material. A nil Secret,
// the zero Secret, and a destroyed Secret all report true.
func (s *Secret) IsDestroyed() bool {
	return s == nil || s.enc == nil || !s.enc.IsAlive()
}

// Clone copies the secret into new locked memory without staging it on the heap; it returns ErrSecretDestroyed or ErrSecretAlloc.
func (s *Secret) Clone() (*Secret, error) {
	if s.IsDestroyed() {
		return nil, &Error{kind: errSecretDestroyed}
	}
	var cloned enclave.ByteAccess
	err := s.enc.WithBytes(func(src []byte) error {
		dst, allocErr := newLockedSized(len(src))
		if allocErr != nil {
			return allocErr
		}
		copyErr := dst.WithBytes(func(buf []byte) error {
			copy(buf, src)
			return nil
		})
		if copyErr != nil {
			return errors.Join(copyErr, dst.Destroy())
		}
		cloned = dst
		return nil
	})
	if err != nil {
		return nil, newAllocError(err)
	}
	return &Secret{enc: cloned}, nil
}

// EqualTo performs a constant-time comparison of the secret against the given
// byte slice. Returns false if the secret has been destroyed.
func (s *Secret) EqualTo(other []byte) bool {
	if s.IsDestroyed() {
		return false
	}
	ok, err := s.enc.EqualTo(other)
	return err == nil && ok
}
