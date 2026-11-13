package secret

import (
	"crypto/rand"
	"errors"
	"io"

	"github.com/jeremyhahn/go-enclave"
)

// Secret holds sensitive key material in mlock'd, guard-page protected memory.
// The underlying region is zeroized on destruction and protected from swap.
//
// The backing store is go-enclave's locked memory, read only through
// ByteAccess.WithBytes: reaching RLIMIT_MEMLOCK returns a typed error from construction
// rather than purging every live buffer in the process the way memguard did.
//
// A zero-length input holds no material: the returned Secret reports Size()==0
// and IsDestroyed()==true, matching the zero Secret. Locked memory cannot be
// allocated with zero length, and no live path constructs an empty secret —
// the serialization helpers route empty input to the zero Secret before
// reaching New.
type Secret struct {
	enc enclave.ByteAccess
}

// New creates a Secret from the given byte slice. The source slice is zeroized
// as part of the move into locked memory.
//
// Returns ErrNilInput if data is nil, or ErrSecretAlloc if the underlying
// locked-memory allocation fails. An empty (non-nil) slice yields a Secret that
// holds no material; see the type doc.
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

// NewRandom creates a Secret filled with cryptographically random data drawn
// directly into locked memory, so the material never exists on the ordinary
// heap. The returned secret is frozen read-only, matching the immutable random
// buffer the previous memguard backend produced: random key material is filled
// once and only read, so a stray write to it should fault rather than silently
// corrupt the key.
//
// A size of zero yields a Secret that holds no material. Returns ErrSecretAlloc
// if the underlying locked-memory allocation or the random read fails. Under a
// budget (see SetAllocator) the call briefly holds two reservations, the
// scratch region and the frozen one, and needs room for both.
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

// NewEmpty creates a Secret of the given size, initialized to zero, whose
// locked pages stay writable so the caller can fill them in place inside
// WithBytes.
//
// A size of zero yields a Secret that holds no material. Returns ErrSecretAlloc
// if the underlying locked-memory allocation fails.
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

// WithBytes calls fn with a view of the secret's locked memory and returns
// fn's error. The view is valid only while fn runs: fn must not retain it
// (or any sub-slice of it) and must not call a method on the same Secret,
// which would deadlock against the enclave's borrow lock. A value that must
// outlive fn is copied inside fn, and the caller wipes the copy when done.
//
// A nil Secret, or one that holds no material (size zero), calls fn with a
// nil slice. A destroyed Secret does not call fn and returns
// ErrSecretDestroyed; a nil fn returns ErrNilInput.
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

// Destroy zeroizes and frees the locked memory. This method is idempotent
// and safe to call multiple times, including on a nil Secret.
func (s *Secret) Destroy() {
	if s == nil || s.enc == nil {
		return
	}
	_ = s.enc.Destroy()
}

// IsDestroyed reports whether the secret holds no live material. A nil Secret,
// the zero Secret, and a destroyed Secret all report true.
func (s *Secret) IsDestroyed() bool {
	return s == nil || s.enc == nil || !s.enc.IsAlive()
}

// Clone creates an independent deep copy of the secret in new locked memory.
//
// The copy goes locked region to locked region. It must not stage the
// plaintext in an ordinary []byte on the way: doing so would put every cloned
// key on a swappable, core-dumpable page for the length of the call, and
// zeroizing such a slice afterwards undoes neither the swap nor the core dump.
// That is why the protected-memory rule is about where the material lives
// rather than how briefly it lives there.
//
// Returns ErrSecretDestroyed if the source has been destroyed, or
// ErrSecretAlloc if the allocation fails.
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
