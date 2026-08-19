package secret

import (
	"fmt"

	"github.com/awnumar/memguard"
)

// Enclave is an encrypted at-rest container for secret material.
// It wraps memguard.Enclave to keep the dependency encapsulated.
type Enclave = memguard.Enclave

// Secret holds sensitive key material in mlock'd, guard-page protected memory.
// The underlying buffer is zeroized on destruction and protected from swap.
type Secret struct {
	buf *memguard.LockedBuffer
}

// New creates a Secret from the given byte slice. The source slice is zeroized
// by memguard as part of the move into guarded memory.
//
// Returns ErrNilInput if data is nil, or ErrSecretAlloc if the underlying
// memguard allocation fails.
func New(data []byte) (s *Secret, err error) {
	if data == nil {
		return nil, &Error{kind: errNilInput}
	}
	// coverage-exempt: defensive OOM panic-recovery for memguard.NewBufferFromBytes;
	// cannot be unit-tested without modifying the host (see CLAUDE.md).
	defer func() {
		if r := recover(); r != nil {
			s = nil
			err = newAllocError(fmt.Sprint(r))
		}
	}()
	buf := memguard.NewBufferFromBytes(data)
	return &Secret{buf: buf}, nil
}

// NewRandom creates a Secret filled with cryptographically random data.
//
// Returns ErrSecretAlloc if the underlying memguard allocation fails.
func NewRandom(size int) (s *Secret, err error) {
	// coverage-exempt: defensive OOM panic-recovery for memguard.NewBufferRandom;
	// cannot be unit-tested without modifying the host (see CLAUDE.md).
	defer func() {
		if r := recover(); r != nil {
			s = nil
			err = newAllocError(fmt.Sprint(r))
		}
	}()
	buf := memguard.NewBufferRandom(size)
	return &Secret{buf: buf}, nil
}

// NewEmpty creates a Secret of the given size, initialized to zero.
//
// Returns ErrSecretAlloc if the underlying memguard allocation fails.
func NewEmpty(size int) (s *Secret, err error) {
	// coverage-exempt: defensive OOM panic-recovery for memguard.NewBuffer;
	// cannot be unit-tested without modifying the host (see CLAUDE.md).
	defer func() {
		if r := recover(); r != nil {
			s = nil
			err = newAllocError(fmt.Sprint(r))
		}
	}()
	buf := memguard.NewBuffer(size)
	return &Secret{buf: buf}, nil
}

// Bytes returns a view into the guarded memory. The returned slice must not
// be retained beyond the lifetime of the Secret.
//
// Panics if the secret has been destroyed. Callers should check IsDestroyed
// first in contexts where destruction is possible.
func (s *Secret) Bytes() []byte {
	if s.IsDestroyed() {
		panic("secret: attempt to access destroyed secret")
	}
	return s.buf.Bytes()
}

// Size returns the size of the secret in bytes.
// Returns 0 if the secret has been destroyed.
func (s *Secret) Size() int {
	if s.IsDestroyed() {
		return 0
	}
	return s.buf.Size()
}

// Destroy zeroizes and frees the guarded memory. This method is idempotent
// and safe to call multiple times, including on a nil Secret.
func (s *Secret) Destroy() {
	if s == nil {
		return
	}
	if s.buf != nil && s.buf.IsAlive() {
		s.buf.Destroy()
	}
}

// IsDestroyed reports whether the secret has been destroyed. A nil Secret
// holds no material and is reported as destroyed.
func (s *Secret) IsDestroyed() bool {
	return s == nil || s.buf == nil || !s.buf.IsAlive()
}

// Clone creates an independent deep copy of the secret in new guarded memory.
//
// Returns ErrSecretDestroyed if the source has been destroyed, or
// ErrSecretAlloc if the allocation fails.
func (s *Secret) Clone() (*Secret, error) {
	if s.IsDestroyed() {
		return nil, &Error{kind: errSecretDestroyed}
	}
	// Copy bytes out then move into new guarded memory.
	src := s.buf.Bytes()
	tmp := make([]byte, len(src))
	copy(tmp, src)
	return New(tmp)
}

// EqualTo performs a constant-time comparison of the secret against the given
// byte slice. Returns false if the secret has been destroyed.
func (s *Secret) EqualTo(other []byte) bool {
	if s.IsDestroyed() {
		return false
	}
	return s.buf.EqualTo(other)
}

// Freeze makes the guarded memory immutable (read-only). Any write attempt
// to the memory after freezing will cause a segfault, providing defense
// against accidental modification.
func (s *Secret) Freeze() {
	if !s.IsDestroyed() {
		s.buf.Freeze()
	}
}

// Melt makes previously frozen guarded memory mutable again.
func (s *Secret) Melt() {
	if !s.IsDestroyed() {
		s.buf.Melt()
	}
}

// Seal encrypts the secret into an Enclave for at-rest storage and destroys
// the plaintext LockedBuffer. The returned Enclave can later be opened with
// OpenEnclave to recover the secret.
//
// Returns nil if the secret has already been destroyed.
func (s *Secret) Seal() *Enclave {
	if s.IsDestroyed() {
		return nil
	}
	data := s.buf.Bytes()
	tmp := make([]byte, len(data))
	copy(tmp, data)
	s.Destroy()
	return memguard.NewEnclave(tmp)
}

// OpenEnclave decrypts an Enclave and returns the secret in guarded memory.
//
// Returns ErrNilInput if the enclave is nil, or wraps any error from the
// decryption operation.
func OpenEnclave(e *Enclave) (*Secret, error) {
	if e == nil {
		return nil, &Error{kind: errNilInput}
	}
	buf, err := e.Open()
	if err != nil {
		return nil, newAllocError(err.Error())
	}
	return &Secret{buf: buf}, nil
}
