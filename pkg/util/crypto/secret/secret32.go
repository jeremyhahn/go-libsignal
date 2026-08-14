package secret

import (
	crypto "github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
)

const secret32Size = 32

// Secret32 holds a fixed 32-byte secret in mlock'd, guard-page protected memory.
// This is the most common size for cryptographic keys in the Signal Protocol:
// EC private keys, chain keys, root keys, shared secrets, and HMAC keys.
type Secret32 struct {
	inner *Secret
}

// NewSecret32 creates a Secret32 from a 32-byte array. The data parameter is
// received by value (Go copies it on function entry), so the caller's source
// array is not zeroized by this function. Callers must zeroize their own array
// after calling NewSecret32 if it contains sensitive key material.
func NewSecret32(data [32]byte) (*Secret32, error) {
	s, err := New(data[:])
	if err != nil {
		// Zeroize on allocation failure since memguard didn't consume it.
		crypto.ZeroizeArray32(&data)
		return nil, err
	}
	return &Secret32{inner: s}, nil
}

// NewSecret32FromSlice creates a Secret32 from a byte slice, validating that
// the length is exactly 32 bytes. The source slice is zeroized by memguard.
//
// Returns ErrNilInput if data is nil, or ErrSecretSizeMismatch if the length
// is not 32.
func NewSecret32FromSlice(data []byte) (*Secret32, error) {
	if data == nil {
		return nil, &Error{kind: errNilInput}
	}
	if len(data) != secret32Size {
		return nil, newSizeMismatchError(secret32Size, len(data))
	}
	s, err := New(data)
	if err != nil {
		return nil, err
	}
	return &Secret32{inner: s}, nil
}

// NewSecret32Random creates a Secret32 filled with cryptographically random data.
func NewSecret32Random() (*Secret32, error) {
	s, err := NewRandom(secret32Size)
	if err != nil {
		return nil, err
	}
	return &Secret32{inner: s}, nil
}

// Bytes returns a view into the guarded memory. The returned slice must not
// be retained beyond the lifetime of the Secret32.
//
// Panics if the secret has been destroyed.
func (s *Secret32) Bytes() []byte {
	return s.inner.Bytes()
}

// Array returns a copy of the secret as a fixed 32-byte array. The caller
// is responsible for zeroizing the returned array when done.
//
// Panics if the secret has been destroyed.
func (s *Secret32) Array() [32]byte {
	var out [32]byte
	copy(out[:], s.inner.Bytes())
	return out
}

// Ptr returns a pointer to the 32-byte array in guarded memory. The pointer
// must not be retained beyond the lifetime of the Secret32.
//
// Panics if the secret has been destroyed.
func (s *Secret32) Ptr() *[32]byte {
	if s.inner.IsDestroyed() {
		panic("secret: attempt to access destroyed secret")
	}
	return s.inner.buf.ByteArray32()
}

// Destroy zeroizes and frees the guarded memory. This method is idempotent
// and safe to call multiple times.
func (s *Secret32) Destroy() {
	s.inner.Destroy()
}

// IsDestroyed reports whether the secret has been destroyed.
func (s *Secret32) IsDestroyed() bool {
	return s.inner.IsDestroyed()
}

// Clone creates an independent deep copy of the secret in new guarded memory.
//
// Returns ErrSecretDestroyed if the source has been destroyed, or
// ErrSecretAlloc if the allocation fails.
func (s *Secret32) Clone() (*Secret32, error) {
	cloned, err := s.inner.Clone()
	if err != nil {
		return nil, err
	}
	return &Secret32{inner: cloned}, nil
}

// EqualTo performs a constant-time comparison of the secret against the given
// 32-byte array. Returns false if the secret has been destroyed.
func (s *Secret32) EqualTo(other [32]byte) bool {
	return s.inner.EqualTo(other[:])
}
