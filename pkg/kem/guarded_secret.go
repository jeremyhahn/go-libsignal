package kem

import (
	"fmt"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// ErrGuardedKeyDestroyedType is the typed error for operations on a destroyed guarded key.
type ErrGuardedKeyDestroyedType struct{}

func (e *ErrGuardedKeyDestroyedType) Error() string {
	return "kem: guarded key has been destroyed"
}

// ErrGuardedKeyDestroyed is returned when an operation is attempted on a
// destroyed GuardedSecretKey or GuardedSharedSecret.
var ErrGuardedKeyDestroyed error = &ErrGuardedKeyDestroyedType{}

// GuardedSecretKey holds a KEM secret key in memguard-protected memory.
// Unlike SecretKey which stores key material in a regular byte slice,
// GuardedSecretKey uses mlock'd, guard-page protected memory that is
// zeroized on destruction.
type GuardedSecretKey struct {
	keyType KeyType
	key     *secret.Secret
}

// NewGuardedSecretKey creates a GuardedSecretKey from the given key type and
// raw key data. The source slice is zeroized by memguard as part of the move
// into guarded memory.
func NewGuardedSecretKey(keyType KeyType, data []byte) (k *GuardedSecretKey, err error) {
	defer func() {
		if r := recover(); r != nil {
			k = nil
			err = &GuardedKeyAllocationError{Operation: "guarded secret key allocation failed", Err: fmt.Errorf("%v", r)}
		}
	}()

	s, sErr := secret.New(data)
	if sErr != nil {
		return nil, &GuardedKeyAllocationError{Operation: "guarded secret key allocation failed", Err: sErr}
	}
	return &GuardedSecretKey{keyType: keyType, key: s}, nil
}

// NewGuardedSecretKeyFromSecret creates a GuardedSecretKey by taking ownership
// of an existing Secret. The caller must not use the Secret after this call.
func NewGuardedSecretKeyFromSecret(keyType KeyType, s *secret.Secret) *GuardedSecretKey {
	return &GuardedSecretKey{keyType: keyType, key: s}
}

// Type returns the KEM algorithm identifier for this secret key.
func (g *GuardedSecretKey) Type() KeyType {
	return g.keyType
}

// Data returns a view into the guarded memory holding the key material.
// The returned slice must not be retained beyond the lifetime of the
// GuardedSecretKey.
//
// Panics if the key has been destroyed.
func (g *GuardedSecretKey) Data() []byte {
	return g.key.Bytes()
}

// Destroy zeroizes and frees the guarded memory holding the secret key.
// This method is idempotent and safe to call multiple times.
func (g *GuardedSecretKey) Destroy() {
	if g.key != nil {
		g.key.Destroy()
	}
}

// IsDestroyed reports whether the guarded key has been destroyed.
func (g *GuardedSecretKey) IsDestroyed() bool {
	return g.key == nil || g.key.IsDestroyed()
}

// Clone creates an independent deep copy of the guarded secret key in new
// guarded memory.
func (g *GuardedSecretKey) Clone() (k *GuardedSecretKey, err error) {
	defer func() {
		if r := recover(); r != nil {
			k = nil
			err = &GuardedKeyAllocationError{Operation: "guarded secret key clone failed", Err: fmt.Errorf("%v", r)}
		}
	}()

	if g.IsDestroyed() {
		return nil, &GuardedKeyDestroyedError{}
	}

	cloned, cloneErr := g.key.Clone()
	if cloneErr != nil {
		return nil, &GuardedKeyAllocationError{Operation: "guarded secret key clone failed", Err: cloneErr}
	}
	return &GuardedSecretKey{keyType: g.keyType, key: cloned}, nil
}

// GuardedSharedSecret holds a 32-byte KEM shared secret in memguard-protected
// memory. This is the output of encapsulation and decapsulation operations
// when using guarded KEM types.
type GuardedSharedSecret struct {
	inner *secret.Secret32
}

// NewGuardedSharedSecret creates a GuardedSharedSecret from a 32-byte array.
// The source array is zeroized after the data is moved into guarded memory.
func NewGuardedSharedSecret(data [32]byte) (ss *GuardedSharedSecret, err error) {
	defer func() {
		if r := recover(); r != nil {
			ss = nil
			err = &GuardedKeyAllocationError{Operation: "guarded shared secret allocation failed", Err: fmt.Errorf("%v", r)}
		}
	}()

	s, sErr := secret.NewSecret32(data)
	if sErr != nil {
		return nil, &GuardedKeyAllocationError{Operation: "guarded shared secret allocation failed", Err: sErr}
	}
	return &GuardedSharedSecret{inner: s}, nil
}

// NewGuardedSharedSecretFromSlice creates a GuardedSharedSecret from a byte
// slice that must be exactly 32 bytes. The source slice is zeroized by
// memguard.
func NewGuardedSharedSecretFromSlice(data []byte) (ss *GuardedSharedSecret, err error) {
	defer func() {
		if r := recover(); r != nil {
			ss = nil
			err = &GuardedKeyAllocationError{Operation: "guarded shared secret allocation failed", Err: fmt.Errorf("%v", r)}
		}
	}()

	s, sErr := secret.NewSecret32FromSlice(data)
	if sErr != nil {
		return nil, &GuardedKeyAllocationError{Operation: "guarded shared secret allocation failed", Err: sErr}
	}
	return &GuardedSharedSecret{inner: s}, nil
}

// NewGuardedSharedSecretFromSecret32 creates a GuardedSharedSecret by taking
// ownership of an existing Secret32. The caller must not use the Secret32
// after this call.
func NewGuardedSharedSecretFromSecret32(s *secret.Secret32) *GuardedSharedSecret {
	return &GuardedSharedSecret{inner: s}
}

// Bytes returns a view into the guarded memory holding the shared secret.
// The returned slice must not be retained beyond the lifetime of the
// GuardedSharedSecret.
//
// Panics if the shared secret has been destroyed.
func (g *GuardedSharedSecret) Bytes() []byte {
	return g.inner.Bytes()
}

// Array returns a copy of the shared secret as a fixed 32-byte array.
// The caller is responsible for zeroizing the returned array when done.
//
// Panics if the shared secret has been destroyed.
func (g *GuardedSharedSecret) Array() [32]byte {
	return g.inner.Array()
}

// Destroy zeroizes and frees the guarded memory holding the shared secret.
// This method is idempotent and safe to call multiple times.
func (g *GuardedSharedSecret) Destroy() {
	if g.inner != nil {
		g.inner.Destroy()
	}
}

// IsDestroyed reports whether the guarded shared secret has been destroyed.
func (g *GuardedSharedSecret) IsDestroyed() bool {
	return g.inner == nil || g.inner.IsDestroyed()
}

// Secret32 returns the underlying Secret32 for direct access to guarded
// memory operations. The caller must not destroy the returned Secret32
// unless they are finished with the GuardedSharedSecret.
func (g *GuardedSharedSecret) Secret32() *secret.Secret32 {
	return g.inner
}

// GuardedKeyPair holds a KEM public key and a memguard-protected secret key.
type GuardedKeyPair struct {
	Public *PublicKey
	Secret *GuardedSecretKey
}

// Destroy zeroizes the guarded secret key. The public key is not sensitive
// and does not need destruction.
func (g *GuardedKeyPair) Destroy() {
	if g.Secret != nil {
		g.Secret.Destroy()
	}
}
