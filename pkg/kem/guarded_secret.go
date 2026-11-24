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

// GuardedSecretKey holds a KEM secret key in locked memory, zeroized on destruction.
type GuardedSecretKey struct {
	keyType KeyType
	key     *secret.Secret
}

// NewGuardedSecretKey creates a GuardedSecretKey from the given key type and
// raw key data. The source slice is zeroized by go-enclave as part of the move
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

// NewGuardedSecretKeyFromSecret takes ownership of a Secret as a KEM key, validating it as NewSecretKey does; the Secret is destroyed on failure.
func NewGuardedSecretKeyFromSecret(keyType KeyType, s *secret.Secret) (*GuardedSecretKey, error) {
	if err := validateSecretKeyMaterial(keyType, guardedLen(s)); err != nil {
		s.Destroy()
		return nil, err
	}
	return &GuardedSecretKey{keyType: keyType, key: s}, nil
}

// validateSecretKeyMaterial reports whether the given key type is supported by
// this library and whether size matches the secret key size for it.
func validateSecretKeyMaterial(keyType KeyType, size int) error {
	if keyType == KeyTypeKyber768 {
		return ErrKeyTypeKyber768Unsupported
	}
	if !validKeyType(keyType) {
		return &BadKEMKeyTypeError{Value: byte(keyType)}
	}
	if expected := expectedSecretKeySize(keyType); size != expected {
		return &BadKeyLengthError{KeyType: keyType, Expected: expected, Actual: size}
	}
	return nil
}

// Type returns the KEM algorithm identifier for this secret key.
func (g *GuardedSecretKey) Type() KeyType {
	return g.keyType
}

// Data returns a copy of the key material that the caller should zeroize; it panics if the key was destroyed.
func (g *GuardedSecretKey) Data() []byte {
	return copyGuarded(g.key)
}

// guardedLen reports the length of s's material, or 0 for a nil or
// destroyed secret.
func guardedLen(s *secret.Secret) int {
	if s.IsDestroyed() {
		return 0
	}
	return s.Size()
}

// copyGuarded copies s's bytes inside its enclave borrow, for the accessors
// whose value must leave the borrow. It panics if s has been destroyed.
func copyGuarded(s interface {
	WithBytes(func([]byte) error) error
}) []byte {
	var out []byte
	if err := s.WithBytes(func(b []byte) error {
		out = append([]byte(nil), b...)
		return nil
	}); err != nil {
		panic("kem: attempt to access destroyed secret")
	}
	return out
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

// CloneSecret returns a guarded copy of the key material that the caller must destroy.
func (g *GuardedSecretKey) CloneSecret() (*secret.Secret, error) {
	if g.IsDestroyed() {
		return nil, &GuardedKeyDestroyedError{}
	}
	cloned, err := g.key.Clone()
	if err != nil {
		return nil, &GuardedKeyAllocationError{Operation: "guarded secret key clone failed", Err: err}
	}
	return cloned, nil
}

// GuardedSharedSecret holds a 32-byte KEM shared secret in locked
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
// go-enclave.
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

// Bytes returns a copy of the shared secret that the caller should zeroize; it panics if destroyed.
func (g *GuardedSharedSecret) Bytes() []byte {
	return copyGuarded(g.inner)
}

// Array returns a copy of the shared secret that the caller should zeroize; it panics if destroyed.
func (g *GuardedSharedSecret) Array() [32]byte {
	var out [32]byte
	if err := g.inner.WithBytes(func(b []byte) error {
		copy(out[:], b)
		return nil
	}); err != nil {
		panic("kem: attempt to access destroyed secret")
	}
	return out
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

// GuardedKeyPair holds a KEM public key and a locked-memory-protected secret key.
type GuardedKeyPair struct {
	Public *PublicKey
	Secret *GuardedSecretKey
}

// GuardedFromPublicAndPrivate builds a GuardedKeyPair from a public key and raw secret key of the same algorithm, zeroizing secretData.
func GuardedFromPublicAndPrivate(publicSerialized []byte, secretData []byte) (*GuardedKeyPair, error) {
	pk, err := DeserializePublicKey(publicSerialized)
	if err != nil {
		// The contract is that secretData does not survive this call, whether
		// or not the move into guarded memory is reached.
		zeroizeSlice(secretData)
		return nil, err
	}
	sk, err := NewGuardedSecretKey(pk.Type(), secretData)
	if err != nil {
		return nil, err
	}
	if err := validateSecretKeyMaterial(pk.Type(), sk.key.Size()); err != nil {
		sk.Destroy()
		return nil, err
	}
	return &GuardedKeyPair{Public: pk, Secret: sk}, nil
}

// Destroy zeroizes the guarded secret key. The public key is not sensitive
// and does not need destruction.
func (g *GuardedKeyPair) Destroy() {
	if g.Secret != nil {
		g.Secret.Destroy()
	}
}
