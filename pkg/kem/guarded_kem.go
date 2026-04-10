package kem

import (
	"fmt"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/jeremyhahn/go-libsignal/pkg/crypto/keyops"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// Compile-time interface assertion.
var _ keyops.Decapsulator = (*GuardedSecretKey)(nil)

var guardedKyber768Scheme = kyber768.Scheme()
var guardedKyber1024Scheme = kyber1024.Scheme()

// GuardedKyber768 implements Kyber-768 KEM operations with key material
// stored in memguard-protected memory. Generated secret keys and shared
// secrets are wrapped in GuardedSecretKey and GuardedSharedSecret types
// that use mlock'd, guard-page protected memory.
type GuardedKyber768 struct{}

// NewGuardedKyber768 returns a new GuardedKyber768 instance.
func NewGuardedKyber768() *GuardedKyber768 {
	return &GuardedKyber768{}
}

// Generate creates a new Kyber-768 key pair with the secret key stored
// in memguard-protected memory.
func (g *GuardedKyber768) Generate() (kp *GuardedKeyPair, err error) {
	defer func() {
		if r := recover(); r != nil {
			kp = nil
			err = &GuardedKeyAllocationError{Operation: "guarded kyber768 key generation failed", Err: fmt.Errorf("%v", r)}
		}
	}()

	pk, sk, genErr := guardedKyber768Scheme.GenerateKeyPair()
	if genErr != nil {
		return nil, &KeyGenError{Algorithm: "kyber768", Err: genErr}
	}

	pkBytes, marshalErr := pk.MarshalBinary()
	if marshalErr != nil {
		return nil, &MarshalError{Algorithm: "kyber768", KeyKind: "public", Err: marshalErr}
	}

	skBytes, marshalErr := sk.MarshalBinary()
	if marshalErr != nil {
		return nil, &MarshalError{Algorithm: "kyber768", KeyKind: "secret", Err: marshalErr}
	}

	// Move secret key bytes into guarded memory (zeroizes skBytes).
	guardedSK, allocErr := NewGuardedSecretKey(KeyTypeKyber768, skBytes)
	if allocErr != nil {
		zeroizeSlice(skBytes)
		return nil, &GuardedKeyAllocationError{Operation: "guarded kyber768 key generation failed", Err: allocErr}
	}

	return &GuardedKeyPair{
		Public: NewPublicKey(KeyTypeKyber768, pkBytes),
		Secret: guardedSK,
	}, nil
}

// Encapsulate generates a shared secret and ciphertext for the given public
// key. The shared secret is returned in a GuardedSharedSecret backed by
// memguard-protected memory.
func (g *GuardedKyber768) Encapsulate(publicKey *PublicKey) (ss *GuardedSharedSecret, ct *Ciphertext, err error) {
	defer func() {
		if r := recover(); r != nil {
			ss = nil
			ct = nil
			err = &GuardedKeyAllocationError{Operation: "guarded kyber768 encapsulation failed", Err: fmt.Errorf("%v", r)}
		}
	}()

	if publicKey.Type() != KeyTypeKyber768 {
		return nil, nil, &KeyTypeMismatchError{Expected: "Kyber768", Actual: publicKey.Type()}
	}

	pk, unmarshalErr := guardedKyber768Scheme.UnmarshalBinaryPublicKey(publicKey.Data())
	if unmarshalErr != nil {
		return nil, nil, &UnmarshalError{Algorithm: "kyber768", KeyKind: "public", Err: unmarshalErr}
	}

	ctBytes, ssBytes, encapErr := guardedKyber768Scheme.Encapsulate(pk)
	if encapErr != nil {
		return nil, nil, &EncapsulationError{Algorithm: "kyber768", Err: encapErr}
	}

	// Move shared secret into guarded memory (zeroizes ssBytes).
	guardedSS, allocErr := NewGuardedSharedSecretFromSlice(ssBytes)
	if allocErr != nil {
		zeroizeSlice(ssBytes)
		return nil, nil, &GuardedKeyAllocationError{Operation: "guarded kyber768 encapsulation failed", Err: allocErr}
	}

	return guardedSS, NewCiphertext(KeyTypeKyber768, ctBytes), nil
}

// Decapsulate recovers the shared secret from the given ciphertext using the
// guarded secret key. The shared secret is returned in a GuardedSharedSecret
// backed by memguard-protected memory.
func (g *GuardedKyber768) Decapsulate(secretKey *GuardedSecretKey, ciphertext *Ciphertext) (ss *GuardedSharedSecret, err error) {
	defer func() {
		if r := recover(); r != nil {
			ss = nil
			err = &GuardedKeyAllocationError{Operation: "guarded kyber768 decapsulation failed", Err: fmt.Errorf("%v", r)}
		}
	}()

	if secretKey.IsDestroyed() {
		return nil, &GuardedKeyDestroyedError{}
	}
	if secretKey.Type() != KeyTypeKyber768 {
		return nil, &KeyTypeMismatchError{Expected: "Kyber768", Actual: secretKey.Type(), KeyKind: "secret key"}
	}
	if ciphertext.Type() != KeyTypeKyber768 {
		return nil, &KeyTypeMismatchError{Expected: "Kyber768", Actual: ciphertext.Type(), KeyKind: "ciphertext"}
	}

	// Use the view into guarded memory for unmarshaling (no copy needed).
	sk, unmarshalErr := guardedKyber768Scheme.UnmarshalBinaryPrivateKey(secretKey.Data())
	if unmarshalErr != nil {
		return nil, &UnmarshalError{Algorithm: "kyber768", KeyKind: "secret", Err: unmarshalErr}
	}

	ssBytes, decapErr := guardedKyber768Scheme.Decapsulate(sk, ciphertext.Data())
	if decapErr != nil {
		return nil, &DecapsulationError{Algorithm: "kyber768", Err: decapErr}
	}

	// Move shared secret into guarded memory (zeroizes ssBytes).
	guardedSS, allocErr := NewGuardedSharedSecretFromSlice(ssBytes)
	if allocErr != nil {
		zeroizeSlice(ssBytes)
		return nil, &GuardedKeyAllocationError{Operation: "guarded kyber768 decapsulation failed", Err: allocErr}
	}

	return guardedSS, nil
}

// GuardedKyber1024 implements Kyber-1024 KEM operations with key material
// stored in memguard-protected memory. Generated secret keys and shared
// secrets are wrapped in GuardedSecretKey and GuardedSharedSecret types
// that use mlock'd, guard-page protected memory.
type GuardedKyber1024 struct{}

// NewGuardedKyber1024 returns a new GuardedKyber1024 instance.
func NewGuardedKyber1024() *GuardedKyber1024 {
	return &GuardedKyber1024{}
}

// Generate creates a new Kyber-1024 key pair with the secret key stored
// in memguard-protected memory.
func (g *GuardedKyber1024) Generate() (kp *GuardedKeyPair, err error) {
	defer func() {
		if r := recover(); r != nil {
			kp = nil
			err = &GuardedKeyAllocationError{Operation: "guarded kyber1024 key generation failed", Err: fmt.Errorf("%v", r)}
		}
	}()

	pk, sk, genErr := guardedKyber1024Scheme.GenerateKeyPair()
	if genErr != nil {
		return nil, &KeyGenError{Algorithm: "kyber1024", Err: genErr}
	}

	pkBytes, marshalErr := pk.MarshalBinary()
	if marshalErr != nil {
		return nil, &MarshalError{Algorithm: "kyber1024", KeyKind: "public", Err: marshalErr}
	}

	skBytes, marshalErr := sk.MarshalBinary()
	if marshalErr != nil {
		return nil, &MarshalError{Algorithm: "kyber1024", KeyKind: "secret", Err: marshalErr}
	}

	// Move secret key bytes into guarded memory (zeroizes skBytes).
	guardedSK, allocErr := NewGuardedSecretKey(KeyTypeKyber1024, skBytes)
	if allocErr != nil {
		zeroizeSlice(skBytes)
		return nil, &GuardedKeyAllocationError{Operation: "guarded kyber1024 key generation failed", Err: allocErr}
	}

	return &GuardedKeyPair{
		Public: NewPublicKey(KeyTypeKyber1024, pkBytes),
		Secret: guardedSK,
	}, nil
}

// Encapsulate generates a shared secret and ciphertext for the given public
// key. The shared secret is returned in a GuardedSharedSecret backed by
// memguard-protected memory.
func (g *GuardedKyber1024) Encapsulate(publicKey *PublicKey) (ss *GuardedSharedSecret, ct *Ciphertext, err error) {
	defer func() {
		if r := recover(); r != nil {
			ss = nil
			ct = nil
			err = &GuardedKeyAllocationError{Operation: "guarded kyber1024 encapsulation failed", Err: fmt.Errorf("%v", r)}
		}
	}()

	if publicKey.Type() != KeyTypeKyber1024 {
		return nil, nil, &KeyTypeMismatchError{Expected: "Kyber1024", Actual: publicKey.Type()}
	}

	pk, unmarshalErr := guardedKyber1024Scheme.UnmarshalBinaryPublicKey(publicKey.Data())
	if unmarshalErr != nil {
		return nil, nil, &UnmarshalError{Algorithm: "kyber1024", KeyKind: "public", Err: unmarshalErr}
	}

	ctBytes, ssBytes, encapErr := guardedKyber1024Scheme.Encapsulate(pk)
	if encapErr != nil {
		return nil, nil, &EncapsulationError{Algorithm: "kyber1024", Err: encapErr}
	}

	// Move shared secret into guarded memory (zeroizes ssBytes).
	guardedSS, allocErr := NewGuardedSharedSecretFromSlice(ssBytes)
	if allocErr != nil {
		zeroizeSlice(ssBytes)
		return nil, nil, &GuardedKeyAllocationError{Operation: "guarded kyber1024 encapsulation failed", Err: allocErr}
	}

	return guardedSS, NewCiphertext(KeyTypeKyber1024, ctBytes), nil
}

// Decapsulate recovers the shared secret from the given ciphertext using the
// guarded secret key. The shared secret is returned in a GuardedSharedSecret
// backed by memguard-protected memory.
func (g *GuardedKyber1024) Decapsulate(secretKey *GuardedSecretKey, ciphertext *Ciphertext) (ss *GuardedSharedSecret, err error) {
	defer func() {
		if r := recover(); r != nil {
			ss = nil
			err = &GuardedKeyAllocationError{Operation: "guarded kyber1024 decapsulation failed", Err: fmt.Errorf("%v", r)}
		}
	}()

	if secretKey.IsDestroyed() {
		return nil, &GuardedKeyDestroyedError{}
	}
	if secretKey.Type() != KeyTypeKyber1024 {
		return nil, &KeyTypeMismatchError{Expected: "Kyber1024", Actual: secretKey.Type(), KeyKind: "secret key"}
	}
	if ciphertext.Type() != KeyTypeKyber1024 {
		return nil, &KeyTypeMismatchError{Expected: "Kyber1024", Actual: ciphertext.Type(), KeyKind: "ciphertext"}
	}

	// Use the view into guarded memory for unmarshaling (no copy needed).
	sk, unmarshalErr := guardedKyber1024Scheme.UnmarshalBinaryPrivateKey(secretKey.Data())
	if unmarshalErr != nil {
		return nil, &UnmarshalError{Algorithm: "kyber1024", KeyKind: "secret", Err: unmarshalErr}
	}

	ssBytes, decapErr := guardedKyber1024Scheme.Decapsulate(sk, ciphertext.Data())
	if decapErr != nil {
		return nil, &DecapsulationError{Algorithm: "kyber1024", Err: decapErr}
	}

	// Move shared secret into guarded memory (zeroizes ssBytes).
	guardedSS, allocErr := NewGuardedSharedSecretFromSlice(ssBytes)
	if allocErr != nil {
		zeroizeSlice(ssBytes)
		return nil, &GuardedKeyAllocationError{Operation: "guarded kyber1024 decapsulation failed", Err: allocErr}
	}

	return guardedSS, nil
}

// Decapsulate recovers the shared secret from the given serialized ciphertext
// using the guarded secret key. Returns the shared secret in a guarded Secret32.
//
// Implements keyops.Decapsulator.
func (g *GuardedSecretKey) Decapsulate(ciphertext []byte) (ss *secret.Secret32, err error) {
	guardedSS, decapErr := g.DecapsulateGuarded(ciphertext)
	if decapErr != nil {
		return nil, decapErr
	}
	return guardedSS.Secret32(), nil
}

// DecapsulateGuarded performs decapsulation and returns the shared secret
// wrapped in a GuardedSharedSecret for callers that want the richer type.
func (g *GuardedSecretKey) DecapsulateGuarded(ciphertext []byte) (ss *GuardedSharedSecret, err error) {
	defer func() {
		if r := recover(); r != nil {
			ss = nil
			err = &GuardedKeyAllocationError{Operation: "guarded decapsulation failed", Err: fmt.Errorf("%v", r)}
		}
	}()

	if g.IsDestroyed() {
		return nil, &GuardedKeyDestroyedError{}
	}

	ct, deserErr := DeserializeCiphertext(ciphertext)
	if deserErr != nil {
		return nil, &DeserializeError{Err: deserErr}
	}

	switch g.keyType {
	case KeyTypeKyber768:
		return NewGuardedKyber768().Decapsulate(g, ct)
	case KeyTypeKyber1024:
		return NewGuardedKyber1024().Decapsulate(g, ct)
	default:
		return nil, &UnsupportedKeyTypeError{KeyType: g.keyType}
	}
}

// zeroizeSlice overwrites a byte slice with zeros.
func zeroizeSlice(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
