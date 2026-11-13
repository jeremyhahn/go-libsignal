package kem

import (
	"github.com/cloudflare/circl/kem/kyber/kyber1024"

	crypto "github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
)

var kyber1024Scheme = kyber1024.Scheme()

// Kyber1024KEM implements the KEM interface using Kyber-1024.
type Kyber1024KEM struct{}

// NewKyber1024KEM returns a new Kyber1024KEM instance.
func NewKyber1024KEM() *Kyber1024KEM {
	return &Kyber1024KEM{}
}

// KeyType returns KeyTypeKyber1024.
func (k *Kyber1024KEM) KeyType() KeyType {
	return KeyTypeKyber1024
}

// Generate creates a new Kyber-1024 key pair.
func (k *Kyber1024KEM) Generate() (*KeyPair, error) {
	pk, sk, err := kyber1024Scheme.GenerateKeyPair()
	if err != nil {
		return nil, &KeyGenError{Algorithm: "kyber1024", Err: err}
	}

	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, &MarshalError{Algorithm: "kyber1024", KeyKind: "public", Err: err}
	}

	skBytes, err := sk.MarshalBinary()
	if err != nil {
		return nil, &MarshalError{Algorithm: "kyber1024", KeyKind: "secret", Err: err}
	}
	defer crypto.Zeroize(skBytes)

	secretKey, skErr := NewSecretKey(KeyTypeKyber1024, skBytes)
	if skErr != nil {
		return nil, skErr
	}

	return &KeyPair{
		Public: NewPublicKey(KeyTypeKyber1024, pkBytes),
		Secret: secretKey,
	}, nil
}

// Encapsulate generates a shared secret and ciphertext for the given public key.
func (k *Kyber1024KEM) Encapsulate(publicKey *PublicKey) (*SharedSecret, *Ciphertext, error) {
	if publicKey.Type() != KeyTypeKyber1024 {
		return nil, nil, &KeyTypeMismatchError{Expected: KeyTypeKyber1024, Actual: publicKey.Type()}
	}

	pk, err := kyber1024Scheme.UnmarshalBinaryPublicKey(publicKey.Data())
	if err != nil {
		return nil, nil, &UnmarshalError{Algorithm: "kyber1024", KeyKind: "public", Err: err}
	}

	ct, ssBytes, err := kyber1024Scheme.Encapsulate(pk)
	if err != nil {
		return nil, nil, &EncapsulationError{Algorithm: "kyber1024", Err: err}
	}
	defer crypto.Zeroize(ssBytes)

	var ss SharedSecret
	copy(ss[:], ssBytes)

	return &ss, NewCiphertext(KeyTypeKyber1024, ct), nil
}

// Decapsulate recovers the shared secret from the given ciphertext using the secret key.
func (k *Kyber1024KEM) Decapsulate(secretKey *SecretKey, ciphertext *Ciphertext) (*SharedSecret, error) {
	if secretKey.Type() != KeyTypeKyber1024 {
		return nil, &KeyTypeMismatchError{Expected: KeyTypeKyber1024, Actual: secretKey.Type(), KeyKind: "secret key"}
	}
	if ciphertext.Type() != KeyTypeKyber1024 {
		return nil, &KeyTypeMismatchError{Expected: KeyTypeKyber1024, Actual: ciphertext.Type(), KeyKind: "ciphertext"}
	}

	// Data returns an owned copy; wipe it once the scheme has parsed it.
	skBytes := secretKey.Data()
	sk, err := kyber1024Scheme.UnmarshalBinaryPrivateKey(skBytes)
	crypto.Zeroize(skBytes)
	if err != nil {
		return nil, &UnmarshalError{Algorithm: "kyber1024", KeyKind: "secret", Err: err}
	}

	ssBytes, err := kyber1024Scheme.Decapsulate(sk, ciphertext.Data())
	if err != nil {
		return nil, &DecapsulationError{Algorithm: "kyber1024", Err: err}
	}
	defer crypto.Zeroize(ssBytes)

	var ss SharedSecret
	copy(ss[:], ssBytes)

	return &ss, nil
}
