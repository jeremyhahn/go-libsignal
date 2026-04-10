package kem

import (
	"github.com/cloudflare/circl/kem/kyber/kyber768"

	crypto "github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
)

var kyber768Scheme = kyber768.Scheme()

// MLKEM768KEM implements the KEM interface using round-3 Kyber-768.
// Despite the type name, this uses Kyber-768 (not NIST-final ML-KEM-768)
// to match the Rust reference implementation (libcrux_ml_kem::kyber768).
type MLKEM768KEM struct{}

// NewMLKEM768KEM returns a new MLKEM768KEM instance.
func NewMLKEM768KEM() *MLKEM768KEM {
	return &MLKEM768KEM{}
}

// KeyType returns KeyTypeKyber768.
func (k *MLKEM768KEM) KeyType() KeyType {
	return KeyTypeKyber768
}

// Generate creates a new Kyber-768 key pair.
func (k *MLKEM768KEM) Generate() (*KeyPair, error) {
	pk, sk, err := kyber768Scheme.GenerateKeyPair()
	if err != nil {
		return nil, &KeyGenError{Algorithm: "kyber768", Err: err}
	}

	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, &MarshalError{Algorithm: "kyber768", KeyKind: "public", Err: err}
	}

	skBytes, err := sk.MarshalBinary()
	if err != nil {
		return nil, &MarshalError{Algorithm: "kyber768", KeyKind: "secret", Err: err}
	}
	defer crypto.Zeroize(skBytes)

	secretKey, skErr := NewSecretKey(KeyTypeKyber768, skBytes)
	if skErr != nil {
		return nil, skErr
	}

	return &KeyPair{
		Public: NewPublicKey(KeyTypeKyber768, pkBytes),
		Secret: secretKey,
	}, nil
}

// Encapsulate generates a shared secret and ciphertext for the given public key.
func (k *MLKEM768KEM) Encapsulate(publicKey *PublicKey) (*SharedSecret, *Ciphertext, error) {
	if publicKey.Type() != KeyTypeKyber768 {
		return nil, nil, &KeyTypeMismatchError{Expected: "Kyber768", Actual: publicKey.Type()}
	}

	pk, err := kyber768Scheme.UnmarshalBinaryPublicKey(publicKey.Data())
	if err != nil {
		return nil, nil, &UnmarshalError{Algorithm: "kyber768", KeyKind: "public", Err: err}
	}

	ct, ssBytes, err := kyber768Scheme.Encapsulate(pk)
	if err != nil {
		return nil, nil, &EncapsulationError{Algorithm: "kyber768", Err: err}
	}
	defer crypto.Zeroize(ssBytes)

	var ss SharedSecret
	copy(ss[:], ssBytes)

	return &ss, NewCiphertext(KeyTypeKyber768, ct), nil
}

// Decapsulate recovers the shared secret from the given ciphertext using the secret key.
func (k *MLKEM768KEM) Decapsulate(secretKey *SecretKey, ciphertext *Ciphertext) (*SharedSecret, error) {
	if secretKey.Type() != KeyTypeKyber768 {
		return nil, &KeyTypeMismatchError{Expected: "Kyber768", Actual: secretKey.Type(), KeyKind: "secret key"}
	}
	if ciphertext.Type() != KeyTypeKyber768 {
		return nil, &KeyTypeMismatchError{Expected: "Kyber768", Actual: ciphertext.Type(), KeyKind: "ciphertext"}
	}

	sk, err := kyber768Scheme.UnmarshalBinaryPrivateKey(secretKey.Data())
	if err != nil {
		return nil, &UnmarshalError{Algorithm: "kyber768", KeyKind: "secret", Err: err}
	}

	ssBytes, err := kyber768Scheme.Decapsulate(sk, ciphertext.Data())
	if err != nil {
		return nil, &DecapsulationError{Algorithm: "kyber768", Err: err}
	}
	defer crypto.Zeroize(ssBytes)

	var ss SharedSecret
	copy(ss[:], ssBytes)

	return &ss, nil
}
