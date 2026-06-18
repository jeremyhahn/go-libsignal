package kem

import (
	"crypto/mlkem"

	crypto "github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
)

// MLKEM768KEM implements the KEM interface using NIST ML-KEM-768 (FIPS 203).
// It uses Go's standard library crypto/mlkem package for a standards-conformant
// implementation.
//
// Rust source: libsignal/rust/protocol/src/kem.rs — mlkem768 feature
// (libcrux_ml_kem::mlkem768).
type MLKEM768KEM struct{}

// NewMLKEM768KEM returns a new MLKEM768KEM instance.
func NewMLKEM768KEM() *MLKEM768KEM {
	return &MLKEM768KEM{}
}

// KeyType returns KeyTypeMLKEM768.
func (k *MLKEM768KEM) KeyType() KeyType {
	return KeyTypeMLKEM768
}

// Generate creates a new ML-KEM-768 key pair. The secret key is stored as
// the 64-byte seed defined in NIST FIPS 203; the public key is the 1184-byte
// encapsulation key.
func (k *MLKEM768KEM) Generate() (*KeyPair, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, &KeyGenError{Algorithm: "mlkem768", Err: err}
	}

	// Seed bytes are the canonical secret key representation (64 bytes).
	seedBytes := dk.Bytes()
	defer crypto.Zeroize(seedBytes)

	ekBytes := dk.EncapsulationKey().Bytes()

	secretKey, skErr := NewSecretKey(KeyTypeMLKEM768, seedBytes)
	if skErr != nil {
		return nil, skErr
	}

	return &KeyPair{
		Public: NewPublicKey(KeyTypeMLKEM768, ekBytes),
		Secret: secretKey,
	}, nil
}

// Encapsulate generates a shared secret and ciphertext for the given public key.
// The public key must be of type KeyTypeMLKEM768.
func (k *MLKEM768KEM) Encapsulate(publicKey *PublicKey) (*SharedSecret, *Ciphertext, error) {
	if publicKey.Type() != KeyTypeMLKEM768 {
		return nil, nil, &KeyTypeMismatchError{Expected: KeyTypeMLKEM768, Actual: publicKey.Type()}
	}

	ek, err := mlkem.NewEncapsulationKey768(publicKey.Data())
	if err != nil {
		return nil, nil, &UnmarshalError{Algorithm: "mlkem768", KeyKind: "public", Err: err}
	}

	// Encapsulate returns (sharedKey, ciphertext) per crypto/mlkem API.
	ssBytes, ctBytes := ek.Encapsulate()
	defer crypto.Zeroize(ssBytes)

	var ss SharedSecret
	copy(ss[:], ssBytes)

	return &ss, NewCiphertext(KeyTypeMLKEM768, ctBytes), nil
}

// Decapsulate recovers the shared secret from the given ciphertext using the
// secret key. Both the secret key and ciphertext must be of type KeyTypeMLKEM768.
func (k *MLKEM768KEM) Decapsulate(secretKey *SecretKey, ciphertext *Ciphertext) (*SharedSecret, error) {
	if secretKey.Type() != KeyTypeMLKEM768 {
		return nil, &KeyTypeMismatchError{Expected: KeyTypeMLKEM768, Actual: secretKey.Type(), KeyKind: "secret key"}
	}
	if ciphertext.Type() != KeyTypeMLKEM768 {
		return nil, &KeyTypeMismatchError{Expected: KeyTypeMLKEM768, Actual: ciphertext.Type(), KeyKind: "ciphertext"}
	}

	// Reconstruct the decapsulation key from the 64-byte seed.
	seedBytes := secretKey.Data()
	defer crypto.Zeroize(seedBytes)

	dk, err := mlkem.NewDecapsulationKey768(seedBytes)
	if err != nil {
		return nil, &UnmarshalError{Algorithm: "mlkem768", KeyKind: "secret", Err: err}
	}

	ssBytes, err := dk.Decapsulate(ciphertext.Data())
	if err != nil {
		return nil, &DecapsulationError{Algorithm: "mlkem768", Err: err}
	}
	defer crypto.Zeroize(ssBytes)

	var ss SharedSecret
	copy(ss[:], ssBytes)

	return &ss, nil
}
