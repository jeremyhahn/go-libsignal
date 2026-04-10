package kem

import (
	"crypto/mlkem"

	crypto "github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
)

// MLKEM1024KEM implements the KEM interface using NIST ML-KEM-1024 (FIPS 203).
// It uses Go's standard library crypto/mlkem package for a standards-conformant
// implementation distinct from the round-3 Kyber-1024 provided by circl.
type MLKEM1024KEM struct{}

// NewMLKEM1024KEM returns a new MLKEM1024KEM instance.
func NewMLKEM1024KEM() *MLKEM1024KEM {
	return &MLKEM1024KEM{}
}

// KeyType returns KeyTypeMLKEM1024.
func (k *MLKEM1024KEM) KeyType() KeyType {
	return KeyTypeMLKEM1024
}

// Generate creates a new ML-KEM-1024 key pair. The secret key is stored as
// the 64-byte seed defined in NIST FIPS 203; the public key is the 1568-byte
// encapsulation key.
func (k *MLKEM1024KEM) Generate() (*KeyPair, error) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, &KeyGenError{Algorithm: "mlkem1024", Err: err}
	}

	// Seed bytes are the canonical secret key representation (64 bytes).
	seedBytes := dk.Bytes()
	defer crypto.Zeroize(seedBytes)

	ekBytes := dk.EncapsulationKey().Bytes()

	secretKey, skErr := NewSecretKey(KeyTypeMLKEM1024, seedBytes)
	if skErr != nil {
		return nil, skErr
	}

	return &KeyPair{
		Public: NewPublicKey(KeyTypeMLKEM1024, ekBytes),
		Secret: secretKey,
	}, nil
}

// Encapsulate generates a shared secret and ciphertext for the given public key.
// The public key must be of type KeyTypeMLKEM1024.
func (k *MLKEM1024KEM) Encapsulate(publicKey *PublicKey) (*SharedSecret, *Ciphertext, error) {
	if publicKey.Type() != KeyTypeMLKEM1024 {
		return nil, nil, &KeyTypeMismatchError{Expected: "MLKEM1024", Actual: publicKey.Type()}
	}

	ek, err := mlkem.NewEncapsulationKey1024(publicKey.Data())
	if err != nil {
		return nil, nil, &UnmarshalError{Algorithm: "mlkem1024", KeyKind: "public", Err: err}
	}

	// Encapsulate returns (sharedKey, ciphertext) per crypto/mlkem API.
	ssBytes, ctBytes := ek.Encapsulate()
	defer crypto.Zeroize(ssBytes)

	var ss SharedSecret
	copy(ss[:], ssBytes)

	return &ss, NewCiphertext(KeyTypeMLKEM1024, ctBytes), nil
}

// Decapsulate recovers the shared secret from the given ciphertext using the
// secret key. Both the secret key and ciphertext must be of type KeyTypeMLKEM1024.
func (k *MLKEM1024KEM) Decapsulate(secretKey *SecretKey, ciphertext *Ciphertext) (*SharedSecret, error) {
	if secretKey.Type() != KeyTypeMLKEM1024 {
		return nil, &KeyTypeMismatchError{Expected: "MLKEM1024", Actual: secretKey.Type(), KeyKind: "secret key"}
	}
	if ciphertext.Type() != KeyTypeMLKEM1024 {
		return nil, &KeyTypeMismatchError{Expected: "MLKEM1024", Actual: ciphertext.Type(), KeyKind: "ciphertext"}
	}

	// Reconstruct the decapsulation key from the 64-byte seed.
	seedBytes := secretKey.Data()
	defer crypto.Zeroize(seedBytes)

	dk, err := mlkem.NewDecapsulationKey1024(seedBytes)
	if err != nil {
		return nil, &UnmarshalError{Algorithm: "mlkem1024", KeyKind: "secret", Err: err}
	}

	ssBytes, err := dk.Decapsulate(ciphertext.Data())
	if err != nil {
		return nil, &DecapsulationError{Algorithm: "mlkem1024", Err: err}
	}
	defer crypto.Zeroize(ssBytes)

	var ss SharedSecret
	copy(ss[:], ssBytes)

	return &ss, nil
}
