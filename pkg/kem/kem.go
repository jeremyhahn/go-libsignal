// Package kem provides a Key Encapsulation Mechanism abstraction for
// post-quantum key exchange in the Signal protocol.
package kem

import (
	"fmt"

	crypto "github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
)

// KeyType identifies the KEM algorithm.
type KeyType byte

const (
	// KeyTypeKyber768 identifies the Kyber-768 KEM algorithm.
	KeyTypeKyber768 KeyType = 0x07
	// KeyTypeKyber1024 identifies the Kyber-1024 KEM algorithm.
	KeyTypeKyber1024 KeyType = 0x08
	// KeyTypeMLKEM1024 identifies the ML-KEM-1024 KEM algorithm.
	KeyTypeMLKEM1024 KeyType = 0x0A
)

// ErrInvalidKeyTypeError is the typed error for an unrecognized key type byte.
type ErrInvalidKeyTypeError struct{}

func (e *ErrInvalidKeyTypeError) Error() string {
	return "kem: invalid key type"
}

// ErrEmptyInputError is the typed error for empty or too-short input.
type ErrEmptyInputError struct{}

func (e *ErrEmptyInputError) Error() string {
	return "kem: input is empty or too short"
}

// ErrKeyTypeMismatchError is the typed error for mismatched key types.
type ErrKeyTypeMismatchError struct{}

func (e *ErrKeyTypeMismatchError) Error() string {
	return "kem: key type mismatch"
}

// Sentinel errors for backward-compatible errors.Is matching.
var (
	// ErrInvalidKeyType is returned when a key type byte is not recognized.
	ErrInvalidKeyType error = &ErrInvalidKeyTypeError{}
	// ErrEmptyInput is returned when the input is empty or too short.
	ErrEmptyInput error = &ErrEmptyInputError{}
	// ErrKeyTypeMismatch is returned when key types do not match the expected algorithm.
	ErrKeyTypeMismatch error = &ErrKeyTypeMismatchError{}
)

// UnsupportedKeyTypeError indicates that a KEM operation was attempted with
// a key type that is not supported by the given operation.
type UnsupportedKeyTypeError struct {
	KeyType KeyType
}

// Error returns a human-readable description of the unsupported key type.
func (e *UnsupportedKeyTypeError) Error() string {
	return fmt.Sprintf("kem: unsupported key type: 0x%02x", e.KeyType)
}

// BadKeyLengthError indicates that a serialized key or ciphertext has the
// wrong length for its algorithm.
type BadKeyLengthError struct {
	KeyType  KeyType
	Expected int
	Actual   int
}

// Error returns a human-readable description of the length mismatch.
func (e *BadKeyLengthError) Error() string {
	return fmt.Sprintf("kem: bad key length for type 0x%02x: expected %d bytes, got %d", e.KeyType, e.Expected, e.Actual)
}

// expectedPublicKeySize returns the expected raw public key data size (without
// the type prefix byte) for the given algorithm.
func expectedPublicKeySize(kt KeyType) int {
	switch kt {
	case KeyTypeKyber768:
		return 1184
	case KeyTypeKyber1024:
		return 1568
	case KeyTypeMLKEM1024:
		return 1568 // NIST FIPS 203 ML-KEM-1024 encapsulation key
	default:
		return -1
	}
}

// expectedSecretKeySize returns the expected raw secret key data size for the
// given algorithm. Kyber-768 secret keys are 2400 bytes, Kyber-1024 secret
// keys are 3168 bytes, and ML-KEM-1024 secret keys are 64-byte seeds per
// NIST FIPS 203.
func expectedSecretKeySize(kt KeyType) int {
	switch kt {
	case KeyTypeKyber768:
		return 2400
	case KeyTypeKyber1024:
		return 3168
	case KeyTypeMLKEM1024:
		return 64 // NIST FIPS 203 seed-based decapsulation key
	default:
		return -1
	}
}

// expectedCiphertextSize returns the expected raw ciphertext data size (without
// the type prefix byte) for the given algorithm.
func expectedCiphertextSize(kt KeyType) int {
	switch kt {
	case KeyTypeKyber768:
		return 1088
	case KeyTypeKyber1024:
		return 1568
	case KeyTypeMLKEM1024:
		return 1568 // NIST FIPS 203 ML-KEM-1024 ciphertext
	default:
		return -1
	}
}

// validKeyType returns true if the given KeyType is a recognized algorithm.
func validKeyType(kt KeyType) bool {
	switch kt {
	case KeyTypeKyber768, KeyTypeKyber1024, KeyTypeMLKEM1024:
		return true
	default:
		return false
	}
}

// PublicKey is a KEM public key with a type prefix byte.
type PublicKey struct {
	keyType KeyType
	data    []byte // raw key material WITHOUT type prefix
}

// NewPublicKey creates a new PublicKey from the given key type and raw key data.
func NewPublicKey(keyType KeyType, data []byte) *PublicKey {
	buf := make([]byte, len(data))
	copy(buf, data)
	return &PublicKey{
		keyType: keyType,
		data:    buf,
	}
}

// DeserializePublicKey reconstructs a PublicKey from its serialized form.
// The first byte is the type prefix.
func DeserializePublicKey(serialized []byte) (*PublicKey, error) {
	if len(serialized) < 2 {
		return nil, ErrEmptyInput
	}
	kt := KeyType(serialized[0])
	if !validKeyType(kt) {
		return nil, ErrInvalidKeyType
	}
	dataLen := len(serialized) - 1
	expected := expectedPublicKeySize(kt)
	if dataLen != expected {
		return nil, &BadKeyLengthError{KeyType: kt, Expected: expected, Actual: dataLen}
	}
	data := make([]byte, dataLen)
	copy(data, serialized[1:])
	return &PublicKey{keyType: kt, data: data}, nil
}

// Type returns the key type of this public key.
func (k *PublicKey) Type() KeyType {
	return k.keyType
}

// Serialize returns the public key as [type_byte] || data.
func (k *PublicKey) Serialize() []byte {
	out := make([]byte, 1+len(k.data))
	out[0] = byte(k.keyType)
	copy(out[1:], k.data)
	return out
}

// Data returns the raw key material without the type prefix.
func (k *PublicKey) Data() []byte {
	buf := make([]byte, len(k.data))
	copy(buf, k.data)
	return buf
}

// SecretKey is a KEM secret/private key.
type SecretKey struct {
	keyType KeyType
	data    []byte
}

// NewSecretKey creates a new SecretKey from the given key type and raw key data.
// Returns an error if the key type is unrecognized or the data length does not
// match the expected size for the algorithm.
func NewSecretKey(keyType KeyType, data []byte) (*SecretKey, error) {
	if !validKeyType(keyType) {
		return nil, ErrInvalidKeyType
	}
	expected := expectedSecretKeySize(keyType)
	if len(data) != expected {
		return nil, &BadKeyLengthError{KeyType: keyType, Expected: expected, Actual: len(data)}
	}
	buf := make([]byte, len(data))
	copy(buf, data)
	return &SecretKey{
		keyType: keyType,
		data:    buf,
	}, nil
}

// Type returns the key type of this secret key.
func (k *SecretKey) Type() KeyType {
	return k.keyType
}

// Zeroize overwrites the secret key material with zeros to prevent
// sensitive data from lingering in memory.
func (k *SecretKey) Zeroize() {
	crypto.Zeroize(k.data)
}

// Data returns the raw key material.
func (k *SecretKey) Data() []byte {
	buf := make([]byte, len(k.data))
	copy(buf, k.data)
	return buf
}

// KeyPair holds a KEM public/secret key pair.
type KeyPair struct {
	Public *PublicKey
	Secret *SecretKey
}

// Ciphertext is a KEM ciphertext from encapsulation.
type Ciphertext struct {
	keyType KeyType
	data    []byte
}

// NewCiphertext creates a new Ciphertext from the given key type and raw data.
func NewCiphertext(keyType KeyType, data []byte) *Ciphertext {
	buf := make([]byte, len(data))
	copy(buf, data)
	return &Ciphertext{
		keyType: keyType,
		data:    buf,
	}
}

// DeserializeCiphertext reconstructs a Ciphertext from its serialized form.
// The first byte is the type prefix.
func DeserializeCiphertext(serialized []byte) (*Ciphertext, error) {
	if len(serialized) < 2 {
		return nil, ErrEmptyInput
	}
	kt := KeyType(serialized[0])
	if !validKeyType(kt) {
		return nil, ErrInvalidKeyType
	}
	dataLen := len(serialized) - 1
	expected := expectedCiphertextSize(kt)
	if dataLen != expected {
		return nil, &BadKeyLengthError{KeyType: kt, Expected: expected, Actual: dataLen}
	}
	data := make([]byte, dataLen)
	copy(data, serialized[1:])
	return &Ciphertext{keyType: kt, data: data}, nil
}

// Type returns the key type of this ciphertext.
func (c *Ciphertext) Type() KeyType {
	return c.keyType
}

// Serialize returns the ciphertext as [type_byte] || data.
func (c *Ciphertext) Serialize() []byte {
	out := make([]byte, 1+len(c.data))
	out[0] = byte(c.keyType)
	copy(out[1:], c.data)
	return out
}

// Data returns the raw ciphertext data without the type prefix.
func (c *Ciphertext) Data() []byte {
	buf := make([]byte, len(c.data))
	copy(buf, c.data)
	return buf
}

// SharedSecret is the output of encapsulate/decapsulate.
type SharedSecret [32]byte

// KEM is the interface for key encapsulation mechanisms.
type KEM interface {
	// KeyType returns the algorithm identifier for this KEM.
	KeyType() KeyType
	// Generate creates a new KEM key pair.
	Generate() (*KeyPair, error)
	// Encapsulate generates a shared secret and ciphertext for the given public key.
	Encapsulate(publicKey *PublicKey) (*SharedSecret, *Ciphertext, error)
	// Decapsulate recovers the shared secret from the given ciphertext using the secret key.
	Decapsulate(secretKey *SecretKey, ciphertext *Ciphertext) (*SharedSecret, error)
}
