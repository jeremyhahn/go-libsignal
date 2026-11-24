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
	// KeyTypeKyber768 identifies round-3 Kyber-768.
	// 0x07 — round-3 Kyber-768. Recognized for deserialization only; never
	// emitted by this Go implementation. Matches Rust kem.rs byte tag 0x07.
	KeyTypeKyber768 KeyType = 0x07
	// KeyTypeKyber1024 identifies the Kyber-1024 KEM algorithm (round-3).
	// Used by PQXDH (DST WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024).
	KeyTypeKyber1024 KeyType = 0x08
	// KeyTypeMLKEM768 identifies ML-KEM-768 (FIPS 203) for SPQR; 0x09 is a Go-only value that upstream does not allocate.
	KeyTypeMLKEM768 KeyType = 0x09
	// KeyTypeMLKEM1024 identifies the ML-KEM-1024 KEM algorithm (FIPS 203).
	KeyTypeMLKEM1024 KeyType = 0x0A
)

// ErrNoKeyTypeIdentifierError is returned for empty input (Rust SignalProtocolError::NoKeyTypeIdentifier).
type ErrNoKeyTypeIdentifierError struct{}

func (e *ErrNoKeyTypeIdentifierError) Error() string {
	return "kem: no key type identifier: input is empty"
}

// ErrEmptyInputError is returned when the input contains only a type byte
// (length == 1) with no key or ciphertext material following it.
type ErrEmptyInputError struct{}

func (e *ErrEmptyInputError) Error() string {
	return "kem: input too short: type byte present but no key material"
}

// ErrKeyTypeMismatchError is the typed error for mismatched key types.
type ErrKeyTypeMismatchError struct{}

func (e *ErrKeyTypeMismatchError) Error() string {
	return "kem: key type mismatch"
}

// ErrKeyTypeKyber768UnsupportedError is returned for Round-3 Kyber-768 (0x07), which has no backend; ML-KEM-768 (0x09) is supported.
type ErrKeyTypeKyber768UnsupportedError struct{}

func (e *ErrKeyTypeKyber768UnsupportedError) Error() string {
	return "kem: Round-3 Kyber-768 (0x07) has no backend in go-libsignal; use Kyber-1024 (0x08) or ML-KEM-768 (0x09)"
}

// BadKEMKeyTypeError indicates an unknown KEM key type byte (Rust SignalProtocolError::BadKEMKeyType).
type BadKEMKeyTypeError struct {
	// Value is the unrecognized key type byte.
	Value byte
}

func (e *BadKEMKeyTypeError) Error() string {
	return fmt.Sprintf("kem: unrecognized key type byte: 0x%02x", e.Value)
}

// Is implements errors.Is so that any BadKEMKeyTypeError matches ErrInvalidKeyType
// (the backward-compatible sentinel) regardless of the Value field.
func (e *BadKEMKeyTypeError) Is(target error) bool {
	_, ok := target.(*BadKEMKeyTypeError)
	return ok
}

// Sentinel errors for backward-compatible errors.Is matching.
var (
	// ErrNoKeyTypeIdentifier is returned when the input is completely empty.
	// Matches Rust SignalProtocolError::NoKeyTypeIdentifier.
	ErrNoKeyTypeIdentifier error = &ErrNoKeyTypeIdentifierError{}
	// ErrEmptyInput is returned when the input has a type byte but no key material.
	ErrEmptyInput error = &ErrEmptyInputError{}
	// ErrInvalidKeyType is a backward-compatible alias; prefer BadKEMKeyTypeError
	// for new code that needs the offending byte value.
	ErrInvalidKeyType error = &BadKEMKeyTypeError{Value: 0}
	// ErrKeyTypeMismatch is returned when key types do not match the expected algorithm.
	ErrKeyTypeMismatch error = &ErrKeyTypeMismatchError{}
	// ErrKeyTypeKyber768Unsupported is returned when a caller attempts to use
	// Round-3 Kyber-768 (KeyType 0x07), which has no backend in go-libsignal.
	ErrKeyTypeKyber768Unsupported error = &ErrKeyTypeKyber768UnsupportedError{}
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

// BadKeyLengthError indicates a serialized key of the wrong length (Rust SignalProtocolError::BadKEMKeyLength).
type BadKeyLengthError struct {
	KeyType  KeyType
	Expected int
	Actual   int
}

// Error returns a human-readable description of the length mismatch.
func (e *BadKeyLengthError) Error() string {
	return fmt.Sprintf("kem: bad key length for type 0x%02x: expected %d bytes, got %d", e.KeyType, e.Expected, e.Actual)
}

// BadCiphertextLengthError indicates a serialized ciphertext of the wrong length (Rust SignalProtocolError::BadKEMCiphertextLength).
type BadCiphertextLengthError struct {
	KeyType  KeyType
	Expected int
	Actual   int
}

// Error returns a human-readable description of the ciphertext length mismatch.
func (e *BadCiphertextLengthError) Error() string {
	return fmt.Sprintf("kem: bad ciphertext length for type 0x%02x: expected %d bytes, got %d", e.KeyType, e.Expected, e.Actual)
}

// expectedPublicKeySize returns the expected raw public key data size (without
// the type prefix byte) for the given algorithm. KeyTypeKyber768 is
// intentionally absent: Kyber-768 has no backend and is rejected by validKeyType.
func expectedPublicKeySize(kt KeyType) int {
	switch kt {
	case KeyTypeKyber1024:
		return 1568
	case KeyTypeMLKEM768:
		return 1184 // NIST FIPS 203 ML-KEM-768 encapsulation key
	case KeyTypeMLKEM1024:
		return 1568 // NIST FIPS 203 ML-KEM-1024 encapsulation key
	default:
		return -1
	}
}

// expectedSecretKeySize returns 3168 bytes for Kyber-1024 and a 64-byte seed for ML-KEM; Kyber-768 has no backend.
func expectedSecretKeySize(kt KeyType) int {
	switch kt {
	case KeyTypeKyber1024:
		return 3168
	case KeyTypeMLKEM768:
		return 64 // NIST FIPS 203 seed-based decapsulation key
	case KeyTypeMLKEM1024:
		return 64 // NIST FIPS 203 seed-based decapsulation key
	default:
		return -1
	}
}

// expectedCiphertextSize returns the expected raw ciphertext data size (without
// the type prefix byte) for the given algorithm. KeyTypeKyber768 is
// intentionally absent: Kyber-768 has no backend and is rejected by validKeyType.
func expectedCiphertextSize(kt KeyType) int {
	switch kt {
	case KeyTypeKyber1024:
		return 1568
	case KeyTypeMLKEM768:
		return 1088 // NIST FIPS 203 ML-KEM-768 ciphertext
	case KeyTypeMLKEM1024:
		return 1568 // NIST FIPS 203 ML-KEM-1024 ciphertext
	default:
		return -1
	}
}

// validKeyType returns true if the given KeyType is a supported algorithm.
// KeyTypeKyber768 (0x07) is explicitly rejected: Round-3 Kyber-768 has no
// backend in go-libsignal. Use ErrKeyTypeKyber768Unsupported for error detail.
func validKeyType(kt KeyType) bool {
	switch kt {
	case KeyTypeKyber1024, KeyTypeMLKEM768, KeyTypeMLKEM1024:
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

// DeserializePublicKey parses a type-prefixed public key, returning the same errors as Rust kem.rs.
func DeserializePublicKey(serialized []byte) (*PublicKey, error) {
	if len(serialized) == 0 {
		return nil, ErrNoKeyTypeIdentifier
	}
	if len(serialized) == 1 {
		return nil, ErrEmptyInput
	}
	kt := KeyType(serialized[0])
	if kt == KeyTypeKyber768 {
		return nil, ErrKeyTypeKyber768Unsupported
	}
	if !validKeyType(kt) {
		return nil, &BadKEMKeyTypeError{Value: serialized[0]}
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

// NewSecretKey returns a SecretKey for a known type and correctly sized data; Kyber-768 returns ErrKeyTypeKyber768Unsupported.
func NewSecretKey(keyType KeyType, data []byte) (*SecretKey, error) {
	if err := validateSecretKeyMaterial(keyType, len(data)); err != nil {
		return nil, err
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

// FromPublicAndPrivate builds a KeyPair from a public key and raw secret key of the same algorithm (Rust KeyPair::from_public_and_private).
func FromPublicAndPrivate(publicSerialized []byte, secretData []byte) (*KeyPair, error) {
	pk, err := DeserializePublicKey(publicSerialized)
	if err != nil {
		return nil, err
	}
	sk, err := NewSecretKey(pk.Type(), secretData)
	if err != nil {
		return nil, err
	}
	return &KeyPair{Public: pk, Secret: sk}, nil
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

// DeserializeCiphertext parses a type-prefixed ciphertext, returning the same errors as Rust kem.rs.
func DeserializeCiphertext(serialized []byte) (*Ciphertext, error) {
	if len(serialized) == 0 {
		return nil, ErrNoKeyTypeIdentifier
	}
	if len(serialized) == 1 {
		return nil, ErrEmptyInput
	}
	kt := KeyType(serialized[0])
	if kt == KeyTypeKyber768 {
		return nil, ErrKeyTypeKyber768Unsupported
	}
	if !validKeyType(kt) {
		return nil, &BadKEMKeyTypeError{Value: serialized[0]}
	}
	dataLen := len(serialized) - 1
	expected := expectedCiphertextSize(kt)
	if dataLen != expected {
		return nil, &BadCiphertextLengthError{KeyType: kt, Expected: expected, Actual: dataLen}
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
