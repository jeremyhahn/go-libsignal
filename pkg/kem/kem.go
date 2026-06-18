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
	// KeyTypeMLKEM768 identifies the NIST ML-KEM-768 KEM algorithm (FIPS 203).
	// Used by SPQR (Sparse Post-Quantum Ratchet).
	//
	// NOTE: 0x09 is a Go-only allocation. Upstream Rust libsignal v0.92.2
	// (RUST_REV 98915c442d) does not define an MLKEM768 variant in its
	// KeyType enum (rust/protocol/src/kem.rs:212-247 lists only 0x07
	// Kyber768, 0x08 Kyber1024, 0x0A MLKEM1024). The reason is that Rust
	// pulls SPQR from an external crate (signalapp/SparsePostQuantumRatchet
	// v1.5.1) that vends its own ML-KEM-768 path, so the libsignal-protocol
	// kem.rs never needs to expose the algorithm. Go embeds SPQR locally
	// (pkg/spqr) and therefore needs a stable wire byte for the algorithm;
	// 0x09 was chosen to avoid colliding with any upstream allocation.
	KeyTypeMLKEM768 KeyType = 0x09
	// KeyTypeMLKEM1024 identifies the ML-KEM-1024 KEM algorithm (FIPS 203).
	KeyTypeMLKEM1024 KeyType = 0x0A
)

// ErrNoKeyTypeIdentifierError is returned when the input is completely empty
// and no key-type byte can be read.
//
// Rust reference: SignalProtocolError::NoKeyTypeIdentifier (error.rs:37).
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

// ErrKeyTypeKyber768UnsupportedError is returned when a caller attempts to use
// Round-3 Kyber-768 (KeyType 0x07). go-libsignal has no Kyber-768 backend;
// the guarded KEM dispatcher and key validation both reject this type.
// Peers that have not yet migrated away from Kyber-768 are unsupported.
//
// NOTE: ML-KEM-768 (KeyType 0x09) is a distinct, fully supported algorithm.
//
// Rust reference: rust/protocol/src/kem.rs KeyType::Kyber768 (0x07).
type ErrKeyTypeKyber768UnsupportedError struct{}

func (e *ErrKeyTypeKyber768UnsupportedError) Error() string {
	return "kem: Round-3 Kyber-768 (0x07) has no backend in go-libsignal; use Kyber-1024 (0x08) or ML-KEM-768 (0x09)"
}

// BadKEMKeyTypeError indicates that a key type byte was recognized syntactically
// but does not correspond to any known KEM algorithm.
//
// Rust reference: SignalProtocolError::BadKEMKeyType(u8) (error.rs:99).
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

// BadKeyLengthError indicates that a serialized key has the wrong length for
// its algorithm.
//
// Rust reference: SignalProtocolError::BadKEMKeyLength(KeyType, usize) (error.rs:103).
type BadKeyLengthError struct {
	KeyType  KeyType
	Expected int
	Actual   int
}

// Error returns a human-readable description of the length mismatch.
func (e *BadKeyLengthError) Error() string {
	return fmt.Sprintf("kem: bad key length for type 0x%02x: expected %d bytes, got %d", e.KeyType, e.Expected, e.Actual)
}

// BadCiphertextLengthError indicates that a serialized ciphertext has the wrong
// length for its algorithm. Distinct from BadKeyLengthError so callers can
// distinguish malformed keys from malformed ciphertexts via type assertion.
//
// Rust reference: SignalProtocolError::BadKEMCiphertextLength(KeyType, usize) (error.rs:105).
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

// expectedSecretKeySize returns the expected raw secret key data size for the
// given algorithm. Kyber-1024 secret keys are 3168 bytes (round-3 full form).
// ML-KEM-768 and ML-KEM-1024 secret keys are 64-byte seeds per NIST FIPS 203.
// KeyTypeKyber768 is intentionally absent: Kyber-768 has no backend.
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

// DeserializePublicKey reconstructs a PublicKey from its serialized form.
// The first byte is the type prefix.
//
// Error mapping (matches Rust kem.rs:319-330 and error.rs:37,99,103):
//   - empty input → ErrNoKeyTypeIdentifier
//   - only a type byte (length 1) → ErrEmptyInput
//   - Kyber-768 tag (0x07) → ErrKeyTypeKyber768Unsupported
//   - unknown tag → BadKEMKeyTypeError{Value}
//   - wrong length → BadKeyLengthError
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

// NewSecretKey creates a new SecretKey from the given key type and raw key data.
// Returns an error if the key type is unrecognized or the data length does not
// match the expected size for the algorithm.
// Returns ErrKeyTypeKyber768Unsupported for Round-3 Kyber-768 (0x07), which
// has no backend in go-libsignal.
func NewSecretKey(keyType KeyType, data []byte) (*SecretKey, error) {
	if keyType == KeyTypeKyber768 {
		return nil, ErrKeyTypeKyber768Unsupported
	}
	if !validKeyType(keyType) {
		return nil, &BadKEMKeyTypeError{Value: byte(keyType)}
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

// FromPublicAndPrivate deserializes a public key and a raw secret key and
// assembles them into a KeyPair, verifying that both carry the same algorithm
// tag.
//
// Rust reference: KeyPair::from_public_and_private (kem.rs:463-477).
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

// DeserializeCiphertext reconstructs a Ciphertext from its serialized form.
// The first byte is the type prefix.
//
// Error mapping (matches Rust kem.rs:490-502 and error.rs:37,99,105):
//   - empty input → ErrNoKeyTypeIdentifier
//   - only a type byte (length 1) → ErrEmptyInput
//   - Kyber-768 tag (0x07) → ErrKeyTypeKyber768Unsupported
//   - unknown tag → BadKEMKeyTypeError{Value}
//   - wrong length → BadCiphertextLengthError
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
