package ecc

import "fmt"

// ErrGuardedKeyDestroyedType is the typed error for operations on a destroyed guarded key.
type ErrGuardedKeyDestroyedType struct{}

func (e *ErrGuardedKeyDestroyedType) Error() string {
	return "ecc: guarded key has been destroyed"
}

// ErrInvalidKeyAgreementType is the typed error for an all-zero DH shared secret.
type ErrInvalidKeyAgreementType struct{}

func (e *ErrInvalidKeyAgreementType) Error() string {
	return "ecc: key agreement produced invalid all-zero shared secret"
}

// ErrBadKeyLengthType is the typed error for a serialized key with insufficient bytes.
type ErrBadKeyLengthType struct{}

func (e *ErrBadKeyLengthType) Error() string {
	return "ecc: bad key length"
}

// ErrInputTooShortType is the typed error for an input buffer too short to read a key type byte.
type ErrInputTooShortType struct{}

func (e *ErrInputTooShortType) Error() string {
	return "ecc: input too short to read key type"
}

// ErrGuardedKeyDestroyed is returned when an operation is attempted on a
// GuardedECPrivateKey whose guarded memory has been destroyed.
var ErrGuardedKeyDestroyed error = &ErrGuardedKeyDestroyedType{}

// ErrInvalidKeyAgreement is returned when a Diffie-Hellman key agreement
// produces an all-zero shared secret, indicating a low-order public key
// or other invalid input that would compromise security.
var ErrInvalidKeyAgreement error = &ErrInvalidKeyAgreementType{}

// ErrBadKeyLength is returned when a serialized key does not contain
// enough bytes to be decoded. For DJB keys, exactly 33 bytes (1 type
// byte + 32 key bytes) are required from the given offset.
var ErrBadKeyLength error = &ErrBadKeyLengthType{}

// ErrInputTooShort is returned when the input buffer is too short to
// read the key type byte at the given offset.
var ErrInputTooShort error = &ErrInputTooShortType{}

// ErrGuardedKeyAllocation indicates a failure allocating guarded memory
// for a private key or key pair.
type ErrGuardedKeyAllocation struct {
	Operation string
	Err       error
}

func (e *ErrGuardedKeyAllocation) Error() string {
	return fmt.Sprintf("ecc: %s failed: %v", e.Operation, e.Err)
}

func (e *ErrGuardedKeyAllocation) Unwrap() error {
	return e.Err
}

// ErrReadingRandomness indicates a failure reading cryptographic randomness.
type ErrReadingRandomness struct {
	Operation string
	Err       error
}

func (e *ErrReadingRandomness) Error() string {
	return fmt.Sprintf("ecc: failed to read randomness for %s: %v", e.Operation, e.Err)
}

func (e *ErrReadingRandomness) Unwrap() error {
	return e.Err
}

// ErrX25519Agreement indicates a failure in the X25519 key agreement operation.
type ErrX25519Agreement struct {
	Err error
}

func (e *ErrX25519Agreement) Error() string {
	return fmt.Sprintf("ecc: X25519 key agreement failed: %v", e.Err)
}

func (e *ErrX25519Agreement) Unwrap() error {
	return e.Err
}

// ErrAllocatingSharedSecret indicates a failure allocating guarded memory
// for the shared secret after key agreement.
type ErrAllocatingSharedSecret struct {
	Err error
}

func (e *ErrAllocatingSharedSecret) Error() string {
	return fmt.Sprintf("ecc: failed to allocate guarded shared secret: %v", e.Err)
}

func (e *ErrAllocatingSharedSecret) Unwrap() error {
	return e.Err
}

// ErrBadKeyType indicates an unrecognized key type byte was encountered
// during key deserialization.
type ErrBadKeyType struct {
	KeyType byte
}

func (e *ErrBadKeyType) Error() string {
	return fmt.Sprintf("ecc: bad key type: 0x%02x", e.KeyType)
}

// ErrGuardedKeyClone indicates a failure cloning a guarded key.
type ErrGuardedKeyClone struct {
	Err error
}

func (e *ErrGuardedKeyClone) Error() string {
	return fmt.Sprintf("ecc: guarded key clone failed: %v", e.Err)
}

func (e *ErrGuardedKeyClone) Unwrap() error {
	return e.Err
}

// ErrGeneratingKeyMaterial indicates a failure generating random key material.
type ErrGeneratingKeyMaterial struct {
	Err error
}

func (e *ErrGeneratingKeyMaterial) Error() string {
	return fmt.Sprintf("ecc: failed to generate random key material: %v", e.Err)
}

func (e *ErrGeneratingKeyMaterial) Unwrap() error {
	return e.Err
}

// ErrSignFailedType is the typed error for a failed XEdDSA sign operation.
type ErrSignFailedType struct{}

func (e *ErrSignFailedType) Error() string {
	return "ecc: XEdDSA sign operation failed"
}

// ErrSignFailed is returned when the XEdDSA sign operation fails to produce
// a signature, typically due to invalid scalar construction.
var ErrSignFailed error = &ErrSignFailedType{}
