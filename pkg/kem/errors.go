package kem

import "fmt"

// KeyGenError indicates a failure during KEM key generation.
type KeyGenError struct {
	Algorithm string
	Err       error
}

func (e *KeyGenError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("kem: %s key generation failed: %v", e.Algorithm, e.Err)
	}
	return fmt.Sprintf("kem: %s key generation failed", e.Algorithm)
}

func (e *KeyGenError) Unwrap() error {
	return e.Err
}

// MarshalError indicates a failure marshaling a KEM key.
type MarshalError struct {
	Algorithm string
	KeyKind   string
	Err       error
}

func (e *MarshalError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("kem: failed to marshal %s %s key: %v", e.Algorithm, e.KeyKind, e.Err)
	}
	return fmt.Sprintf("kem: failed to marshal %s %s key", e.Algorithm, e.KeyKind)
}

func (e *MarshalError) Unwrap() error {
	return e.Err
}

// UnmarshalError indicates a failure unmarshaling a KEM key.
type UnmarshalError struct {
	Algorithm string
	KeyKind   string
	Err       error
}

func (e *UnmarshalError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("kem: failed to unmarshal %s %s key: %v", e.Algorithm, e.KeyKind, e.Err)
	}
	return fmt.Sprintf("kem: failed to unmarshal %s %s key", e.Algorithm, e.KeyKind)
}

func (e *UnmarshalError) Unwrap() error {
	return e.Err
}

// EncapsulationError indicates a failure during KEM encapsulation.
type EncapsulationError struct {
	Algorithm string
	Err       error
}

func (e *EncapsulationError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("kem: %s encapsulation failed: %v", e.Algorithm, e.Err)
	}
	return fmt.Sprintf("kem: %s encapsulation failed", e.Algorithm)
}

func (e *EncapsulationError) Unwrap() error {
	return e.Err
}

// DecapsulationError indicates a failure during KEM decapsulation.
type DecapsulationError struct {
	Algorithm string
	Err       error
}

func (e *DecapsulationError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("kem: %s decapsulation failed: %v", e.Algorithm, e.Err)
	}
	return fmt.Sprintf("kem: %s decapsulation failed", e.Algorithm)
}

func (e *DecapsulationError) Unwrap() error {
	return e.Err
}

// KeyTypeMismatchError indicates a key type does not match the expected algorithm.
type KeyTypeMismatchError struct {
	Expected string
	Actual   KeyType
	KeyKind  string
}

func (e *KeyTypeMismatchError) Error() string {
	if e.KeyKind != "" {
		return fmt.Sprintf("kem: key type mismatch: %s expected %s, got 0x%02x", e.KeyKind, e.Expected, e.Actual)
	}
	return fmt.Sprintf("kem: key type mismatch: expected %s, got 0x%02x", e.Expected, e.Actual)
}

// GuardedKeyAllocationError indicates a failure allocating guarded key memory.
type GuardedKeyAllocationError struct {
	Operation string
	Err       error
}

func (e *GuardedKeyAllocationError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("kem: %s: %v", e.Operation, e.Err)
	}
	return fmt.Sprintf("kem: %s", e.Operation)
}

func (e *GuardedKeyAllocationError) Unwrap() error {
	return e.Err
}

// GuardedKeyDestroyedError indicates an operation was attempted on a destroyed guarded key.
type GuardedKeyDestroyedError struct{}

func (e *GuardedKeyDestroyedError) Error() string {
	return "kem: guarded key has been destroyed"
}

// DeserializeError indicates a failure deserializing a ciphertext.
type DeserializeError struct {
	Err error
}

func (e *DeserializeError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("kem: failed to deserialize ciphertext: %v", e.Err)
	}
	return "kem: failed to deserialize ciphertext"
}

func (e *DeserializeError) Unwrap() error {
	return e.Err
}
