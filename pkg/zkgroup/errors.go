package zkgroup

import "fmt"

// ErrVerificationFailureType is the typed error for a zkgroup verification failure.
type ErrVerificationFailureType struct{}

func (e *ErrVerificationFailureType) Error() string {
	return "zkgroup: verification failure"
}

// ErrDeserializationFailureType is the typed error for a zkgroup deserialization failure.
type ErrDeserializationFailureType struct{}

func (e *ErrDeserializationFailureType) Error() string {
	return "zkgroup: deserialization failure"
}

// ErrVerificationFailure indicates that a zkgroup cryptographic verification
// operation has failed.
var ErrVerificationFailure error = &ErrVerificationFailureType{}

// ErrDeserializationFailure indicates that a zkgroup deserialization operation
// has failed (e.g., invalid byte format or unexpected version).
var ErrDeserializationFailure error = &ErrDeserializationFailureType{}

// ZkGroupVerificationFailure wraps ErrVerificationFailure with context.
type ZkGroupVerificationFailure struct {
	Context string
}

// Error implements the error interface.
func (e *ZkGroupVerificationFailure) Error() string {
	if e.Context != "" {
		return "zkgroup: verification failure: " + e.Context
	}
	return "zkgroup: verification failure"
}

// Unwrap returns the underlying sentinel error.
func (e *ZkGroupVerificationFailure) Unwrap() error {
	return ErrVerificationFailure
}

// ZkGroupDeserializationFailure wraps ErrDeserializationFailure with context.
type ZkGroupDeserializationFailure struct {
	TypeName string
}

// Error implements the error interface.
func (e *ZkGroupDeserializationFailure) Error() string {
	if e.TypeName != "" {
		return "zkgroup: failed to deserialize " + e.TypeName
	}
	return "zkgroup: deserialization failure"
}

// Unwrap returns the underlying sentinel error.
func (e *ZkGroupDeserializationFailure) Unwrap() error {
	return ErrDeserializationFailure
}

// ErrGeneratingSigningKey indicates a failure generating a signing key pair.
type ErrGeneratingSigningKey struct {
	Err error
}

func (e *ErrGeneratingSigningKey) Error() string {
	return fmt.Sprintf("zkgroup: failed to generate signing key: %v", e.Err)
}

func (e *ErrGeneratingSigningKey) Unwrap() error {
	return e.Err
}

// ErrGeneratingSignatureKeyPair indicates a failure generating a signature key pair.
type ErrGeneratingSignatureKeyPair struct {
	Err error
}

func (e *ErrGeneratingSignatureKeyPair) Error() string {
	return fmt.Sprintf("zkgroup: failed to generate signature key pair: %v", e.Err)
}

func (e *ErrGeneratingSignatureKeyPair) Unwrap() error {
	return e.Err
}

// ErrGeneratingEndorsementKeyPair indicates a failure generating an endorsement key pair.
type ErrGeneratingEndorsementKeyPair struct {
	Err error
}

func (e *ErrGeneratingEndorsementKeyPair) Error() string {
	return fmt.Sprintf("zkgroup: failed to generate endorsement key pair: %v", e.Err)
}

func (e *ErrGeneratingEndorsementKeyPair) Unwrap() error {
	return e.Err
}

// ErrDataTooShort indicates the data is too short for deserialization.
type ErrDataTooShort struct{}

func (e *ErrDataTooShort) Error() string {
	return "zkgroup: data too short for deserialization"
}

// ErrUnexpectedReservedByte indicates an unexpected reserved byte value
// in the serialized data.
type ErrUnexpectedReservedByte struct {
	Value byte
}

func (e *ErrUnexpectedReservedByte) Error() string {
	return fmt.Sprintf("zkgroup: unexpected reserved byte %d", e.Value)
}
