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

// ErrUnknownPresentationVersion indicates that the first byte of a serialized
// credential presentation does not correspond to any known version (V1–V4).
type ErrUnknownPresentationVersion struct {
	Version byte
}

// Error implements the error interface.
func (e *ErrUnknownPresentationVersion) Error() string {
	return fmt.Sprintf("zkgroup: unknown presentation version %d", e.Version)
}

// Unwrap returns the underlying sentinel deserialization error.
func (e *ErrUnknownPresentationVersion) Unwrap() error {
	return ErrDeserializationFailure
}

// ErrInvalidServiceIDKind indicates that a ServiceID with an unexpected kind
// was passed to an operation that requires a specific kind (e.g., ACI only).
type ErrInvalidServiceIDKind struct {
	Got ServiceIDType
}

// Error implements the error interface.
func (e *ErrInvalidServiceIDKind) Error() string {
	return fmt.Sprintf("zkgroup: invalid service ID kind %d: operation requires ACI", e.Got)
}

// ErrInvalidReceiptPresentation is the sentinel for a receipt credential
// presentation that fails deserialization.
var ErrInvalidReceiptPresentation error = &ErrInvalidReceiptPresentationType{}

// ErrInvalidReceiptPresentationType is the typed sentinel.
type ErrInvalidReceiptPresentationType struct{}

func (e *ErrInvalidReceiptPresentationType) Error() string {
	return "zkgroup: invalid receipt credential presentation"
}

// ErrInvalidBackupAuthPresentation is the sentinel for a backup auth credential
// presentation that fails deserialization.
var ErrInvalidBackupAuthPresentation error = &ErrInvalidBackupAuthPresentationType{}

// ErrInvalidBackupAuthPresentationType is the typed sentinel.
type ErrInvalidBackupAuthPresentationType struct{}

func (e *ErrInvalidBackupAuthPresentationType) Error() string {
	return "zkgroup: invalid backup auth credential presentation"
}

// ErrInvalidCallLinkAuthPresentation is the sentinel for a call link auth
// credential presentation that fails deserialization.
var ErrInvalidCallLinkAuthPresentation error = &ErrInvalidCallLinkAuthPresentationType{}

// ErrInvalidCallLinkAuthPresentationType is the typed sentinel.
type ErrInvalidCallLinkAuthPresentationType struct{}

func (e *ErrInvalidCallLinkAuthPresentationType) Error() string {
	return "zkgroup: invalid call link auth credential presentation"
}

// ErrInvalidCreateCallLinkPresentation is the sentinel for a create call link
// credential presentation that fails deserialization.
var ErrInvalidCreateCallLinkPresentation error = &ErrInvalidCreateCallLinkPresentationType{}

// ErrInvalidCreateCallLinkPresentationType is the typed sentinel.
type ErrInvalidCreateCallLinkPresentationType struct{}

func (e *ErrInvalidCreateCallLinkPresentationType) Error() string {
	return "zkgroup: invalid create call link credential presentation"
}

// ErrInvalidCredentialLength indicates that a serialized credential or
// sub-structure has an unexpected byte length.
type ErrInvalidCredentialLength struct {
	Got  int
	Want int
}

// Error implements the error interface.
func (e *ErrInvalidCredentialLength) Error() string {
	return fmt.Sprintf("zkgroup: invalid credential length: got %d bytes, want %d", e.Got, e.Want)
}

// Unwrap returns the underlying sentinel deserialization error.
func (e *ErrInvalidCredentialLength) Unwrap() error {
	return ErrDeserializationFailure
}

// ErrTrailingBytes indicates that bytes remain unconsumed after a public
// Deserialize* function completes. Rust's bincode with reject_trailing_bytes()
// treats this as a decode error; Go matches that behavior.
type ErrTrailingBytes struct {
	TypeName string
	Count    int
}

// Error implements the error interface.
func (e *ErrTrailingBytes) Error() string {
	return fmt.Sprintf("zkgroup: %d unexpected trailing bytes after %s", e.Count, e.TypeName)
}

// Unwrap returns the underlying sentinel deserialization error.
func (e *ErrTrailingBytes) Unwrap() error {
	return ErrDeserializationFailure
}
