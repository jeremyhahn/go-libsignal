package identity

import "fmt"

// ErrNilOtherKeyType is the typed error for a nil other key argument.
type ErrNilOtherKeyType struct{}

func (e *ErrNilOtherKeyType) Error() string {
	return "identity: other key must not be nil"
}

// ErrNilOtherKey is returned when the other *Key argument is nil.
var ErrNilOtherKey error = &ErrNilOtherKeyType{}

// ErrAltIdentitySignFailedType is the typed error for a failed alternate-identity sign.
type ErrAltIdentitySignFailedType struct{}

func (e *ErrAltIdentitySignFailedType) Error() string {
	return "identity: alternate-identity sign operation failed"
}

// ErrAltIdentitySignFailed is returned when SignAlternateIdentity fails to
// produce a signature (e.g., nil private key).
var ErrAltIdentitySignFailed error = &ErrAltIdentitySignFailedType{}

// ErrAltIdentitySignOperation wraps an underlying sign error with context.
type ErrAltIdentitySignOperation struct {
	Err error
}

func (e *ErrAltIdentitySignOperation) Error() string {
	return fmt.Sprintf("identity: alternate-identity sign failed: %v", e.Err)
}

func (e *ErrAltIdentitySignOperation) Unwrap() error {
	return e.Err
}

// ErrAltIdentityVerificationFailedType is the typed error for a failed alternate-identity verify.
type ErrAltIdentityVerificationFailedType struct{}

func (e *ErrAltIdentityVerificationFailedType) Error() string {
	return "identity: alternate-identity signature verification failed"
}

// ErrAltIdentityVerificationFailed is returned when VerifyAlternateIdentity
// fails because the signature does not match.
var ErrAltIdentityVerificationFailed error = &ErrAltIdentityVerificationFailedType{}

// ErrAltIdentityInvalidSignatureLength is returned when the provided signature
// is not exactly 64 bytes.
type ErrAltIdentityInvalidSignatureLength struct {
	Got int
}

func (e *ErrAltIdentityInvalidSignatureLength) Error() string {
	return fmt.Sprintf("identity: alternate-identity signature must be 64 bytes, got %d", e.Got)
}

// ErrReadingAltIdentityRandomness is returned when reading crypto/rand fails
// during SignAlternateIdentityRandom.
type ErrReadingAltIdentityRandomness struct {
	Err error
}

func (e *ErrReadingAltIdentityRandomness) Error() string {
	return fmt.Sprintf("identity: failed to read randomness for alternate-identity sign: %v", e.Err)
}

func (e *ErrReadingAltIdentityRandomness) Unwrap() error {
	return e.Err
}
