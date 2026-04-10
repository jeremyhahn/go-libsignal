package devicetransfer

// Error represents a device transfer error.
type Error struct {
	kind  errorKind
	cause string
	err   error
}

type errorKind int

const (
	errKeyGeneration    errorKind = iota + 1
	errKeyParsing
	errCertCreation
	errPEMDecode
	errUnsupportedFormat
	errInvalidKeySize
	errNilSigner
)

// ErrKeyGeneration indicates that RSA key generation failed.
var ErrKeyGeneration = &Error{kind: errKeyGeneration}

// ErrKeyParsing indicates that private key parsing failed.
var ErrKeyParsing = &Error{kind: errKeyParsing}

// ErrCertCreation indicates that certificate creation failed.
var ErrCertCreation = &Error{kind: errCertCreation}

// ErrPEMDecode indicates that PEM decoding failed.
var ErrPEMDecode = &Error{kind: errPEMDecode}

// ErrUnsupportedFormat indicates an unsupported key format.
var ErrUnsupportedFormat = &Error{kind: errUnsupportedFormat}

// ErrInvalidKeySize indicates the requested key size is below the minimum.
var ErrInvalidKeySize = &Error{kind: errInvalidKeySize}

// ErrNilSigner indicates that a nil signer was provided to CreateSelfSignedCertWithSigner.
var ErrNilSigner = &Error{kind: errNilSigner}

// Error implements the error interface.
func (e *Error) Error() string {
	prefix := "devicetransfer: "
	var msg string
	switch e.kind {
	case errKeyGeneration:
		msg = "failed to generate RSA key"
	case errKeyParsing:
		msg = "failed to parse private key"
	case errCertCreation:
		msg = "failed to create certificate"
	case errPEMDecode:
		msg = "failed to decode PEM block"
	case errUnsupportedFormat:
		msg = "unsupported key format"
	case errInvalidKeySize:
		msg = "key size below minimum"
	case errNilSigner:
		msg = "signer must not be nil"
	default:
		msg = "unknown error"
	}
	if e.cause != "" {
		return prefix + msg + ": " + e.cause
	}
	if e.err != nil {
		return prefix + msg + ": " + e.err.Error()
	}
	return prefix + msg
}

// Is implements errors.Is matching. Sentinel errors match by kind,
// regardless of cause detail.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	return e.kind == t.kind
}

// Unwrap returns the wrapped error, if any.
func (e *Error) Unwrap() error {
	return e.err
}

// newKeyGenerationError creates a key generation error wrapping an underlying error.
func newKeyGenerationError(err error) *Error {
	return &Error{kind: errKeyGeneration, err: err}
}

// newKeyParsingError creates a key parsing error with a cause description.
func newKeyParsingError(cause string) *Error {
	return &Error{kind: errKeyParsing, cause: cause}
}

// newKeyParsingErrorWrap creates a key parsing error wrapping an underlying error.
func newKeyParsingErrorWrap(err error) *Error {
	return &Error{kind: errKeyParsing, err: err}
}

// newCertCreationError creates a certificate creation error wrapping an underlying error.
func newCertCreationError(err error) *Error {
	return &Error{kind: errCertCreation, err: err}
}

// newUnsupportedFormatError creates an unsupported format error with a cause description.
func newUnsupportedFormatError(cause string) *Error {
	return &Error{kind: errUnsupportedFormat, cause: cause}
}

// newInvalidKeySizeError creates an invalid key size error with a cause description.
func newInvalidKeySizeError(cause string) *Error {
	return &Error{kind: errInvalidKeySize, cause: cause}
}
