package keyops

// Error represents a key operations error.
type Error struct {
	kind  errorKind
	cause string
}

type errorKind int

const (
	errKeyDestroyed errorKind = iota + 1
	errUnsupportedOperation
	errHardwareKeyExport
	errSignatureFailed
	errDHFailed
	errDecapsulationFailed
)

// ErrKeyDestroyed indicates an attempt to use a key that has been destroyed.
var ErrKeyDestroyed = &Error{kind: errKeyDestroyed}

// ErrUnsupportedOperation indicates that the requested operation is not
// supported by this key type or implementation.
var ErrUnsupportedOperation = &Error{kind: errUnsupportedOperation}

// ErrHardwareKeyExport indicates an attempt to export raw key material
// from a hardware-backed key. Hardware keys never expose private material.
var ErrHardwareKeyExport = &Error{kind: errHardwareKeyExport}

// ErrSignatureFailed indicates that a signing operation failed.
var ErrSignatureFailed = &Error{kind: errSignatureFailed}

// ErrDHFailed indicates that an ECDH key agreement operation failed.
var ErrDHFailed = &Error{kind: errDHFailed}

// ErrDecapsulationFailed indicates that a KEM decapsulation operation failed.
var ErrDecapsulationFailed = &Error{kind: errDecapsulationFailed}

// Error implements the error interface.
func (e *Error) Error() string {
	prefix := "keyops: "
	var msg string
	switch e.kind {
	case errKeyDestroyed:
		msg = "attempt to use a destroyed key"
	case errUnsupportedOperation:
		msg = "unsupported operation"
	case errHardwareKeyExport:
		msg = "cannot export raw material from hardware-backed key"
	case errSignatureFailed:
		msg = "signing operation failed"
	case errDHFailed:
		msg = "ECDH key agreement failed"
	case errDecapsulationFailed:
		msg = "KEM decapsulation failed"
	default:
		msg = "unknown error"
	}
	if e.cause != "" {
		return prefix + msg + ": " + e.cause
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

// NewSignatureError creates a signature failed error with a cause description.
func NewSignatureError(cause string) *Error {
	return &Error{kind: errSignatureFailed, cause: cause}
}

// NewDHError creates a DH failed error with a cause description.
func NewDHError(cause string) *Error {
	return &Error{kind: errDHFailed, cause: cause}
}

// NewDecapsulationError creates a decapsulation failed error with a cause description.
func NewDecapsulationError(cause string) *Error {
	return &Error{kind: errDecapsulationFailed, cause: cause}
}

// NewKeyDestroyedError creates a key destroyed error with a cause description.
func NewKeyDestroyedError(cause string) *Error {
	return &Error{kind: errKeyDestroyed, cause: cause}
}

// NewUnsupportedOperationError creates an unsupported operation error with a cause description.
func NewUnsupportedOperationError(cause string) *Error {
	return &Error{kind: errUnsupportedOperation, cause: cause}
}
