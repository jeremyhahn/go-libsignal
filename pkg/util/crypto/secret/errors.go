package secret

import "fmt"

// Error represents a secret storage error.
type Error struct {
	kind     errorKind
	expected int
	got      int
	cause    string
}

type errorKind int

const (
	errSecretDestroyed    errorKind = iota + 1
	errSecretSizeMismatch
	errSecretAlloc
	errNilInput
)

// ErrSecretDestroyed indicates an attempt to use a destroyed secret.
var ErrSecretDestroyed = &Error{kind: errSecretDestroyed}

// ErrNilInput indicates that nil input was provided where data was expected.
var ErrNilInput = &Error{kind: errNilInput}

// Error implements the error interface.
func (e *Error) Error() string {
	switch e.kind {
	case errSecretDestroyed:
		return "secret: attempt to use a destroyed secret"
	case errSecretSizeMismatch:
		return fmt.Sprintf("secret: size mismatch: expected %d bytes, got %d", e.expected, e.got)
	case errSecretAlloc:
		if e.cause != "" {
			return fmt.Sprintf("secret: allocation failed: %s", e.cause)
		}
		return "secret: allocation failed"
	case errNilInput:
		return "secret: nil input provided"
	default:
		return "secret: unknown error"
	}
}

// Is implements errors.Is matching. Sentinel errors match by kind.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	return e.kind == t.kind
}

// newSizeMismatchError creates an error indicating an expected vs actual size mismatch.
func newSizeMismatchError(expected, got int) *Error {
	return &Error{kind: errSecretSizeMismatch, expected: expected, got: got}
}

// newAllocError creates an error indicating a memguard allocation failure.
func newAllocError(cause string) *Error {
	return &Error{kind: errSecretAlloc, cause: cause}
}
