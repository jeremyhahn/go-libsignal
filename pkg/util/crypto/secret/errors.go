package secret

import "fmt"

// Error represents a secret storage error.
type Error struct {
	kind     errorKind
	expected int
	got      int
	cause    error
}

type errorKind int

const (
	errSecretDestroyed errorKind = iota + 1
	errSecretSizeMismatch
	errSecretAlloc
	errNilInput
	errInvalidBudget
	errAllocatorAlreadySet
	errAllocatorAfterAllocation
)

// ErrSecretDestroyed indicates an attempt to use a destroyed secret.
var ErrSecretDestroyed = &Error{kind: errSecretDestroyed}

// ErrNilInput indicates that nil input was provided where data was expected.
var ErrNilInput = &Error{kind: errNilInput}

// ErrInvalidBudget indicates that SetAllocator was given a non-positive budget.
var ErrInvalidBudget = &Error{kind: errInvalidBudget}

// ErrAllocatorAlreadySet indicates that SetAllocator was called more than once.
var ErrAllocatorAlreadySet = &Error{kind: errAllocatorAlreadySet}

// ErrAllocatorAfterAllocation indicates that SetAllocator was called after the
// package had already allocated locked memory without a budget.
var ErrAllocatorAfterAllocation = &Error{kind: errAllocatorAfterAllocation}

// Error implements the error interface.
func (e *Error) Error() string {
	switch e.kind {
	case errSecretDestroyed:
		return "secret: attempt to use a destroyed secret"
	case errSecretSizeMismatch:
		return fmt.Sprintf("secret: size mismatch: expected %d bytes, got %d", e.expected, e.got)
	case errSecretAlloc:
		if e.cause != nil {
			return fmt.Sprintf("secret: allocation failed: %s", e.cause)
		}
		return "secret: allocation failed"
	case errNilInput:
		return "secret: nil input provided"
	case errInvalidBudget:
		return "secret: allocator budget must be positive"
	case errAllocatorAlreadySet:
		return "secret: SetAllocator already called"
	case errAllocatorAfterAllocation:
		return "secret: SetAllocator called after the first allocation"
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

// Unwrap returns the underlying go-enclave failure, if any, so callers can
// match its sentinels — enclave.ErrBudgetExhausted for an allocation refused
// by the installed Allocator, enclave.ErrLockedMemoryUnavailable for one
// refused by the kernel.
func (e *Error) Unwrap() error {
	return e.cause
}

// newSizeMismatchError creates an error indicating an expected vs actual size mismatch.
func newSizeMismatchError(expected, got int) *Error {
	return &Error{kind: errSecretSizeMismatch, expected: expected, got: got}
}

// newAllocError creates an error indicating a locked-memory allocation failure.
func newAllocError(cause error) *Error {
	return &Error{kind: errSecretAlloc, cause: cause}
}
