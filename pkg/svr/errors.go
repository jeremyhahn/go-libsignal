package svr

import "fmt"

// Error represents an SVR protocol error.
type Error struct {
	kind    errorKind
	status  ResponseStatus
	servers int
	got     int
	tries   uint32
	detail  string
	cause   error
}

type errorKind int

const (
	errBadData errorKind = iota + 1
	errBadResponse
	errNumServers
	errNoUsableVersion
	errBadResponseStatus
	errRestoreFailed
	errEmptyPIN
	errHKDFExpansion
	errCipherCreate
	errDecryption
	errSecretSize
)

// ErrBadData indicates invalid protobuf data.
var ErrBadData = &Error{kind: errBadData}

// ErrBadResponse indicates an unexpected or missing server response.
var ErrBadResponse = &Error{kind: errBadResponse}

// ErrNoUsableVersion indicates that no auth version was usable across all servers.
var ErrNoUsableVersion = &Error{kind: errNoUsableVersion}

// ErrEmptyPIN indicates the PIN was empty.
var ErrEmptyPIN = &Error{kind: errEmptyPIN}

// ErrHKDFExpansion indicates HKDF expansion failed.
var ErrHKDFExpansion = &Error{kind: errHKDFExpansion}

// ErrCipherCreate indicates cipher creation failed.
var ErrCipherCreate = &Error{kind: errCipherCreate}

// ErrDecryption indicates decryption failed.
var ErrDecryption = &Error{kind: errDecryption}

// ErrSecretSize indicates the decrypted secret has the wrong size.
var ErrSecretSize = &Error{kind: errSecretSize}

// ResponseStatus represents the status field in an SVR4 response.
type ResponseStatus int32

const (
	StatusUnset          ResponseStatus = 0
	StatusOK             ResponseStatus = 1
	StatusInvalidRequest ResponseStatus = 2
	StatusMissing        ResponseStatus = 3
	StatusError          ResponseStatus = 4
	StatusRestore1Missing ResponseStatus = 5
	StatusVersionMismatch ResponseStatus = 6
)

func (s ResponseStatus) String() string {
	switch s {
	case StatusUnset:
		return "UNSET"
	case StatusOK:
		return "OK"
	case StatusInvalidRequest:
		return "INVALID_REQUEST"
	case StatusMissing:
		return "MISSING"
	case StatusError:
		return "ERROR"
	case StatusRestore1Missing:
		return "RESTORE1_MISSING"
	case StatusVersionMismatch:
		return "VERSION_MISMATCH"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", s)
	}
}

func (e *Error) Error() string {
	switch e.kind {
	case errBadData:
		return "svr: invalid protobuf data"
	case errBadResponse:
		return "svr: unexpected or missing server response"
	case errNumServers:
		return fmt.Sprintf("svr: inputs %d do not match the correct number of servers %d", e.got, e.servers)
	case errNoUsableVersion:
		return "svr: no auth version was usable"
	case errBadResponseStatus:
		return fmt.Sprintf("svr: response status is not OK: %s", e.status)
	case errRestoreFailed:
		return fmt.Sprintf("svr: restore failed, %d tries remaining", e.tries)
	case errEmptyPIN:
		return "svr: PIN must not be empty"
	case errHKDFExpansion:
		if e.cause != nil {
			return fmt.Sprintf("svr: HKDF expansion failed: %v", e.cause)
		}
		return "svr: HKDF expansion failed"
	case errCipherCreate:
		if e.cause != nil {
			return fmt.Sprintf("svr: failed to create cipher: %v", e.cause)
		}
		return "svr: failed to create cipher"
	case errDecryption:
		if e.cause != nil {
			return fmt.Sprintf("svr: decryption failed: %v", e.cause)
		}
		return "svr: decryption failed"
	case errSecretSize:
		return fmt.Sprintf("svr: decrypted secret has wrong size: %s", e.detail)
	default:
		return "svr: unknown error"
	}
}

// Unwrap returns the underlying cause, if any.
func (e *Error) Unwrap() error {
	return e.cause
}

// Is implements errors.Is matching. Sentinel errors match by kind.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	return e.kind == t.kind
}

// TriesRemaining returns the number of tries remaining, valid for
// RestoreFailed errors.
func (e *Error) TriesRemaining() uint32 {
	return e.tries
}

// Status returns the bad response status, valid for BadResponseStatus errors.
func (e *Error) Status() ResponseStatus {
	return e.status
}

// newNumServersError creates an error indicating a mismatch between expected
// and actual number of server inputs.
func newNumServersError(servers, got int) *Error {
	return &Error{kind: errNumServers, servers: servers, got: got}
}

// newBadResponseStatusError creates an error for a non-OK response status.
func newBadResponseStatusError(status ResponseStatus) *Error {
	return &Error{kind: errBadResponseStatus, status: status}
}

// newRestoreFailedError creates an error indicating restore failure with the
// number of tries remaining.
func newRestoreFailedError(tries uint32) *Error {
	return &Error{kind: errRestoreFailed, tries: tries}
}
