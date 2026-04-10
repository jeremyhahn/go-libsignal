// Package sesame implements the Sesame session management algorithm for
// the Signal Protocol. It manages sessions across multiple users and devices,
// handling session lifecycle, expiration, and encryption/decryption routing.
package sesame

import "fmt"

// SesameError is the base error type for all Sesame session management errors.
type SesameError struct {
	Kind    ErrorKind
	Message string
	Cause   error
}

// ErrorKind classifies the type of Sesame error.
type ErrorKind int

const (
	// ErrorKindNoActiveSession indicates no active session exists for encryption.
	ErrorKindNoActiveSession ErrorKind = iota + 1
	// ErrorKindNoUserRecord indicates the user record was not found.
	ErrorKindNoUserRecord
	// ErrorKindNoDeviceRecord indicates the device record was not found.
	ErrorKindNoDeviceRecord
	// ErrorKindSessionExpired indicates the session has expired.
	ErrorKindSessionExpired
	// ErrorKindStaleDevice indicates the device has been marked stale.
	ErrorKindStaleDevice
	// ErrorKindStaleUser indicates the user has been marked stale.
	ErrorKindStaleUser
	// ErrorKindDecryptionFailed indicates all sessions failed to decrypt.
	ErrorKindDecryptionFailed
	// ErrorKindMaxLatencyExceeded indicates a stale record exceeded max latency.
	ErrorKindMaxLatencyExceeded
	// ErrorKindInvalidConfig indicates the configuration is invalid.
	ErrorKindInvalidConfig
	// ErrorKindMaxRetriesExceeded indicates the send loop exceeded the retry limit.
	ErrorKindMaxRetriesExceeded
	// ErrorKindUserNotFound indicates the server reported the user does not exist.
	ErrorKindUserNotFound
	// ErrorKindSelfDevice indicates an attempt to store a session for the local device.
	ErrorKindSelfDevice
	// ErrorKindMaxDevicesExceeded indicates the per-user device limit has been reached.
	ErrorKindMaxDevicesExceeded
	// ErrorKindMaxUsersExceeded indicates the maximum number of stored users has been reached.
	ErrorKindMaxUsersExceeded
	// ErrorKindStoreCloneFailed indicates a store operation failed because
	// cloning a record was not possible.
	ErrorKindStoreCloneFailed
	// ErrorKindSendExpired indicates the active session has exceeded MAXSEND
	// and can no longer be used for encryption.
	ErrorKindSendExpired
	// ErrorKindRestoreFailed indicates that a rollback of the user record
	// failed after an operation error. The Cause holds the original error
	// and RestoreErr holds the restore-specific error.
	ErrorKindRestoreFailed
)

// Error returns the string representation of the error.
func (e *SesameError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("sesame: %s: %v", e.Message, e.Cause)
	}
	return fmt.Sprintf("sesame: %s", e.Message)
}

// Unwrap returns the underlying cause of the error.
func (e *SesameError) Unwrap() error {
	return e.Cause
}

// Is reports whether the target error matches this error's kind.
func (e *SesameError) Is(target error) bool {
	t, ok := target.(*SesameError)
	if !ok {
		return false
	}
	return e.Kind == t.Kind
}

// Sentinel errors for comparison with errors.Is.
var (
	ErrNoActiveSession    = &SesameError{Kind: ErrorKindNoActiveSession, Message: "no active session"}
	ErrNoUserRecord       = &SesameError{Kind: ErrorKindNoUserRecord, Message: "no user record"}
	ErrNoDeviceRecord     = &SesameError{Kind: ErrorKindNoDeviceRecord, Message: "no device record"}
	ErrSessionExpired     = &SesameError{Kind: ErrorKindSessionExpired, Message: "session expired"}
	ErrStaleDevice        = &SesameError{Kind: ErrorKindStaleDevice, Message: "device is stale"}
	ErrStaleUser          = &SesameError{Kind: ErrorKindStaleUser, Message: "user is stale"}
	ErrDecryptionFailed   = &SesameError{Kind: ErrorKindDecryptionFailed, Message: "decryption failed"}
	ErrMaxLatencyExceeded = &SesameError{Kind: ErrorKindMaxLatencyExceeded, Message: "max latency exceeded"}
	ErrInvalidConfig      = &SesameError{Kind: ErrorKindInvalidConfig, Message: "invalid configuration"}
	ErrMaxRetriesExceeded = &SesameError{Kind: ErrorKindMaxRetriesExceeded, Message: "max send retries exceeded"}
	ErrUserNotFound       = &SesameError{Kind: ErrorKindUserNotFound, Message: "user not found"}
	ErrSelfDevice         = &SesameError{Kind: ErrorKindSelfDevice, Message: "cannot store session for local device"}
	ErrMaxDevicesExceeded = &SesameError{Kind: ErrorKindMaxDevicesExceeded, Message: "max devices per user exceeded"}
	ErrMaxUsersExceeded   = &SesameError{Kind: ErrorKindMaxUsersExceeded, Message: "max users exceeded"}
	ErrStoreCloneFailed   = &SesameError{Kind: ErrorKindStoreCloneFailed, Message: "store clone failed"}
	ErrSendExpired        = &SesameError{Kind: ErrorKindSendExpired, Message: "session send-expired"}
	ErrRestoreFailed      = &SesameError{Kind: ErrorKindRestoreFailed, Message: "user record restore failed"}
)

// RestoreError wraps both an original operation error and a restore/rollback
// error, so the caller knows both what failed and that the rollback also failed.
type RestoreError struct {
	// OriginalErr is the error from the operation that triggered the rollback.
	OriginalErr error
	// RestoreErr is the error from the failed rollback attempt.
	RestoreErr error
}

// Error returns a string describing both the original and restore errors.
func (e *RestoreError) Error() string {
	return fmt.Sprintf("sesame: restore failed after error: original=%v, restore=%v", e.OriginalErr, e.RestoreErr)
}

// Unwrap returns the original error so errors.Is/As can match it.
func (e *RestoreError) Unwrap() error {
	return e.OriginalErr
}

// Is reports whether the target matches RestoreError by kind.
func (e *RestoreError) Is(target error) bool {
	_, ok := target.(*RestoreError)
	return ok
}

// NewRestoreFailedError creates a RestoreError wrapping both the original
// operation error and the restore error.
func NewRestoreFailedError(originalErr, restoreErr error) *RestoreError {
	return &RestoreError{
		OriginalErr: originalErr,
		RestoreErr:  restoreErr,
	}
}

// NewNoActiveSessionError creates an error indicating no active session for a device.
func NewNoActiveSessionError(userID string, deviceID uint32) *SesameError {
	return &SesameError{
		Kind:    ErrorKindNoActiveSession,
		Message: fmt.Sprintf("no active session for user %s device %d", userID, deviceID),
	}
}

// NewNoUserRecordError creates an error indicating a missing user record.
func NewNoUserRecordError(userID string) *SesameError {
	return &SesameError{
		Kind:    ErrorKindNoUserRecord,
		Message: fmt.Sprintf("no user record for %s", userID),
	}
}

// NewNoDeviceRecordError creates an error indicating a missing device record.
func NewNoDeviceRecordError(userID string, deviceID uint32) *SesameError {
	return &SesameError{
		Kind:    ErrorKindNoDeviceRecord,
		Message: fmt.Sprintf("no device record for user %s device %d", userID, deviceID),
	}
}

// NewDecryptionFailedError creates an error indicating all sessions failed to decrypt.
func NewDecryptionFailedError(userID string, deviceID uint32, cause error) *SesameError {
	return &SesameError{
		Kind:    ErrorKindDecryptionFailed,
		Message: fmt.Sprintf("all sessions failed to decrypt for user %s device %d", userID, deviceID),
		Cause:   cause,
	}
}

// NewMaxLatencyExceededError creates an error for stale records past max latency.
func NewMaxLatencyExceededError(entity string) *SesameError {
	return &SesameError{
		Kind:    ErrorKindMaxLatencyExceeded,
		Message: fmt.Sprintf("stale %s exceeded max latency", entity),
	}
}

// NewInvalidConfigError creates an error for invalid configuration parameters.
func NewInvalidConfigError(reason string) *SesameError {
	return &SesameError{
		Kind:    ErrorKindInvalidConfig,
		Message: fmt.Sprintf("invalid configuration: %s", reason),
	}
}

// NewMaxRetriesExceededError creates an error for exceeding the send retry limit.
func NewMaxRetriesExceededError(userID string, attempts int) *SesameError {
	return &SesameError{
		Kind:    ErrorKindMaxRetriesExceeded,
		Message: fmt.Sprintf("send loop for user %s exceeded %d retries", userID, attempts),
	}
}

// NewUserNotFoundError creates an error indicating the server reported
// the user does not exist.
func NewUserNotFoundError(userID string) *SesameError {
	return &SesameError{
		Kind:    ErrorKindUserNotFound,
		Message: fmt.Sprintf("server reported user %s not found", userID),
	}
}

// NewSelfDeviceError creates an error indicating an attempt to create a session
// for the local device, which is prohibited by the Sesame specification.
func NewSelfDeviceError(userID string, deviceID uint32) *SesameError {
	return &SesameError{
		Kind:    ErrorKindSelfDevice,
		Message: fmt.Sprintf("cannot store session for local device: user %s device %d", userID, deviceID),
	}
}

// NewMaxDevicesExceededError creates an error indicating the per-user device
// limit has been reached.
func NewMaxDevicesExceededError(userID string, max int) *SesameError {
	return &SesameError{
		Kind:    ErrorKindMaxDevicesExceeded,
		Message: fmt.Sprintf("user %s has reached the maximum of %d devices", userID, max),
	}
}

// NewMaxUsersExceededError creates an error indicating the maximum number of
// stored users has been reached.
func NewMaxUsersExceededError(max int) *SesameError {
	return &SesameError{
		Kind:    ErrorKindMaxUsersExceeded,
		Message: fmt.Sprintf("store has reached the maximum of %d users", max),
	}
}

// NewSendExpiredError creates an error indicating the active session has
// exceeded MAXSEND and can no longer be used for encryption per spec section 4.2.
func NewSendExpiredError(userID string, deviceID uint32) *SesameError {
	return &SesameError{
		Kind:    ErrorKindSendExpired,
		Message: fmt.Sprintf("active session for user %s device %d has exceeded MAXSEND", userID, deviceID),
	}
}
