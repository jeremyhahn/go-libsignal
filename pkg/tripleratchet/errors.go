// Package tripleratchet implements the Triple Ratchet: a hybrid EC + PQ
// encrypt/decrypt interface combining the Double Ratchet (via ECCipher) and
// the ML-KEM Braid SCKA (via mlkembraid) with SPQR chain key derivation.
//
// Rust source: rust/protocol/src/triple_ratchet.rs
package tripleratchet

import "fmt"

// ErrHybridKDFFailed is returned when the hybrid KDF fails to produce valid output.
type ErrHybridKDFFailed struct {
	Cause error
}

func (e *ErrHybridKDFFailed) Error() string {
	return fmt.Sprintf("tripleratchet: hybrid KDF failed: %v", e.Cause)
}

func (e *ErrHybridKDFFailed) Unwrap() error {
	return e.Cause
}

// ErrECRatchetFailed is returned when the EC Double Ratchet operation fails.
type ErrECRatchetFailed struct {
	Op    string
	Cause error
}

func (e *ErrECRatchetFailed) Error() string {
	return fmt.Sprintf("tripleratchet: EC ratchet %s failed: %v", e.Op, e.Cause)
}

func (e *ErrECRatchetFailed) Unwrap() error {
	return e.Cause
}

// ErrSPQRFailed is returned when an SPQR operation fails.
type ErrSPQRFailed struct {
	Op    string
	Cause error
}

func (e *ErrSPQRFailed) Error() string {
	return fmt.Sprintf("tripleratchet: SPQR %s failed: %v", e.Op, e.Cause)
}

func (e *ErrSPQRFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidCompositeMessage is returned when a composite message has structural issues.
type ErrInvalidCompositeMessage struct {
	Reason string
}

func (e *ErrInvalidCompositeMessage) Error() string {
	return fmt.Sprintf("tripleratchet: invalid composite message: %s", e.Reason)
}

// ErrMACVerificationFailed is returned when the HMAC tag does not match.
type ErrMACVerificationFailed struct{}

func (e *ErrMACVerificationFailed) Error() string {
	return "tripleratchet: MAC verification failed"
}

// ErrInvalidInput is returned when input validation fails.
type ErrInvalidInput struct {
	Field  string
	Reason string
}

func (e *ErrInvalidInput) Error() string {
	return fmt.Sprintf("tripleratchet: invalid input %s: %s", e.Field, e.Reason)
}

// ErrBraidFailed is returned when a Braid (SCKA) operation fails.
type ErrBraidFailed struct {
	Op    string
	Cause error
}

func (e *ErrBraidFailed) Error() string {
	return fmt.Sprintf("tripleratchet: braid %s failed: %v", e.Op, e.Cause)
}

func (e *ErrBraidFailed) Unwrap() error {
	return e.Cause
}

// ErrPQKeyOutOfRange is returned when a PQ counter jump exceeds maxPQJump.
type ErrPQKeyOutOfRange struct {
	Current uint32
	Got     uint32
	Max     uint32
}

func (e *ErrPQKeyOutOfRange) Error() string {
	return fmt.Sprintf("tripleratchet: PQ counter %d too far ahead of current %d (max jump %d)", e.Got, e.Current, e.Max)
}

// ErrPQKeyConsumed is returned when a PQ message key has already been consumed.
type ErrPQKeyConsumed struct {
	Counter uint32
}

func (e *ErrPQKeyConsumed) Error() string {
	return fmt.Sprintf("tripleratchet: PQ key at counter %d already consumed", e.Counter)
}

// ErrDecryptFailed is returned when AES-CBC decryption fails (e.g., bad padding).
type ErrDecryptFailed struct {
	Cause error
}

func (e *ErrDecryptFailed) Error() string {
	return fmt.Sprintf("tripleratchet: decryption failed: %v", e.Cause)
}

func (e *ErrDecryptFailed) Unwrap() error {
	return e.Cause
}

// ErrStateCorrupted is returned when a Decrypt fails AND the subsequent
// snapshot restore also fails, leaving the session in an unrecoverable state.
// Callers must discard the TripleRatchet session when they receive this error.
type ErrStateCorrupted struct {
	// DecryptErr is the original error that triggered the rollback attempt.
	DecryptErr error
	// RestoreErr is the error that occurred during snapshot restoration.
	RestoreErr error
}

func (e *ErrStateCorrupted) Error() string {
	return fmt.Sprintf("tripleratchet: session state corrupted: decrypt=%v; restore=%v", e.DecryptErr, e.RestoreErr)
}

// Unwrap implements multi-error unwrapping so errors.Is/As can inspect both causes.
func (e *ErrStateCorrupted) Unwrap() []error {
	return []error{e.DecryptErr, e.RestoreErr}
}
