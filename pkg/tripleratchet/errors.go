// Package tripleratchet implements the Triple Ratchet protocol as defined in
// Section 6 of the Double Ratchet specification. The Triple Ratchet combines
// the EC Double Ratchet with the Sparse PQ Ratchet (SPQR) to provide hybrid
// EC+PQ forward secrecy.
package tripleratchet

import "fmt"

// ErrHybridKDFFailed is returned when the hybrid key derivation function
// fails to produce valid output from the combined EC and PQ message keys.
type ErrHybridKDFFailed struct {
	Err error
}

func (e *ErrHybridKDFFailed) Error() string {
	return fmt.Sprintf("tripleratchet: hybrid KDF failed: %v", e.Err)
}

func (e *ErrHybridKDFFailed) Unwrap() error {
	return e.Err
}

// ErrECRatchetFailed is returned when the EC Double Ratchet operation
// (encrypt or decrypt) fails.
type ErrECRatchetFailed struct {
	Op  string
	Err error
}

func (e *ErrECRatchetFailed) Error() string {
	return fmt.Sprintf("tripleratchet: EC ratchet %s failed: %v", e.Op, e.Err)
}

func (e *ErrECRatchetFailed) Unwrap() error {
	return e.Err
}

// ErrSPQRFailed is returned when the SPQR (Sparse Post-Quantum Ratchet)
// operation fails during send or receive.
type ErrSPQRFailed struct {
	Op  string
	Err error
}

func (e *ErrSPQRFailed) Error() string {
	return fmt.Sprintf("tripleratchet: SPQR %s failed: %v", e.Op, e.Err)
}

func (e *ErrSPQRFailed) Unwrap() error {
	return e.Err
}

// ErrInvalidCompositeMessage is returned when a composite message cannot be
// parsed due to structural issues such as insufficient length, invalid
// framing, or corrupted data.
type ErrInvalidCompositeMessage struct {
	Reason string
}

func (e *ErrInvalidCompositeMessage) Error() string {
	return fmt.Sprintf("tripleratchet: invalid composite message: %s", e.Reason)
}

// ErrMACVerificationFailed is returned when the HMAC authentication tag
// on a ciphertext does not match the expected value, indicating the message
// was tampered with or corrupted in transit.
type ErrMACVerificationFailed struct{}

func (e *ErrMACVerificationFailed) Error() string {
	return "tripleratchet: MAC verification failed"
}

// ErrMessageTooLarge is returned when a composite message component exceeds
// the maximum allowed size during deserialization.
type ErrMessageTooLarge struct {
	Component string
	Size      int
	Max       int
}

func (e *ErrMessageTooLarge) Error() string {
	return fmt.Sprintf("tripleratchet: %s length %d exceeds maximum %d", e.Component, e.Size, e.Max)
}

// ErrInvalidInput is returned when input parameters fail validation.
type ErrInvalidInput struct {
	Field  string
	Reason string
}

func (e *ErrInvalidInput) Error() string {
	return fmt.Sprintf("tripleratchet: invalid input %s: %s", e.Field, e.Reason)
}
