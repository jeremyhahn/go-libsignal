// Package spqr implements the Sparse Post-Quantum Ratchet (SPQR) protocol
// as defined in Section 5 of the Double Ratchet specification. SPQR provides
// epoch-based post-quantum key derivation using an SCKA (Sparse Continuous
// Key Agreement) protocol, layered on top of the ML-KEM Braid.
package spqr

import "fmt"

// ErrUnknownEpoch is returned when an operation references an epoch
// that does not exist in the chain map.
type ErrUnknownEpoch struct {
	Epoch uint64
}

func (e *ErrUnknownEpoch) Error() string {
	return fmt.Sprintf("spqr: unknown epoch %d", e.Epoch)
}

// ErrOldEpoch is returned when a new epoch is not strictly greater
// than the current epoch.
type ErrOldEpoch struct {
	Current  uint64
	Received uint64
}

func (e *ErrOldEpoch) Error() string {
	return fmt.Sprintf("spqr: old epoch %d, current is %d", e.Received, e.Current)
}

// ErrMaxSkippedKeys is returned when attempting to skip more message keys
// than the configured maximum, which prevents denial-of-service via
// unbounded memory growth.
type ErrMaxSkippedKeys struct {
	Limit uint32
}

func (e *ErrMaxSkippedKeys) Error() string {
	return fmt.Sprintf("spqr: exceeded max skipped keys limit of %d", e.Limit)
}

// ErrDecryptionFailed is returned when decryption of a ciphertext fails,
// typically due to an invalid message key or corrupted data.
type ErrDecryptionFailed struct {
	Epoch   uint64
	Counter uint32
	Err     error
}

func (e *ErrDecryptionFailed) Error() string {
	return fmt.Sprintf("spqr: decryption failed at epoch %d counter %d: %v",
		e.Epoch, e.Counter, e.Err)
}

func (e *ErrDecryptionFailed) Unwrap() error {
	return e.Err
}

// ErrKeyAlreadyRequested is returned when a message key at the given counter
// has already been derived and consumed. Re-requesting the same counter is
// not allowed to prevent key reuse.
type ErrKeyAlreadyRequested struct {
	Counter uint32
}

func (e *ErrKeyAlreadyRequested) Error() string {
	return fmt.Sprintf("spqr: key already requested at counter %d", e.Counter)
}

// ErrKeyTrimmed is returned when a message key at the given counter has been
// garbage-collected because the receive chain has advanced too far past it.
type ErrKeyTrimmed struct {
	Counter uint32
}

func (e *ErrKeyTrimmed) Error() string {
	return fmt.Sprintf("spqr: key trimmed at counter %d", e.Counter)
}

// ErrMaxJump is returned when the requested counter exceeds the maximum
// allowed forward jump from the current receive counter.
type ErrMaxJump struct {
	From uint32
	To   uint32
}

func (e *ErrMaxJump) Error() string {
	return fmt.Sprintf("spqr: key jump too large from %d to %d", e.From, e.To)
}

// ErrSendEpochDecreased is returned when the send path requests an epoch
// that is strictly less than the last epoch used for sending, violating
// send epoch monotonicity.
type ErrSendEpochDecreased struct {
	Current   uint64
	Requested uint64
}

func (e *ErrSendEpochDecreased) Error() string {
	return fmt.Sprintf("spqr: send epoch decreased from %d to %d", e.Current, e.Requested)
}

// ErrCounterExhausted is returned when a chain's send or receive counter
// has reached math.MaxUint32 and cannot be incremented further.
type ErrCounterExhausted struct {
	Epoch uint64
}

func (e *ErrCounterExhausted) Error() string {
	return fmt.Sprintf("spqr: counter exhausted at epoch %d", e.Epoch)
}

// ErrSendKeyDestroyed is returned when the send key for the requested epoch
// has already been destroyed (cleared during epoch advancement).
type ErrSendKeyDestroyed struct {
	Epoch uint64
}

func (e *ErrSendKeyDestroyed) Error() string {
	return fmt.Sprintf("spqr: send key destroyed at epoch %d", e.Epoch)
}

// ErrInvalidInput is returned when input parameters fail validation.
type ErrInvalidInput struct {
	Field  string
	Reason string
}

func (e *ErrInvalidInput) Error() string {
	return fmt.Sprintf("spqr: invalid input %s: %s", e.Field, e.Reason)
}

// ErrEpochOverflow is returned when the epoch counter has reached math.MaxUint64
// and cannot be incremented further without wrapping.
type ErrEpochOverflow struct{}

func (e *ErrEpochOverflow) Error() string {
	return "spqr: epoch counter overflow"
}

// ErrBraidTooLarge is returned when serialized braid state exceeds the
// maximum allowed size during deserialization.
type ErrBraidTooLarge struct {
	Size uint32
	Max  int
}

func (e *ErrBraidTooLarge) Error() string {
	return fmt.Sprintf("spqr: braid serialized length %d exceeds maximum %d", e.Size, e.Max)
}

// ErrVersionNegotiationFailed is returned when version negotiation fails because
// the remote peer's PQR version is below the minimum acceptable version.
type ErrVersionNegotiationFailed struct {
	MinVersion Version
	GotVersion Version
}

func (e *ErrVersionNegotiationFailed) Error() string {
	return fmt.Sprintf("spqr: version negotiation failed: minimum %s, got %s",
		e.MinVersion, e.GotVersion)
}

// ErrInvalidPrevEncoding is returned when the proto Chain.Epoch.recv.prev
// field contains bytes whose length is not a multiple of 36 (the Rust
// KeyHistory record size: 4-byte BE index + 32-byte key). This indicates a
// corrupt or foreign-format state buffer.
//
// Rust reference: spqr/src/chain.rs KeyHistory::KEY_SIZE = 36.
type ErrInvalidPrevEncoding struct {
	Len int
}

func (e *ErrInvalidPrevEncoding) Error() string {
	return fmt.Sprintf("spqr: invalid prev encoding: length %d is not a multiple of 36", e.Len)
}

// ErrMacVerifyFailed is returned when MAC verification of a received message
// fails. Matches Rust's Error::MacVerifyFailed (lib.rs).
type ErrMacVerifyFailed struct{}

func (e *ErrMacVerifyFailed) Error() string {
	return "spqr: MAC verification failed"
}

// ErrVersionMismatch is returned when the received message version does not
// match the current state version and no negotiation is in progress. Matches
// Rust's Error::VersionMismatch (lib.rs recv:383).
type ErrVersionMismatch struct {
	State   Version
	Message Version
}

func (e *ErrVersionMismatch) Error() string {
	return fmt.Sprintf("spqr: version mismatch: state is %s, message is %s", e.State, e.Message)
}

// ErrErroneousDataReceived is returned when a message contains data that is
// structurally valid but semantically erroneous (e.g., unexpected payload for
// the current state). Matches Rust's Error::ErroneousDataReceived (lib.rs).
type ErrErroneousDataReceived struct {
	Reason string
}

func (e *ErrErroneousDataReceived) Error() string {
	return fmt.Sprintf("spqr: erroneous data received: %s", e.Reason)
}

// ErrChainNotAvailable is returned when a chain key is needed but no chain
// has been established (e.g., sending before negotiation completes with
// MinVersion > V0). Matches Rust's Error::ChainNotAvailable (lib.rs:283).
type ErrChainNotAvailable struct{}

func (e *ErrChainNotAvailable) Error() string {
	return "spqr: chain not available"
}
