// Package mlkembraid implements the ML-KEM Braid Sparse Continuous Key Agreement
// (SCKA) protocol, porting the Rust sparsepostquantumratchet crate v1.5.1
// (github.com/signalapp/sparsepostquantumratchet).
//
// It provides post-quantum key agreement using ML-KEM-768 alongside the EC
// Double Ratchet for hybrid post-quantum security in ongoing sessions.
//
// The preferred KEM implementation is IncrementalMLKEM768KEM, which uses
// internal/incremental_mlkem768 — a pure-Go, byte-wire-compatible port of the
// libcrux-ml-kem `incremental` feature. It splits ML-KEM-768 encapsulation
// into Encaps1 (using only pk1 = rho||H(ek), 64 bytes) and Encaps2 (using the
// full t-vector, pk2, 1152 bytes), matching the Rust SPQR wire format exactly:
//
//   - Header:       pk1 = rho(32) || H(ek)(32)              64 bytes
//   - EK vector:    pk2 = ByteEncode12(t_ntt)             1152 bytes
//   - ct1:          ringCompressEncode10(u)                 960 bytes
//   - ct2:          ringCompressEncode4(v)                  128 bytes
//   - EncapsState:  r_as_ntt(1536) || error2(512) || rnd(32) 2080 bytes
//
// The legacy MLKEM768IncrementalKEM is retained for backward compatibility but
// does not produce Rust-compatible wire bytes.
package mlkembraid

import "fmt"

// ErrInvalidState is returned when a state transition is not valid for the current state.
type ErrInvalidState struct {
	Current  StateKind
	Expected StateKind
	Op       string
}

func (e *ErrInvalidState) Error() string {
	return fmt.Sprintf("mlkembraid: invalid state for %s: current=%s, expected=%s",
		e.Op, e.Current, e.Expected)
}

// ErrInvalidEpoch is returned when a received message has an unexpected epoch.
type ErrInvalidEpoch struct {
	Expected uint64
	Received uint64
}

func (e *ErrInvalidEpoch) Error() string {
	return fmt.Sprintf("mlkembraid: invalid epoch: expected=%d, received=%d",
		e.Expected, e.Received)
}

// ErrInvalidMessageType is returned when a received message has an unexpected type.
type ErrInvalidMessageType struct {
	Expected MessageType
	Received MessageType
}

func (e *ErrInvalidMessageType) Error() string {
	return fmt.Sprintf("mlkembraid: invalid message type: expected=%s, received=%s",
		e.Expected, e.Received)
}

// ErrMACVerification is returned when a MAC verification fails.
type ErrMACVerification struct {
	Epoch uint64
	Kind  string
}

func (e *ErrMACVerification) Error() string {
	return fmt.Sprintf("mlkembraid: MAC verification failed for %s at epoch %d",
		e.Kind, e.Epoch)
}

// ErrDecoderIncomplete is returned when attempting to read a message from
// a decoder that has not received all required chunks.
type ErrDecoderIncomplete struct {
	Received int
	Required int
}

func (e *ErrDecoderIncomplete) Error() string {
	return fmt.Sprintf("mlkembraid: decoder incomplete: received %d of %d chunks",
		e.Received, e.Required)
}

// ErrKEMOperation is returned when a KEM operation fails.
type ErrKEMOperation struct {
	Op  string
	Err error
}

func (e *ErrKEMOperation) Error() string {
	return fmt.Sprintf("mlkembraid: KEM %s failed: %v", e.Op, e.Err)
}

func (e *ErrKEMOperation) Unwrap() error {
	return e.Err
}

// ErrInvalidInput is returned when input parameters are invalid.
type ErrInvalidInput struct {
	Field  string
	Reason string
}

func (e *ErrInvalidInput) Error() string {
	return fmt.Sprintf("mlkembraid: invalid input %s: %s", e.Field, e.Reason)
}

// ErrChunkSize is returned when the chunk size is invalid.
type ErrChunkSize struct {
	Size   int
	Reason string
}

func (e *ErrChunkSize) Error() string {
	return fmt.Sprintf("mlkembraid: invalid chunk size %d: %s", e.Size, e.Reason)
}

// ErrHeaderFormat is returned when a header has an invalid format.
type ErrHeaderFormat struct {
	Reason string
}

func (e *ErrHeaderFormat) Error() string {
	return fmt.Sprintf("mlkembraid: invalid header format: %s", e.Reason)
}

// ErrChunkFormat is returned when a chunk has an invalid wire format.
type ErrChunkFormat struct {
	Reason string
}

func (e *ErrChunkFormat) Error() string {
	return fmt.Sprintf("mlkembraid: invalid chunk format: %s", e.Reason)
}

// ErrChunkIndex is returned when a chunk index is out of range.
type ErrChunkIndex struct {
	Index uint16
	Total uint16
}

func (e *ErrChunkIndex) Error() string {
	return fmt.Sprintf("mlkembraid: chunk index %d out of range [0, %d)", e.Index, e.Total)
}

// ErrChunkCount is returned when the number of chunks exceeds the maximum.
type ErrChunkCount struct {
	Count int
	Max   int
}

func (e *ErrChunkCount) Error() string {
	return fmt.Sprintf("mlkembraid: chunk count %d exceeds maximum %d", e.Count, e.Max)
}

// ErrEpochOverflow is returned when the epoch counter has reached math.MaxUint64
// and cannot be incremented further without wrapping.
type ErrEpochOverflow struct{}

func (e *ErrEpochOverflow) Error() string {
	return "mlkembraid: epoch counter overflow"
}

// ErrEpochOutOfRange is returned when a received message has an epoch that is
// too far ahead of the current state epoch.
type ErrEpochOutOfRange struct {
	Expected uint64
	Got      uint64
}

func (e *ErrEpochOutOfRange) Error() string {
	return fmt.Sprintf("mlkembraid: epoch out of range: expected at most %d, got %d",
		e.Expected+1, e.Got)
}
