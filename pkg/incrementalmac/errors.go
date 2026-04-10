package incrementalmac

// Error represents an incremental MAC error.
type Error struct {
	msg string
}

// Error implements the error interface.
func (e *Error) Error() string {
	return e.msg
}

var (
	// ErrChunkSizeTooSmall is returned when the chunk size is below MinChunkSize.
	ErrChunkSizeTooSmall = &Error{msg: "incrementalmac: chunk size below minimum"}

	// ErrChunkSizeTooLarge is returned when the chunk size exceeds MaxChunkSize.
	ErrChunkSizeTooLarge = &Error{msg: "incrementalmac: chunk size exceeds maximum"}

	// ErrMACMismatch is returned when a computed MAC does not match the expected value.
	ErrMACMismatch = &Error{msg: "incrementalmac: MAC mismatch"}

	// ErrTooFewMACs is returned when validation runs out of expected MACs before all data is consumed.
	ErrTooFewMACs = &Error{msg: "incrementalmac: not enough expected MACs"}

	// ErrUnconsumedMACs is returned when finalization completes but expected MACs remain.
	ErrUnconsumedMACs = &Error{msg: "incrementalmac: unconsumed expected MACs"}

	// ErrAlreadyFinalized is returned when Update or Finalize is called after
	// the incremental MAC has already been finalized.
	ErrAlreadyFinalized = &Error{msg: "incrementalmac: already finalized"}
)
