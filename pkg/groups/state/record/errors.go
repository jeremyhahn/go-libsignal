package record

// SenderKeyRecordError represents an error from sender key record operations.
type SenderKeyRecordError struct {
	kind senderKeyRecordErrorKind
}

type senderKeyRecordErrorKind int

const (
	errNoSenderKeys     senderKeyRecordErrorKind = iota + 1
	errNoSenderKeyForID
)

// ErrNoSenderKeys indicates the sender key record contains no states.
var ErrNoSenderKeys = &SenderKeyRecordError{kind: errNoSenderKeys}

// ErrNoSenderKeyForID indicates no sender key state was found for the given chain ID.
var ErrNoSenderKeyForID = &SenderKeyRecordError{kind: errNoSenderKeyForID}

func (e *SenderKeyRecordError) Error() string {
	switch e.kind {
	case errNoSenderKeys:
		return "record: no sender keys"
	case errNoSenderKeyForID:
		return "record: no sender key for ID"
	default:
		return "record: unknown sender key error"
	}
}

// Is implements errors.Is matching by error kind.
func (e *SenderKeyRecordError) Is(target error) bool {
	t, ok := target.(*SenderKeyRecordError)
	if !ok {
		return false
	}
	return e.kind == t.kind
}
