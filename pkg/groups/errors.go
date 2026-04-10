package groups

import "fmt"

// Error represents a group cipher error.
type Error struct {
	kind           errorKind
	groupID        string
	chainIteration uint32
	msgIteration   uint32
	version        uint32
}

type errorKind int

const (
	errNilSenderKeyStore errorKind = iota + 1
	errNilSenderKeyRecord
	errNilSenderKeyState
	errNoSenderKey
	errNoSenderKeyForID
	errInvalidSenderKeySession
	errSignatureVerification
	errTooManyFutureMessages
	errOldCounter
	errUnrecognizedMessageVersion
)

// ErrNilSenderKeyStore indicates a nil sender key store was provided.
var ErrNilSenderKeyStore = &Error{kind: errNilSenderKeyStore}

// ErrNilSenderKeyRecord indicates LoadSenderKey returned a nil record.
var ErrNilSenderKeyRecord = &Error{kind: errNilSenderKeyRecord}

// ErrNilSenderKeyState indicates SenderKeyState returned nil.
var ErrNilSenderKeyState = &Error{kind: errNilSenderKeyState}

// ErrNoSenderKey indicates no sender key exists for a given group.
var ErrNoSenderKey = &Error{kind: errNoSenderKey}

// ErrNoSenderKeyForID indicates no sender key state was found for the given chain ID.
var ErrNoSenderKeyForID = &Error{kind: errNoSenderKeyForID}

// ErrInvalidSenderKeySession indicates the sender key session is in an invalid
// state, such as having a nil chain key.
var ErrInvalidSenderKeySession = &Error{kind: errInvalidSenderKeySession}

// ErrSignatureVerification indicates the sender key message failed signature verification.
var ErrSignatureVerification = &Error{kind: errSignatureVerification}

// ErrTooManyFutureMessages indicates the message iteration is more than
// maxForwardJumps (25000) ahead of the current chain iteration.
var ErrTooManyFutureMessages = &Error{kind: errTooManyFutureMessages}

// ErrOldCounter indicates a message was received with an old counter that
// has already been consumed.
var ErrOldCounter = &Error{kind: errOldCounter}

// ErrUnrecognizedMessageVersion indicates the message version does not match
// the sender key state's expected version.
var ErrUnrecognizedMessageVersion = &Error{kind: errUnrecognizedMessageVersion}

func (e *Error) Error() string {
	switch e.kind {
	case errNilSenderKeyStore:
		return "groups: nil sender key store"
	case errNilSenderKeyRecord:
		return "groups: nil sender key record"
	case errNilSenderKeyState:
		return "groups: nil sender key state"
	case errNoSenderKey:
		return fmt.Sprintf("groups: no sender key for: %s", e.groupID)
	case errNoSenderKeyForID:
		return "groups: no sender key for ID"
	case errInvalidSenderKeySession:
		return "groups: invalid sender key session (nil chain key)"
	case errSignatureVerification:
		return "groups: sender key state failed signature verification"
	case errTooManyFutureMessages:
		return "groups: over 25000 messages into the future"
	case errOldCounter:
		return fmt.Sprintf("groups: received message with old counter: chain=%d, message=%d",
			e.chainIteration, e.msgIteration)
	case errUnrecognizedMessageVersion:
		return fmt.Sprintf("groups: unrecognized message version: %d", e.version)
	default:
		return "groups: unknown error"
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

// newNoSenderKeyError creates an error indicating no sender key for the given group.
func newNoSenderKeyError(groupID string) *Error {
	return &Error{kind: errNoSenderKey, groupID: groupID}
}

// newOldCounterError creates an error indicating an old counter was received.
func newOldCounterError(chainIteration, msgIteration uint32) *Error {
	return &Error{kind: errOldCounter, chainIteration: chainIteration, msgIteration: msgIteration}
}

// newUnrecognizedMessageVersionError creates an error indicating a version mismatch.
func newUnrecognizedMessageVersionError(version uint32) *Error {
	return &Error{kind: errUnrecognizedMessageVersion, version: version}
}
