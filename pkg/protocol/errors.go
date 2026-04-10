package protocol

import "fmt"

// Error represents a protocol message error.
type Error struct {
	kind    errorKind
	version int
	msgType string
	detail  string
}

type errorKind int

const (
	errLegacyVersion       errorKind = iota + 1
	errUnrecognizedVersion
	errIncompleteMessage
	errMissingKyberPayload
	errBadMac
	errInvalidMacKeyLength
	errInvalidKeyLength
	errMessageTooShort
)

// ErrLegacyVersion indicates a message with an unsupported legacy version was received.
var ErrLegacyVersion = &Error{kind: errLegacyVersion}

// ErrUnrecognizedVersion indicates a message with an unrecognized future version was received.
var ErrUnrecognizedVersion = &Error{kind: errUnrecognizedVersion}

// ErrIncompleteMessage indicates a message is missing required fields.
var ErrIncompleteMessage = &Error{kind: errIncompleteMessage}

// ErrMissingKyberPayload indicates a version 4+ PreKeySignalMessage is missing
// the required Kyber pre-key ID and ciphertext fields (PQXDH enforcement).
var ErrMissingKyberPayload = &Error{kind: errMissingKyberPayload}

// ErrBadMac indicates that message authentication code verification failed.
var ErrBadMac = &Error{kind: errBadMac}

// ErrInvalidMacKeyLength indicates the MAC key has an invalid length (must be 32 bytes).
var ErrInvalidMacKeyLength = &Error{kind: errInvalidMacKeyLength}

// ErrInvalidKeyLength indicates a key field has an invalid length.
var ErrInvalidKeyLength = &Error{kind: errInvalidKeyLength}

// ErrMessageTooShort indicates the serialized message is too short to be valid.
var ErrMessageTooShort = &Error{kind: errMessageTooShort}

func (e *Error) Error() string {
	switch e.kind {
	case errLegacyVersion:
		return fmt.Sprintf("protocol: legacy %s version %d", e.msgType, e.version)
	case errUnrecognizedVersion:
		return fmt.Sprintf("protocol: unrecognized %s version %d", e.msgType, e.version)
	case errIncompleteMessage:
		if e.detail != "" {
			return fmt.Sprintf("protocol: incomplete %s: %s", e.msgType, e.detail)
		}
		return fmt.Sprintf("protocol: incomplete %s", e.msgType)
	case errMissingKyberPayload:
		return fmt.Sprintf("protocol: version %d PreKeySignalMessage requires Kyber pre-key payload (PQXDH)", e.version)
	case errBadMac:
		return "protocol: bad mac"
	case errInvalidMacKeyLength:
		return fmt.Sprintf("protocol: invalid MAC key length %d, expected 32", e.version)
	case errInvalidKeyLength:
		return fmt.Sprintf("protocol: invalid %s length: %s", e.msgType, e.detail)
	case errMessageTooShort:
		return fmt.Sprintf("protocol: %s too short", e.msgType)
	default:
		return "protocol: unknown error"
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

// newLegacyVersionError creates a legacy version error for the given message type and version.
func newLegacyVersionError(msgType string, version int) *Error {
	return &Error{kind: errLegacyVersion, msgType: msgType, version: version}
}

// newUnrecognizedVersionError creates an unrecognized version error for the given message type and version.
func newUnrecognizedVersionError(msgType string, version int) *Error {
	return &Error{kind: errUnrecognizedVersion, msgType: msgType, version: version}
}

// newIncompleteMessageError creates an incomplete message error for the given message type.
func newIncompleteMessageError(msgType string, detail string) *Error {
	return &Error{kind: errIncompleteMessage, msgType: msgType, detail: detail}
}

// newMissingKyberPayloadError creates a missing Kyber payload error for the given version.
func newMissingKyberPayloadError(version int) *Error {
	return &Error{kind: errMissingKyberPayload, version: version}
}

// newBadMacError creates a bad MAC error.
func newBadMacError() *Error {
	return &Error{kind: errBadMac}
}

// newInvalidMacKeyLengthError creates an invalid MAC key length error.
func newInvalidMacKeyLengthError(length int) *Error {
	return &Error{kind: errInvalidMacKeyLength, version: length}
}

// newInvalidKeyLengthError creates an invalid key length error.
func newInvalidKeyLengthError(keyName string, detail string) *Error {
	return &Error{kind: errInvalidKeyLength, msgType: keyName, detail: detail}
}

// newMessageTooShortError creates a message too short error.
func newMessageTooShortError(msgType string) *Error {
	return &Error{kind: errMessageTooShort, msgType: msgType}
}

// ServiceIdParseError indicates a failure parsing a ServiceId.
type ServiceIdParseError struct {
	Detail string
	Err    error
}

func (e *ServiceIdParseError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("protocol: %s: %v", e.Detail, e.Err)
	}
	return fmt.Sprintf("protocol: %s", e.Detail)
}

func (e *ServiceIdParseError) Unwrap() error {
	return e.Err
}

// EmptyMessageError indicates a message was empty when content was expected.
type EmptyMessageError struct {
	MessageType string
}

func (e *EmptyMessageError) Error() string {
	return fmt.Sprintf("protocol: %s data is empty", e.MessageType)
}

// ContentTooShortError indicates content is too short to parse.
type ContentTooShortError struct {
	MessageType string
}

func (e *ContentTooShortError) Error() string {
	return fmt.Sprintf("protocol: %s too short", e.MessageType)
}
