package sealed

import "fmt"

// Error represents a sealed sender error.
type Error struct {
	kind  errorKind
	keyID uint32
}

type errorKind int

const (
	errSenderKeyMismatch        errorKind = iota + 1
	errServerCertificateRevoked
	errV2ReceivedMessageTooShort
	errV2ReceivedUnsupportedVersion
	errV2ReceivedEphemeralKeyMismatch
	errV2ReceivedDecryptFailed
	errV2ReceivedAuthTagMismatch
	errV2ReceivedDeserializeFailed
	errUnknownServerCertificateID
	errSelfSend
	errUnsupportedVersion
	errInvalidDeviceID
	errUnsupportedMessageType
	errDeviceIDOverflow
	errUnknownUSMCType
	errInvalidRegistrationID
)


// ErrSenderKeyMismatch indicates the decrypted static key does not match
// the sender's identity key in the certificate. This is a critical security
// check that prevents an attacker from substituting a different sender
// certificate inside a sealed sender message.
var ErrSenderKeyMismatch = &Error{kind: errSenderKeyMismatch}

// ErrServerCertificateRevoked indicates the server certificate's key ID
// has been revoked and must not be accepted.
var ErrServerCertificateRevoked = &Error{kind: errServerCertificateRevoked}

// ErrV2ReceivedMessageTooShort indicates the received v2 message is too short
// to contain the required fixed-size fields (C, AT, E.pub).
var ErrV2ReceivedMessageTooShort = &Error{kind: errV2ReceivedMessageTooShort}

// ErrV2ReceivedUnsupportedVersion indicates the received v2 message has an
// unsupported version byte (major version is not 2).
var ErrV2ReceivedUnsupportedVersion = &Error{kind: errV2ReceivedUnsupportedVersion}

// ErrV2ReceivedEphemeralKeyMismatch indicates the derived ephemeral public key
// does not match the one provided in the received v2 message.
var ErrV2ReceivedEphemeralKeyMismatch = &Error{kind: errV2ReceivedEphemeralKeyMismatch}

// ErrV2ReceivedDecryptFailed indicates AES-256-GCM-SIV decryption of the
// received v2 message payload failed.
var ErrV2ReceivedDecryptFailed = &Error{kind: errV2ReceivedDecryptFailed}

// ErrV2ReceivedAuthTagMismatch indicates the sender authentication tag in the
// received v2 message did not match the expected value.
var ErrV2ReceivedAuthTagMismatch = &Error{kind: errV2ReceivedAuthTagMismatch}

// ErrV2ReceivedDeserializeFailed indicates the decrypted USMC payload in the
// received v2 message could not be deserialized.
var ErrV2ReceivedDeserializeFailed = &Error{kind: errV2ReceivedDeserializeFailed}

// ErrUnknownServerCertificateID indicates the sender certificate references
// a server certificate ID that is not present in the known certificates table.
var ErrUnknownServerCertificateID = &Error{kind: errUnknownServerCertificateID}

// ErrSelfSend indicates the sealed sender message was sent by the local
// device to itself, which is not permitted.
var ErrSelfSend = &Error{kind: errSelfSend}

// ErrUnsupportedVersion indicates the sealed sender message has an
// unrecognized version byte.
var ErrUnsupportedVersion = &Error{kind: errUnsupportedVersion}

// ErrInvalidDeviceID indicates the sender certificate has a device ID of 0,
// which is invalid. The Rust reference uses NonZeroU8 for DeviceId, which
// rejects zero at the type level.
var ErrInvalidDeviceID = &Error{kind: errInvalidDeviceID}

// ErrUnsupportedMessageType indicates the USMC contains a message type that
// is not handled in the sealed sender decrypt path. The Rust reference only
// handles PREKEY_MESSAGE and MESSAGE types; SENDERKEY_MESSAGE and
// PLAINTEXT_CONTENT are not valid in this context.
var ErrUnsupportedMessageType = &Error{kind: errUnsupportedMessageType}

// ErrDeviceIDOverflow indicates a device ID exceeds the maximum value (255)
// that can be encoded in the v2 multi-recipient wire format.
var ErrDeviceIDOverflow = &Error{kind: errDeviceIDOverflow}

// ErrUnknownUSMCType indicates the USMC contains a message type value that
// does not correspond to any known protobuf enum variant (1=PreKey, 2=Message,
// 7=SenderKey, 8=Plaintext).
var ErrUnknownUSMCType = &Error{kind: errUnknownUSMCType}

// ErrInvalidRegistrationID indicates the registration ID contains bits set
// outside the valid 14-bit range (0x3FFF), which signals corruption or
// tampering rather than a value that should be silently masked.
var ErrInvalidRegistrationID = &Error{kind: errInvalidRegistrationID}

func (e *Error) Error() string {
	switch e.kind {
	case errSenderKeyMismatch:
		return "sealed: sender certificate key does not match message key"
	case errServerCertificateRevoked:
		return fmt.Sprintf("sealed: server certificate with key ID 0x%X has been revoked", e.keyID)
	case errV2ReceivedMessageTooShort:
		return "sealed: v2 received message too short"
	case errV2ReceivedUnsupportedVersion:
		return "sealed: v2 received message has unsupported version"
	case errV2ReceivedEphemeralKeyMismatch:
		return "sealed: v2 received message ephemeral key validation failed"
	case errV2ReceivedDecryptFailed:
		return "sealed: v2 received message payload decryption failed"
	case errV2ReceivedAuthTagMismatch:
		return "sealed: v2 received message sender authentication tag mismatch"
	case errV2ReceivedDeserializeFailed:
		return "sealed: v2 received message USMC deserialization failed"
	case errUnknownServerCertificateID:
		return fmt.Sprintf("sealed: unknown server certificate ID 0x%X", e.keyID)
	case errSelfSend:
		return "sealed: self-send detected"
	case errUnsupportedVersion:
		return "sealed: unsupported sealed sender version"
	case errInvalidDeviceID:
		return "sealed: sender certificate has invalid device ID (must be > 0)"
	case errUnsupportedMessageType:
		return "sealed: unsupported message type in USMC"
	case errDeviceIDOverflow:
		return "sealed: device ID exceeds maximum value 255 for v2 wire format"
	case errUnknownUSMCType:
		return "sealed: unknown USMC message type"
	case errInvalidRegistrationID:
		return "sealed: registration ID has bits set outside valid 14-bit range"
	default:
		return "sealed: unknown error"
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

// newServerCertificateRevokedError creates an error for a revoked server certificate key ID.
func newServerCertificateRevokedError(keyID uint32) *Error {
	return &Error{kind: errServerCertificateRevoked, keyID: keyID}
}

// newUnknownServerCertificateIDError creates an error for an unrecognized server certificate ID.
func newUnknownServerCertificateIDError(keyID uint32) *Error {
	return &Error{kind: errUnknownServerCertificateID, keyID: keyID}
}

// V2OperationError represents an error during v2 sealed sender encrypt/decrypt
// operations that wraps an underlying cause with context.
type V2OperationError struct {
	Operation string
	Err       error
}

// Error returns a human-readable description of the v2 operation error.
func (e *V2OperationError) Error() string {
	return fmt.Sprintf("sealed: %s: %v", e.Operation, e.Err)
}

// Unwrap returns the underlying error.
func (e *V2OperationError) Unwrap() error {
	return e.Err
}

// V2InputError represents an invalid input to a v2 sealed sender operation.
type V2InputError struct {
	Detail string
}

// Error returns a human-readable description of the input error.
func (e *V2InputError) Error() string {
	return fmt.Sprintf("sealed: %s", e.Detail)
}

// V2ParseError represents an error parsing a v2 sealed sender message.
type V2ParseError struct {
	Detail string
	Err    error
}

// Error returns a human-readable description of the parse error.
func (e *V2ParseError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("sealed: %s: %v", e.Detail, e.Err)
	}
	return fmt.Sprintf("sealed: %s", e.Detail)
}

// Unwrap returns the underlying error.
func (e *V2ParseError) Unwrap() error {
	return e.Err
}

// V1StructureError represents a structural error in a v1 sealed sender message.
type V1StructureError struct {
	Detail string
}

// Error returns a human-readable description of the structure error.
func (e *V1StructureError) Error() string {
	return fmt.Sprintf("sealed: %s", e.Detail)
}

// CertificateError represents a structural error in a sealed sender certificate.
type CertificateError struct {
	Detail string
}

// Error returns a human-readable description of the certificate error.
func (e *CertificateError) Error() string {
	return fmt.Sprintf("sealed: %s", e.Detail)
}

// IdentityStoreError indicates the identity store does not support loading
// remote identities.
type IdentityStoreError struct{}

// Error returns a human-readable description of the identity store error.
func (e *IdentityStoreError) Error() string {
	return "sealed: cannot retrieve recipient identity key; identity store does not support loading remote identities"
}
