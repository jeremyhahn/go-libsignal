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
	errLegacyVersion errorKind = iota + 1
	errUnrecognizedVersion
	errIncompleteMessage
	errMissingKyberPayload
	errBadMac
	errInvalidMacKeyLength
	errInvalidKeyLength
	errMessageTooShort
	errInvalidContentProto
	errMissingDecryptionErrorMessage
	errDecryptionErrorMessageDeserialize
	errAddressMismatch
	errInvalidArgumentPlaintext
	errInvalidAddressForBinding
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

// ErrInvalidContentProto indicates the body could not be parsed as a Content protobuf.
var ErrInvalidContentProto = &Error{kind: errInvalidContentProto}

// ErrMissingDecryptionErrorMessage indicates the Content proto has no decryption_error_message field.
var ErrMissingDecryptionErrorMessage = &Error{kind: errMissingDecryptionErrorMessage}

// ErrDecryptionErrorMessageDeserialize indicates the nested DecryptionErrorMessage bytes
// could not be deserialized.
var ErrDecryptionErrorMessageDeserialize = &Error{kind: errDecryptionErrorMessageDeserialize}

// ErrAddressMismatch indicates that the addresses field carried in a SignalMessage
// does not match the expected (sender, recipient) reserialization.
var ErrAddressMismatch = &Error{kind: errAddressMismatch}

// ErrInvalidArgumentPlaintext is returned by DecryptionErrorMessageForOriginal
// when the caller passes PLAINTEXT_TYPE as the original message type. Rust returns
// SignalProtocolError::InvalidArgument in this case; plaintext content is not
// encrypted and therefore cannot produce a meaningful ratchet key for re-delivery.
//
// Mirrors Rust libsignal_protocol SignalProtocolError::InvalidArgument at
// rust/protocol/src/protocol.rs:898-900.
var ErrInvalidArgumentPlaintext = &Error{kind: errInvalidArgumentPlaintext}

// ErrInvalidAddressForBinding is returned by NewSignalMessage when non-nil
// addresses are provided but cannot be serialized into the addresses binding
// field (proto field 6) because a device ID is outside the valid range [1, 127]
// or an address name is not a valid ServiceId string.
//
// Passing nil for both addresses is the legacy unbound format and does not
// return this error. Only asymmetric (one nil, one non-nil) or structurally
// invalid addresses trigger this error.
//
// Mirrors Rust SignalProtocolError::InvalidArgument raised in
// rust/protocol/src/protocol.rs when address serialization fails.
var ErrInvalidAddressForBinding = &Error{kind: errInvalidAddressForBinding}

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
	case errInvalidContentProto:
		return "protocol: body is not a valid Content protobuf"
	case errMissingDecryptionErrorMessage:
		return "protocol: Content does not contain a decryption_error_message field"
	case errDecryptionErrorMessageDeserialize:
		if e.detail != "" {
			return fmt.Sprintf("protocol: failed to deserialize DecryptionErrorMessage: %s", e.detail)
		}
		return "protocol: failed to deserialize DecryptionErrorMessage"
	case errAddressMismatch:
		return "protocol: address mismatch: SignalMessage addresses field does not match expected sender/recipient"
	case errInvalidArgumentPlaintext:
		return "protocol: cannot create a DecryptionErrorMessage for plaintext content; it is not encrypted"
	case errInvalidAddressForBinding:
		return "protocol: non-nil addresses cannot be serialized into the address-binding field; device ID must be 1-127 and names must be valid ServiceId strings"
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

// newInvalidContentProtoError creates an invalid Content proto error.
func newInvalidContentProtoError() *Error {
	return &Error{kind: errInvalidContentProto}
}

// newMissingDecryptionErrorMessageError creates a missing decryption error message error.
func newMissingDecryptionErrorMessageError() *Error {
	return &Error{kind: errMissingDecryptionErrorMessage}
}

// newDecryptionErrorMessageDeserializeError creates a deserialization failure error
// for the nested DecryptionErrorMessage, including the underlying cause as detail.
func newDecryptionErrorMessageDeserializeError(detail string) *Error {
	return &Error{kind: errDecryptionErrorMessageDeserialize, detail: detail}
}

// newAddressMismatchError creates an address mismatch error for VerifyMacWithAddresses.
func newAddressMismatchError() *Error {
	return &Error{kind: errAddressMismatch}
}

// newInvalidArgumentPlaintextError creates the error returned by
// DecryptionErrorMessageForOriginal when the original message type is PLAINTEXT_TYPE.
func newInvalidArgumentPlaintextError() *Error {
	return &Error{kind: errInvalidArgumentPlaintext}
}

// newInvalidAddressForBindingError creates the error returned by NewSignalMessage
// when non-nil addresses fail SerializeAddresses validation.
func newInvalidAddressForBindingError() *Error {
	return &Error{kind: errInvalidAddressForBinding}
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

// ErrInvalidServiceIdLength indicates a ServiceId binary encoding has an
// invalid length. For the variable-width format: ACI must be exactly 16 bytes;
// PNI must be exactly 17 bytes (0x01 tag || 16-byte UUID).
//
// Mirrors Rust libsignal_core ServiceId::parse_from_service_id_binary at
// rust/core/src/address.rs:230-245.
var ErrInvalidServiceIdLength = &ServiceIdParseError{Detail: "invalid ServiceId binary length"}

// ErrInvalidServiceIdString indicates a ServiceId string has an invalid format.
// Accepted formats: bare hyphenated UUID (→ ACI), "ACI:<hyphenated-uuid>" (→ ACI,
// legacy Go form), or "PNI:<hyphenated-uuid>" (→ PNI). The lowercase "aci:" prefix
// and un-hyphenated (32-char) forms are rejected.
//
// Mirrors Rust libsignal_core ServiceId::parse_from_service_id_string at
// rust/core/src/address.rs:263-279.
var ErrInvalidServiceIdString = &ServiceIdParseError{Detail: "invalid ServiceId string"}

// ErrInvalidDeviceID indicates a device ID is outside the valid range 1-127.
// Signal protocol requires device IDs to be in [1, 127] (Java DeviceId int,
// Rust DeviceId u8 constrained to non-zero ≤ 127).
var ErrInvalidDeviceID = &DeviceIDError{}

// DeviceIDError indicates a device ID is outside the valid Signal range 1-127.
type DeviceIDError struct {
	ID uint32
}

func (e *DeviceIDError) Error() string {
	if e.ID == 0 {
		return "protocol: device ID must be between 1 and 127 (got 0)"
	}
	return fmt.Sprintf("protocol: device ID must be between 1 and 127 (got %d)", e.ID)
}

// Is implements errors.Is matching for DeviceIDError sentinels.
func (e *DeviceIDError) Is(target error) bool {
	_, ok := target.(*DeviceIDError)
	return ok
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
