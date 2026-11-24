package serialize

import "fmt"

// MessageDeserializeError indicates a failure deserializing a protocol message.
type MessageDeserializeError struct {
	MessageType string
	Detail      string
}

func (e *MessageDeserializeError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("serialize: %s: %s", e.MessageType, e.Detail)
	}
	return fmt.Sprintf("serialize: %s too short", e.MessageType)
}

// ErrInvalidProtobufEncoding indicates a required protobuf field is absent or
// has an invalid value. Mirrors Rust's SignalProtocolError::InvalidProtobufEncoding
// (rust/protocol/src/protocol.rs:614-657 for SKM, :748-800 for SKDM).
type ErrInvalidProtobufEncoding struct {
	MessageType string
	Field       string
}

func (e *ErrInvalidProtobufEncoding) Error() string {
	return fmt.Sprintf("serialize: %s: missing required field %q", e.MessageType, e.Field)
}

// FieldLengthError indicates a deserialized field has an invalid length.
type FieldLengthError struct {
	MessageType string
	Field       string
	Expected    int
	Actual      int
}

func (e *FieldLengthError) Error() string {
	return fmt.Sprintf("serialize: %s: invalid %s length %d, expected %d",
		e.MessageType, e.Field, e.Actual, e.Expected)
}

// BoundsExceededError indicates a deserialized collection exceeds the allowed maximum.
type BoundsExceededError struct {
	MessageType string
	Field       string
	Max         int
	Actual      int
}

func (e *BoundsExceededError) Error() string {
	return fmt.Sprintf("serialize: %s: %s count %d exceeds maximum %d",
		e.MessageType, e.Field, e.Actual, e.Max)
}
