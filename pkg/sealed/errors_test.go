package sealed

import (
	"errors"
	"testing"
)

func TestErrUnsupportedMessageType(t *testing.T) {
	t.Run("error message", func(t *testing.T) {
		err := ErrUnsupportedMessageType
		expected := "sealed: unsupported message type in USMC"
		if err.Error() != expected {
			t.Errorf("got %q, want %q", err.Error(), expected)
		}
	})

	t.Run("errors.Is matching", func(t *testing.T) {
		err := &Error{kind: errUnsupportedMessageType}
		if !errors.Is(err, ErrUnsupportedMessageType) {
			t.Error("expected errors.Is to match ErrUnsupportedMessageType")
		}
	})

	t.Run("does not match other errors", func(t *testing.T) {
		err := ErrUnsupportedMessageType
		if errors.Is(err, ErrSelfSend) {
			t.Error("ErrUnsupportedMessageType should not match ErrSelfSend")
		}
	})
}

func TestAllSealedErrors(t *testing.T) {
	// Verify all sentinel errors produce non-empty messages
	sentinels := []*Error{
		ErrSenderKeyMismatch,
		ErrServerCertificateRevoked,
		ErrV2ReceivedMessageTooShort,
		ErrV2ReceivedUnsupportedVersion,
		ErrV2ReceivedEphemeralKeyMismatch,
		ErrV2ReceivedDecryptFailed,
		ErrV2ReceivedAuthTagMismatch,
		ErrV2ReceivedDeserializeFailed,
		ErrUnknownServerCertificateID,
		ErrSelfSend,
		ErrUnsupportedVersion,
		ErrInvalidDeviceID,
		ErrUnsupportedMessageType,
	}
	for _, err := range sentinels {
		if err.Error() == "" {
			t.Errorf("error kind %d produced empty message", err.kind)
		}
		if err.Error() == "sealed: unknown error" {
			t.Errorf("error kind %d fell through to default case", err.kind)
		}
	}
}
