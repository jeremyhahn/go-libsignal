package protocol

import (
	"errors"
	"testing"
)

// TestError_Error_AllKinds verifies Error() produces meaningful messages for
// every error kind in the protocol package.
func TestError_Error_AllKinds(t *testing.T) {
	tests := []struct {
		name     string
		err      *Error
		contains string
	}{
		{
			name:     "legacyVersion",
			err:      newLegacyVersionError("SignalMessage", 2),
			contains: "legacy",
		},
		{
			name:     "unrecognizedVersion",
			err:      newUnrecognizedVersionError("SignalMessage", 99),
			contains: "unrecognized",
		},
		{
			name:     "incompleteMessage with detail",
			err:      newIncompleteMessageError("SignalMessage", "missing field"),
			contains: "incomplete",
		},
		{
			name:     "incompleteMessage without detail",
			err:      newIncompleteMessageError("SignalMessage", ""),
			contains: "incomplete",
		},
		{
			name:     "missingKyberPayload",
			err:      newMissingKyberPayloadError(4),
			contains: "Kyber",
		},
		{
			name:     "badMac",
			err:      newBadMacError(),
			contains: "mac",
		},
		{
			name:     "invalidMacKeyLength",
			err:      newInvalidMacKeyLengthError(16),
			contains: "MAC key",
		},
		{
			name:     "invalidKeyLength",
			err:      newInvalidKeyLengthError("ratchet key", "got 10"),
			contains: "invalid",
		},
		{
			name:     "messageTooShort",
			err:      newMessageTooShortError("SignalMessage"),
			contains: "too short",
		},
		{
			name:     "sentinel ErrBadMac",
			err:      ErrBadMac,
			contains: "mac",
		},
		{
			name:     "sentinel ErrLegacyVersion",
			err:      ErrLegacyVersion,
			contains: "legacy",
		},
		{
			name:     "sentinel ErrUnrecognizedVersion",
			err:      ErrUnrecognizedVersion,
			contains: "unrecognized",
		},
		{
			name:     "sentinel ErrIncompleteMessage",
			err:      ErrIncompleteMessage,
			contains: "incomplete",
		},
		{
			name:     "sentinel ErrMissingKyberPayload",
			err:      ErrMissingKyberPayload,
			contains: "Kyber",
		},
		{
			name:     "sentinel ErrInvalidMacKeyLength",
			err:      ErrInvalidMacKeyLength,
			contains: "MAC key",
		},
		{
			name:     "sentinel ErrInvalidKeyLength",
			err:      ErrInvalidKeyLength,
			contains: "invalid",
		},
		{
			name:     "sentinel ErrMessageTooShort",
			err:      ErrMessageTooShort,
			contains: "too short",
		},
		{
			name:     "unknown kind",
			err:      &Error{kind: 999},
			contains: "unknown",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.err.Error()
			if msg == "" {
				t.Fatal("Error() returned empty string")
			}
			// Case-insensitive substring check.
			lower := lowerStr(msg)
			lowerSub := lowerStr(tc.contains)
			if !strContains(lower, lowerSub) {
				t.Errorf("Error() = %q, want substring %q", msg, tc.contains)
			}
		})
	}
}

// TestError_Is_MatchesByKind verifies that errors.Is uses kind matching.
func TestError_Is_MatchesByKind(t *testing.T) {
	err := newLegacyVersionError("SignalMessage", 2)

	if !errors.Is(err, ErrLegacyVersion) {
		t.Error("errors.Is should match ErrLegacyVersion by kind")
	}
	if errors.Is(err, ErrUnrecognizedVersion) {
		t.Error("errors.Is should not match ErrUnrecognizedVersion")
	}
}

// TestError_Is_NonErrorTarget verifies false is returned for non-*Error targets.
func TestError_Is_NonErrorTarget(t *testing.T) {
	err := newBadMacError()
	other := errors.New("unrelated")

	if errors.Is(err, other) {
		t.Error("errors.Is should return false for non-*Error target")
	}
}

// TestNewInvalidMacKeyLengthError verifies the constructor and Is match.
func TestNewInvalidMacKeyLengthError_MatchesSentinel(t *testing.T) {
	err := newInvalidMacKeyLengthError(16)
	if !errors.Is(err, ErrInvalidMacKeyLength) {
		t.Error("newInvalidMacKeyLengthError should match ErrInvalidMacKeyLength sentinel")
	}
	msg := err.Error()
	if !strContains(msg, "16") {
		t.Errorf("Error() = %q, expected to contain '16'", msg)
	}
}

// TestNewMessageTooShortError verifies the constructor and Is match.
func TestNewMessageTooShortError_MatchesSentinel(t *testing.T) {
	err := newMessageTooShortError("PreKeySignalMessage")
	if !errors.Is(err, ErrMessageTooShort) {
		t.Error("newMessageTooShortError should match ErrMessageTooShort sentinel")
	}
	msg := err.Error()
	if !strContains(msg, "PreKeySignalMessage") {
		t.Errorf("Error() = %q, expected to contain 'PreKeySignalMessage'", msg)
	}
}

// TestServiceIdParseError_ErrorAndUnwrap verifies ServiceIdParseError.
func TestServiceIdParseError_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("base64 decode failed")
	e := &ServiceIdParseError{Detail: "invalid UUID", Err: inner}

	msg := e.Error()
	if !strContains(msg, "invalid UUID") {
		t.Errorf("Error() = %q, expected 'invalid UUID'", msg)
	}
	if !strContains(msg, "base64 decode failed") {
		t.Errorf("Error() = %q, expected 'base64 decode failed'", msg)
	}
	if e.Unwrap() != inner {
		t.Error("Unwrap() should return the inner error")
	}
}

// TestServiceIdParseError_NoInnerError verifies ServiceIdParseError without Err.
func TestServiceIdParseError_NoInnerError(t *testing.T) {
	e := &ServiceIdParseError{Detail: "bad prefix"}

	msg := e.Error()
	if !strContains(msg, "bad prefix") {
		t.Errorf("Error() = %q, expected 'bad prefix'", msg)
	}
	if e.Unwrap() != nil {
		t.Error("Unwrap() should return nil when no inner error")
	}
}

// TestEmptyMessageError_Error verifies EmptyMessageError.
func TestEmptyMessageError_Error(t *testing.T) {
	e := &EmptyMessageError{MessageType: "SignalMessage"}

	msg := e.Error()
	if !strContains(msg, "SignalMessage") {
		t.Errorf("Error() = %q, expected 'SignalMessage'", msg)
	}
	if !strContains(msg, "empty") {
		t.Errorf("Error() = %q, expected 'empty'", msg)
	}
}

// TestContentTooShortError_Error verifies ContentTooShortError.
func TestContentTooShortError_Error(t *testing.T) {
	e := &ContentTooShortError{MessageType: "PreKeySignalMessage"}

	msg := e.Error()
	if !strContains(msg, "PreKeySignalMessage") {
		t.Errorf("Error() = %q, expected 'PreKeySignalMessage'", msg)
	}
	if !strContains(msg, "too short") {
		t.Errorf("Error() = %q, expected 'too short'", msg)
	}
}

// Helper: case-insensitive substring check.
func lowerStr(s string) string {
	b := make([]byte, len(s))
	for i := range s {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	return string(b)
}

func strContains(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
