package svr

import (
	"errors"
	"strings"
	"testing"
)

func TestResponseStatusString(t *testing.T) {
	tests := []struct {
		status ResponseStatus
		want   string
	}{
		{StatusUnset, "UNSET"},
		{StatusOK, "OK"},
		{StatusInvalidRequest, "INVALID_REQUEST"},
		{StatusMissing, "MISSING"},
		{StatusError, "ERROR"},
		{StatusRestore1Missing, "RESTORE1_MISSING"},
		{StatusVersionMismatch, "VERSION_MISMATCH"},
		{ResponseStatus(99), "UNKNOWN(99)"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.status.String()
			if got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestErrorMessages(t *testing.T) {
	tests := []struct {
		name string
		err  *Error
		want string
	}{
		{"bad data", ErrBadData, "invalid protobuf"},
		{"bad response", ErrBadResponse, "unexpected or missing"},
		{"no usable version", ErrNoUsableVersion, "no auth version"},
		{"num servers", newNumServersError(3, 2), "inputs 2"},
		{"bad status", newBadResponseStatusError(StatusMissing), "MISSING"},
		{"restore failed", newRestoreFailedError(5), "5 tries remaining"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			if !strings.Contains(msg, tt.want) {
				t.Errorf("Error() = %q, want substring %q", msg, tt.want)
			}
		})
	}
}

func TestErrorIs(t *testing.T) {
	t.Run("matching kind", func(t *testing.T) {
		err := &Error{kind: errBadData}
		if !errors.Is(err, ErrBadData) {
			t.Error("expected errors.Is to match ErrBadData")
		}
	})

	t.Run("different kind", func(t *testing.T) {
		err := &Error{kind: errBadData}
		if errors.Is(err, ErrBadResponse) {
			t.Error("expected errors.Is to not match ErrBadResponse")
		}
	})

	t.Run("non Error target", func(t *testing.T) {
		err := &Error{kind: errBadData}
		if errors.Is(err, errors.New("other")) {
			t.Error("expected errors.Is to not match non-Error")
		}
	})

	t.Run("restore failed matches", func(t *testing.T) {
		err1 := newRestoreFailedError(3)
		err2 := newRestoreFailedError(7)
		if !errors.Is(err1, err2) {
			t.Error("expected errors.Is to match by kind regardless of tries")
		}
	})
}

func TestErrorDefaultKind(t *testing.T) {
	err := &Error{}
	msg := err.Error()
	if !strings.Contains(msg, "unknown") {
		t.Errorf("Error() = %q, want 'unknown'", msg)
	}
}
