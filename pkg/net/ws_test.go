package net

import (
	"errors"
	"testing"
)

func TestWebSocketServiceConnectError(t *testing.T) {
	t.Run("rejected by server", func(t *testing.T) {
		err := &WebSocketServiceConnectError{
			RejectedByServer: true,
			StatusCode:       403,
		}
		s := err.Error()
		if s != "rejected by server with status 403" {
			t.Errorf("Error() = %q", s)
		}
	})

	t.Run("with underlying error", func(t *testing.T) {
		err := &WebSocketServiceConnectError{
			Err: errors.New("timeout"),
		}
		if err.Error() != "timeout" {
			t.Errorf("Error() = %q", err.Error())
		}
	})

	t.Run("no details", func(t *testing.T) {
		err := &WebSocketServiceConnectError{}
		if err.Error() != "websocket connection failed" {
			t.Errorf("Error() = %q", err.Error())
		}
	})

	t.Run("unwrap", func(t *testing.T) {
		inner := errors.New("inner")
		err := &WebSocketServiceConnectError{Err: inner}
		if err.Unwrap() != inner {
			t.Error("Unwrap mismatch")
		}
	})
}

func TestWebSocketCloseError(t *testing.T) {
	err := &WebSocketCloseError{Code: 1000, Reason: "normal"}
	if err.Error() != "websocket closed: code=1000 reason=normal" {
		t.Errorf("Error() = %q", err.Error())
	}
}

func TestIsWebSocketCloseError(t *testing.T) {
	t.Run("is close error", func(t *testing.T) {
		closeErr := &WebSocketCloseError{Code: 1000}
		result, ok := IsWebSocketCloseError(closeErr)
		if !ok {
			t.Fatal("should be ok")
		}
		if result.Code != 1000 {
			t.Error("Code mismatch")
		}
	})

	t.Run("not close error", func(t *testing.T) {
		_, ok := IsWebSocketCloseError(errors.New("generic"))
		if ok {
			t.Fatal("should not be ok for generic error")
		}
	})
}
