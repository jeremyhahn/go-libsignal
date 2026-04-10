package net

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestChatConnectionInfo_String(t *testing.T) {
	ci := &ChatConnectionInfo{
		RouteInfo:  RouteInfo{Description: "direct"},
		LocalAddr:  "192.168.1.1:12345",
		RemoteAddr: "1.2.3.4:443",
	}
	s := ci.String()
	if s != "from 192.168.1.1:12345 via direct" {
		t.Errorf("String() = %q", s)
	}
}

func TestChatConnectError(t *testing.T) {
	tests := []struct {
		name string
		err  *ChatConnectError
		want string
	}{
		{
			"all attempts failed",
			&ChatConnectError{Kind: ChatConnectErrorAllAttemptsFailed},
			"chat: all connection attempts failed",
		},
		{
			"device deregistered",
			&ChatConnectError{Kind: ChatConnectErrorDeviceDeregistered},
			"chat: device deregistered",
		},
		{
			"app expired",
			&ChatConnectError{Kind: ChatConnectErrorAppExpired},
			"chat: app version expired",
		},
		{
			"retry later",
			&ChatConnectError{Kind: ChatConnectErrorRetryLater, RetryAfter: 30 * time.Second},
			fmt.Sprintf("chat: retry after %v", 30*time.Second),
		},
		{
			"unknown with err",
			&ChatConnectError{Kind: ChatConnectErrorKind(99), Err: errors.New("custom")},
			"chat: custom",
		},
		{
			"unknown no err",
			&ChatConnectError{Kind: ChatConnectErrorKind(99)},
			"chat: unknown error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestChatConnectError_Unwrap(t *testing.T) {
	inner := errors.New("inner")
	err := &ChatConnectError{Err: inner}
	if err.Unwrap() != inner {
		t.Error("Unwrap mismatch")
	}
}

func TestChatSendError(t *testing.T) {
	tests := []struct {
		name string
		err  *ChatSendError
		want string
	}{
		{
			"disconnected",
			&ChatSendError{Kind: ChatSendErrorDisconnected},
			"chat: disconnected",
		},
		{
			"timed out",
			&ChatSendError{Kind: ChatSendErrorRequestTimedOut},
			"chat: request timed out",
		},
		{
			"invalid data",
			&ChatSendError{Kind: ChatSendErrorIncomingDataInvalid},
			"chat: invalid incoming data",
		},
		{
			"unknown with err",
			&ChatSendError{Kind: ChatSendErrorKind(99), Err: errors.New("custom")},
			"chat: custom",
		},
		{
			"unknown no err",
			&ChatSendError{Kind: ChatSendErrorKind(99)},
			"chat: unknown send error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestChatSendError_Unwrap(t *testing.T) {
	inner := errors.New("inner")
	err := &ChatSendError{Err: inner}
	if err.Unwrap() != inner {
		t.Error("Unwrap mismatch")
	}
}
