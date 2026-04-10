// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package net

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// WebSocketServiceConnectError represents an error during WebSocket
// connection to a Signal service.
type WebSocketServiceConnectError struct {
	// RejectedByServer is true when the error response is confirmed to
	// come from the Signal server (not a proxy or load balancer).
	RejectedByServer bool
	// StatusCode is the HTTP status code if the error was an HTTP rejection.
	// Zero if the error was not HTTP-related.
	StatusCode int
	// Response is the full HTTP response if this was a server rejection.
	Response *http.Response
	// Err is the underlying error.
	Err error
}

// Error returns the error string.
func (e *WebSocketServiceConnectError) Error() string {
	if e.RejectedByServer {
		return fmt.Sprintf("rejected by server with status %d", e.StatusCode)
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return "websocket connection failed"
}

// Unwrap returns the underlying error.
func (e *WebSocketServiceConnectError) Unwrap() error {
	return e.Err
}

// WebSocketTransport is the interface for establishing WebSocket connections
// to Signal services. Implementations handle the low-level transport including
// TLS, proxy/domain-fronting, and WebSocket upgrade.
type WebSocketTransport interface {
	// Connect establishes a WebSocket connection to the specified URL with
	// the given headers. The returned WebSocketConnection is ready for
	// sending and receiving messages.
	Connect(ctx context.Context, url string, headers http.Header) (WebSocketConnection, error)
}

// WebSocketConnection represents an established WebSocket connection.
// It supports sending and receiving binary frames, as well as receiving
// close notifications.
type WebSocketConnection interface {
	// SendMessage sends a binary WebSocket message.
	SendMessage(ctx context.Context, data []byte) error

	// ReceiveMessage blocks until a message is received, the connection
	// is closed, or the context is canceled.
	// Returns the message data, or an error if the connection closed
	// or the context was canceled.
	ReceiveMessage(ctx context.Context) ([]byte, error)

	// Close sends a close frame and closes the connection.
	Close() error
}

// WebSocketCloseError represents a WebSocket close frame received from
// the remote end.
type WebSocketCloseError struct {
	// Code is the WebSocket close code.
	Code int
	// Reason is the human-readable close reason.
	Reason string
}

// Error returns the error string.
func (e *WebSocketCloseError) Error() string {
	return fmt.Sprintf("websocket closed: code=%d reason=%s", e.Code, e.Reason)
}

// IsWebSocketCloseError checks if an error is a WebSocketCloseError and
// returns it.
func IsWebSocketCloseError(err error) (*WebSocketCloseError, bool) {
	var closeErr *WebSocketCloseError
	if errors.As(err, &closeErr) {
		return closeErr, true
	}
	return nil, false
}
