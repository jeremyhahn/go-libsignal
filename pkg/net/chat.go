// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package net

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// ChatRequest represents a request to the chat service.
type ChatRequest struct {
	// Method is the HTTP method (GET, POST, PUT, DELETE, etc.).
	Method string
	// Path is the request path (e.g., "/v1/messages").
	Path string
	// Headers are additional HTTP headers for the request.
	Headers http.Header
	// Body is the optional request body.
	Body []byte
}

// ChatResponse represents a response from the chat service.
type ChatResponse struct {
	// Status is the HTTP status code.
	Status int
	// Message is an optional status message.
	Message string
	// Headers are the response headers.
	Headers http.Header
	// Body is the optional response body.
	Body []byte
}

// ChatDebugInfo contains diagnostic information about a chat request.
type ChatDebugInfo struct {
	// IpType indicates whether IPv4 or IPv6 was used.
	IpType IpType
	// Duration is how long the request took.
	Duration time.Duration
	// ConnectionInfo is a human-readable summary of the connection.
	ConnectionInfo string
}

// ChatConnectionInfo contains information about an established chat
// connection.
type ChatConnectionInfo struct {
	// RouteInfo describes the route used (direct, proxy type, etc.).
	RouteInfo RouteInfo
	// LocalAddr is the local address of the connection.
	LocalAddr string
	// RemoteAddr is the remote address of the connection.
	RemoteAddr string
}

// String returns a human-readable description of the connection info.
func (ci *ChatConnectionInfo) String() string {
	return fmt.Sprintf("from %s via %s", ci.LocalAddr, ci.RouteInfo.Description)
}

// ChatEventListener is a callback for events on a chat connection.
// Events include incoming server requests and connection state changes.
type ChatEventListener func(event ChatEvent)

// ChatEvent represents an event on a chat connection.
type ChatEvent struct {
	// Kind identifies the event type.
	Kind ChatEventKind
	// Request is set for ChatEventKindServerRequest events.
	Request *ChatRequest
	// Error is set for ChatEventKindDisconnected events.
	Error error
}

// ChatEventKind categorizes chat connection events.
type ChatEventKind int

const (
	// ChatEventKindServerRequest indicates the server sent a request
	// to the client (e.g., a push notification).
	ChatEventKindServerRequest ChatEventKind = iota
	// ChatEventKindDisconnected indicates the connection was lost.
	ChatEventKindDisconnected
)

// ReceiveStories indicates whether the client wants to receive story
// messages.
type ReceiveStories bool

// LanguageList is a list of preferred languages for the Accept-Language
// header.
type LanguageList []string

// AuthenticatedChatHeaders contains headers for authenticated chat
// connections.
type AuthenticatedChatHeaders struct {
	// Auth contains the authentication credentials.
	Auth Auth
	// ReceiveStories indicates whether to receive story messages.
	ReceiveStories ReceiveStories
	// Languages is the preferred language list.
	Languages LanguageList
}

// UnauthenticatedChatHeaders contains headers for unauthenticated chat
// connections.
type UnauthenticatedChatHeaders struct {
	// Languages is the preferred language list.
	Languages LanguageList
}

// ChatConnectError represents an error connecting to the chat service.
type ChatConnectError struct {
	// Kind categorizes the error.
	Kind ChatConnectErrorKind
	// RetryAfter is set when Kind is ChatConnectErrorRetryLater.
	RetryAfter time.Duration
	// Err is the underlying error.
	Err error
}

// ChatConnectErrorKind categorizes chat connection errors.
type ChatConnectErrorKind int

const (
	// ChatConnectErrorAllAttemptsFailed indicates no route succeeded.
	ChatConnectErrorAllAttemptsFailed ChatConnectErrorKind = iota
	// ChatConnectErrorDeviceDeregistered indicates the device has been
	// deregistered from the server.
	ChatConnectErrorDeviceDeregistered
	// ChatConnectErrorAppExpired indicates the client version is too old.
	ChatConnectErrorAppExpired
	// ChatConnectErrorRetryLater indicates the server is temporarily
	// unavailable, with a suggested retry time.
	ChatConnectErrorRetryLater
)

// Error returns the error string.
func (e *ChatConnectError) Error() string {
	switch e.Kind {
	case ChatConnectErrorAllAttemptsFailed:
		return "chat: all connection attempts failed"
	case ChatConnectErrorDeviceDeregistered:
		return "chat: device deregistered"
	case ChatConnectErrorAppExpired:
		return "chat: app version expired"
	case ChatConnectErrorRetryLater:
		return fmt.Sprintf("chat: retry after %v", e.RetryAfter)
	default:
		if e.Err != nil {
			return fmt.Sprintf("chat: %v", e.Err)
		}
		return "chat: unknown error"
	}
}

// Unwrap returns the underlying error.
func (e *ChatConnectError) Unwrap() error {
	return e.Err
}

// ChatSendError represents an error sending a request on the chat service.
type ChatSendError struct {
	// Kind categorizes the error.
	Kind ChatSendErrorKind
	// Err is the underlying error.
	Err error
}

// ChatSendErrorKind categorizes chat send errors.
type ChatSendErrorKind int

const (
	// ChatSendErrorDisconnected indicates the connection is no longer active.
	ChatSendErrorDisconnected ChatSendErrorKind = iota
	// ChatSendErrorRequestTimedOut indicates the request timed out.
	ChatSendErrorRequestTimedOut
	// ChatSendErrorIncomingDataInvalid indicates the response could not
	// be parsed.
	ChatSendErrorIncomingDataInvalid
)

// Error returns the error string.
func (e *ChatSendError) Error() string {
	switch e.Kind {
	case ChatSendErrorDisconnected:
		return "chat: disconnected"
	case ChatSendErrorRequestTimedOut:
		return "chat: request timed out"
	case ChatSendErrorIncomingDataInvalid:
		return "chat: invalid incoming data"
	default:
		if e.Err != nil {
			return fmt.Sprintf("chat: %v", e.Err)
		}
		return "chat: unknown send error"
	}
}

// Unwrap returns the underlying error.
func (e *ChatSendError) Unwrap() error {
	return e.Err
}

// ChatService defines the interface for the Signal chat service.
// It supports both authenticated and unauthenticated connections.
type ChatService interface {
	// ConnectAuthenticated establishes an authenticated chat connection.
	ConnectAuthenticated(
		ctx context.Context,
		headers *AuthenticatedChatHeaders,
		listener ChatEventListener,
	) (ChatConnection, error)

	// ConnectUnauthenticated establishes an unauthenticated chat connection.
	ConnectUnauthenticated(
		ctx context.Context,
		headers *UnauthenticatedChatHeaders,
		listener ChatEventListener,
	) (ChatConnection, error)
}

// ChatConnection represents an active connection to the chat service
// over which requests can be sent and server-originated messages received.
type ChatConnection interface {
	// Send sends a request and waits for the response, with the given timeout.
	Send(ctx context.Context, request *ChatRequest, timeout time.Duration) (*ChatResponse, error)

	// Disconnect gracefully closes the connection.
	Disconnect(ctx context.Context) error

	// ConnectionInfo returns information about the established connection.
	ConnectionInfo() *ChatConnectionInfo
}

// ErrChatDisconnected is returned when an operation is attempted on a
// disconnected chat connection.
var ErrChatDisconnected error = &ErrChatDisconnectedType{}
