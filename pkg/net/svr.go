// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package net

import (
	"context"
	"fmt"
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/attest"
)

// SvrConnection represents an attested connection to a Secure Value Recovery
// enclave. It wraps the attested connection with metadata about the route
// used to establish it.
type SvrConnection struct {
	// Attested is the underlying attested connection to the enclave.
	Attested *attest.ClientConnection
	// RouteInfo describes the route used to reach the enclave.
	RouteInfo RouteInfo
	// EnclaveKind identifies the type of SVR enclave.
	EnclaveKind EnclaveKind
}

// SvrError represents an error from SVR operations.
type SvrError struct {
	// Kind categorizes the error.
	Kind SvrErrorKind
	// RetryAfter is set when Kind is SvrErrorRateLimited.
	RetryAfter time.Duration
	// Err is the underlying error.
	Err error
}

// SvrErrorKind categorizes SVR connection errors.
type SvrErrorKind int

const (
	// SvrErrorWebSocketConnect indicates a WebSocket connection failure.
	SvrErrorWebSocketConnect SvrErrorKind = iota
	// SvrErrorRateLimited indicates rate limiting.
	SvrErrorRateLimited
	// SvrErrorWebSocket indicates a WebSocket protocol error.
	SvrErrorWebSocket
	// SvrErrorProtocol indicates a protocol error after connection.
	SvrErrorProtocol
	// SvrErrorAttestation indicates attestation failure.
	SvrErrorAttestation
	// SvrErrorAllAttemptsFailed indicates all routes were exhausted.
	SvrErrorAllAttemptsFailed
)

// Error returns the error string.
func (e *SvrError) Error() string {
	switch e.Kind {
	case SvrErrorRateLimited:
		return fmt.Sprintf("svr: rate limited, retry after %v", e.RetryAfter)
	case SvrErrorAttestation:
		return fmt.Sprintf("svr: attestation failed: %v", e.Err)
	case SvrErrorAllAttemptsFailed:
		return "svr: all connection attempts failed"
	default:
		if e.Err != nil {
			return fmt.Sprintf("svr: %v", e.Err)
		}
		return "svr: unknown error"
	}
}

// Unwrap returns the underlying error.
func (e *SvrError) Unwrap() error {
	return e.Err
}

// SvrService defines the interface for connecting to SVR enclaves.
type SvrService interface {
	// ConnectSVR2 establishes an attested connection to the SVR2 enclave.
	ConnectSVR2(ctx context.Context, auth *Auth) (*SvrConnection, error)

	// ConnectSVRB establishes attested connections to the current SVRB
	// enclave endpoints.
	ConnectSVRB(ctx context.Context, auth *Auth) ([]*SvrConnection, error)
}
