// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package net

import (
	"context"
	"fmt"
	"time"
)

// E164 represents an E.164 phone number as its numeric value.
type E164 uint64

// AciAndAccessKey pairs an ACI (Account Contact Identifier) UUID with its
// associated profile access key.
type AciAndAccessKey struct {
	// ACI is the 16-byte Account Contact Identifier.
	ACI [16]byte
	// AccessKey is the 16-byte profile access key.
	AccessKey [16]byte
}

// CdsiLookupRequest contains the parameters for a CDSI lookup operation.
type CdsiLookupRequest struct {
	// NewE164s are phone numbers to look up that were not in the previous
	// request's token.
	NewE164s []E164
	// PrevE164s are phone numbers that were included in the previous
	// request (covered by the token).
	PrevE164s []E164
	// AcisAndAccessKeys are ACI/access key pairs for profile key verification.
	AcisAndAccessKeys []AciAndAccessKey
	// Token is a continuation token from a previous CDSI request.
	// Empty for initial requests.
	Token []byte
}

// CdsiLookupResponse contains the results of a CDSI lookup.
type CdsiLookupResponse struct {
	// Records contains the lookup results.
	Records []CdsiLookupResponseEntry
	// DebugPermitsUsed is the number of rate limit permits consumed.
	DebugPermitsUsed int32
}

// CdsiLookupResponseEntry contains a single record from a CDSI lookup.
type CdsiLookupResponseEntry struct {
	// E164 is the phone number for this record.
	E164 E164
	// ACI is the Account Contact Identifier, if found.
	// All zeros means not found.
	ACI [16]byte
	// PNI is the Phone Number Identifier, if found.
	// All zeros means not found.
	PNI [16]byte
}

// HasACI returns true if the entry has a non-nil ACI.
func (e *CdsiLookupResponseEntry) HasACI() bool {
	var zero [16]byte
	return e.ACI != zero
}

// HasPNI returns true if the entry has a non-nil PNI.
func (e *CdsiLookupResponseEntry) HasPNI() bool {
	var zero [16]byte
	return e.PNI != zero
}

// CdsiToken is a continuation token from a CDSI lookup that can be reused
// in subsequent requests to avoid re-sending previously looked-up numbers.
type CdsiToken []byte

// CdsiLookupError represents an error that can occur during a CDSI lookup.
type CdsiLookupError struct {
	// Kind categorizes the error.
	Kind CdsiLookupErrorKind
	// RetryAfter is set when Kind is CdsiLookupErrorRateLimited.
	RetryAfter time.Duration
	// ServerReason is set when Kind is CdsiLookupErrorInvalidArgument.
	ServerReason string
	// Err is the underlying error, if any.
	Err error
}

// CdsiLookupErrorKind categorizes CDSI lookup errors.
type CdsiLookupErrorKind int

const (
	// CdsiLookupErrorAttestationFailed indicates SGX attestation failed.
	CdsiLookupErrorAttestationFailed CdsiLookupErrorKind = iota
	// CdsiLookupErrorRateLimited indicates the request was rate limited.
	CdsiLookupErrorRateLimited
	// CdsiLookupErrorInvalidToken indicates the continuation token was invalid.
	CdsiLookupErrorInvalidToken
	// CdsiLookupErrorProtocol indicates a protocol error after connection.
	CdsiLookupErrorProtocol
	// CdsiLookupErrorTransport indicates a transport-level failure.
	CdsiLookupErrorTransport
	// CdsiLookupErrorWebSocket indicates a WebSocket error.
	CdsiLookupErrorWebSocket
	// CdsiLookupErrorTimeout indicates all connection attempts timed out.
	CdsiLookupErrorTimeout
	// CdsiLookupErrorInvalidArgument indicates the request was invalid.
	CdsiLookupErrorInvalidArgument
	// CdsiLookupErrorServer indicates a server-side error.
	CdsiLookupErrorServer
	// CdsiLookupErrorInvalidResponse indicates the response could not be parsed.
	CdsiLookupErrorInvalidResponse
)

// Error returns the error string.
func (e *CdsiLookupError) Error() string {
	switch e.Kind {
	case CdsiLookupErrorAttestationFailed:
		return fmt.Sprintf("cdsi: attestation failed: %v", e.Err)
	case CdsiLookupErrorRateLimited:
		return fmt.Sprintf("cdsi: rate limited, retry after %v", e.RetryAfter)
	case CdsiLookupErrorInvalidToken:
		return "cdsi: invalid token"
	case CdsiLookupErrorInvalidArgument:
		return fmt.Sprintf("cdsi: invalid argument: %s", e.ServerReason)
	case CdsiLookupErrorServer:
		return fmt.Sprintf("cdsi: server error: %v", e.Err)
	default:
		if e.Err != nil {
			return fmt.Sprintf("cdsi: %v", e.Err)
		}
		return "cdsi: unknown error"
	}
}

// Unwrap returns the underlying error.
func (e *CdsiLookupError) Unwrap() error {
	return e.Err
}

// CdsiCloseCode represents WebSocket close codes specific to CDSI.
type CdsiCloseCode int

const (
	// CdsiCloseCodeInvalidArgument indicates the request was invalid.
	CdsiCloseCodeInvalidArgument CdsiCloseCode = 4003
	// CdsiCloseCodeRateLimitExceeded indicates rate limiting.
	CdsiCloseCodeRateLimitExceeded CdsiCloseCode = 4008
	// CdsiCloseCodeServerInternalError indicates an internal server error.
	CdsiCloseCodeServerInternalError CdsiCloseCode = 4013
	// CdsiCloseCodeServerUnavailable indicates the server is unavailable.
	CdsiCloseCodeServerUnavailable CdsiCloseCode = 4014
	// CdsiCloseCodeInvalidToken indicates the token was invalid.
	CdsiCloseCodeInvalidToken CdsiCloseCode = 4101
)

// CdsiService defines the interface for performing CDSI lookups.
// Implementations establish attested connections to the CDSI enclave,
// send lookup requests, and collect responses.
type CdsiService interface {
	// Lookup performs a complete CDSI lookup: connect, send request,
	// receive token, acknowledge, and collect results.
	Lookup(ctx context.Context, auth *Auth, request *CdsiLookupRequest) (*CdsiToken, *CdsiLookupResponse, error)
}

// ErrCdsiNoTokenInResponse is returned when the CDSI server does not
// include a token in the initial response.
var ErrCdsiNoTokenInResponse error = &ErrCdsiNoTokenInResponseType{}
