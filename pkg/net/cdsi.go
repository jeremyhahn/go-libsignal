// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package net

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"
)

// CDSI wire sizes, equal to the Rust FixedLengthSerializable constants in rust/net/src/cdsi.rs.
const (
	// E164SerializedLen is the wire size of an E.164 phone number: 8-byte big-endian uint64.
	E164SerializedLen = 8
	// UUIDSerializedLen is the wire size of a UUID: 16 raw bytes.
	UUIDSerializedLen = 16
	// AciAndAccessKeySerializedLen is the wire size of an ACI + access key pair: 32 bytes.
	AciAndAccessKeySerializedLen = UUIDSerializedLen + 16
	// LookupResponseEntrySerializedLen is the wire size of a response entry: E164 + PNI UUID + ACI UUID.
	LookupResponseEntrySerializedLen = E164SerializedLen + UUIDSerializedLen*2
)

// E164 represents an E.164 phone number as its numeric value.
type E164 uint64

// Bytes returns the E.164 number as an 8-byte big-endian encoded value.
// This matches the Rust FixedLengthSerializable implementation for E164
// in rust/net/src/cdsi.rs.
func (e E164) Bytes() [E164SerializedLen]byte {
	var b [E164SerializedLen]byte
	binary.BigEndian.PutUint64(b[:], uint64(e))
	return b
}

// E164FromBytes decodes an E.164 number from its 8-byte big-endian wire form.
// Returns an error if the decoded value is zero (not a valid E.164 number).
func E164FromBytes(b [E164SerializedLen]byte) (E164, error) {
	v := binary.BigEndian.Uint64(b[:])
	if v == 0 {
		return 0, &CdsiSerializeError{
			Field: "E164",
			Msg:   "zero is not a valid E.164 phone number",
		}
	}
	return E164(v), nil
}

// AciAndAccessKey pairs an ACI (Account Contact Identifier) UUID with its
// associated profile access key.
type AciAndAccessKey struct {
	// ACI is the 16-byte Account Contact Identifier.
	ACI [16]byte
	// AccessKey is the 16-byte profile access key.
	AccessKey [16]byte
}

// Bytes returns the 32-byte wire encoding: ACI then the 16-byte access key.
func (a *AciAndAccessKey) Bytes() [AciAndAccessKeySerializedLen]byte {
	var b [AciAndAccessKeySerializedLen]byte
	copy(b[:UUIDSerializedLen], a.ACI[:])
	copy(b[UUIDSerializedLen:], a.AccessKey[:])
	return b
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
	// Token is a continuation token from a previous request; empty at first.
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

// Bytes returns the 40-byte wire encoding E164(8, big-endian) || PNI(16) || ACI(16); zero UUIDs mean absent.
func (e *CdsiLookupResponseEntry) Bytes() [LookupResponseEntrySerializedLen]byte {
	var b [LookupResponseEntrySerializedLen]byte
	e164b := e.E164.Bytes()
	copy(b[:E164SerializedLen], e164b[:])
	copy(b[E164SerializedLen:E164SerializedLen+UUIDSerializedLen], e.PNI[:])
	copy(b[E164SerializedLen+UUIDSerializedLen:], e.ACI[:])
	return b
}

// LookupResponseEntryFromBytes decodes a 40-byte entry; a zero E164 is an error; use HasACI and HasPNI for presence.
func LookupResponseEntryFromBytes(b [LookupResponseEntrySerializedLen]byte) (CdsiLookupResponseEntry, error) {
	var e164b [E164SerializedLen]byte
	copy(e164b[:], b[:E164SerializedLen])
	e164, err := E164FromBytes(e164b)
	if err != nil {
		return CdsiLookupResponseEntry{}, err
	}

	var pni [16]byte
	copy(pni[:], b[E164SerializedLen:E164SerializedLen+UUIDSerializedLen])

	var aci [16]byte
	copy(aci[:], b[E164SerializedLen+UUIDSerializedLen:])

	return CdsiLookupResponseEntry{
		E164: e164,
		PNI:  pni,
		ACI:  aci,
	}, nil
}

// SerializeE164s packs E.164 numbers big-endian, 8 bytes each.
func SerializeE164s(e164s []E164) []byte {
	out := make([]byte, len(e164s)*E164SerializedLen)
	for i, e := range e164s {
		b := e.Bytes()
		copy(out[i*E164SerializedLen:], b[:])
	}
	return out
}

// SerializeAciAndAccessKeys packs ACI and access-key pairs, 32 bytes each.
func SerializeAciAndAccessKeys(pairs []AciAndAccessKey) []byte {
	out := make([]byte, len(pairs)*AciAndAccessKeySerializedLen)
	for i := range pairs {
		b := pairs[i].Bytes()
		copy(out[i*AciAndAccessKeySerializedLen:], b[:])
	}
	return out
}

// DeserializeLookupResponseEntries splits a response into entries; a ragged length or a zero E164 is an error.
func DeserializeLookupResponseEntries(data []byte) ([]CdsiLookupResponseEntry, error) {
	if len(data)%LookupResponseEntrySerializedLen != 0 {
		return nil, &CdsiSerializeError{
			Field: "e164_pni_aci_triples",
			Msg:   fmt.Sprintf("length %d is not a multiple of %d", len(data), LookupResponseEntrySerializedLen),
		}
	}
	count := len(data) / LookupResponseEntrySerializedLen
	entries := make([]CdsiLookupResponseEntry, 0, count)
	for i := range count {
		var chunk [LookupResponseEntrySerializedLen]byte
		copy(chunk[:], data[i*LookupResponseEntrySerializedLen:])
		entry, err := LookupResponseEntryFromBytes(chunk)
		if err != nil {
			// Rust's try_parse_from silently skips zero-E164 entries; we do the same.
			continue
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// CdsiToken is a continuation token that spares resending numbers already looked up.
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

// CdsiService performs CDSI lookups over attested enclave connections.
type CdsiService interface {
	// Lookup connects, sends the request, acknowledges the token and collects the results.
	Lookup(ctx context.Context, auth *Auth, request *CdsiLookupRequest) (*CdsiToken, *CdsiLookupResponse, error)
}

// ErrCdsiNoTokenInResponse is returned when the first response carries no token.
var ErrCdsiNoTokenInResponse error = &ErrCdsiNoTokenInResponseType{}
