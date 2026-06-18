// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package net

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"
)

// Wire-format sizes for CDSI fixed-length serialization.
// These must match the Rust FixedLengthSerializable constants in
// rust/net/src/cdsi.rs exactly.
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

// Bytes returns the ACI+AccessKey pair as a 32-byte wire encoding: ACI bytes
// followed by the 16-byte access key.
// This matches the Rust FixedLengthSerializable for AciAndAccessKey
// in rust/net/src/cdsi.rs.
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

// Bytes serializes the response entry to its 40-byte wire encoding:
// 8 bytes E164 (big-endian) || 16 bytes PNI UUID || 16 bytes ACI UUID.
// All-zero UUID bytes indicate an absent optional field.
//
// This matches the Rust FixedLengthSerializable for LookupResponseEntry
// in rust/net/src/cdsi.rs (SERIALIZED_LEN = 8 + 16 + 16 = 40).
func (e *CdsiLookupResponseEntry) Bytes() [LookupResponseEntrySerializedLen]byte {
	var b [LookupResponseEntrySerializedLen]byte
	e164b := e.E164.Bytes()
	copy(b[:E164SerializedLen], e164b[:])
	copy(b[E164SerializedLen:E164SerializedLen+UUIDSerializedLen], e.PNI[:])
	copy(b[E164SerializedLen+UUIDSerializedLen:], e.ACI[:])
	return b
}

// LookupResponseEntryFromBytes deserializes a response entry from its 40-byte
// wire encoding. It mirrors LookupResponseEntry::try_parse_from in Rust:
// a zero E164 returns an error; all-zero UUID bytes decode to the zero [16]byte
// (callers should use HasACI/HasPNI to distinguish absent from present).
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

// SerializeE164s encodes a slice of E.164 numbers into a packed big-endian
// byte slice suitable for sending in a CDSI client request.
// The returned length is always len(e164s)*8.
func SerializeE164s(e164s []E164) []byte {
	out := make([]byte, len(e164s)*E164SerializedLen)
	for i, e := range e164s {
		b := e.Bytes()
		copy(out[i*E164SerializedLen:], b[:])
	}
	return out
}

// SerializeAciAndAccessKeys encodes a slice of ACI+access-key pairs into a
// packed byte slice suitable for sending in a CDSI client request.
// The returned length is always len(pairs)*32.
func SerializeAciAndAccessKeys(pairs []AciAndAccessKey) []byte {
	out := make([]byte, len(pairs)*AciAndAccessKeySerializedLen)
	for i := range pairs {
		b := pairs[i].Bytes()
		copy(out[i*AciAndAccessKeySerializedLen:], b[:])
	}
	return out
}

// DeserializeLookupResponseEntries decodes a packed byte slice from a CDSI
// server response into individual response entries.
// It returns an error if the byte slice length is not a multiple of
// LookupResponseEntrySerializedLen, or if any entry has a zero E164.
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
