// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package attest

import (
	"errors"
	"fmt"
	"strings"
)

// AttestationError represents a failure to attest a remote enclave.
type AttestationError struct {
	Message string
}

func (e *AttestationError) Error() string {
	return fmt.Sprintf("failure to attest remote enclave: %s", e.Message)
}

// EnclaveError represents error types for an enclave noise session.
type EnclaveError struct {
	Kind    EnclaveErrorKind
	Message string
	Err     error
}

// EnclaveErrorKind enumerates the kinds of enclave errors.
type EnclaveErrorKind int

const (
	// ErrAttestationFailure indicates failure to attest remote enclave.
	ErrAttestationFailure EnclaveErrorKind = iota
	// ErrNoiseCommunication indicates failure to communicate on established Noise channel.
	ErrNoiseCommunication
	// ErrNoiseHandshake indicates failure to complete Noise handshake.
	ErrNoiseHandshake
	// ErrAttestationData indicates attestation data was invalid.
	ErrAttestationData
	// ErrInvalidBridgeState indicates invalid bridge state.
	ErrInvalidBridgeState
)

func (e *EnclaveError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *EnclaveError) Unwrap() error {
	return e.Err
}

func newAttestationDataError(reason string) *EnclaveError {
	return &EnclaveError{
		Kind:    ErrAttestationData,
		Message: fmt.Sprintf("attestation data invalid: %s", reason),
	}
}

func newNoiseHandshakeError(err error) *EnclaveError {
	return &EnclaveError{
		Kind:    ErrNoiseHandshake,
		Message: "failure to complete Noise handshake to the enclave",
		Err:     err,
	}
}

func newNoiseCommunicationError(err error) *EnclaveError {
	return &EnclaveError{
		Kind:    ErrNoiseCommunication,
		Message: "failure to communicate on established Noise channel",
		Err:     err,
	}
}

func newAttestationError(err error) *EnclaveError {
	return &EnclaveError{
		Kind:    ErrAttestationFailure,
		Message: "failure to attest remote enclave",
		Err:     err,
	}
}

// ClientConnectionError represents an error in the Noise transport layer.
type ClientConnectionError struct {
	Message string
	Err     error
}

func (e *ClientConnectionError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("noise error: %v", e.Err)
	}
	return fmt.Sprintf("noise error: %s", e.Message)
}

func (e *ClientConnectionError) Unwrap() error {
	return e.Err
}

// HSMError represents error types for HSM enclave operations.
type HSMError struct {
	Kind    HSMErrorKind
	Message string
	Err     error
}

// HSMErrorKind enumerates the kinds of HSM errors.
type HSMErrorKind int

const (
	// ErrHSMCommunication indicates failure to connect to a trusted HSM.
	ErrHSMCommunication HSMErrorKind = iota
	// ErrHSMHandshake indicates failure to handshake to trusted HSM.
	ErrHSMHandshake
	// ErrTrustedCode indicates failure to connect to trusted code on the given HSM.
	ErrTrustedCode
	// ErrInvalidPublicKey indicates an invalid public key was provided.
	ErrInvalidPublicKey
	// ErrInvalidCodeHash indicates an invalid code hash was provided.
	ErrInvalidCodeHash
	// ErrHSMInvalidBridgeState indicates invalid state of wrapper.
	ErrHSMInvalidBridgeState
)

func (e *HSMError) Error() string {
	switch e.Kind {
	case ErrHSMCommunication:
		return fmt.Sprintf("error in communication to HSM (%v)", e.Err)
	case ErrHSMHandshake:
		return fmt.Sprintf("error in handshake to HSM (%v)", e.Err)
	case ErrTrustedCode:
		return "trusted HSM process does not match trusted code hash"
	case ErrInvalidPublicKey:
		return fmt.Sprintf("invalid public key, must be %d bytes", PubKeySize)
	case ErrInvalidCodeHash:
		return fmt.Sprintf("invalid code hashes, must be >0 hashes, each exactly %d bytes", CodeHashSize)
	case ErrHSMInvalidBridgeState:
		return "invalid bridge state"
	default:
		return e.Message
	}
}

func (e *HSMError) Unwrap() error {
	return e.Err
}

// DcapError represents errors during DCAP attestation verification.
type DcapError struct {
	Message string
	Context []string
}

func (e *DcapError) Error() string {
	if len(e.Context) == 0 {
		return e.Message
	}
	var sb strings.Builder
	sb.WriteString("(")
	for i := len(e.Context) - 1; i >= 0; i-- {
		if i < len(e.Context)-1 {
			sb.WriteString(" -> ")
		}
		sb.WriteString(e.Context[i])
	}
	sb.WriteString(") ")
	sb.WriteString(e.Message)
	return sb.String()
}

func newDcapError(message string) *DcapError {
	return &DcapError{Message: message}
}

func (e *DcapError) withContext(ctx string) *DcapError {
	e.Context = append(e.Context, ctx)
	return e
}

// IsDcapError checks if the error is a DcapError.
func IsDcapError(err error) bool {
	var dcapErr *DcapError
	return errors.As(err, &dcapErr)
}

// CRLVerificationError indicates a certificate was found on a revocation list.
type CRLVerificationError struct {
	SerialNumber string
	Issuer       string
}

func (e *CRLVerificationError) Error() string {
	return fmt.Sprintf("certificate with serial %s from issuer %s is revoked", e.SerialNumber, e.Issuer)
}

// CRLSignatureError indicates a CRL failed signature verification.
type CRLSignatureError struct {
	Message string
}

func (e *CRLSignatureError) Error() string {
	return fmt.Sprintf("CRL signature verification failed: %s", e.Message)
}

// EndorsementSignatureError indicates an endorsement JSON signature verification failure.
type EndorsementSignatureError struct {
	Field   string
	Message string
}

func (e *EndorsementSignatureError) Error() string {
	return fmt.Sprintf("endorsement signature verification failed for %s: %s", e.Field, e.Message)
}

// QETCBStatusError indicates the quoting enclave TCB status is not acceptable.
type QETCBStatusError struct {
	Status string
	ISVSVN uint16
}

func (e *QETCBStatusError) Error() string {
	return fmt.Sprintf("QE TCB status %q is not acceptable for isvsvn %d", e.Status, e.ISVSVN)
}

// EnclaveIdentityTypeError indicates the enclave identity type is unexpected.
type EnclaveIdentityTypeError struct {
	Expected string
	Actual   string
}

func (e *EnclaveIdentityTypeError) Error() string {
	return fmt.Sprintf("enclave identity type mismatch: expected %q, got %q", e.Expected, e.Actual)
}

// EnclaveIdentityVersionError indicates the enclave identity version is unsupported.
type EnclaveIdentityVersionError struct {
	Expected int
	Actual   int
}

func (e *EnclaveIdentityVersionError) Error() string {
	return fmt.Sprintf("unsupported enclave identity version: expected %d, got %d", e.Expected, e.Actual)
}

// TCBTypeError indicates the tcbType field is not the expected value.
type TCBTypeError struct {
	Expected int
	Actual   int
}

func (e *TCBTypeError) Error() string {
	return fmt.Sprintf("unsupported tcbType: expected %d, got %d", e.Expected, e.Actual)
}

// TrailingDataError indicates unexpected trailing bytes after a parsed structure.
type TrailingDataError struct {
	Expected int
	Actual   int
}

func (e *TrailingDataError) Error() string {
	return fmt.Sprintf("trailing data after evidence: expected %d bytes, got %d", e.Expected, e.Actual)
}

// QETCBLevelNotFoundError indicates no matching QE TCB level was found.
type QETCBLevelNotFoundError struct {
	ISVSVN uint16
}

func (e *QETCBLevelNotFoundError) Error() string {
	return fmt.Sprintf("no matching QE TCB level found for isvsvn %d", e.ISVSVN)
}

// PostQuantumUnsupportedError indicates that PostQuantum Noise handshakes
// are not supported in the Go implementation.
type PostQuantumUnsupportedError struct{}

func (e *PostQuantumUnsupportedError) Error() string {
	return "PostQuantum Noise handshakes are not supported: Go flynn/noise does not support HFS patterns"
}

// PCKExtensionParseError indicates that the PCK certificate extension
// could not be parsed during TCB verification.
type PCKExtensionParseError struct {
	Field string
	Err   error
}

func (e *PCKExtensionParseError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("failed to parse PCK extension field %q: %v", e.Field, e.Err)
	}
	return fmt.Sprintf("failed to parse PCK extension field %q", e.Field)
}

func (e *PCKExtensionParseError) Unwrap() error {
	return e.Err
}

// RootCRLVerificationError indicates the root CRL could not be verified
// against the Intel root public key.
type RootCRLVerificationError struct {
	Err error
}

func (e *RootCRLVerificationError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("root CRL signature verification against Intel root key failed: %v", e.Err)
	}
	return "root CRL signature verification against Intel root key failed"
}

func (e *RootCRLVerificationError) Unwrap() error {
	return e.Err
}

// Uint16OverflowError indicates a parsed integer value exceeded the uint16 range.
type Uint16OverflowError struct {
	Field string
	Value uint32
}

func (e *Uint16OverflowError) Error() string {
	return fmt.Sprintf("value %d for field %q exceeds uint16 range", e.Value, e.Field)
}

// QEVendorIDMismatchError indicates the QE vendor ID does not match Intel.
type QEVendorIDMismatchError struct {
	Actual [16]byte
}

func (e *QEVendorIDMismatchError) Error() string {
	return fmt.Sprintf("QE vendor ID not Intel: %x", e.Actual)
}

// QEAttributesMismatchError indicates the QE attributes do not match the expected masked value.
type QEAttributesMismatchError struct {
	Index    int
	Expected byte
	Actual   byte
}

func (e *QEAttributesMismatchError) Error() string {
	return fmt.Sprintf("QE attributes mismatch at byte %d: expected 0x%02x, got 0x%02x", e.Index, e.Expected, e.Actual)
}

// MRSignerMismatchError indicates the QE MRSIGNER does not match the endorsement.
type MRSignerMismatchError struct {
	Expected [32]byte
	Actual   [32]byte
}

func (e *MRSignerMismatchError) Error() string {
	return fmt.Sprintf("QE mrsigner mismatch: expected %x, got %x", e.Expected, e.Actual)
}

// ISVProdIDMismatchError indicates the QE ISV Product ID does not match.
type ISVProdIDMismatchError struct {
	Expected uint16
	Actual   uint16
}

func (e *ISVProdIDMismatchError) Error() string {
	return fmt.Sprintf("QE isvprodid mismatch: expected %d, got %d", e.Expected, e.Actual)
}

// MiscselectMismatchError indicates the QE miscselect does not match the expected masked value.
type MiscselectMismatchError struct {
	Expected uint32
	Actual   uint32
}

func (e *MiscselectMismatchError) Error() string {
	return fmt.Sprintf("QE miscselect mismatch: expected 0x%08x, got 0x%08x", e.Expected, e.Actual)
}

// TCBStatusUnacceptableError indicates the TCB status is not acceptable for attestation.
type TCBStatusUnacceptableError struct {
	Status string
}

func (e *TCBStatusUnacceptableError) Error() string {
	return fmt.Sprintf("TCB status not acceptable for attestation: %s", e.Status)
}

// EnclaveIdentityParseError indicates a failure to parse the enclave identity JSON.
type EnclaveIdentityParseError struct {
	Err error
}

func (e *EnclaveIdentityParseError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("failed to parse enclave identity JSON: %v", e.Err)
	}
	return "failed to parse enclave identity JSON"
}

func (e *EnclaveIdentityParseError) Unwrap() error {
	return e.Err
}

// TCBLevelVersionInconsistencyError indicates that TCB levels use inconsistent format versions.
type TCBLevelVersionInconsistencyError struct {
	ExpectedV3 bool
}

func (e *TCBLevelVersionInconsistencyError) Error() string {
	if e.ExpectedV3 {
		return "TCB levels use inconsistent format versions: first level uses v3, found v2 level"
	}
	return "TCB levels use inconsistent format versions: first level uses v2, found v3 level"
}

// TCBUnsupportedError indicates an unsupported TCB level was found in the PCK extension.
type TCBUnsupportedError struct{}

func (e *TCBUnsupportedError) Error() string {
	return "unsupported TCB in PCK extension"
}

// ProtobufDecodeError indicates a failure during manual protobuf decoding.
type ProtobufDecodeError struct {
	Detail string
}

func (e *ProtobufDecodeError) Error() string {
	return fmt.Sprintf("attest: protobuf decode: %s", e.Detail)
}

// DcapOperationError wraps an underlying error with context about which
// DCAP verification step failed.
type DcapOperationError struct {
	Operation string
	Err       error
}

func (e *DcapOperationError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("attest: %s: %v", e.Operation, e.Err)
	}
	return fmt.Sprintf("attest: %s", e.Operation)
}

func (e *DcapOperationError) Unwrap() error {
	return e.Err
}

// DcapValidationError indicates a specific DCAP validation check failed.
type DcapValidationError struct {
	Detail string
}

func (e *DcapValidationError) Error() string {
	return fmt.Sprintf("attest: %s", e.Detail)
}

// EvidenceParseError indicates a failure parsing DCAP evidence data.
type EvidenceParseError struct {
	Detail string
	Err    error
}

func (e *EvidenceParseError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("attest: %s: %v", e.Detail, e.Err)
	}
	return fmt.Sprintf("attest: %s", e.Detail)
}

func (e *EvidenceParseError) Unwrap() error {
	return e.Err
}

// EndorsementParseError indicates a failure parsing DCAP endorsement data.
type EndorsementParseError struct {
	Detail string
	Err    error
}

func (e *EndorsementParseError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("attest: %s: %v", e.Detail, e.Err)
	}
	return fmt.Sprintf("attest: %s", e.Detail)
}

func (e *EndorsementParseError) Unwrap() error {
	return e.Err
}

// ASN1ParseError indicates a failure parsing ASN.1 data in PCK extensions.
type ASN1ParseError struct {
	Detail string
	Err    error
}

func (e *ASN1ParseError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("attest: ASN.1: %s: %v", e.Detail, e.Err)
	}
	return fmt.Sprintf("attest: ASN.1: %s", e.Detail)
}

func (e *ASN1ParseError) Unwrap() error {
	return e.Err
}

// CertChainError indicates a failure in certificate chain verification.
type CertChainError struct {
	Detail string
	Err    error
}

func (e *CertChainError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("attest: %s: %v", e.Detail, e.Err)
	}
	return fmt.Sprintf("attest: %s", e.Detail)
}

func (e *CertChainError) Unwrap() error {
	return e.Err
}

// ClaimsError indicates a failure in custom claims parsing or verification.
type ClaimsError struct {
	Detail string
}

func (e *ClaimsError) Error() string {
	return fmt.Sprintf("attest: %s", e.Detail)
}

// FMSPCMismatchError indicates the FMSPC from the PCK extension does not
// match the FMSPC from the TCB info.
type FMSPCMismatchError struct {
	PCKExtension []byte
	TCBInfo      []byte
}

func (e *FMSPCMismatchError) Error() string {
	return fmt.Sprintf("attest: tcb fmspc mismatch (pck extension fmspc was %x, tcb_info fmspc was %x)",
		e.PCKExtension, e.TCBInfo)
}

// PCEIDMismatchError indicates the PCEID from the PCK extension does not
// match the PCEID from the TCB info.
type PCEIDMismatchError struct {
	PCKExtension []byte
	TCBInfo      []byte
}

func (e *PCEIDMismatchError) Error() string {
	return fmt.Sprintf("attest: tcb pceid mismatch (pck extension pceid was %x, tcb_info pceid was %x)",
		e.PCKExtension, e.TCBInfo)
}

// HexDecodeError indicates an invalid hex character was encountered during
// endorsement hex field parsing.
type HexDecodeError struct {
	Char byte
}

func (e *HexDecodeError) Error() string {
	return fmt.Sprintf("attest: invalid hex character: %c", e.Char)
}

// JSONFieldError indicates a JSON field parsing failure in endorsement data.
type JSONFieldError struct {
	Field  string
	Detail string
}

func (e *JSONFieldError) Error() string {
	return fmt.Sprintf("attest: %s: %s", e.Detail, e.Field)
}

// AttestKeyError indicates a failure parsing or validating an attestation key.
type AttestKeyError struct {
	Detail string
}

func (e *AttestKeyError) Error() string {
	return fmt.Sprintf("attest: %s", e.Detail)
}

// SignatureFormatError indicates an ECDSA signature has an invalid format.
type SignatureFormatError struct {
	Expected int
	Actual   int
}

func (e *SignatureFormatError) Error() string {
	return fmt.Sprintf("attest: expected %d byte signature, got %d", e.Expected, e.Actual)
}

// PEMParseError indicates a failure parsing PEM-encoded certificates.
type PEMParseError struct {
	Detail string
	Err    error
}

func (e *PEMParseError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("attest: %s: %v", e.Detail, e.Err)
	}
	return fmt.Sprintf("attest: %s", e.Detail)
}

func (e *PEMParseError) Unwrap() error {
	return e.Err
}

// CRLParseError indicates a failure parsing a DER-encoded CRL.
type CRLParseError struct {
	Err error
}

func (e *CRLParseError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("attest: parsing CRL: %v", e.Err)
	}
	return "attest: parsing CRL"
}

func (e *CRLParseError) Unwrap() error {
	return e.Err
}

// HandshakeIncompleteError indicates that a Noise handshake did not
// produce the expected cipher states.
type HandshakeIncompleteError struct{}

func (e *HandshakeIncompleteError) Error() string {
	return "attest: handshake did not complete: expected cipher states after handshake completion"
}

// ProtobufWireTypeError indicates an unexpected protobuf wire type
// was encountered during manual decoding.
type ProtobufWireTypeError struct {
	WireType    uint64
	FieldNumber uint64
}

func (e *ProtobufWireTypeError) Error() string {
	return fmt.Sprintf("attest: unexpected wire type %d for field %d", e.WireType, e.FieldNumber)
}

// ClaimsParseError indicates a failure parsing custom claims data.
type ClaimsParseError struct {
	Detail string
}

func (e *ClaimsParseError) Error() string {
	return fmt.Sprintf("attest: claims: %s", e.Detail)
}

// RaftConfigDecodeError indicates a failure decoding a RaftGroupConfig from claims.
type RaftConfigDecodeError struct {
	Err error
}

func (e *RaftConfigDecodeError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("attest: failed to decode raft group config: %v", e.Err)
	}
	return "attest: failed to decode raft group config"
}

func (e *RaftConfigDecodeError) Unwrap() error {
	return e.Err
}

// EndorsementValidationError indicates a specific endorsement validation check failed.
type EndorsementValidationError struct {
	Detail string
}

func (e *EndorsementValidationError) Error() string {
	return fmt.Sprintf("attest: endorsement: %s", e.Detail)
}
