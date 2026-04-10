// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package attest

import (
	"errors"
	"fmt"
	"testing"
)

func TestAttestationError_Error(t *testing.T) {
	tests := []struct {
		name    string
		message string
		want    string
	}{
		{
			name:    "simple message",
			message: "bad attestation",
			want:    "failure to attest remote enclave: bad attestation",
		},
		{
			name:    "empty message",
			message: "",
			want:    "failure to attest remote enclave: ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &AttestationError{Message: tt.message}
			if got := e.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEnclaveError_Error(t *testing.T) {
	tests := []struct {
		name    string
		err     *EnclaveError
		want    string
	}{
		{
			name: "with wrapped error",
			err: &EnclaveError{
				Kind:    ErrNoiseHandshake,
				Message: "handshake failed",
				Err:     fmt.Errorf("underlying"),
			},
			want: "handshake failed: underlying",
		},
		{
			name: "without wrapped error",
			err: &EnclaveError{
				Kind:    ErrAttestationData,
				Message: "data invalid",
			},
			want: "data invalid",
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

func TestEnclaveError_Unwrap(t *testing.T) {
	inner := fmt.Errorf("inner error")
	e := &EnclaveError{Err: inner}
	if got := e.Unwrap(); got != inner {
		t.Errorf("Unwrap() = %v, want %v", got, inner)
	}

	eNoInner := &EnclaveError{}
	if got := eNoInner.Unwrap(); got != nil {
		t.Errorf("Unwrap() on nil Err = %v, want nil", got)
	}
}

func TestNewAttestationDataError(t *testing.T) {
	e := newAttestationDataError("bad data")
	if e.Kind != ErrAttestationData {
		t.Errorf("Kind = %d, want %d", e.Kind, ErrAttestationData)
	}
	if e.Err != nil {
		t.Errorf("Err should be nil")
	}
	if got := e.Error(); got != "attestation data invalid: bad data" {
		t.Errorf("Error() = %q", got)
	}
}

func TestNewNoiseHandshakeError(t *testing.T) {
	inner := fmt.Errorf("noise fail")
	e := newNoiseHandshakeError(inner)
	if e.Kind != ErrNoiseHandshake {
		t.Errorf("Kind = %d, want %d", e.Kind, ErrNoiseHandshake)
	}
	if !errors.Is(e, inner) {
		t.Error("should unwrap to inner error")
	}
}

func TestNewNoiseCommunicationError(t *testing.T) {
	inner := fmt.Errorf("comm fail")
	e := newNoiseCommunicationError(inner)
	if e.Kind != ErrNoiseCommunication {
		t.Errorf("Kind = %d, want %d", e.Kind, ErrNoiseCommunication)
	}
	if !errors.Is(e, inner) {
		t.Error("should unwrap to inner error")
	}
}

func TestNewAttestationError(t *testing.T) {
	inner := fmt.Errorf("attest fail")
	e := newAttestationError(inner)
	if e.Kind != ErrAttestationFailure {
		t.Errorf("Kind = %d, want %d", e.Kind, ErrAttestationFailure)
	}
	if !errors.Is(e, inner) {
		t.Error("should unwrap to inner error")
	}
}

func TestClientConnectionError_Error(t *testing.T) {
	tests := []struct {
		name string
		err  *ClientConnectionError
		want string
	}{
		{
			name: "with wrapped error",
			err:  &ClientConnectionError{Err: fmt.Errorf("decrypt failed")},
			want: "noise error: decrypt failed",
		},
		{
			name: "with message only",
			err:  &ClientConnectionError{Message: "bad state"},
			want: "noise error: bad state",
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

func TestClientConnectionError_Unwrap(t *testing.T) {
	inner := fmt.Errorf("inner")
	e := &ClientConnectionError{Err: inner}
	if got := e.Unwrap(); got != inner {
		t.Errorf("Unwrap() = %v, want %v", got, inner)
	}

	eNil := &ClientConnectionError{}
	if got := eNil.Unwrap(); got != nil {
		t.Errorf("Unwrap() on nil = %v, want nil", got)
	}
}

func TestHSMError_Error(t *testing.T) {
	tests := []struct {
		name string
		err  *HSMError
		want string
	}{
		{
			name: "communication error",
			err:  &HSMError{Kind: ErrHSMCommunication, Err: fmt.Errorf("timeout")},
			want: "error in communication to HSM (timeout)",
		},
		{
			name: "handshake error",
			err:  &HSMError{Kind: ErrHSMHandshake, Err: fmt.Errorf("bad key")},
			want: "error in handshake to HSM (bad key)",
		},
		{
			name: "trusted code error",
			err:  &HSMError{Kind: ErrTrustedCode},
			want: "trusted HSM process does not match trusted code hash",
		},
		{
			name: "invalid public key",
			err:  &HSMError{Kind: ErrInvalidPublicKey},
			want: fmt.Sprintf("invalid public key, must be %d bytes", PubKeySize),
		},
		{
			name: "invalid code hash",
			err:  &HSMError{Kind: ErrInvalidCodeHash},
			want: fmt.Sprintf("invalid code hashes, must be >0 hashes, each exactly %d bytes", CodeHashSize),
		},
		{
			name: "invalid bridge state",
			err:  &HSMError{Kind: ErrHSMInvalidBridgeState},
			want: "invalid bridge state",
		},
		{
			name: "default/unknown kind",
			err:  &HSMError{Kind: HSMErrorKind(99), Message: "custom msg"},
			want: "custom msg",
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

func TestHSMError_Unwrap(t *testing.T) {
	inner := fmt.Errorf("hsm inner")
	e := &HSMError{Err: inner}
	if got := e.Unwrap(); got != inner {
		t.Errorf("Unwrap() = %v, want %v", got, inner)
	}
}

func TestDcapError_Error(t *testing.T) {
	tests := []struct {
		name    string
		err     *DcapError
		want    string
	}{
		{
			name: "no context",
			err:  &DcapError{Message: "bad quote"},
			want: "bad quote",
		},
		{
			name: "single context",
			err:  &DcapError{Message: "bad quote", Context: []string{"verify"}},
			want: "(verify) bad quote",
		},
		{
			name: "multiple contexts reversed",
			err:  &DcapError{Message: "fail", Context: []string{"inner", "outer"}},
			want: "(outer -> inner) fail",
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

func TestDcapError_withContext(t *testing.T) {
	e := newDcapError("msg")
	if len(e.Context) != 0 {
		t.Fatal("expected empty context")
	}
	e2 := e.withContext("ctx1")
	if e2 != e {
		t.Error("withContext should return the same pointer")
	}
	if len(e.Context) != 1 || e.Context[0] != "ctx1" {
		t.Errorf("Context = %v, want [ctx1]", e.Context)
	}
	_ = e.withContext("ctx2")
	if len(e.Context) != 2 {
		t.Errorf("Context should have 2 entries, got %d", len(e.Context))
	}
}

func TestIsDcapError(t *testing.T) {
	dcap := &DcapError{Message: "test"}
	if !IsDcapError(dcap) {
		t.Error("IsDcapError should return true for DcapError")
	}

	wrapped := fmt.Errorf("wrapped: %w", dcap)
	if !IsDcapError(wrapped) {
		t.Error("IsDcapError should return true for wrapped DcapError")
	}

	other := fmt.Errorf("not dcap")
	if IsDcapError(other) {
		t.Error("IsDcapError should return false for non-DcapError")
	}
}

func TestCRLVerificationError(t *testing.T) {
	e := &CRLVerificationError{SerialNumber: "123", Issuer: "Intel"}
	got := e.Error()
	if got != "certificate with serial 123 from issuer Intel is revoked" {
		t.Errorf("Error() = %q", got)
	}
}

func TestCRLSignatureError(t *testing.T) {
	e := &CRLSignatureError{Message: "bad sig"}
	got := e.Error()
	if got != "CRL signature verification failed: bad sig" {
		t.Errorf("Error() = %q", got)
	}
}

func TestEndorsementSignatureError(t *testing.T) {
	e := &EndorsementSignatureError{Field: "tcbInfo", Message: "invalid"}
	got := e.Error()
	if got != "endorsement signature verification failed for tcbInfo: invalid" {
		t.Errorf("Error() = %q", got)
	}
}

func TestQETCBStatusError(t *testing.T) {
	e := &QETCBStatusError{Status: "OutOfDate", ISVSVN: 3}
	got := e.Error()
	if got != `QE TCB status "OutOfDate" is not acceptable for isvsvn 3` {
		t.Errorf("Error() = %q", got)
	}
}

func TestEnclaveIdentityTypeError(t *testing.T) {
	e := &EnclaveIdentityTypeError{Expected: "QE", Actual: "TDX"}
	got := e.Error()
	if got != `enclave identity type mismatch: expected "QE", got "TDX"` {
		t.Errorf("Error() = %q", got)
	}
}

func TestEnclaveIdentityVersionError(t *testing.T) {
	e := &EnclaveIdentityVersionError{Expected: 2, Actual: 3}
	got := e.Error()
	if got != "unsupported enclave identity version: expected 2, got 3" {
		t.Errorf("Error() = %q", got)
	}
}

func TestTCBTypeError(t *testing.T) {
	e := &TCBTypeError{Expected: 0, Actual: 1}
	got := e.Error()
	if got != "unsupported tcbType: expected 0, got 1" {
		t.Errorf("Error() = %q", got)
	}
}

func TestTrailingDataError(t *testing.T) {
	e := &TrailingDataError{Expected: 100, Actual: 120}
	got := e.Error()
	if got != "trailing data after evidence: expected 100 bytes, got 120" {
		t.Errorf("Error() = %q", got)
	}
}

func TestQETCBLevelNotFoundError(t *testing.T) {
	e := &QETCBLevelNotFoundError{ISVSVN: 7}
	got := e.Error()
	if got != "no matching QE TCB level found for isvsvn 7" {
		t.Errorf("Error() = %q", got)
	}
}
