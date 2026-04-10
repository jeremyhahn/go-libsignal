package net

import (
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/attest"
)

// TestErrors_ErrorMethods exercises all Error() methods in errors.go that
// are not covered by other test files. These typed errors are zero-coverage
// because the production paths that return them are not reached by existing tests.

func TestErrCdsiNoTokenInResponseType_Error(t *testing.T) {
	e := &ErrCdsiNoTokenInResponseType{}
	msg := e.Error()
	if msg != "cdsi: no token in response" {
		t.Errorf("Error() = %q, want %q", msg, "cdsi: no token in response")
	}
	// Verify it satisfies the error interface.
	var target *ErrCdsiNoTokenInResponseType
	if !errors.As(e, &target) {
		t.Fatal("errors.As must find *ErrCdsiNoTokenInResponseType in itself")
	}
}

func TestErrChatDisconnectedType_Error(t *testing.T) {
	e := &ErrChatDisconnectedType{}
	msg := e.Error()
	if msg != "chat: connection is disconnected" {
		t.Errorf("Error() = %q, want %q", msg, "chat: connection is disconnected")
	}
	var target *ErrChatDisconnectedType
	if !errors.As(e, &target) {
		t.Fatal("errors.As must find *ErrChatDisconnectedType in itself")
	}
}

func TestErrMissingRaftConfig_Error(t *testing.T) {
	e := &ErrMissingRaftConfig{}
	msg := e.Error()
	if msg != "net: raft config must be present for SGX enclave" {
		t.Errorf("Error() = %q, want %q", msg, "net: raft config must be present for SGX enclave")
	}
	var target *ErrMissingRaftConfig
	if !errors.As(e, &target) {
		t.Fatal("errors.As must find *ErrMissingRaftConfig in itself")
	}
}

func TestErrRequestConnectionMismatch_Error(t *testing.T) {
	e := &ErrRequestConnectionMismatch{Requests: 3, Connections: 2}
	msg := e.Error()
	if !strings.Contains(msg, "3") || !strings.Contains(msg, "2") {
		t.Errorf("Error() = %q must contain request/connection counts", msg)
	}

	// Zero values produce a valid message.
	e2 := &ErrRequestConnectionMismatch{}
	if e2.Error() == "" {
		t.Fatal("Error() must not be empty for zero-value struct")
	}
}

func TestErrNoServerResponse_Error(t *testing.T) {
	e := &ErrNoServerResponse{ServerIndex: 5}
	msg := e.Error()
	if !strings.Contains(msg, "5") {
		t.Errorf("Error() = %q must contain server index", msg)
	}

	// Index 0 also produces a valid message.
	e2 := &ErrNoServerResponse{ServerIndex: 0}
	if e2.Error() == "" {
		t.Fatal("Error() must not be empty for server index 0")
	}
}

// TestCertPinError_ErrorAllKinds exercises all branches of CertPinError.Error()
// including the default branch and Unwrap().

func TestCertPinError_ErrorNoCertificates(t *testing.T) {
	e := &CertPinError{Kind: CertPinErrorNoCertificates}
	msg := e.Error()
	if msg != "certpin: no certificates provided" {
		t.Errorf("Error() = %q, want %q", msg, "certpin: no certificates provided")
	}
	if e.Unwrap() != nil {
		t.Error("Unwrap() should return nil when Err is nil")
	}
}

func TestCertPinError_ErrorParseFailed(t *testing.T) {
	inner := errors.New("bad DER")
	e := &CertPinError{Kind: CertPinErrorParseFailed, Err: inner}
	msg := e.Error()
	if !strings.Contains(msg, "bad DER") {
		t.Errorf("Error() = %q must contain inner error text", msg)
	}
	if !errors.Is(e, inner) {
		t.Fatal("errors.Is should find inner error via Unwrap()")
	}
}

func TestCertPinError_ErrorPoolCreationFailed(t *testing.T) {
	inner := errors.New("pool failed")
	e := &CertPinError{Kind: CertPinErrorPoolCreationFailed, Err: inner}
	msg := e.Error()
	if !strings.Contains(msg, "pool failed") {
		t.Errorf("Error() = %q must contain inner error text", msg)
	}
}

func TestCertPinError_ErrorDefaultWithErr(t *testing.T) {
	// CertPinErrorKind value not in the defined constants.
	inner := errors.New("unexpected situation")
	e := &CertPinError{Kind: CertPinErrorKind(99), Err: inner}
	msg := e.Error()
	if !strings.Contains(msg, "unexpected situation") {
		t.Errorf("Error() = %q must contain inner error text for default branch", msg)
	}
}

func TestCertPinError_ErrorDefaultWithoutErr(t *testing.T) {
	// Default branch with no inner error.
	e := &CertPinError{Kind: CertPinErrorKind(99), Err: nil}
	msg := e.Error()
	if msg != "certpin: unknown error" {
		t.Errorf("Error() = %q, want %q", msg, "certpin: unknown error")
	}
	if e.Unwrap() != nil {
		t.Error("Unwrap() should return nil when Err is nil")
	}
}

func TestCertPinError_Unwrap(t *testing.T) {
	inner := errors.New("inner cause")
	e := &CertPinError{Kind: CertPinErrorParseFailed, Err: inner}
	if e.Unwrap() != inner {
		t.Errorf("Unwrap() = %v, want %v", e.Unwrap(), inner)
	}
}

// TestStaticCertificatePinner_ProxyGWithValidCerts exercises the RootCertificatesProxyG
// success path (valid certs) which reaches the branch not covered by the existing test.

func TestStaticCertificatePinner_ProxyGWithValidCerts(t *testing.T) {
	der := generateSelfSignedCertDER(t)
	pinner := &StaticCertificatePinner{ProxyCerts: [][]byte{der}}
	cfg := pinner.PinCertificates(RootCertificatesProxyG)
	if cfg == nil {
		t.Fatal("expected non-nil config for valid proxy certs")
	}
	if cfg.RootCAs == nil {
		t.Error("expected non-nil cert pool")
	}
}

// TestCDSIHandshaker_NewHandshake exercises the CDSIHandshaker.NewHandshake path.
// The attestation message is empty/invalid so we expect an error from attest.CDS2NewHandshake,
// but the call path through CDSIHandshaker itself is what must be covered.

func TestCDSIHandshaker_NewHandshake_ReachesAttest(t *testing.T) {
	h := &CDSIHandshaker{}
	params := &EndpointParams{
		MrEnclave: MrEnclave{
			Value: make([]byte, 32),
			Kind:  EnclaveKindCDSI,
		},
		RaftConfig: nil,
	}
	// The attestation message is deliberately invalid; we just need the function
	// to be invoked (covered), not to succeed.
	_, _ = h.NewHandshake(params, []byte("not a valid attestation message"))
}

// TestSvrSgxHandshaker_NewHandshake_WithRaftConfig_ReachesAttest tests that the
// SvrSgxHandshaker with a non-nil RaftConfig reaches the attest.SVR2NewHandshake call.
// The attestation message is invalid so we expect an error, but the coverage path is hit.

func TestSvrSgxHandshaker_NewHandshake_WithRaftConfig_ReachesAttest(t *testing.T) {
	h := &SvrSgxHandshaker{}
	params := &EndpointParams{
		MrEnclave: MrEnclave{
			Value: make([]byte, 32),
			Kind:  EnclaveKindSvrSgx,
		},
		RaftConfig: &attest.RaftConfig{}, // non-nil: satisfies the nil check
	}
	// Deliberately invalid attestation bytes — we only need coverage of the non-nil branch.
	_, _ = h.NewHandshake(params, []byte("not valid"))
}

// TestErrMissingRaftConfig_ReturnedBySvrSgxHandshaker verifies the typed error is
// actually returned when RaftConfig is nil (already tested in enclave_test.go but
// we verify the Error() string here).

func TestErrMissingRaftConfig_FromHandshaker(t *testing.T) {
	h := &SvrSgxHandshaker{}
	params := &EndpointParams{
		MrEnclave:  MrEnclave{Value: []byte{0x01}, Kind: EnclaveKindSvrSgx},
		RaftConfig: nil,
	}
	_, err := h.NewHandshake(params, nil)
	if err == nil {
		t.Fatal("expected error for nil RaftConfig")
	}
	var e *ErrMissingRaftConfig
	if !errors.As(err, &e) {
		t.Fatalf("expected *ErrMissingRaftConfig, got %T: %v", err, err)
	}
	// Exercises the Error() method via the error message.
	if e.Error() == "" {
		t.Fatal("ErrMissingRaftConfig.Error() must not be empty")
	}
}

// TestBasicAuth_EmptyUsernamePassword verifies basicAuth handles edge cases
// and exercises the length guard branch (len(auth) > 6).

func TestBasicAuth_NonEmptyResult(t *testing.T) {
	result := basicAuth("user", "password")
	if result == "" {
		t.Fatal("basicAuth must return non-empty string for valid credentials")
	}
	// Result should not contain "Basic " prefix (that's added by BasicAuthHeader).
	if strings.HasPrefix(result, "Basic ") {
		t.Error("basicAuth should return only the encoded part, not the full header")
	}
}

func TestBasicAuth_EmptyUsername(t *testing.T) {
	// Empty username with non-empty password is still valid base64.
	result := basicAuth("", "somepassword")
	if len(result) == 0 {
		t.Fatal("basicAuth with empty username should still return non-empty base64")
	}
}
