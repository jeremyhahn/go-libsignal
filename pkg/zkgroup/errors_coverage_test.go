package zkgroup

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestErrGeneratingSigningKey exercises the Error() and Unwrap() methods.
func TestErrGeneratingSigningKey(t *testing.T) {
	cause := errors.New("entropy exhausted")
	err := &ErrGeneratingSigningKey{Err: cause}

	msg := err.Error()
	if !strings.Contains(msg, "signing key") {
		t.Errorf("Error() = %q, should mention 'signing key'", msg)
	}
	if !strings.Contains(msg, "entropy exhausted") {
		t.Errorf("Error() = %q, should contain cause", msg)
	}
	if !errors.Is(err, cause) {
		t.Error("errors.Is should traverse Unwrap() to the cause")
	}
}

// TestErrGeneratingSignatureKeyPair exercises Error() and Unwrap().
func TestErrGeneratingSignatureKeyPair(t *testing.T) {
	cause := errors.New("keygen failure")
	err := &ErrGeneratingSignatureKeyPair{Err: cause}

	msg := err.Error()
	if !strings.Contains(msg, "signature key pair") {
		t.Errorf("Error() = %q, should mention 'signature key pair'", msg)
	}
	if err.Unwrap() != cause {
		t.Error("Unwrap() should return the wrapped cause")
	}
}

// TestErrGeneratingEndorsementKeyPair exercises Error() and Unwrap().
func TestErrGeneratingEndorsementKeyPair(t *testing.T) {
	cause := errors.New("endorsement failure")
	err := &ErrGeneratingEndorsementKeyPair{Err: cause}

	msg := err.Error()
	if !strings.Contains(msg, "endorsement key pair") {
		t.Errorf("Error() = %q, should mention 'endorsement key pair'", msg)
	}
	if err.Unwrap() != cause {
		t.Error("Unwrap() should return the wrapped cause")
	}
}

// TestErrDataTooShort exercises the Error() method.
func TestErrDataTooShort(t *testing.T) {
	err := &ErrDataTooShort{}
	msg := err.Error()
	if !strings.Contains(msg, "too short") {
		t.Errorf("Error() = %q, should mention 'too short'", msg)
	}
	// Satisfies the error interface.
	var _ error = err
}

// TestErrUnexpectedReservedByte exercises the Error() method with the byte value.
func TestErrUnexpectedReservedByte(t *testing.T) {
	err := &ErrUnexpectedReservedByte{Value: 0x42}
	msg := err.Error()
	if !strings.Contains(msg, "66") && !strings.Contains(msg, "0x42") {
		// %d format will produce "66" for 0x42
		t.Errorf("Error() = %q, should contain the byte value 66", msg)
	}
	if !strings.Contains(msg, "reserved") {
		t.Errorf("Error() = %q, should mention 'reserved'", msg)
	}
}

// TestErrUnknownPresentationVersion_Coverage exercises Error() and Unwrap()
// specifically for the coverage of the types declared in errors.go.
func TestErrUnknownPresentationVersion_Coverage(t *testing.T) {
	err := &ErrUnknownPresentationVersion{Version: 0xFF}
	msg := err.Error()
	if !strings.Contains(msg, fmt.Sprintf("%d", 0xFF)) {
		t.Errorf("Error() = %q, should contain the version number", msg)
	}
	if !errors.Is(err, ErrDeserializationFailure) {
		t.Error("errors.Is should find ErrDeserializationFailure via Unwrap()")
	}
}

// TestErrInvalidServiceIDKind exercises the Error() method.
func TestErrInvalidServiceIDKind(t *testing.T) {
	err := &ErrInvalidServiceIDKind{Got: ServiceIDType(2)}
	msg := err.Error()
	if !strings.Contains(msg, "service ID") {
		t.Errorf("Error() = %q, should mention 'service ID'", msg)
	}
	if !strings.Contains(msg, "ACI") {
		t.Errorf("Error() = %q, should mention 'ACI'", msg)
	}
}

// TestErrInvalidReceiptPresentationType exercises the sentinel and its Error().
func TestErrInvalidReceiptPresentationType(t *testing.T) {
	err := ErrInvalidReceiptPresentation
	if err == nil {
		t.Fatal("ErrInvalidReceiptPresentation should not be nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "receipt credential presentation") {
		t.Errorf("Error() = %q, should mention 'receipt credential presentation'", msg)
	}
}

// TestErrInvalidBackupAuthPresentationType exercises the sentinel and its Error().
func TestErrInvalidBackupAuthPresentationType(t *testing.T) {
	err := ErrInvalidBackupAuthPresentation
	if err == nil {
		t.Fatal("ErrInvalidBackupAuthPresentation should not be nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "backup auth credential presentation") {
		t.Errorf("Error() = %q, should mention 'backup auth credential presentation'", msg)
	}
}

// TestErrInvalidCallLinkAuthPresentationType exercises the sentinel and its Error().
func TestErrInvalidCallLinkAuthPresentationType(t *testing.T) {
	err := ErrInvalidCallLinkAuthPresentation
	if err == nil {
		t.Fatal("ErrInvalidCallLinkAuthPresentation should not be nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "call link auth credential presentation") {
		t.Errorf("Error() = %q, should mention 'call link auth'", msg)
	}
}

// TestErrInvalidCreateCallLinkPresentationType exercises the sentinel and its Error().
func TestErrInvalidCreateCallLinkPresentationType(t *testing.T) {
	err := ErrInvalidCreateCallLinkPresentation
	if err == nil {
		t.Fatal("ErrInvalidCreateCallLinkPresentation should not be nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "create call link") {
		t.Errorf("Error() = %q, should mention 'create call link'", msg)
	}
}

// TestErrInvalidCredentialLength exercises Error() and Unwrap().
func TestErrInvalidCredentialLength(t *testing.T) {
	err := &ErrInvalidCredentialLength{Got: 10, Want: 32}
	msg := err.Error()
	if !strings.Contains(msg, "10") || !strings.Contains(msg, "32") {
		t.Errorf("Error() = %q, should contain got=10 and want=32", msg)
	}
	if !errors.Is(err, ErrDeserializationFailure) {
		t.Error("errors.Is should find ErrDeserializationFailure via Unwrap()")
	}
}

// TestErrVerificationFailureType_Sentinel confirms the sentinel's Error() method.
func TestErrVerificationFailureType_Sentinel(t *testing.T) {
	err := &ErrVerificationFailureType{}
	if err.Error() != "zkgroup: verification failure" {
		t.Errorf("Error() = %q", err.Error())
	}
}

// TestErrDeserializationFailureType_Sentinel confirms the sentinel's Error() method.
func TestErrDeserializationFailureType_Sentinel(t *testing.T) {
	err := &ErrDeserializationFailureType{}
	if err.Error() != "zkgroup: deserialization failure" {
		t.Errorf("Error() = %q", err.Error())
	}
}
