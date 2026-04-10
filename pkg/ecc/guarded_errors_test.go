package ecc

import (
	"errors"
	"testing"
)

// TestErrGuardedKeyAllocation_ErrorAndUnwrap verifies Error() and Unwrap()
// for ErrGuardedKeyAllocation.
func TestErrGuardedKeyAllocation_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("out of memory")
	e := &ErrGuardedKeyAllocation{Operation: "key-gen", Err: inner}

	msg := e.Error()
	if msg == "" {
		t.Fatal("Error() returned empty string")
	}
	if !contains(msg, "key-gen") {
		t.Errorf("Error() = %q, expected to contain 'key-gen'", msg)
	}
	if !contains(msg, "out of memory") {
		t.Errorf("Error() = %q, expected to contain 'out of memory'", msg)
	}
	if e.Unwrap() != inner {
		t.Error("Unwrap() should return the wrapped error")
	}
}

// TestErrReadingRandomness_ErrorAndUnwrap verifies ErrReadingRandomness.
func TestErrReadingRandomness_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("read EOF")
	e := &ErrReadingRandomness{Operation: "signing", Err: inner}

	msg := e.Error()
	if !contains(msg, "signing") {
		t.Errorf("Error() = %q, expected to contain 'signing'", msg)
	}
	if !contains(msg, "read EOF") {
		t.Errorf("Error() = %q, expected to contain 'read EOF'", msg)
	}
	if e.Unwrap() != inner {
		t.Error("Unwrap() should return the wrapped error")
	}
}

// TestErrX25519Agreement_ErrorAndUnwrap verifies ErrX25519Agreement.
func TestErrX25519Agreement_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("curve error")
	e := &ErrX25519Agreement{Err: inner}

	msg := e.Error()
	if !contains(msg, "X25519") {
		t.Errorf("Error() = %q, expected to contain 'X25519'", msg)
	}
	if !contains(msg, "curve error") {
		t.Errorf("Error() = %q, expected to contain 'curve error'", msg)
	}
	if e.Unwrap() != inner {
		t.Error("Unwrap() should return the wrapped error")
	}
}

// TestErrAllocatingSharedSecret_ErrorAndUnwrap verifies ErrAllocatingSharedSecret.
func TestErrAllocatingSharedSecret_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("alloc failed")
	e := &ErrAllocatingSharedSecret{Err: inner}

	msg := e.Error()
	if !contains(msg, "shared secret") {
		t.Errorf("Error() = %q, expected to contain 'shared secret'", msg)
	}
	if !contains(msg, "alloc failed") {
		t.Errorf("Error() = %q, expected to contain 'alloc failed'", msg)
	}
	if e.Unwrap() != inner {
		t.Error("Unwrap() should return the wrapped error")
	}
}

// TestErrBadKeyType_Error verifies ErrBadKeyType.
func TestErrBadKeyType_Error(t *testing.T) {
	e := &ErrBadKeyType{KeyType: 0xAB}

	msg := e.Error()
	if msg == "" {
		t.Fatal("Error() returned empty string")
	}
	// Should include the hex key type value.
	if !contains(msg, "ab") && !contains(msg, "AB") {
		t.Errorf("Error() = %q, expected to contain hex key type 'ab'", msg)
	}
}

// TestErrGuardedKeyClone_ErrorAndUnwrap verifies ErrGuardedKeyClone.
func TestErrGuardedKeyClone_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("clone failed")
	e := &ErrGuardedKeyClone{Err: inner}

	msg := e.Error()
	if !contains(msg, "clone") {
		t.Errorf("Error() = %q, expected to contain 'clone'", msg)
	}
	if !contains(msg, "clone failed") {
		t.Errorf("Error() = %q, expected to contain 'clone failed'", msg)
	}
	if e.Unwrap() != inner {
		t.Error("Unwrap() should return the wrapped error")
	}
}

// TestErrGeneratingKeyMaterial_ErrorAndUnwrap verifies ErrGeneratingKeyMaterial.
func TestErrGeneratingKeyMaterial_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("rand failure")
	e := &ErrGeneratingKeyMaterial{Err: inner}

	msg := e.Error()
	if !contains(msg, "key material") {
		t.Errorf("Error() = %q, expected to contain 'key material'", msg)
	}
	if !contains(msg, "rand failure") {
		t.Errorf("Error() = %q, expected to contain 'rand failure'", msg)
	}
	if e.Unwrap() != inner {
		t.Error("Unwrap() should return the wrapped error")
	}
}

// TestErrSignFailed_IsComparable verifies ErrSignFailed sentinel behavior.
func TestErrSignFailed_IsComparable(t *testing.T) {
	if ErrSignFailed == nil {
		t.Fatal("ErrSignFailed should not be nil")
	}
	if ErrSignFailed.Error() == "" {
		t.Fatal("ErrSignFailed.Error() should not be empty")
	}
	if errors.Is(ErrSignFailed, ErrGuardedKeyDestroyed) {
		t.Error("ErrSignFailed should not match ErrGuardedKeyDestroyed")
	}
}

// TestErrInvalidKeyAgreement_IsComparable verifies ErrInvalidKeyAgreement sentinel.
func TestErrInvalidKeyAgreement_IsComparable(t *testing.T) {
	if ErrInvalidKeyAgreement == nil {
		t.Fatal("ErrInvalidKeyAgreement should not be nil")
	}
	msg := ErrInvalidKeyAgreement.Error()
	if !contains(msg, "all-zero") {
		t.Errorf("Error() = %q, expected to contain 'all-zero'", msg)
	}
}

// TestErrBadKeyLength_IsComparable verifies ErrBadKeyLength sentinel.
func TestErrBadKeyLength_IsComparable(t *testing.T) {
	if ErrBadKeyLength == nil {
		t.Fatal("ErrBadKeyLength should not be nil")
	}
	if ErrBadKeyLength.Error() == "" {
		t.Fatal("ErrBadKeyLength.Error() should not be empty")
	}
}

// TestErrInputTooShort_IsComparable verifies ErrInputTooShort sentinel.
func TestErrInputTooShort_IsComparable(t *testing.T) {
	if ErrInputTooShort == nil {
		t.Fatal("ErrInputTooShort should not be nil")
	}
	if ErrInputTooShort.Error() == "" {
		t.Fatal("ErrInputTooShort.Error() should not be empty")
	}
}

// TestErrGuardedKeyAllocation_WrapsAsError ensures errors.As works.
func TestErrGuardedKeyAllocation_WrapsAsError(t *testing.T) {
	inner := errors.New("heap full")
	e := &ErrGuardedKeyAllocation{Operation: "test", Err: inner}

	var target *ErrGuardedKeyAllocation
	if !errors.As(e, &target) {
		t.Error("errors.As should find ErrGuardedKeyAllocation")
	}
	if target.Operation != "test" {
		t.Errorf("Operation = %q, want 'test'", target.Operation)
	}
}

// TestErrReadingRandomness_WrapsAsError ensures errors.As works.
func TestErrReadingRandomness_WrapsAsError(t *testing.T) {
	e := &ErrReadingRandomness{Operation: "VRF", Err: errors.New("io error")}

	var target *ErrReadingRandomness
	if !errors.As(e, &target) {
		t.Error("errors.As should find ErrReadingRandomness")
	}
	if target.Operation != "VRF" {
		t.Errorf("Operation = %q, want 'VRF'", target.Operation)
	}
}

// contains is a local helper to check substring presence.
func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}
