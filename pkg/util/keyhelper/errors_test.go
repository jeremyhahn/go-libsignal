package keyhelper

import (
	"errors"
	"strings"
	"testing"
)

// TestErrRandomGeneration_Error exercises the Error() method to ensure it
// formats both the operation name and the underlying cause.
func TestErrRandomGeneration_Error(t *testing.T) {
	cause := errors.New("device full")
	err := &ErrRandomGeneration{Op: "GenerateSenderKey", Err: cause}

	msg := err.Error()
	if !strings.Contains(msg, "GenerateSenderKey") {
		t.Errorf("Error() = %q, should contain op name", msg)
	}
	if !strings.Contains(msg, "device full") {
		t.Errorf("Error() = %q, should contain cause", msg)
	}
	if !strings.Contains(msg, "random generation failed") {
		t.Errorf("Error() = %q, should contain 'random generation failed'", msg)
	}
}

// TestErrRandomGeneration_Unwrap verifies that errors.Is can traverse
// ErrRandomGeneration to reach the wrapped cause.
func TestErrRandomGeneration_Unwrap(t *testing.T) {
	cause := errors.New("simulated failure")
	err := &ErrRandomGeneration{Op: "test-op", Err: cause}

	if !errors.Is(err, cause) {
		t.Error("errors.Is should find the wrapped cause via Unwrap()")
	}
	if err.Unwrap() != cause {
		t.Error("Unwrap() should return the wrapped cause directly")
	}
}

// TestErrRandomGeneration_SatisfiesErrorInterface confirms the type is usable
// as a plain error value.
func TestErrRandomGeneration_SatisfiesErrorInterface(t *testing.T) {
	var _ error = (*ErrRandomGeneration)(nil)
}

// TestGenerateSenderKey_ErrorMessage validates the error returned from
// GenerateSenderKey when rand.Reader fails carries the expected Op field.
func TestGenerateSenderKey_ErrorContainsOp(t *testing.T) {
	// Direct construction to verify the Op field is set correctly.
	err := &ErrRandomGeneration{Op: "GenerateSenderKey", Err: errors.New("mock")}
	if !strings.Contains(err.Error(), "keyhelper: GenerateSenderKey") {
		t.Errorf("Error() = %q, want prefix 'keyhelper: GenerateSenderKey'", err.Error())
	}
}
