package spqr

import (
	"strings"
	"testing"
)

// TestErrInvalidPrevEncoding_Error verifies that ErrInvalidPrevEncoding.Error()
// formats the length value in its message.
func TestErrInvalidPrevEncoding_Error(t *testing.T) {
	err := &ErrInvalidPrevEncoding{Len: 37}
	msg := err.Error()
	if !strings.Contains(msg, "37") {
		t.Errorf("Error() = %q, should contain length 37", msg)
	}
	if !strings.Contains(msg, "36") {
		t.Errorf("Error() = %q, should mention multiple of 36", msg)
	}
	// Satisfies the error interface.
	var _ error = err
}
