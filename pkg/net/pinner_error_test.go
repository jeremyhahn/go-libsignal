package net

import (
	"errors"
	"strings"
	"testing"
)

// TestEmbeddedPinnerError exercises the Error() and Unwrap() methods.
func TestEmbeddedPinnerError(t *testing.T) {
	inner := errors.New("parse failure")
	err := &EmbeddedPinnerError{Err: inner}
	if err.Error() == "" {
		t.Fatal("Error() returned empty string")
	}
	if !strings.Contains(err.Error(), "embedded") {
		t.Errorf("Error() = %q, want 'embedded'", err.Error())
	}
	if !errors.Is(err, inner) {
		t.Error("Unwrap should expose inner via errors.Is")
	}
}
