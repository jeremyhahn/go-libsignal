package embeddedcerts

import (
	"errors"
	"strings"
	"testing"
)

// TestEmbeddedCertError exercises the Error() and Unwrap() methods.
func TestEmbeddedCertError(t *testing.T) {
	inner := errors.New("asn1: structure error")
	err := &EmbeddedCertError{Name: "signal.cer", Err: inner}
	if !strings.Contains(err.Error(), "signal.cer") {
		t.Errorf("Error() = %q, want 'signal.cer'", err.Error())
	}
	if !errors.Is(err, inner) {
		t.Error("Unwrap should expose inner via errors.Is")
	}
}
