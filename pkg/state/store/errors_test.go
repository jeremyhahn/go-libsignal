package store

import (
	"errors"
	"strings"
	"testing"
)

// TestErrStoreIO_WithCause verifies that ErrStoreIO.Error() includes both the
// operation name and the underlying error message.
func TestErrStoreIO_WithCause(t *testing.T) {
	cause := errors.New("disk full")
	err := &ErrStoreIO{Op: "LoadSession", Err: cause}

	msg := err.Error()
	if !strings.Contains(msg, "LoadSession") {
		t.Errorf("Error() = %q, should contain 'LoadSession'", msg)
	}
	if !strings.Contains(msg, "disk full") {
		t.Errorf("Error() = %q, should contain cause message", msg)
	}
	if !errors.Is(err, cause) {
		t.Error("errors.Is should traverse Unwrap() to the cause")
	}
	if err.Unwrap() != cause {
		t.Error("Unwrap() should return the wrapped cause directly")
	}
}

// TestErrStoreIO_NilCause verifies that ErrStoreIO.Error() formats gracefully
// when the wrapped error is nil.
func TestErrStoreIO_NilCause(t *testing.T) {
	err := &ErrStoreIO{Op: "StorePreKey", Err: nil}
	msg := err.Error()
	if !strings.Contains(msg, "StorePreKey") {
		t.Errorf("Error() = %q, should contain 'StorePreKey'", msg)
	}
	if !strings.Contains(msg, "I/O error") {
		t.Errorf("Error() = %q, should contain 'I/O error'", msg)
	}
	if err.Unwrap() != nil {
		t.Error("Unwrap() should return nil when no cause is set")
	}
}

// TestErrStoreNotFound_Error verifies that ErrStoreNotFound.Error() includes
// the operation and ID.
func TestErrStoreNotFound_Error(t *testing.T) {
	err := &ErrStoreNotFound{Op: "LoadPreKey", ID: 42}
	msg := err.Error()
	if !strings.Contains(msg, "LoadPreKey") {
		t.Errorf("Error() = %q, should contain 'LoadPreKey'", msg)
	}
	if !strings.Contains(msg, "42") {
		t.Errorf("Error() = %q, should contain ID '42'", msg)
	}
	if !strings.Contains(msg, "not found") {
		t.Errorf("Error() = %q, should contain 'not found'", msg)
	}
	// Satisfies the error interface.
	var _ error = err
}

// TestNewErrLastResortReplay_Valid verifies that NewErrLastResortReplay creates
// an error with all fields set correctly.
func TestNewErrLastResortReplay_Valid(t *testing.T) {
	baseKey := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	err := NewErrLastResortReplay(10, 20, baseKey)

	if err.KyberPreKeyID != 10 {
		t.Errorf("KyberPreKeyID = %d, want 10", err.KyberPreKeyID)
	}
	if err.SignedPreKeyID != 20 {
		t.Errorf("SignedPreKeyID = %d, want 20", err.SignedPreKeyID)
	}
	if err.BaseKeyHex != "deadbeef" {
		t.Errorf("BaseKeyHex = %q, want 'deadbeef'", err.BaseKeyHex)
	}

	msg := err.Error()
	if !strings.Contains(msg, "10") {
		t.Errorf("Error() = %q, should contain kyberPreKeyID 10", msg)
	}
	if !strings.Contains(msg, "20") {
		t.Errorf("Error() = %q, should contain signedPreKeyID 20", msg)
	}
	if !strings.Contains(msg, "deadbeef") {
		t.Errorf("Error() = %q, should contain hex-encoded base key", msg)
	}
	if !strings.Contains(msg, "replay") {
		t.Errorf("Error() = %q, should mention 'replay'", msg)
	}
}

// TestNewErrLastResortReplay_NilBaseKey verifies that nil baseKey produces an
// empty hex string in the error message.
func TestNewErrLastResortReplay_NilBaseKey(t *testing.T) {
	err := NewErrLastResortReplay(5, 7, nil)
	if err.BaseKeyHex != "" {
		t.Errorf("BaseKeyHex = %q, want empty for nil baseKey", err.BaseKeyHex)
	}
	// Must not panic.
	_ = err.Error()
}

// TestIdentityChangeFromChanged verifies both branches of the helper function.
func TestIdentityChangeFromChanged(t *testing.T) {
	if got := IdentityChangeFromChanged(true); got != IdentityChangeReplacedExisting {
		t.Errorf("IdentityChangeFromChanged(true) = %v, want IdentityChangeReplacedExisting", got)
	}
	if got := IdentityChangeFromChanged(false); got != IdentityChangeNewOrUnchanged {
		t.Errorf("IdentityChangeFromChanged(false) = %v, want IdentityChangeNewOrUnchanged", got)
	}
}
