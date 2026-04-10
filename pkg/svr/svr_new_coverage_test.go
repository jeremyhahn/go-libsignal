package svr

import (
	"bytes"
	"errors"
	"testing"
)

// TestOPRFBackup4_Zeroize_WithNilOutput verifies Zeroize does not panic when Output is nil.
func TestOPRFBackup4_Zeroize_WithNilOutput(t *testing.T) {
	b := &OPRFBackup4{
		Requests: [][]byte{{}},
		Output:   nil,
	}
	// Should not panic.
	b.Zeroize()
}

// TestOPRFBackup4_Zeroize_WithValidOutput verifies Zeroize destroys the Output secret.
func TestOPRFBackup4_Zeroize_WithValidOutput(t *testing.T) {
	backup, err := NewOPRFBackup4([]uint64{1}, []byte("password"), 5)
	if err != nil {
		t.Fatalf("NewOPRFBackup4 failed: %v", err)
	}
	if backup.Output == nil {
		t.Fatal("expected non-nil Output")
	}

	// Zeroize should destroy the output.
	backup.Zeroize()
	if !backup.Output.IsDestroyed() {
		t.Error("Output should be destroyed after Zeroize()")
	}

	// Second Zeroize should not panic.
	backup.Zeroize()
}

// TestMasterKeyGuarded_ValidPIN verifies MasterKeyGuarded returns guarded memory.
func TestMasterKeyGuarded_ValidPIN(t *testing.T) {
	var svrSecret Secret
	copy(svrSecret[:], bytes.Repeat([]byte{0x42}, 32))

	guarded, err := MasterKeyGuarded("my-pin", svrSecret)
	if err != nil {
		t.Fatalf("MasterKeyGuarded failed: %v", err)
	}
	if guarded == nil {
		t.Fatal("expected non-nil guarded secret")
	}
	defer guarded.Destroy()

	if guarded.Size() != 32 {
		t.Errorf("guarded secret size = %d, want 32", guarded.Size())
	}

	// Verify determinism: same PIN+secret should give same key.
	raw1, err := MasterKey("my-pin", svrSecret)
	if err != nil {
		t.Fatal(err)
	}
	if !guarded.EqualTo(raw1[:]) {
		t.Error("MasterKeyGuarded should match MasterKey output")
	}
}

// TestMasterKeyGuarded_EmptyPIN verifies MasterKeyGuarded propagates empty PIN error.
func TestMasterKeyGuarded_EmptyPIN(t *testing.T) {
	var svrSecret Secret
	_, err := MasterKeyGuarded("", svrSecret)
	if err == nil {
		t.Fatal("expected error for empty PIN")
	}
	if !errors.Is(err, ErrEmptyPIN) {
		t.Errorf("error = %v, want ErrEmptyPIN", err)
	}
}

// TestErrorMessages_AllKinds exercises the Error.Error() switch for all known kinds,
// including the case-with-cause variants that aren't covered by basic tests.
func TestErrorMessages_AllKinds_WithCause(t *testing.T) {
	inner := errors.New("inner cause")
	tests := []struct {
		name    string
		err     *Error
		wantSub string
	}{
		{
			name:    "HKDF with cause",
			err:     &Error{kind: errHKDFExpansion, cause: inner},
			wantSub: "HKDF expansion failed: inner cause",
		},
		{
			name:    "cipher create with cause",
			err:     &Error{kind: errCipherCreate, cause: inner},
			wantSub: "create cipher: inner cause",
		},
		{
			name:    "decryption with cause",
			err:     &Error{kind: errDecryption, cause: inner},
			wantSub: "decryption failed: inner cause",
		},
		{
			name:    "secret size",
			err:     &Error{kind: errSecretSize, detail: "got 10, want 32"},
			wantSub: "wrong size",
		},
		{
			name:    "HKDF without cause",
			err:     &Error{kind: errHKDFExpansion},
			wantSub: "HKDF expansion failed",
		},
		{
			name:    "cipher create without cause",
			err:     &Error{kind: errCipherCreate},
			wantSub: "create cipher",
		},
		{
			name:    "decryption without cause",
			err:     &Error{kind: errDecryption},
			wantSub: "decryption failed",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.err.Error()
			if !containsStr(msg, tc.wantSub) {
				t.Errorf("Error() = %q, expected substring %q", msg, tc.wantSub)
			}
		})
	}
}

// TestError_Unwrap verifies Error.Unwrap returns the cause.
func TestError_Unwrap(t *testing.T) {
	inner := errors.New("root cause")
	e := &Error{kind: errBadData, cause: inner}

	if e.Unwrap() != inner {
		t.Error("Unwrap() should return the inner cause")
	}

	e2 := &Error{kind: errBadData}
	if e2.Unwrap() != nil {
		t.Error("Unwrap() should return nil when no cause")
	}
}

// containsStr is a simple case-sensitive substring check.
func containsStr(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
