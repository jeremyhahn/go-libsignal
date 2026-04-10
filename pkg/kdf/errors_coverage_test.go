package kdf

import (
	"errors"
	"testing"
)

// TestKeyMaterialZeroize verifies that Zeroize overwrites all fields with zeros,
// ensuring sensitive key material is not retained in memory after use.
func TestKeyMaterialZeroize(t *testing.T) {
	km := KeyMaterial{
		CipherKey: []byte{0xAA, 0xBB, 0xCC, 0xDD},
		MacKey:    []byte{0x11, 0x22, 0x33, 0x44},
		IV:        []byte{0xFF, 0xEE, 0xDD, 0xCC},
	}

	km.Zeroize()

	for i, b := range km.CipherKey {
		if b != 0 {
			t.Errorf("CipherKey[%d] = 0x%02X, want 0x00 after Zeroize", i, b)
		}
	}
	for i, b := range km.MacKey {
		if b != 0 {
			t.Errorf("MacKey[%d] = 0x%02X, want 0x00 after Zeroize", i, b)
		}
	}
	for i, b := range km.IV {
		if b != 0 {
			t.Errorf("IV[%d] = 0x%02X, want 0x00 after Zeroize", i, b)
		}
	}
}

// TestKeyMaterialZeroizeEmptyFields verifies Zeroize is safe when fields are nil or empty.
func TestKeyMaterialZeroizeEmptyFields(t *testing.T) {
	km := KeyMaterial{
		CipherKey: nil,
		MacKey:    []byte{},
		IV:        nil,
	}

	// Must not panic.
	km.Zeroize()
}

// TestErrAllZeroSharedSecret_Error verifies the error message for the all-zero
// shared secret sentinel. This is a defence-in-depth guard against low-order keys.
func TestErrAllZeroSharedSecret_Error(t *testing.T) {
	err := &ErrAllZeroSharedSecret{}
	msg := err.Error()
	if msg == "" {
		t.Fatal("Error() should return a non-empty string")
	}
	if !containsString(msg, "zero") && !containsString(msg, "invalid") {
		t.Errorf("error message should describe the problem, got: %s", msg)
	}
}

// TestErrAllZeroSharedSecret_ErrorsIs verifies errors.As finds the type correctly.
func TestErrAllZeroSharedSecret_ErrorsAs(t *testing.T) {
	// The all-zero check is done inside validateAndCopySharedSecret.
	// We cannot trigger it via CalculateSharedSecret since curve25519.X25519
	// already rejects low-order keys. Test the error type directly instead.
	err := &ErrAllZeroSharedSecret{}
	var target *ErrAllZeroSharedSecret
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match ErrAllZeroSharedSecret")
	}
}

// TestErrHKDFReadFull_Error verifies the error message for HKDF read failure.
func TestErrHKDFReadFull_Error(t *testing.T) {
	inner := errors.New("unexpected EOF")
	err := &ErrHKDFReadFull{Err: inner}
	msg := err.Error()
	if msg == "" {
		t.Fatal("Error() should return a non-empty string")
	}
	if !containsString(msg, "HKDF") {
		t.Errorf("error message should mention HKDF, got: %s", msg)
	}
	if !containsString(msg, inner.Error()) {
		t.Errorf("error message should include inner error, got: %s", msg)
	}
}

// TestErrHKDFReadFull_Unwrap verifies that Unwrap returns the inner error.
func TestErrHKDFReadFull_Unwrap(t *testing.T) {
	inner := errors.New("inner EOF")
	err := &ErrHKDFReadFull{Err: inner}
	if !errors.Is(err, inner) {
		t.Fatal("errors.Is should find inner error through Unwrap on ErrHKDFReadFull")
	}
}

// TestErrShortRead_Error verifies the error message for short reads from HKDF.
func TestErrShortRead_Error(t *testing.T) {
	err := &ErrShortRead{Expected: 96, Got: 64}
	msg := err.Error()
	if msg == "" {
		t.Fatal("Error() should return a non-empty string")
	}
	if !containsString(msg, "96") || !containsString(msg, "64") {
		t.Errorf("error message should contain expected and got values, got: %s", msg)
	}
}

// TestErrShortRead_ErrorsAs verifies that errors.As can extract ErrShortRead.
func TestErrShortRead_ErrorsAs(t *testing.T) {
	err := &ErrShortRead{Expected: 32, Got: 16}
	var target *ErrShortRead
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match ErrShortRead")
	}
	if target.Expected != 32 || target.Got != 16 {
		t.Errorf("fields: Expected=%d Got=%d, want Expected=32 Got=16", target.Expected, target.Got)
	}
}

// containsString is a test helper to check for substring presence.
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}
