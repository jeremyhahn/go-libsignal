package cipher

import (
	"errors"
	"strings"
	"testing"
)

// TestErrorTypes exercises the Error() and Unwrap() methods on all cipher
// error types to ensure they produce meaningful messages and chain correctly.
// These tests guard against regressions in error formatting and wrapping.

func TestErrAESGCMSIVKeySize_Error(t *testing.T) {
	err := &ErrAESGCMSIVKeySize{Expected: 32, Got: 16}
	msg := err.Error()
	if !strings.Contains(msg, "32") || !strings.Contains(msg, "16") {
		t.Errorf("ErrAESGCMSIVKeySize.Error() = %q, want it to contain 32 and 16", msg)
	}
}

func TestErrAESGCMSIVKeySize_ErrorZero(t *testing.T) {
	err := &ErrAESGCMSIVKeySize{Expected: 32, Got: 0}
	if !strings.Contains(err.Error(), "0") {
		t.Errorf("ErrAESGCMSIVKeySize.Error() should contain 0, got %q", err.Error())
	}
}

func TestErrAESGCMSIVNonceSize_Error(t *testing.T) {
	err := &ErrAESGCMSIVNonceSize{Expected: 12, Got: 8}
	msg := err.Error()
	if !strings.Contains(msg, "12") || !strings.Contains(msg, "8") {
		t.Errorf("ErrAESGCMSIVNonceSize.Error() = %q, want it to contain 12 and 8", msg)
	}
}

func TestErrAESGCMSIVNonceSize_ErrorLarge(t *testing.T) {
	err := &ErrAESGCMSIVNonceSize{Expected: 12, Got: 24}
	if !strings.Contains(err.Error(), "24") {
		t.Errorf("ErrAESGCMSIVNonceSize.Error() should contain 24, got %q", err.Error())
	}
}

func TestErrAESGCMSIVProtectKey_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("memguard failure")
	err := &ErrAESGCMSIVProtectKey{Err: inner}
	msg := err.Error()
	if !strings.Contains(msg, "memguard failure") {
		t.Errorf("ErrAESGCMSIVProtectKey.Error() = %q, want to contain inner error", msg)
	}
	if !errors.Is(err, inner) {
		t.Error("ErrAESGCMSIVProtectKey.Unwrap() should expose inner error via errors.Is")
	}
}

func TestErrAESGCMSIVIncorrectNonce_Error(t *testing.T) {
	err := &ErrAESGCMSIVIncorrectNonce{}
	msg := err.Error()
	if msg == "" {
		t.Error("ErrAESGCMSIVIncorrectNonce.Error() should not be empty")
	}
	if !strings.Contains(msg, "nonce") {
		t.Errorf("ErrAESGCMSIVIncorrectNonce.Error() = %q, want to mention nonce", msg)
	}
}

func TestErrAESGCMSIVCiphertextTooShort_Error(t *testing.T) {
	err := &ErrAESGCMSIVCiphertextTooShort{}
	msg := err.Error()
	if msg == "" {
		t.Error("ErrAESGCMSIVCiphertextTooShort.Error() should not be empty")
	}
	if !strings.Contains(msg, "short") {
		t.Errorf("ErrAESGCMSIVCiphertextTooShort.Error() = %q, want to mention short", msg)
	}
}

func TestErrAESGCMSIVKeyDerivation_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("aes block error")
	err := &ErrAESGCMSIVKeyDerivation{Err: inner}
	msg := err.Error()
	if !strings.Contains(msg, "aes block error") {
		t.Errorf("ErrAESGCMSIVKeyDerivation.Error() = %q, want to contain inner error", msg)
	}
	if !errors.Is(err, inner) {
		t.Error("ErrAESGCMSIVKeyDerivation.Unwrap() should expose inner error via errors.Is")
	}
}

func TestErrAESGCMSIVTagComputation_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("tag error")
	err := &ErrAESGCMSIVTagComputation{Err: inner}
	msg := err.Error()
	if !strings.Contains(msg, "tag error") {
		t.Errorf("ErrAESGCMSIVTagComputation.Error() = %q, want to contain inner error", msg)
	}
	if !errors.Is(err, inner) {
		t.Error("ErrAESGCMSIVTagComputation.Unwrap() should expose inner error via errors.Is")
	}
}

func TestErrAESGCMSIVAuthFailed_Error(t *testing.T) {
	err := &ErrAESGCMSIVAuthFailed{}
	msg := err.Error()
	if msg == "" {
		t.Error("ErrAESGCMSIVAuthFailed.Error() should not be empty")
	}
	if !strings.Contains(msg, "auth") {
		t.Errorf("ErrAESGCMSIVAuthFailed.Error() = %q, want to mention authentication", msg)
	}
}

func TestErrAESCTRKeySize_Error(t *testing.T) {
	err := &ErrAESCTRKeySize{}
	msg := err.Error()
	if msg == "" {
		t.Error("ErrAESCTRKeySize.Error() should not be empty")
	}
	if !strings.Contains(msg, "32") {
		t.Errorf("ErrAESCTRKeySize.Error() = %q, want to mention key size 32", msg)
	}
}

func TestErrAESCTRInputTooLong_Error(t *testing.T) {
	err := &ErrAESCTRInputTooLong{Length: 1000, Max: 999}
	msg := err.Error()
	if !strings.Contains(msg, "1000") || !strings.Contains(msg, "999") {
		t.Errorf("ErrAESCTRInputTooLong.Error() = %q, want to contain length and max", msg)
	}
}

func TestErrAESCBCInvalidKey_Error(t *testing.T) {
	err := &ErrAESCBCInvalidKey{Got: 10}
	msg := err.Error()
	if !strings.Contains(msg, "10") {
		t.Errorf("ErrAESCBCInvalidKey.Error() = %q, want to contain key size 10", msg)
	}
}

func TestErrAESCBCInvalidIVSize_Error(t *testing.T) {
	err := &ErrAESCBCInvalidIVSize{Got: 8}
	msg := err.Error()
	if !strings.Contains(msg, "8") {
		t.Errorf("ErrAESCBCInvalidIVSize.Error() = %q, want to contain IV size 8", msg)
	}
}

func TestErrAESCBCCiphertextNotAligned_Error(t *testing.T) {
	err := &ErrAESCBCCiphertextNotAligned{Length: 17, BlockSize: 16}
	msg := err.Error()
	if !strings.Contains(msg, "17") || !strings.Contains(msg, "16") {
		t.Errorf("ErrAESCBCCiphertextNotAligned.Error() = %q, want to contain 17 and 16", msg)
	}
}

func TestErrAESCBCCiphertextEmpty_Error(t *testing.T) {
	err := &ErrAESCBCCiphertextEmpty{}
	msg := err.Error()
	if msg == "" {
		t.Error("ErrAESCBCCiphertextEmpty.Error() should not be empty")
	}
	if !strings.Contains(msg, "empty") {
		t.Errorf("ErrAESCBCCiphertextEmpty.Error() = %q, want to mention empty", msg)
	}
}

// TestErrHPKEAllKinds verifies ErrHPKE.Error() produces non-empty messages for
// all defined kinds, including the default/unknown branch.
func TestErrHPKEAllKinds(t *testing.T) {
	tests := []struct {
		name    string
		err     *ErrHPKE
		contain string
	}{
		{"invalid public key", ErrHPKEInvalidPublicKey, "public key"},
		{"invalid private key", ErrHPKEInvalidPrivateKey, "private key"},
		{"seal failed", ErrHPKESealFailed, "seal"},
		{"open failed", ErrHPKEOpenFailed, "open"},
		{"invalid ciphertext", ErrHPKEInvalidCiphertext, "ciphertext"},
		{"unknown type", ErrHPKEUnknownType, "type"},
		{"receiver zeroized", ErrHPKEReceiverZeroized, "zeroized"},
		{"default branch", &ErrHPKE{kind: hpkeErrKind(99)}, "unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.err.Error()
			if msg == "" {
				t.Errorf("ErrHPKE(%v).Error() should not be empty", tc.err.kind)
			}
			if !strings.Contains(msg, tc.contain) {
				t.Errorf("ErrHPKE(%v).Error() = %q, want to contain %q", tc.err.kind, msg, tc.contain)
			}
		})
	}
}

// TestErrHPKEIs verifies Is() matching by kind for all sentinel errors.
func TestErrHPKEIs(t *testing.T) {
	sentinels := []*ErrHPKE{
		ErrHPKEInvalidPublicKey,
		ErrHPKEInvalidPrivateKey,
		ErrHPKESealFailed,
		ErrHPKEOpenFailed,
		ErrHPKEInvalidCiphertext,
		ErrHPKEUnknownType,
		ErrHPKEReceiverZeroized,
	}

	for _, sentinel := range sentinels {
		t.Run(sentinel.Error(), func(t *testing.T) {
			// Same kind should match.
			same := &ErrHPKE{kind: sentinel.kind}
			if !same.Is(sentinel) {
				t.Errorf("ErrHPKE.Is() should return true for same kind %d", sentinel.kind)
			}
			// errors.Is should work transitively.
			if !errors.Is(same, sentinel) {
				t.Errorf("errors.Is() should return true for same kind %d", sentinel.kind)
			}
			// Non-ErrHPKE target should not match.
			if same.Is(errors.New("other")) {
				t.Errorf("ErrHPKE.Is(non-ErrHPKE) should return false")
			}
		})
	}

	// Different kinds should not match each other.
	if ErrHPKEInvalidPublicKey.Is(ErrHPKEInvalidPrivateKey) {
		t.Error("different HPKE error kinds should not match")
	}
}

// TestAESGCMSIVZeroize verifies the AEAD's Zeroize method can be called
// and that the type assertion is accessible for internal testing.
func TestAESGCMSIVZeroize(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	aead, err := NewAESGCMSIV(key)
	if err != nil {
		t.Fatalf("NewAESGCMSIV: %v", err)
	}

	// Zeroize via the concrete type assertion.
	z, ok := aead.(interface{ Zeroize() })
	if !ok {
		t.Fatal("aesGCMSIV should implement Zeroize()")
	}

	// Zeroize should not panic.
	z.Zeroize()

	// Calling Zeroize again must be idempotent (no panic).
	z.Zeroize()
}

func TestErrCipherInvalidKeySize_Error(t *testing.T) {
	err := &ErrCipherInvalidKeySize{Got: 16}
	msg := err.Error()
	if !strings.Contains(msg, "16") {
		t.Errorf("ErrCipherInvalidKeySize.Error() = %q, want '16'", msg)
	}
	if !strings.Contains(msg, "32") {
		t.Errorf("ErrCipherInvalidKeySize.Error() = %q, want '32'", msg)
	}
}

func TestErrCipherCiphertextTooShort_Error(t *testing.T) {
	err := &ErrCipherCiphertextTooShort{}
	if err.Error() == "" {
		t.Fatal("ErrCipherCiphertextTooShort.Error() returned empty string")
	}
}

func TestErrCipherInvalidBlockSize_Error(t *testing.T) {
	err := &ErrCipherInvalidBlockSize{Got: -1}
	msg := err.Error()
	if !strings.Contains(msg, "-1") {
		t.Errorf("ErrCipherInvalidBlockSize.Error() = %q, want '-1'", msg)
	}
}

func TestErrCipherInvalidPKCS7Data_Error(t *testing.T) {
	err := &ErrCipherInvalidPKCS7Data{}
	if err.Error() == "" {
		t.Fatal("ErrCipherInvalidPKCS7Data.Error() returned empty string")
	}
}

func TestErrCipherInvalidPKCS7Padding_Error(t *testing.T) {
	err := &ErrCipherInvalidPKCS7Padding{}
	if err.Error() == "" {
		t.Fatal("ErrCipherInvalidPKCS7Padding.Error() returned empty string")
	}
}

func TestErrInvalidKeyLength_Error(t *testing.T) {
	err := &ErrInvalidKeyLength{Got: 16, Expected: 32}
	msg := err.Error()
	if !strings.Contains(msg, "16") || !strings.Contains(msg, "32") {
		t.Errorf("ErrInvalidKeyLength.Error() = %q, want got and expected sizes", msg)
	}
}

func TestErrInvalidNonceLength_Error(t *testing.T) {
	err := &ErrInvalidNonceLength{Got: 8, Expected: 12}
	msg := err.Error()
	if !strings.Contains(msg, "8") || !strings.Contains(msg, "12") {
		t.Errorf("ErrInvalidNonceLength.Error() = %q, want got and expected sizes", msg)
	}
}

func TestErrAESGCMAuthFailed_Error(t *testing.T) {
	err := &ErrAESGCMAuthFailed{}
	msg := err.Error()
	if msg == "" {
		t.Fatal("ErrAESGCMAuthFailed.Error() returned empty string")
	}
	if !strings.Contains(msg, "auth") {
		t.Errorf("ErrAESGCMAuthFailed.Error() = %q, want 'auth'", msg)
	}
}
