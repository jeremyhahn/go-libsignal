package identity

import (
	"errors"
	"strings"
	"testing"
)

// TestAltIdentityErrorMessages exercises the Error() and Unwrap() methods on
// all alt_identity_errors types to guard against message regressions.
func TestAltIdentityErrorMessages(t *testing.T) {
	t.Run("ErrNilOtherKeyType", func(t *testing.T) {
		err := &ErrNilOtherKeyType{}
		if !strings.Contains(err.Error(), "nil") {
			t.Errorf("ErrNilOtherKeyType.Error() = %q, want 'nil'", err.Error())
		}
	})
	t.Run("ErrAltIdentitySignFailedType", func(t *testing.T) {
		err := &ErrAltIdentitySignFailedType{}
		if !strings.Contains(err.Error(), "sign") {
			t.Errorf("ErrAltIdentitySignFailedType.Error() = %q, want 'sign'", err.Error())
		}
	})
	t.Run("ErrAltIdentitySignOperation", func(t *testing.T) {
		inner := errors.New("nil private key")
		err := &ErrAltIdentitySignOperation{Err: inner}
		if !strings.Contains(err.Error(), "sign") {
			t.Errorf("ErrAltIdentitySignOperation.Error() = %q, want 'sign'", err.Error())
		}
		if !errors.Is(err, inner) {
			t.Error("Unwrap should expose inner via errors.Is")
		}
	})
	t.Run("ErrAltIdentityVerificationFailedType", func(t *testing.T) {
		err := &ErrAltIdentityVerificationFailedType{}
		if !strings.Contains(err.Error(), "verif") {
			t.Errorf("ErrAltIdentityVerificationFailedType.Error() = %q, want 'verif'", err.Error())
		}
	})
	t.Run("ErrAltIdentityInvalidSignatureLength", func(t *testing.T) {
		err := &ErrAltIdentityInvalidSignatureLength{Got: 32}
		if !strings.Contains(err.Error(), "32") {
			t.Errorf("ErrAltIdentityInvalidSignatureLength.Error() = %q, want '32'", err.Error())
		}
	})
	t.Run("ErrReadingAltIdentityRandomness", func(t *testing.T) {
		inner := errors.New("crypto/rand: failed")
		err := &ErrReadingAltIdentityRandomness{Err: inner}
		if !strings.Contains(err.Error(), "randomness") {
			t.Errorf("ErrReadingAltIdentityRandomness.Error() = %q, want 'randomness'", err.Error())
		}
		if !errors.Is(err, inner) {
			t.Error("Unwrap should expose inner via errors.Is")
		}
	})
}

// TestIdentityErrorMessages exercises the Error() method on errors.go types.
func TestIdentityErrorMessages(t *testing.T) {
	t.Run("ErrInvalidIdentityKeyPairProtoType", func(t *testing.T) {
		err := &ErrInvalidIdentityKeyPairProtoType{}
		if !strings.Contains(err.Error(), "protobuf") {
			t.Errorf("Error() = %q, want 'protobuf'", err.Error())
		}
	})
	t.Run("ErrInvalidIdentityKeyPairPublicKeyType", func(t *testing.T) {
		inner := errors.New("bad key prefix")
		err := &ErrInvalidIdentityKeyPairPublicKeyType{Err: inner}
		if !strings.Contains(err.Error(), "public key") {
			t.Errorf("Error() = %q, want 'public key'", err.Error())
		}
		if !errors.Is(err, inner) {
			t.Error("Unwrap should expose inner via errors.Is")
		}
	})
	t.Run("ErrInvalidIdentityKeyPairPrivateKeyType", func(t *testing.T) {
		err := &ErrInvalidIdentityKeyPairPrivateKeyType{Got: 16}
		if !strings.Contains(err.Error(), "16") {
			t.Errorf("Error() = %q, want '16'", err.Error())
		}
	})
}
