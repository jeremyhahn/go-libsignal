package usernames

import (
	"errors"
	"strings"
	"testing"

	"github.com/gtank/ristretto255"
)

// TestCreateProof_MismatchedHashReturnsError ensures that createProof returns a
// typed *CryptoError (rather than panicking) when the underlying poksho proof
// fails self-verification. This happens when the supplied hashPoint does not
// correspond to the provided scalars, so the freshly created proof cannot
// verify against it and Prove reports an error.
func TestCreateProof_MismatchedHashReturnsError(t *testing.T) {
	u, err := New("alice.42")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// A hashPoint that does not match u.scalars (the basepoint generator).
	mismatched := ristretto255.NewGeneratorElement()
	var randomness [32]byte

	_, err = createProof(u.scalars, mismatched, mismatched.Bytes(), randomness)
	if err == nil {
		t.Fatal("expected error from createProof with mismatched hashPoint")
	}
	var ce *CryptoError
	if !errors.As(err, &ce) {
		t.Fatalf("expected *CryptoError, got %T: %v", err, err)
	}
	if !strings.Contains(ce.Error(), "failed to create proof") {
		t.Errorf("Error() = %q must mention proof creation failure", ce.Error())
	}
	if ce.Unwrap() == nil {
		t.Error("CryptoError must wrap the underlying poksho error")
	}
}

// TestCryptoError_Error exercises the CryptoError.Error() method with and
// without a wrapped inner error.

func TestCryptoError_Error_WithInnerError(t *testing.T) {
	inner := errors.New("rand read failed")
	e := &CryptoError{Operation: "random generation failed", Err: inner}
	msg := e.Error()
	if !strings.Contains(msg, "random generation failed") {
		t.Errorf("Error() = %q must contain operation name", msg)
	}
	if !strings.Contains(msg, "rand read failed") {
		t.Errorf("Error() = %q must contain inner error text", msg)
	}
}

func TestCryptoError_Error_WithoutInnerError(t *testing.T) {
	e := &CryptoError{Operation: "some operation", Err: nil}
	msg := e.Error()
	if !strings.Contains(msg, "some operation") {
		t.Errorf("Error() = %q must contain operation name", msg)
	}
	// Must not contain a nil pointer reference.
	if strings.Contains(msg, "<nil>") {
		t.Errorf("Error() = %q must not contain '<nil>'", msg)
	}
}

func TestCryptoError_Unwrap(t *testing.T) {
	inner := errors.New("inner cause")
	e := &CryptoError{Operation: "op", Err: inner}

	if e.Unwrap() != inner {
		t.Errorf("Unwrap() = %v, want %v", e.Unwrap(), inner)
	}

	// errors.Is must traverse the chain.
	if !errors.Is(e, inner) {
		t.Fatal("errors.Is should find inner error via Unwrap()")
	}
}

func TestCryptoError_Unwrap_NilInner(t *testing.T) {
	e := &CryptoError{Operation: "op", Err: nil}
	if e.Unwrap() != nil {
		t.Errorf("Unwrap() = %v, want nil", e.Unwrap())
	}
}

// TestCBCDecryptError_Error exercises the CBCDecryptError.Error() method.

func TestCBCDecryptError_Error(t *testing.T) {
	e := &CBCDecryptError{Detail: "ciphertext is not a multiple of block size"}
	msg := e.Error()
	if !strings.Contains(msg, "ciphertext is not a multiple of block size") {
		t.Errorf("Error() = %q must contain detail text", msg)
	}
	if !strings.HasPrefix(msg, "usernames: ") {
		t.Errorf("Error() = %q must have 'usernames: ' prefix", msg)
	}
}

func TestCBCDecryptError_Error_EmptyDetail(t *testing.T) {
	e := &CBCDecryptError{Detail: ""}
	msg := e.Error()
	if msg == "" {
		t.Fatal("Error() must not be empty even with empty Detail")
	}
}

// TestPKCS7Error_Error exercises the PKCS7Error.Error() method, which is triggered
// by pkcs7Unpad returning errors.

func TestPKCS7Error_Error(t *testing.T) {
	e := &PKCS7Error{Detail: "invalid padding"}
	msg := e.Error()
	if !strings.Contains(msg, "invalid padding") {
		t.Errorf("Error() = %q must contain detail text", msg)
	}
	if !strings.HasPrefix(msg, "usernames: pkcs7 unpad: ") {
		t.Errorf("Error() = %q must have 'usernames: pkcs7 unpad: ' prefix", msg)
	}
}

func TestPKCS7Error_Error_EmptyBlockAligned(t *testing.T) {
	// pkcs7Unpad with empty data returns a PKCS7Error with "empty data" detail.
	_, err := pkcs7Unpad([]byte{})
	if err == nil {
		t.Fatal("expected error from pkcs7Unpad for empty input")
	}
	var e *PKCS7Error
	if !errors.As(err, &e) {
		t.Fatalf("expected *PKCS7Error, got %T", err)
	}
	if e.Error() == "" {
		t.Fatal("PKCS7Error.Error() must not be empty")
	}
}

func TestPKCS7Error_Error_NotBlockAligned(t *testing.T) {
	// Non-block-aligned data returns a PKCS7Error with "data not block-aligned" detail.
	_, err := pkcs7Unpad([]byte{0x01, 0x02, 0x03})
	if err == nil {
		t.Fatal("expected error from pkcs7Unpad for non-block-aligned data")
	}
	var e *PKCS7Error
	if !errors.As(err, &e) {
		t.Fatalf("expected *PKCS7Error, got %T", err)
	}
	msg := e.Error()
	if !strings.Contains(msg, "block-aligned") {
		t.Errorf("Error() = %q must contain 'block-aligned'", msg)
	}
}

// TestProtobufError_Error exercises the ProtobufError.Error() method, which is
// triggered by decodeUsernameData/readVarint on malformed data.

func TestProtobufError_Error(t *testing.T) {
	e := &ProtobufError{Detail: "unsupported wire type"}
	msg := e.Error()
	if !strings.Contains(msg, "unsupported wire type") {
		t.Errorf("Error() = %q must contain detail text", msg)
	}
	if !strings.HasPrefix(msg, "usernames: protobuf: ") {
		t.Errorf("Error() = %q must have 'usernames: protobuf: ' prefix", msg)
	}
}

func TestProtobufError_Error_ViaDecodeUnsupportedWireType(t *testing.T) {
	// Wire type 5 (32-bit) triggers ProtobufError from decodeUsernameData.
	// field 1, wire type 5 (tag = 0x0d).
	_, err := decodeUsernameData([]byte{0x0d})
	if err == nil {
		t.Fatal("expected error for unsupported wire type")
	}
	var e *ProtobufError
	if !errors.As(err, &e) {
		t.Fatalf("expected *ProtobufError, got %T", err)
	}
	if e.Error() == "" {
		t.Fatal("ProtobufError.Error() must not be empty")
	}
}

func TestProtobufError_Error_ViaReadVarintTooLong(t *testing.T) {
	// Ten continuation bytes without a terminating byte triggers ProtobufError.
	data := make([]byte, 10)
	for i := range data {
		data[i] = 0x80
	}
	_, _, err := readVarint(data)
	if err == nil {
		t.Fatal("expected error for varint too long")
	}
	var e *ProtobufError
	if !errors.As(err, &e) {
		t.Fatalf("expected *ProtobufError, got %T", err)
	}
	msg := e.Error()
	if !strings.Contains(msg, "varint too long") {
		t.Errorf("Error() = %q must contain 'varint too long'", msg)
	}
}

func TestProtobufError_Error_ViaReadVarintUnexpectedEnd(t *testing.T) {
	// Empty varint data triggers "unexpected end of varint" ProtobufError.
	_, _, err := readVarint([]byte{})
	if err == nil {
		t.Fatal("expected error for empty varint data")
	}
	var e *ProtobufError
	if !errors.As(err, &e) {
		t.Fatalf("expected *ProtobufError, got %T", err)
	}
	msg := e.Error()
	if !strings.Contains(msg, "unexpected end") {
		t.Errorf("Error() = %q must contain 'unexpected end'", msg)
	}
}

// TestCBCDecryptError_Error_ViaAES256CBCDecrypt exercises the CBCDecryptError
// returned from aes256CBCDecrypt for a non-block-size-multiple ciphertext.

func TestCBCDecryptError_Error_ViaAES256CBCDecrypt(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	// Ciphertext that is non-zero but not a multiple of 16.
	_, err := aes256CBCDecrypt([]byte{0x01, 0x02, 0x03}, key, iv)
	if err == nil {
		t.Fatal("expected error for non-block-aligned ciphertext")
	}
	var e *CBCDecryptError
	if !errors.As(err, &e) {
		t.Fatalf("expected *CBCDecryptError, got %T", err)
	}
	msg := e.Error()
	if !strings.Contains(msg, "block size") {
		t.Errorf("Error() = %q must contain 'block size'", msg)
	}
}
