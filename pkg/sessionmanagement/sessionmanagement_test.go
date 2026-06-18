package sessionmanagement_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/sessionmanagement"
)

// TestInvalidCiphertextTypeError_EmptyKind verifies the error string
// when constructed with the zero value (nil input case).
func TestInvalidCiphertextTypeError_EmptyKind(t *testing.T) {
	e := &sessionmanagement.InvalidCiphertextTypeError{}
	if !strings.Contains(e.Error(), "nil ciphertext") {
		t.Fatalf("expected error to mention nil ciphertext, got %q", e.Error())
	}
}

// TestInvalidCiphertextTypeError_KindFormatted verifies the error string
// includes the kind when a non-routable message is passed.
func TestInvalidCiphertextTypeError_KindFormatted(t *testing.T) {
	e := &sessionmanagement.InvalidCiphertextTypeError{Kind: "SenderKeyMessage"}
	if !strings.Contains(e.Error(), "SenderKeyMessage") {
		t.Fatalf("expected error to name kind SenderKeyMessage, got %q", e.Error())
	}
}

// TestMessageDecrypt_NilCiphertext exercises the explicit nil branch.
func TestMessageDecrypt_NilCiphertext(t *testing.T) {
	addr := protocol.NewSignalAddress("a", 0)
	_, err := sessionmanagement.MessageDecrypt(
		nil, addr, addr, nil, nil, nil, nil, nil, serialize.NewJSONSerializer(),
	)
	if err == nil {
		t.Fatal("expected error on nil ciphertext")
	}
	var typed *sessionmanagement.InvalidCiphertextTypeError
	if !errors.As(err, &typed) {
		t.Fatalf("got %T (%v), want *InvalidCiphertextTypeError", err, err)
	}
	if typed.Kind != "" {
		t.Fatalf("nil branch should set empty Kind, got %q", typed.Kind)
	}
}

// TestMessageDecrypt_PlaintextContentRejected verifies that a
// non-routable CiphertextMessage (PlaintextContent) yields a typed error
// whose Kind names the concrete type.
func TestMessageDecrypt_PlaintextContentRejected(t *testing.T) {
	addr := protocol.NewSignalAddress("a", 0)
	pt := protocol.NewPlaintextContent([]byte{0x01})
	_, err := sessionmanagement.MessageDecrypt(
		pt, addr, addr, nil, nil, nil, nil, nil, serialize.NewJSONSerializer(),
	)
	if err == nil {
		t.Fatal("expected error on PlaintextContent")
	}
	var typed *sessionmanagement.InvalidCiphertextTypeError
	if !errors.As(err, &typed) {
		t.Fatalf("got %T (%v), want *InvalidCiphertextTypeError", err, err)
	}
	if typed.Kind != "PlaintextContent" {
		t.Fatalf("Kind = %q, want PlaintextContent", typed.Kind)
	}
}
