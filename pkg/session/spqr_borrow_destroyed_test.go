//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md. The session setup exercises
// X25519, which the fips140only build drops.

package session_test

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/internal/testseam"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// destroySPQRBorrows destroys every secret spqr is about to copy out, as a
// concurrent wipe between lookup and borrow would, and counts the borrows it
// hit. The hook is cleared when the test ends or when the returned stop is
// called.
func destroySPQRBorrows(t *testing.T) (hits *int, stop func()) {
	t.Helper()
	hits = new(int)
	testseam.SPQRBeforeCopyBorrow = func(s *secret.Secret) {
		*hits++
		s.Destroy()
	}
	stop = func() { testseam.SPQRBeforeCopyBorrow = nil }
	t.Cleanup(stop)
	return hits, stop
}

// TestCipherEncrypt_SPQRKeyDestroyedBeforeCopyFails covers the Send side: a
// destroyed SPQR key used to come back as nil with no error, which means "no
// PQR", so Encrypt sent a message without its post-quantum part.
func TestCipherEncrypt_SPQRKeyDestroyedBeforeCopyFails(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	_, _, aliceCipher, bobCipher := setupSessionPair(t, serializer)

	hits, stop := destroySPQRBorrows(t)
	msg, err := aliceCipher.Encrypt([]byte("must not leave without PQR"))
	stop()
	if !errors.Is(err, secret.ErrSecretDestroyed) {
		t.Fatalf("Encrypt err = %v, want ErrSecretDestroyed", err)
	}
	if msg != nil {
		t.Fatal("Encrypt returned a message built without the SPQR key")
	}
	if *hits == 0 {
		t.Fatal("Encrypt never borrowed an SPQR secret")
	}

	// The failed send left the stored session usable.
	next, err := aliceCipher.Encrypt([]byte("after"))
	if err != nil {
		t.Fatalf("Encrypt after failure: %v", err)
	}
	raw, err := next.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := protocol.NewSignalMessageFromBytes(raw, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bobCipher.Decrypt(parsed); err != nil {
		t.Fatalf("Decrypt after failed send: %v", err)
	}
}

// TestCipherDecrypt_SPQRKeyDestroyedBeforeCopyFails covers the Recv side: a
// destroyed SPQR key must fail the decrypt with the borrow error, not be
// treated as a message without PQR.
func TestCipherDecrypt_SPQRKeyDestroyedBeforeCopyFails(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	_, _, aliceCipher, bobCipher := setupSessionPair(t, serializer)

	msg, err := aliceCipher.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := protocol.NewSignalMessageFromBytes(raw, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	hits, stop := destroySPQRBorrows(t)
	plaintext, err := bobCipher.Decrypt(parsed)
	stop()
	if !errors.Is(err, secret.ErrSecretDestroyed) {
		t.Fatalf("Decrypt err = %v, want ErrSecretDestroyed", err)
	}
	if plaintext != nil {
		t.Fatal("Decrypt returned plaintext without the SPQR key")
	}
	if *hits == 0 {
		t.Fatal("Decrypt never borrowed an SPQR secret")
	}

	// The failed receive left the stored session untouched, so the same
	// message still decrypts.
	reparsed, err := protocol.NewSignalMessageFromBytes(raw, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}
	got, err := bobCipher.Decrypt(reparsed)
	if err != nil {
		t.Fatalf("Decrypt after failed receive: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("Decrypt = %q, want %q", got, "hello")
	}
}
