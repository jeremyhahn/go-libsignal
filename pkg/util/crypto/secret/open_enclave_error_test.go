package secret

import (
	"testing"

	"github.com/awnumar/memguard"
)

// TestOpenEnclave_DecryptionFailure exercises the error branch in OpenEnclave
// where the underlying memguard Enclave.Open fails with a decryption error.
//
// memguard encrypts every Enclave under a process-global rolling key. Calling
// memguard.Purge destroys that key; the next enclave operation lazily creates a
// brand-new key. An Enclave sealed under the old key therefore can no longer be
// decrypted, so Open returns core.ErrDecryptionFailed and OpenEnclave must wrap
// it as an alloc error rather than returning a usable Secret.
//
// This test runs last (it tears down the global key) and must not be parallel.
func TestOpenEnclave_DecryptionFailure(t *testing.T) {
	plaintext := []byte("0123456789abcdef0123456789abcdef")
	enclave := memguard.NewEnclave(append([]byte(nil), plaintext...))
	if enclave == nil {
		t.Fatal("expected non-nil enclave")
	}

	// Invalidate the global key that the enclave was sealed under.
	memguard.Purge()

	s, err := OpenEnclave(enclave)
	if err == nil {
		if s != nil {
			s.Destroy()
		}
		t.Fatal("expected OpenEnclave to fail after key purge")
	}
	if s != nil {
		t.Fatal("expected nil Secret on decryption failure")
	}

	var se *Error
	if !asSecretError(err, &se) {
		t.Fatalf("expected *secret.Error, got %T: %v", err, err)
	}
}

// asSecretError reports whether err is a *Error and, if so, stores it in target.
func asSecretError(err error, target **Error) bool {
	e, ok := err.(*Error)
	if ok {
		*target = e
	}
	return ok
}
