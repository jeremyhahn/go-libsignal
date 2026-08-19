package svr

import (
	"bytes"
	gocipher "crypto/cipher"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/cipher"
)

func newTestAEAD(key []byte) (gocipher.AEAD, error) {
	return cipher.NewAESGCMSIV(key)
}

func TestDecryptSecretShortCiphertext(t *testing.T) {
	var key [32]byte
	// AES-GCM-SIV ciphertext for 32 bytes should be 32 + 16 (tag) = 48 bytes
	_, err := DecryptSecret(key, make([]byte, 10))
	if err == nil {
		t.Fatal("expected error for short ciphertext")
	}
}

func TestDecryptSecretWrongSize(t *testing.T) {
	// Encrypt a 16-byte value using the raw GCM-SIV cipher, then try DecryptSecret
	// which expects exactly 32 bytes of plaintext.
	var key [32]byte
	copy(key[:], bytes.Repeat([]byte{0xAA}, 32))

	// Create a valid ciphertext for a 16-byte plaintext (not 32)
	aead, err := newTestAEAD(key[:])
	if err != nil {
		t.Fatalf("create cipher: %v", err)
	}
	nonce := make([]byte, aead.NonceSize())
	shortPlaintext := make([]byte, 16)
	ciphertext := aead.Seal(nil, nonce, shortPlaintext, nil)

	_, err = DecryptSecret(key, ciphertext)
	if err == nil {
		t.Fatal("expected error for wrong plaintext size")
	}
}

func TestEncryptDecryptDeterministic(t *testing.T) {
	var key [32]byte
	copy(key[:], bytes.Repeat([]byte{0x11}, 32))
	var secret Secret
	copy(secret[:], bytes.Repeat([]byte{0x22}, 32))

	// Encrypt twice with same key should produce same ciphertext (GCM-SIV with zero nonce)
	ct1, err := EncryptSecret(key, secret)
	if err != nil {
		t.Fatalf("first EncryptSecret: %v", err)
	}
	ct2, err := EncryptSecret(key, secret)
	if err != nil {
		t.Fatalf("second EncryptSecret: %v", err)
	}
	if !bytes.Equal(ct1, ct2) {
		t.Error("deterministic encryption should produce identical ciphertext")
	}
}

func TestMasterKeyDifferentPINSameSecret(t *testing.T) {
	var secret Secret
	k1, _ := MasterKey("pin1", secret)
	k2, _ := MasterKey("pin2", secret)
	if k1 == k2 {
		t.Error("different PINs should produce different keys")
	}
}

func TestDeriveStorageKeyEmptySlice(t *testing.T) {
	_, err := DeriveStorageKey([]byte{})
	if err == nil {
		t.Fatal("expected error for empty byte slice")
	}
}

// TestEvaluationResultSerialize verifies the wire encoding matches the Rust
// format: big-endian uint32 tries_remaining || 32-byte value.
//
// Rust libsignal ref: rust/svrb/src/lib.rs EvaluationResult::serialize
func TestEvaluationResultSerialize(t *testing.T) {
	t.Run("known values", func(t *testing.T) {
		var val Secret
		for i := range val {
			val[i] = byte(i + 1)
		}
		er := &EvaluationResult{Value: val, TriesRemaining: 0x0A0B0C0D}
		got := er.Serialize()

		if len(got) != 4+secretSize {
			t.Fatalf("Serialize length = %d, want %d", len(got), 4+secretSize)
		}
		// First 4 bytes: big-endian tries_remaining.
		if got[0] != 0x0A || got[1] != 0x0B || got[2] != 0x0C || got[3] != 0x0D {
			t.Errorf("tries_remaining bytes = %x, want 0a0b0c0d", got[:4])
		}
		// Remaining 32 bytes: value.
		for i := 0; i < secretSize; i++ {
			if got[4+i] != val[i] {
				t.Errorf("value[%d] = %d, want %d", i, got[4+i], val[i])
			}
		}
	})

	t.Run("zero tries remaining", func(t *testing.T) {
		er := &EvaluationResult{TriesRemaining: 0}
		got := er.Serialize()
		if got[0] != 0 || got[1] != 0 || got[2] != 0 || got[3] != 0 {
			t.Errorf("tries_remaining for 0 = %x, want 00000000", got[:4])
		}
	})
}

// TestSentinelErrorsIs verifies that ErrNumServers, ErrRestoreFailed, and
// ErrBadResponseStatus act as correct errors.Is sentinels for dynamically
// constructed errors of the same kind.
func TestSentinelErrorsIs(t *testing.T) {
	t.Run("ErrNumServers matches newNumServersError", func(t *testing.T) {
		err := newNumServersError(3, 2)
		if !isErrKind(err, ErrNumServers) {
			t.Error("expected errors.Is to match ErrNumServers")
		}
	})

	t.Run("ErrRestoreFailed matches newRestoreFailedError", func(t *testing.T) {
		err := newRestoreFailedError(7)
		if !isErrKind(err, ErrRestoreFailed) {
			t.Error("expected errors.Is to match ErrRestoreFailed")
		}
		// Verify tries-remaining is accessible.
		if err.TriesRemaining() != 7 {
			t.Errorf("TriesRemaining() = %d, want 7", err.TriesRemaining())
		}
	})

	t.Run("ErrBadResponseStatus matches newBadResponseStatusError", func(t *testing.T) {
		err := newBadResponseStatusError(StatusMissing)
		if !isErrKind(err, ErrBadResponseStatus) {
			t.Error("expected errors.Is to match ErrBadResponseStatus")
		}
		// Verify status is accessible.
		if err.Status() != StatusMissing {
			t.Errorf("Status() = %v, want MISSING", err.Status())
		}
	})

	t.Run("sentinels do not cross-match", func(t *testing.T) {
		if isErrKind(ErrNumServers, ErrRestoreFailed) {
			t.Error("ErrNumServers should not match ErrRestoreFailed")
		}
		if isErrKind(ErrRestoreFailed, ErrBadResponseStatus) {
			t.Error("ErrRestoreFailed should not match ErrBadResponseStatus")
		}
	})
}

// isErrKind is a helper that calls err.Is(target) via the Error.Is method.
func isErrKind(err, target *Error) bool {
	return err.Is(target)
}

func TestNewBackup4Fields(t *testing.T) {
	var secret Secret
	for i := range secret {
		secret[i] = byte(i)
	}
	b, err := NewBackup4(secret, 5)
	if err != nil {
		t.Fatalf("NewBackup4: %v", err)
	}
	if b.MaxTries != 5 {
		t.Errorf("MaxTries = %d, want 5", b.MaxTries)
	}
	if !b.Secret.EqualTo(secret) {
		t.Error("Secret mismatch")
	}
	if len(b.RequestID) != requestIDSize {
		t.Errorf("RequestID length = %d, want %d", len(b.RequestID), requestIDSize)
	}
	if b.Entropy.Size() != entropySize {
		t.Errorf("Entropy length = %d, want %d", b.Entropy.Size(), entropySize)
	}
}
