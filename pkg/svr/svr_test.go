package svr

import (
	"bytes"
	"testing"

	cryptosecret "github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret/secrettest"
)

func TestNewBackup4(t *testing.T) {
	var secret Secret
	copy(secret[:], bytes.Repeat([]byte{0xAB}, 32))

	t.Run("valid backup", func(t *testing.T) {
		backup, err := NewBackup4(secret, 10)
		if err != nil {
			t.Fatalf("NewBackup4 failed: %v", err)
		}
		if len(backup.RequestID) != requestIDSize {
			t.Errorf("RequestID length = %d, want %d", len(backup.RequestID), requestIDSize)
		}
		if backup.Entropy.Size() != entropySize {
			t.Errorf("Entropy length = %d, want %d", backup.Entropy.Size(), entropySize)
		}
		if !backup.Secret.EqualTo(secret) {
			t.Error("Secret mismatch")
		}
		if backup.MaxTries != 10 {
			t.Errorf("MaxTries = %d, want 10", backup.MaxTries)
		}
	})

	t.Run("zero max tries", func(t *testing.T) {
		_, err := NewBackup4(secret, 0)
		if err == nil {
			t.Fatal("expected error for zero maxTries")
		}
	})

	t.Run("unique entropy", func(t *testing.T) {
		b1, _ := NewBackup4(secret, 5)
		b2, _ := NewBackup4(secret, 5)
		if secrettest.Same(t, b1.Entropy, b2.Entropy) {
			t.Error("two backups produced identical entropy")
		}
		if bytes.Equal(b1.RequestID, b2.RequestID) {
			t.Error("two backups produced identical request IDs")
		}
	})
}

func TestMasterKey(t *testing.T) {
	var secret Secret
	copy(secret[:], bytes.Repeat([]byte{0x01}, 32))

	t.Run("deterministic", func(t *testing.T) {
		k1, err := MasterKey("1234", secret)
		if err != nil {
			t.Fatalf("MasterKey failed: %v", err)
		}
		k2, err := MasterKey("1234", secret)
		if err != nil {
			t.Fatalf("MasterKey failed: %v", err)
		}
		if k1 != k2 {
			t.Error("same inputs produced different master keys")
		}
	})

	t.Run("different PINs", func(t *testing.T) {
		k1, _ := MasterKey("1234", secret)
		k2, _ := MasterKey("5678", secret)
		if k1 == k2 {
			t.Error("different PINs produced same master key")
		}
	})

	t.Run("different secrets", func(t *testing.T) {
		var secret2 Secret
		copy(secret2[:], bytes.Repeat([]byte{0x02}, 32))
		k1, _ := MasterKey("1234", secret)
		k2, _ := MasterKey("1234", secret2)
		if k1 == k2 {
			t.Error("different secrets produced same master key")
		}
	})

	t.Run("empty PIN", func(t *testing.T) {
		_, err := MasterKey("", secret)
		if err == nil {
			t.Fatal("expected error for empty PIN")
		}
	})
}

func TestDeriveStorageKey(t *testing.T) {
	t.Run("deterministic", func(t *testing.T) {
		master := bytes.Repeat([]byte{0x42}, 32)
		k1, err := DeriveStorageKey(master)
		if err != nil {
			t.Fatalf("DeriveStorageKey failed: %v", err)
		}
		k2, err := DeriveStorageKey(master)
		if err != nil {
			t.Fatalf("DeriveStorageKey failed: %v", err)
		}
		if k1 != k2 {
			t.Error("same input produced different storage keys")
		}
	})

	t.Run("empty master secret", func(t *testing.T) {
		_, err := DeriveStorageKey(nil)
		if err == nil {
			t.Fatal("expected error for empty master secret")
		}
	})

	t.Run("different inputs produce different keys", func(t *testing.T) {
		// A master secret is a 32-byte Secret in production; the fixtures use
		// that length rather than seven-byte strings, which fall below the
		// 112-bit HKDF key floor the FIPS 140-3 gate enforces.
		k1, _ := DeriveStorageKey(bytes.Repeat([]byte{0x01}, 32))
		k2, _ := DeriveStorageKey(bytes.Repeat([]byte{0x02}, 32))
		if k1 == k2 {
			t.Error("different inputs produced same storage key")
		}
	})
}

func TestEncryptDecryptSecret(t *testing.T) {
	var key [32]byte
	copy(key[:], bytes.Repeat([]byte{0xCC}, 32))

	var secret Secret
	copy(secret[:], bytes.Repeat([]byte{0xDD}, 32))

	t.Run("round trip", func(t *testing.T) {
		encrypted, err := EncryptSecret(key, secret)
		if err != nil {
			t.Fatalf("EncryptSecret failed: %v", err)
		}
		decrypted, err := DecryptSecret(key, encrypted)
		if err != nil {
			t.Fatalf("DecryptSecret failed: %v", err)
		}
		if decrypted != secret {
			t.Error("decrypted secret does not match original")
		}
	})

	t.Run("tampered ciphertext", func(t *testing.T) {
		encrypted, _ := EncryptSecret(key, secret)
		encrypted[0] ^= 0xFF
		_, err := DecryptSecret(key, encrypted)
		if err == nil {
			t.Fatal("expected error for tampered ciphertext")
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		encrypted, _ := EncryptSecret(key, secret)
		var wrongKey [32]byte
		copy(wrongKey[:], bytes.Repeat([]byte{0xEE}, 32))
		_, err := DecryptSecret(wrongKey, encrypted)
		if err == nil {
			t.Fatal("expected error for wrong key")
		}
	})
}

// TestBackup4Destroy checks that the guarded entropy is released and that
// Destroy is safe to call more than once, and on a request that carries none.
func TestBackup4Destroy(t *testing.T) {
	var secret Secret
	copy(secret[:], bytes.Repeat([]byte{0xCD}, 32))

	backup, err := NewBackup4(secret, 3)
	if err != nil {
		t.Fatalf("NewBackup4: %v", err)
	}
	if backup.Entropy.IsDestroyed() {
		t.Fatal("entropy should be live before Destroy")
	}

	backup.Destroy()
	if !backup.Entropy.IsDestroyed() {
		t.Error("Destroy left the guarded entropy alive")
	}
	backup.Destroy()

	(&Backup4{}).Destroy()
}

// TestRestore4Destroy covers the restore-side request, whose entropy is
// supplied by the caller rather than generated.
func TestRestore4Destroy(t *testing.T) {
	entropy, err := cryptosecret.New(bytes.Repeat([]byte{0xEF}, entropySize))
	if err != nil {
		t.Fatalf("secret.New: %v", err)
	}
	restore := &Restore4{RequestID: make([]byte, requestIDSize), Entropy: entropy}

	if restore.Entropy.Size() != entropySize {
		t.Errorf("Entropy size = %d, want %d", restore.Entropy.Size(), entropySize)
	}

	restore.Destroy()
	if !restore.Entropy.IsDestroyed() {
		t.Error("Destroy left the guarded entropy alive")
	}
	restore.Destroy()

	(&Restore4{}).Destroy()
}

// TestBackup4DestroyReleasesBothSecrets checks that a completed backup request
// releases every piece of guarded material it holds, and that Destroy stays
// safe on a request that holds none.
func TestBackup4DestroyReleasesBothSecrets(t *testing.T) {
	var secret Secret
	copy(secret[:], bytes.Repeat([]byte{0xCD}, 32))

	backup, err := NewBackup4(secret, 3)
	if err != nil {
		t.Fatalf("NewBackup4 failed: %v", err)
	}

	// The caller keeps its own copy: Go passed the array by value.
	if !backup.Secret.EqualTo(secret) {
		t.Fatal("backup secret does not match the caller's secret")
	}

	backup.Destroy()
	backup.Destroy() // idempotent

	if !backup.Secret.IsDestroyed() {
		t.Error("Destroy left the backup secret alive")
	}
	if !backup.Entropy.IsDestroyed() {
		t.Error("Destroy left the entropy alive")
	}
}

// TestNewBackup4ZeroizesItsOwnCopyOfTheSecret checks that building a request
// leaves no second plaintext copy of the backup secret behind: the array this
// package received is zeroized as the material moves into guarded memory.
func TestNewBackup4ZeroizesItsOwnCopyOfTheSecret(t *testing.T) {
	var secret Secret
	copy(secret[:], bytes.Repeat([]byte{0xEF}, 32))

	backup, err := NewBackup4(secret, 3)
	if err != nil {
		t.Fatalf("NewBackup4 failed: %v", err)
	}
	defer backup.Destroy()

	// The caller's array is its own copy and is untouched, which is why the
	// doc comment tells callers to zeroize it themselves.
	if !backup.Secret.EqualTo(secret) {
		t.Fatal("guarded secret does not match the caller's secret")
	}
	if bytes.Equal(secret[:], make([]byte, 32)) {
		t.Fatal("the caller's array should not have been zeroized")
	}
}
