package svr

import (
	"bytes"
	"testing"
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
		if len(backup.Entropy) != entropySize {
			t.Errorf("Entropy length = %d, want %d", len(backup.Entropy), entropySize)
		}
		if backup.Secret != secret {
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
		if bytes.Equal(b1.Entropy, b2.Entropy) {
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
		k1, _ := DeriveStorageKey([]byte("secret1"))
		k2, _ := DeriveStorageKey([]byte("secret2"))
		if k1 == k2 {
			t.Error("different inputs produced same storage key")
		}
	})
}
