package accountkeys

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret/secrettest"
)

// Test vectors from the Rust libsignal implementation.
const fakeEntropyPool = AccountEntropyPool("dtjs858asj6tv0jzsqrsmj0ubp335pisj98e9ssnss8myoc08drhtcktyawvx45l")

// fakeACI is the 16-byte service ID binary for ACI 659aa5f4-a28d-fcc1-1ea1-b997537a3d95.
// For ACIs, service_id_binary() returns just the raw 16 UUID bytes (no type prefix).
var fakeACI = mustHex("659aa5f4a28dfcc11ea1b997537a3d95")

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestDeriveBackupKeyFromEntropyPool(t *testing.T) {
	t.Run("known test vector", func(t *testing.T) {
		key, err := DeriveBackupKeyFromEntropyPool(fakeEntropyPool)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key.Zeroize()
		expected := mustHex("ea26a2ddb5dba5ef9e34e1b8dea1f5ae7f255306a6d2d883e542306eaa9fe985")
		if !secrettest.Matches(t, key.data, expected) {
			t.Fatalf("backup key mismatch")
		}
	})

	t.Run("invalid pool returns error", func(t *testing.T) {
		_, err := DeriveBackupKeyFromEntropyPool(AccountEntropyPool("short"))
		if err == nil {
			t.Fatal("expected error for invalid pool")
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		key1, err := DeriveBackupKeyFromEntropyPool(fakeEntropyPool)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key1.Zeroize()
		key2, err := DeriveBackupKeyFromEntropyPool(fakeEntropyPool)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key2.Zeroize()
		if !secrettest.Same(t, key1.data, key2.data) {
			t.Fatal("same pool should derive same key")
		}
	})
}

func TestBackupKey_DeriveBackupId(t *testing.T) {
	t.Run("known test vector", func(t *testing.T) {
		key, err := DeriveBackupKeyFromEntropyPool(fakeEntropyPool)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key.Zeroize()
		id, err := key.DeriveBackupId(fakeACI)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := mustHex("8a624fbc45379043f39f1391cddc5fe8")
		if !bytes.Equal(id.data[:], expected) {
			t.Fatalf("backup ID mismatch\ngot:  %x\nwant: %x", id.data, expected)
		}
	})

	t.Run("different ACIs produce different IDs", func(t *testing.T) {
		key, err := DeriveBackupKeyFromEntropyPool(fakeEntropyPool)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key.Zeroize()
		id1, err := key.DeriveBackupId(fakeACI)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		otherACI := mustHex("00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		id2, err := key.DeriveBackupId(otherACI)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if id1.data == id2.data {
			t.Fatal("different ACIs should produce different backup IDs")
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		key, err := DeriveBackupKeyFromEntropyPool(fakeEntropyPool)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key.Zeroize()
		id1, err := key.DeriveBackupId(fakeACI)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		id2, err := key.DeriveBackupId(fakeACI)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if id1.data != id2.data {
			t.Fatal("same inputs should produce same backup ID")
		}
	})
}

func TestNewBackupKey(t *testing.T) {
	var data [BackupKeyLength]byte
	for i := range data {
		data[i] = byte(i)
	}
	key := NewBackupKey(data)
	defer key.Zeroize()
	got := key.Bytes()
	if got != data {
		t.Fatalf("NewBackupKey round-trip failed")
	}
}

func TestNewBackupId(t *testing.T) {
	var data [BackupIDLength]byte
	for i := range data {
		data[i] = byte(i + 10)
	}
	id := NewBackupId(data)
	got := id.Bytes()
	if got != data {
		t.Fatalf("NewBackupId round-trip failed")
	}
}

func TestBackupKey_DeriveECKey(t *testing.T) {
	t.Run("produces 32 bytes", func(t *testing.T) {
		key, err := DeriveBackupKeyFromEntropyPool(fakeEntropyPool)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key.Zeroize()
		ecKey, err := key.DeriveECKey(fakeACI)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer ecKey.Destroy()
		if secrettest.IsZero(t, ecKey) {
			t.Fatal("EC key should not be all zeros")
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		key, err := DeriveBackupKeyFromEntropyPool(fakeEntropyPool)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key.Zeroize()
		ec1, err := key.DeriveECKey(fakeACI)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer ec1.Destroy()
		ec2, err := key.DeriveECKey(fakeACI)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer ec2.Destroy()
		if !secrettest.Same(t, ec1, ec2) {
			t.Fatal("same inputs should produce same EC key")
		}
	})

	t.Run("differs from backup ID", func(t *testing.T) {
		key, err := DeriveBackupKeyFromEntropyPool(fakeEntropyPool)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key.Zeroize()
		ecKey, err := key.DeriveECKey(fakeACI)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer ecKey.Destroy()
		id, err := key.DeriveBackupId(fakeACI)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// They are different lengths, but check the first 16 bytes differ.
		samePrefix := false
		secrettest.With(t, ecKey, func(b []byte) {
			samePrefix = len(b) >= BackupIDLength && bytes.Equal(b[:BackupIDLength], id.data[:])
		})
		if samePrefix {
			t.Fatal("EC key should differ from backup ID")
		}
	})
}

func TestBackupKey_DeriveLocalBackupMetadataKey(t *testing.T) {
	t.Run("produces correct length", func(t *testing.T) {
		key, err := DeriveBackupKeyFromEntropyPool(fakeEntropyPool)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key.Zeroize()
		metaKey, err := key.DeriveLocalBackupMetadataKey()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer metaKey.Destroy()
		if metaKey.Size() != LocalBackupMetadataKeyLength {
			t.Fatalf("expected length %d, got %d", LocalBackupMetadataKeyLength, metaKey.Size())
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		key, err := DeriveBackupKeyFromEntropyPool(fakeEntropyPool)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key.Zeroize()
		mk1, err := key.DeriveLocalBackupMetadataKey()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer mk1.Destroy()
		mk2, err := key.DeriveLocalBackupMetadataKey()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer mk2.Destroy()
		if !secrettest.Same(t, mk1, mk2) {
			t.Fatal("same key should produce same metadata key")
		}
	})
}

func TestBackupKey_DeriveMediaId(t *testing.T) {
	t.Run("produces correct length", func(t *testing.T) {
		key, err := DeriveBackupKeyFromEntropyPool(fakeEntropyPool)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key.Zeroize()
		mediaId, err := key.DeriveMediaId("test-media")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mediaId == ([MediaIDLength]byte{}) {
			t.Fatal("derived media ID must not be all-zero")
		}
	})

	t.Run("different names produce different IDs", func(t *testing.T) {
		key, err := DeriveBackupKeyFromEntropyPool(fakeEntropyPool)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key.Zeroize()
		id1, err := key.DeriveMediaId("media-a")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		id2, err := key.DeriveMediaId("media-b")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if id1 == id2 {
			t.Fatal("different media names should produce different IDs")
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		key, err := DeriveBackupKeyFromEntropyPool(fakeEntropyPool)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key.Zeroize()
		id1, err := key.DeriveMediaId("test")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		id2, err := key.DeriveMediaId("test")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if id1 != id2 {
			t.Fatal("same inputs should produce same media ID")
		}
	})
}

func TestBackupKey_DeriveMediaEncryptionKeyData(t *testing.T) {
	t.Run("produces correct length", func(t *testing.T) {
		key, err := DeriveBackupKeyFromEntropyPool(fakeEntropyPool)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key.Zeroize()
		mediaId, err := key.DeriveMediaId("test")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		encKey, err := key.DeriveMediaEncryptionKeyData(mediaId)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer encKey.Destroy()
		if encKey.Size() != MediaEncryptionKeyLength {
			t.Fatalf("expected length %d, got %d", MediaEncryptionKeyLength, encKey.Size())
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		key, err := DeriveBackupKeyFromEntropyPool(fakeEntropyPool)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key.Zeroize()
		mediaId, err := key.DeriveMediaId("test")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		ek1, err := key.DeriveMediaEncryptionKeyData(mediaId)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer ek1.Destroy()
		ek2, err := key.DeriveMediaEncryptionKeyData(mediaId)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer ek2.Destroy()
		if !secrettest.Same(t, ek1, ek2) {
			t.Fatal("same inputs should produce same encryption key")
		}
	})
}

func TestBackupKey_DeriveThumbnailTransitEncryptionKeyData(t *testing.T) {
	t.Run("produces correct length", func(t *testing.T) {
		key, err := DeriveBackupKeyFromEntropyPool(fakeEntropyPool)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key.Zeroize()
		mediaId, err := key.DeriveMediaId("thumb")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		thumbKey, err := key.DeriveThumbnailTransitEncryptionKeyData(mediaId)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer thumbKey.Destroy()
		if thumbKey.Size() != MediaEncryptionKeyLength {
			t.Fatalf("expected length %d, got %d", MediaEncryptionKeyLength, thumbKey.Size())
		}
	})

	t.Run("differs from media encryption key", func(t *testing.T) {
		key, err := DeriveBackupKeyFromEntropyPool(fakeEntropyPool)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key.Zeroize()
		mediaId, err := key.DeriveMediaId("test")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mediaKey, err := key.DeriveMediaEncryptionKeyData(mediaId)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer mediaKey.Destroy()
		thumbKey, err := key.DeriveThumbnailTransitEncryptionKeyData(mediaId)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer thumbKey.Destroy()
		if secrettest.Same(t, mediaKey, thumbKey) {
			t.Fatal("thumbnail key should differ from media encryption key")
		}
	})
}

func TestBackupKey_DeriveForwardSecrecyPassword(t *testing.T) {
	t.Run("produces 32 bytes", func(t *testing.T) {
		key, err := DeriveBackupKeyFromEntropyPool(fakeEntropyPool)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key.Zeroize()
		salt := []byte("test-salt-for-password-derivation")
		pw, err := key.DeriveForwardSecrecyPassword(salt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pw.data == [32]byte{} {
			t.Fatal("password should not be all zeros")
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		key, err := DeriveBackupKeyFromEntropyPool(fakeEntropyPool)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key.Zeroize()
		salt := []byte("deterministic-salt")
		pw1, err := key.DeriveForwardSecrecyPassword(salt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		pw2, err := key.DeriveForwardSecrecyPassword(salt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pw1.data != pw2.data {
			t.Fatal("same inputs should produce same password")
		}
	})

	t.Run("different salts produce different passwords", func(t *testing.T) {
		key, err := DeriveBackupKeyFromEntropyPool(fakeEntropyPool)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key.Zeroize()
		pw1, err := key.DeriveForwardSecrecyPassword([]byte("salt-1"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		pw2, err := key.DeriveForwardSecrecyPassword([]byte("salt-2"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pw1.data == pw2.data {
			t.Fatal("different salts should produce different passwords")
		}
	})

	t.Run("nil salt succeeds", func(t *testing.T) {
		key, err := DeriveBackupKeyFromEntropyPool(fakeEntropyPool)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key.Zeroize()
		_, err = key.DeriveForwardSecrecyPassword(nil)
		if err != nil {
			t.Fatalf("unexpected error with nil salt: %v", err)
		}
	})

	t.Run("Bytes returns correct data", func(t *testing.T) {
		key, err := DeriveBackupKeyFromEntropyPool(fakeEntropyPool)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key.Zeroize()
		pw, err := key.DeriveForwardSecrecyPassword([]byte("salt"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		b := pw.Bytes()
		if b != pw.data {
			t.Fatal("Bytes() should return internal data")
		}
	})
}

func TestBackupKey_DeriveForwardSecrecyEncryptionKey(t *testing.T) {
	t.Run("produces non-zero cipher and HMAC keys", func(t *testing.T) {
		key, err := DeriveBackupKeyFromEntropyPool(fakeEntropyPool)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key.Zeroize()
		salt := []byte("test-encryption-salt")
		encKey, err := key.DeriveForwardSecrecyEncryptionKey(salt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer encKey.Zeroize()
		if secrettest.IsZero(t, encKey.CipherKey) {
			t.Fatal("cipher key should not be all zeros")
		}
		if secrettest.IsZero(t, encKey.HMACKey) {
			t.Fatal("HMAC key should not be all zeros")
		}
	})

	t.Run("cipher key differs from HMAC key", func(t *testing.T) {
		key, err := DeriveBackupKeyFromEntropyPool(fakeEntropyPool)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key.Zeroize()
		encKey, err := key.DeriveForwardSecrecyEncryptionKey([]byte("salt"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer encKey.Zeroize()
		if secrettest.Same(t, encKey.CipherKey, encKey.HMACKey) {
			t.Fatal("cipher key and HMAC key should differ")
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		key, err := DeriveBackupKeyFromEntropyPool(fakeEntropyPool)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key.Zeroize()
		salt := []byte("deterministic-salt")
		ek1, err := key.DeriveForwardSecrecyEncryptionKey(salt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer ek1.Zeroize()
		ek2, err := key.DeriveForwardSecrecyEncryptionKey(salt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer ek2.Zeroize()
		if !secrettest.Same(t, ek1.CipherKey, ek2.CipherKey) || !secrettest.Same(t, ek1.HMACKey, ek2.HMACKey) {
			t.Fatal("same inputs should produce same encryption key")
		}
	})

	t.Run("different salts produce different keys", func(t *testing.T) {
		key, err := DeriveBackupKeyFromEntropyPool(fakeEntropyPool)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key.Zeroize()
		ek1, err := key.DeriveForwardSecrecyEncryptionKey([]byte("salt-a"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer ek1.Zeroize()
		ek2, err := key.DeriveForwardSecrecyEncryptionKey([]byte("salt-b"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer ek2.Zeroize()
		if secrettest.Same(t, ek1.CipherKey, ek2.CipherKey) {
			t.Fatal("different salts should produce different cipher keys")
		}
		if secrettest.Same(t, ek1.HMACKey, ek2.HMACKey) {
			t.Fatal("different salts should produce different HMAC keys")
		}
	})

	t.Run("nil salt succeeds", func(t *testing.T) {
		key, err := DeriveBackupKeyFromEntropyPool(fakeEntropyPool)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key.Zeroize()
		ek, err := key.DeriveForwardSecrecyEncryptionKey(nil)
		if err != nil {
			t.Fatalf("unexpected error with nil salt: %v", err)
		}
		ek.Zeroize()
	})

	t.Run("differs from forward secrecy password", func(t *testing.T) {
		key, err := DeriveBackupKeyFromEntropyPool(fakeEntropyPool)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key.Zeroize()
		salt := []byte("same-salt")
		pw, err := key.DeriveForwardSecrecyPassword(salt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		ek, err := key.DeriveForwardSecrecyEncryptionKey(salt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer ek.Zeroize()
		if secrettest.Matches(t, ek.CipherKey, pw.data[:]) {
			t.Fatal("password should differ from cipher key even with same salt")
		}
	})
}

func TestNewBackupForwardSecrecyToken(t *testing.T) {
	var data [BackupForwardSecrecyTokenLength]byte
	for i := range data {
		data[i] = byte(i + 42)
	}
	token := NewBackupForwardSecrecyToken(data)
	got := token.Bytes()
	if got != data {
		t.Fatal("NewBackupForwardSecrecyToken round-trip failed")
	}
}

func TestBackupForwardSecrecyToken_Bytes(t *testing.T) {
	var data [BackupForwardSecrecyTokenLength]byte
	for i := range data {
		data[i] = 0xff
	}
	token := NewBackupForwardSecrecyToken(data)
	b := token.Bytes()
	for i, v := range b {
		if v != 0xff {
			t.Fatalf("byte %d: got %d, want 255", i, v)
		}
	}
}

func TestBackupKey_Zeroize(t *testing.T) {
	var data [BackupKeyLength]byte
	for i := range data {
		data[i] = byte(i + 1)
	}
	key := NewBackupKey(data)
	key.Zeroize()
	if !key.data.IsDestroyed() {
		t.Fatal("Zeroize should destroy the backup key secret")
	}
}

func TestBackupId_Zeroize(t *testing.T) {
	var data [BackupIDLength]byte
	for i := range data {
		data[i] = byte(i + 1)
	}
	id := NewBackupId(data)
	id.Zeroize()
	got := id.Bytes()
	if got != [BackupIDLength]byte{} {
		t.Fatal("Zeroize should clear the backup ID to zero")
	}
}

func TestBackupForwardSecrecyPassword_Zeroize(t *testing.T) {
	key, err := DeriveBackupKeyFromEntropyPool(fakeEntropyPool)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer key.Zeroize()
	pw, err := key.DeriveForwardSecrecyPassword([]byte("salt"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pw.Bytes() == [32]byte{} {
		t.Fatal("password should be non-zero before Zeroize")
	}
	pw.Zeroize()
	if pw.Bytes() != [32]byte{} {
		t.Fatal("Zeroize should clear the password to zero")
	}
}

func TestBackupForwardSecrecyEncryptionKey_Zeroize(t *testing.T) {
	key, err := DeriveBackupKeyFromEntropyPool(fakeEntropyPool)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer key.Zeroize()
	encKey, err := key.DeriveForwardSecrecyEncryptionKey([]byte("salt"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secrettest.IsZero(t, encKey.CipherKey) || secrettest.IsZero(t, encKey.HMACKey) {
		t.Fatal("keys should be non-zero before Zeroize")
	}
	encKey.Zeroize()
	if !encKey.CipherKey.IsDestroyed() {
		t.Fatal("Zeroize should destroy CipherKey")
	}
	if !encKey.HMACKey.IsDestroyed() {
		t.Fatal("Zeroize should destroy HMACKey")
	}
}

func TestBackupForwardSecrecyToken_Zeroize(t *testing.T) {
	var data [BackupForwardSecrecyTokenLength]byte
	for i := range data {
		data[i] = 0xFF
	}
	token := NewBackupForwardSecrecyToken(data)
	token.Zeroize()
	if token.Bytes() != [BackupForwardSecrecyTokenLength]byte{} {
		t.Fatal("Zeroize should clear the token to zero")
	}
}

func TestBackupKey_DeriveFromRawBytes(t *testing.T) {
	// Verify that constructing a BackupKey from known bytes and deriving
	// a backup ID matches the expected test vector.
	keyBytes := mustHex("ea26a2ddb5dba5ef9e34e1b8dea1f5ae7f255306a6d2d883e542306eaa9fe985")
	var rawKey [BackupKeyLength]byte
	copy(rawKey[:], keyBytes)
	key := NewBackupKey(rawKey)
	defer key.Zeroize()

	id, err := key.DeriveBackupId(fakeACI)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := mustHex("8a624fbc45379043f39f1391cddc5fe8")
	if !bytes.Equal(id.data[:], expected) {
		t.Fatalf("backup ID mismatch\ngot:  %x\nwant: %x", id.data, expected)
	}
}
