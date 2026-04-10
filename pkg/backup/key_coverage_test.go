package backup

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/accountkeys"
)

// TestBackupIDZeroize verifies that BackupID.Zeroize() wipes all bytes to zero.
func TestBackupIDZeroize(t *testing.T) {
	var id BackupID
	for i := range id.id {
		id.id[i] = 0xAB
	}
	id.Zeroize()
	for i, b := range id.id {
		if b != 0 {
			t.Errorf("BackupID.Zeroize() left non-zero byte at index %d: 0x%02x", i, b)
		}
	}
}

// TestBackupIDZeroize_AlreadyZero verifies Zeroize is a no-op on zeroed data.
func TestBackupIDZeroize_AlreadyZero(t *testing.T) {
	var id BackupID
	// Already zeroed; Zeroize should not panic.
	id.Zeroize()
	for i, b := range id.id {
		if b != 0 {
			t.Errorf("byte at index %d should still be 0, got 0x%02x", i, b)
		}
	}
}

// TestDeriveMessageBackupKey_EmptyToken verifies that a zero-length token
// slice follows the legacy (nil salt) path and produces the same keys as nil.
func TestDeriveMessageBackupKey_EmptyToken(t *testing.T) {
	bk, err := DeriveBackupKey(accountkeys.AccountEntropyPool(fakeAccountEntropyPool))
	if err != nil {
		t.Fatalf("DeriveBackupKey: %v", err)
	}
	defer bk.Zeroize()

	id, err := bk.DeriveBackupID(fakeACI())
	if err != nil {
		t.Fatalf("DeriveBackupID: %v", err)
	}

	mkEmpty, err := DeriveMessageBackupKey(bk, id, []byte{})
	if err != nil {
		t.Fatalf("DeriveMessageBackupKey with empty token: %v", err)
	}
	defer mkEmpty.Zeroize()

	mkNil, err := DeriveMessageBackupKey(bk, id, nil)
	if err != nil {
		t.Fatalf("DeriveMessageBackupKey with nil token: %v", err)
	}
	defer mkNil.Zeroize()

	if string(mkEmpty.HMACKey.Bytes()) != string(mkNil.HMACKey.Bytes()) {
		t.Error("empty and nil token should produce identical HMAC key (legacy path)")
	}
	if string(mkEmpty.AESKey.Bytes()) != string(mkNil.AESKey.Bytes()) {
		t.Error("empty and nil token should produce identical AES key (legacy path)")
	}
}
