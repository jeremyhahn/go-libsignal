package backup

import (
	"errors"
	"testing"
)

// TestZeroValueBackupKey_RefusesToDerive checks that a BackupKey with no
// root key (WithBytes borrows it as nil) derives nothing from the public
// inputs alone.
func TestZeroValueBackupKey_RefusesToDerive(t *testing.T) {
	var bk BackupKey

	_, err := bk.DeriveBackupID(fakeACI())
	var kl *ErrInvalidKeyLength
	if !errors.As(err, &kl) || kl.Got != 0 || kl.Want != BackupKeyLen {
		t.Fatalf("DeriveBackupID: want ErrInvalidKeyLength{Got:0}, got %v", err)
	}

	var id BackupID
	for _, token := range [][]byte{nil, []byte("forward-secrecy-token")} {
		mk, err := DeriveMessageBackupKey(&bk, &id, token)
		if !errors.As(err, &kl) || kl.Got != 0 {
			t.Fatalf("DeriveMessageBackupKey(token=%q): want ErrInvalidKeyLength, got %v", token, err)
		}
		if mk != nil {
			t.Fatal("DeriveMessageBackupKey: want nil key")
		}
	}
}
