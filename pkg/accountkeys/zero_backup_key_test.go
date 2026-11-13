package accountkeys

import (
	"errors"
	"testing"
)

// TestZeroValueBackupKey_RefusesToDerive checks that every derivation of
// a BackupKey with no root key fails instead of expanding public inputs.
func TestZeroValueBackupKey_RefusesToDerive(t *testing.T) {
	var k BackupKey
	aci := make([]byte, 16)
	salt := make([]byte, 32)
	var mediaID [MediaIDLength]byte

	errs := map[string]error{}
	_, errs["DeriveBackupId"] = k.DeriveBackupId(aci)
	_, errs["DeriveECKey"] = k.DeriveECKey(aci)
	_, errs["DeriveLocalBackupMetadataKey"] = k.DeriveLocalBackupMetadataKey()
	_, errs["DeriveMediaId"] = k.DeriveMediaId("media")
	_, errs["DeriveMediaEncryptionKeyData"] = k.DeriveMediaEncryptionKeyData(mediaID)
	_, errs["DeriveThumbnailTransitEncryptionKeyData"] = k.DeriveThumbnailTransitEncryptionKeyData(mediaID)
	_, errs["DeriveForwardSecrecyPassword"] = k.DeriveForwardSecrecyPassword(salt)
	_, errs["DeriveForwardSecrecyEncryptionKey"] = k.DeriveForwardSecrecyEncryptionKey(salt)

	for name, err := range errs {
		var ik *ErrInvalidBackupKey
		if !errors.As(err, &ik) || ik.Got != 0 || ik.Expected != BackupKeyLength {
			t.Errorf("%s: want ErrInvalidBackupKey{Got:0}, got %v", name, err)
		}
	}
}
