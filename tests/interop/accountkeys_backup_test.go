// Conformance: BackupKey and BackupId derivation against the Rust account-keys tests, from fixtures/accountkeys/backup_known_answers.json.

package interop

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/accountkeys"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

type backupKnownAnswers struct {
	FakeAccountEntropyPool string `json:"fake_account_entropy_pool"`
	FakeAciUUIDHex         string `json:"fake_aci_uuid_hex"`
	ExpectedBackupKeyHex   string `json:"expected_backup_key_hex"`
	ExpectedBackupIDHex    string `json:"expected_backup_id_hex"`
}

func loadBackupKnownAnswers(t *testing.T) backupKnownAnswers {
	t.Helper()
	raw := loader.MustRead("accountkeys/backup_known_answers.json")
	var ka backupKnownAnswers
	if err := json.Unmarshal(raw, &ka); err != nil {
		t.Fatalf("decode backup_known_answers.json: %v", err)
	}
	if ka.FakeAccountEntropyPool == "" || ka.ExpectedBackupKeyHex == "" {
		t.Fatalf("backup_known_answers.json missing required fields")
	}
	return ka
}

// TestAccountKeys_BackupKey_FromEntropy_Known mirrors the Rust test
// backup_key_known_from_account_entropy and asserts that
// DeriveBackupKeyFromEntropyPool produces the byte-identical 32-byte
// BackupKey value the upstream test expects.
func TestAccountKeys_BackupKey_FromEntropy_Known(t *testing.T) {
	ka := loadBackupKnownAnswers(t)

	want, err := hex.DecodeString(ka.ExpectedBackupKeyHex)
	if err != nil {
		t.Fatalf("decode expected key hex: %v", err)
	}

	pool := accountkeys.AccountEntropyPool(ka.FakeAccountEntropyPool)
	key, err := accountkeys.DeriveBackupKeyFromEntropyPool(pool)
	if err != nil {
		t.Fatalf("DeriveBackupKeyFromEntropyPool: %v", err)
	}
	defer key.Zeroize()

	got := key.Bytes()
	if !bytes.Equal(got[:], want) {
		t.Fatalf("BackupKey mismatch:\n  got  %x\n  want %x", got, want)
	}
}

// TestAccountKeys_BackupId_FromEntropy_Known checks AccountEntropyPool -> BackupKey -> BackupId(BackupKey, ACI) matches Rust.
func TestAccountKeys_BackupId_FromEntropy_Known(t *testing.T) {
	ka := loadBackupKnownAnswers(t)

	aci, err := hex.DecodeString(ka.FakeAciUUIDHex)
	if err != nil {
		t.Fatalf("decode ACI hex: %v", err)
	}
	if len(aci) != 16 {
		t.Fatalf("ACI must be 16 bytes, got %d", len(aci))
	}
	want, err := hex.DecodeString(ka.ExpectedBackupIDHex)
	if err != nil {
		t.Fatalf("decode expected id hex: %v", err)
	}

	pool := accountkeys.AccountEntropyPool(ka.FakeAccountEntropyPool)
	key, err := accountkeys.DeriveBackupKeyFromEntropyPool(pool)
	if err != nil {
		t.Fatalf("DeriveBackupKeyFromEntropyPool: %v", err)
	}
	defer key.Zeroize()

	id, err := key.DeriveBackupId(aci)
	if err != nil {
		t.Fatalf("DeriveBackupId: %v", err)
	}

	gotBytes := id.Bytes()
	if !bytes.Equal(gotBytes[:], want) {
		t.Fatalf("BackupId mismatch:\n  got  %x\n  want %x", gotBytes, want)
	}
}
