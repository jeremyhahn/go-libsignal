// Conformance test: backup-key and backup-id derivation.
//
// Mirrors Rust's inline test_module tests in rust/account-keys/src/backup.rs:
//   - backup_key_known_from_account_entropy
//   - backup_id_known_from_account_entropy
//
// The fixture JSON at fixtures/accountkeys/backup_known_answers.json carries
// the same hex constants as those Rust tests (AccountEntropyPool seed, fake
// ACI UUID, expected BackupKey, expected BackupId). The drift detector
// runs grep against the upstream source so a change to those Rust
// constants fails the conformance gate before this test runs.
//
// Goal: prove byte-identical output between Go's
// pkg/accountkeys.BackupKey derivation chain and Rust's
// libsignal-account-keys for the same inputs. This exercises the
// Argon2/HKDF info strings and the BackupKey → BackupId chain end-to-end.

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

// TestAccountKeys_BackupId_FromEntropy_Known mirrors the Rust test
// backup_id_known_from_account_entropy. The chain is:
//
//	AccountEntropyPool → BackupKey → BackupId(BackupKey, ACI).
//
// We verify the end of that chain matches Rust byte for byte, which also
// transitively verifies (a) HKDF info string "20240801_SIGNAL_BACKUP_KEY",
// (b) HKDF info "20241024_SIGNAL_BACKUP_ID:", and (c) the ACI binary
// concatenation policy.
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
