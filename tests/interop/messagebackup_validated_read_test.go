// Interop tests for BackupReader.ValidatedReadAll against Rust-generated
// fixtures.
//
// These tests wire the canonical fixture files under
// tests/interop/fixtures/messagebackup/ into the full read-and-validate path
// implemented by pkg/backup.BackupReader.ValidatedReadAll.
//
// Rust libsignal ref: rust/message-backup/src/backup.rs BackupReader::read_all
// at Rust libsignal commit 98915c442d.
package interop

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/backup"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

// TestMessageBackup_ValidatedReadLegacy exercises ValidatedReadAll on the
// Rust-generated legacy CBC+HMAC backup fixture. It verifies that:
// 1. DecryptFrames succeeds (HMAC+CBC path).
// 2. ValidatedReadAll parses the first frame as BackupInfo.
// 3. The BackupInfo version is 1.
//
// Fixture: messagebackup/cases/valid/legacy_account_encrypted.json
// Rust source: rust/message-backup/tests/res/test-cases/valid-encrypted/legacy-account.binproto.encrypted
func TestMessageBackup_ValidatedReadLegacy(t *testing.T) {
	raw := loader.MustRead("messagebackup/cases/valid/legacy_account_encrypted.json")
	var fix mbCaseFixture
	if err := json.Unmarshal(raw, &fix); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if fix.ExpectedOutcome != "valid_decode" {
		t.Fatalf("fixture expected_outcome = %q; want valid_decode", fix.ExpectedOutcome)
	}

	input, err := hex.DecodeString(fix.InputBytesHex)
	if err != nil {
		t.Fatalf("decode input_bytes_hex: %v", err)
	}

	key := mbKeyFromFixture(t, &fix)
	defer key.Zeroize()

	// Decrypt to get the plaintext varint-delimited frames.
	dec := backup.NewFrameDecryptor(key)
	frames, err := dec.DecryptFrames(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("DecryptFrames: %v", err)
	}
	if len(frames) == 0 {
		t.Fatal("no frames decoded")
	}

	// Feed the decoded frames into a BackupReader and run ValidatedReadAll.
	// Reconstruct the varint-delimited stream.
	var stream bytes.Buffer
	for _, f := range frames {
		if err := backup.WriteVarintDelimited(&stream, f); err != nil {
			t.Fatalf("WriteVarintDelimited: %v", err)
		}
	}

	br := backup.NewBackupReader(&stream, backup.PurposeRemoteBackup)
	result, err := br.ValidatedReadAll(backup.PurposeRemoteBackup)
	if err != nil {
		t.Fatalf("ValidatedReadAll: %v", err)
	}

	if result.Info.Version != backup.BackupInfoVersion1 {
		t.Errorf("BackupInfo.Version = %d, want %d", result.Info.Version, backup.BackupInfoVersion1)
	}
	t.Logf("ValidatedReadAll decoded %d frames from Rust legacy backup (source: %s)", len(result.Frames)+1, fix.Source)
}

// TestMessageBackup_ValidatedReadModernMagicCheck verifies that the modern
// SBACKUP\x01 fixture is correctly identified as a modern format stream and
// that DecryptFrames can decode it end-to-end via the modern header path.
//
// Fixture: messagebackup/cases/valid/new_account_encrypted.json
// Rust source: rust/message-backup/tests/res/test-cases/valid-encrypted/new-account.binproto.encrypted
func TestMessageBackup_ValidatedReadModernMagicCheck(t *testing.T) {
	raw := loader.MustRead("messagebackup/cases/valid/new_account_encrypted.json")
	var fix mbCaseFixture
	if err := json.Unmarshal(raw, &fix); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	input, err := hex.DecodeString(fix.InputBytesHex)
	if err != nil {
		t.Fatalf("decode input_bytes_hex: %v", err)
	}

	// Verify the magic is present.
	if !backup.IsMagicNumber(input) {
		t.Fatalf("modern fixture does not start with SBACKUP\\x01 magic (got %x)", input[:8])
	}

	// The modern format: DecryptFrames must detect SBACKUP\x01, parse the
	// metadata header, validate it, then decrypt the payload.
	key := mbKeyFromFixture(t, &fix)
	defer key.Zeroize()

	dec := backup.NewFrameDecryptor(key)
	frames, err := dec.DecryptFrames(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("DecryptFrames (modern format): %v", err)
	}
	if len(frames) == 0 {
		t.Fatal("no frames decoded from modern format")
	}

	// Run ValidatedReadAll on the decoded frames.
	var stream bytes.Buffer
	for _, f := range frames {
		if err := backup.WriteVarintDelimited(&stream, f); err != nil {
			t.Fatalf("WriteVarintDelimited: %v", err)
		}
	}

	br := backup.NewBackupReader(&stream, backup.PurposeRemoteBackup)
	result, err := br.ValidatedReadAll(backup.PurposeRemoteBackup)
	if err != nil {
		t.Fatalf("ValidatedReadAll (modern): %v", err)
	}

	if result.Info.Version != backup.BackupInfoVersion1 {
		t.Errorf("BackupInfo.Version = %d, want %d", result.Info.Version, backup.BackupInfoVersion1)
	}
	t.Logf("ValidatedReadAll decoded %d frames from Rust modern backup (source: %s)", len(result.Frames)+1, fix.Source)
}
