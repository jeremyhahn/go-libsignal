// BackupReader.ValidatedReadAll against the Rust message-backup fixtures (Rust BackupReader::read_all).
package interop

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/backup"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

// TestMessageBackup_ValidatedReadLegacy checks the legacy CBC+HMAC fixture decrypts and its first frame is BackupInfo version 1.
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
	defer result.Destroy()

	if result.Info.Version != backup.BackupInfoVersion1 {
		t.Errorf("BackupInfo.Version = %d, want %d", result.Info.Version, backup.BackupInfoVersion1)
	}
	t.Logf("ValidatedReadAll decoded %d frames from Rust legacy backup (source: %s)", len(result.Frames)+1, fix.Source)
}

// TestMessageBackup_ValidatedReadModernMagicCheck checks the SBACKUP\x01 fixture decrypts through the modern header path.
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

	// DecryptFrames detects SBACKUP\x01, validates the metadata header, then decrypts.
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
	defer result.Destroy()

	if result.Info.Version != backup.BackupInfoVersion1 {
		t.Errorf("BackupInfo.Version = %d, want %d", result.Info.Version, backup.BackupInfoVersion1)
	}
	t.Logf("ValidatedReadAll decoded %d frames from Rust modern backup (source: %s)", len(result.Frames)+1, fix.Source)
}
