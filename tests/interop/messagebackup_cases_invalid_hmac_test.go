// Interop tests for message-backup frames with invalid HMAC.
//
// Source: rust/message-backup/tests/res/test-cases/valid-encrypted/
// legacy-account.binproto.encrypted (HMAC bytes mutated) at commit 98915c442d.
//
// Rust libsignal rejects these payloads in BackupReader::new_encrypted_compressed
// before attempting decryption — the MAC check happens first. Go pkg/backup
// FrameDecryptor follows the same order: HMAC verify → decrypt → decompress.
// These tests confirm that DecryptFrames returns an error without panicking.
package interop

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/backup"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

// TestMessageBackup_InvalidHMACLastByte verifies that flipping the final byte
// of the HMAC tag causes DecryptFrames to return HMACMismatchError.
//
// Mirrors the rejection that Rust BackupReader produces for a tampered
// MAC tag (test_cases.rs:287, is_valid_encrypted_proto — negated).
func TestMessageBackup_InvalidHMACLastByte(t *testing.T) {
	assertHMACRejected(t, "messagebackup/cases/invalid_hmac/corrupted_last_byte.json")
}

// TestMessageBackup_InvalidHMACFirstByte verifies that flipping the first byte
// of the HMAC block causes DecryptFrames to return HMACMismatchError.
func TestMessageBackup_InvalidHMACFirstByte(t *testing.T) {
	assertHMACRejected(t, "messagebackup/cases/invalid_hmac/corrupted_first_hmac_byte.json")
}

// assertHMACRejected is shared logic for the two invalid-HMAC cases.
func assertHMACRejected(t *testing.T, fixturePath string) {
	t.Helper()
	raw := loader.MustRead(fixturePath)
	var fix mbCaseFixture
	if err := json.Unmarshal(raw, &fix); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if fix.ExpectedOutcome != "rejected_hmac" {
		t.Fatalf("fixture expected_outcome = %q; want rejected_hmac", fix.ExpectedOutcome)
	}

	input, err := hex.DecodeString(fix.InputBytesHex)
	if err != nil {
		t.Fatalf("decode input_bytes_hex: %v", err)
	}

	key := mbKeyFromFixture(t, &fix)
	defer key.Zeroize()

	dec := backup.NewFrameDecryptor(key)
	_, decErr := dec.DecryptFrames(bytes.NewReader(input))
	if decErr == nil {
		t.Fatalf("DecryptFrames succeeded on corrupted HMAC; want error (source: %s)", fix.Source)
	}

	var hmacErr *backup.HMACMismatchError
	if !errors.As(decErr, &hmacErr) {
		t.Fatalf("DecryptFrames returned %T (%v); want *backup.HMACMismatchError", decErr, decErr)
	}
	t.Logf("Correctly rejected with HMACMismatchError (source: %s)", fix.Source)
}
