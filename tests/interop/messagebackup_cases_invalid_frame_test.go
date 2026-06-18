// Interop tests for message-backup frames with invalid/malformed structure.
//
// Source: synthetic cases exercising pkg/backup.FrameDecryptor error paths
// at Rust libsignal commit 98915c442d. Rust BackupReader::new_encrypted_compressed
// rejects these before the HMAC phase; Go FrameDecryptor rejects at the
// ErrDataTooShort check.
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

// TestMessageBackup_InvalidFrameTooShort verifies that input shorter than
// the minimum (IV + HMAC = 48 bytes) is rejected with ErrDataTooShort.
//
// Rust BackupReader::new_encrypted_compressed returns an error when the
// backing stream is shorter than the required header/MAC sizes
// (test_cases.rs context: any encrypted input must carry at least the IV and
// HMAC before any frame data).
func TestMessageBackup_InvalidFrameTooShort(t *testing.T) {
	assertFrameRejected(t, "messagebackup/cases/invalid_frame/too_short.json")
}

// TestMessageBackup_InvalidFrameEmpty verifies that empty input is rejected.
//
// Equivalent to feeding an empty byte slice to Rust BackupReader::new_encrypted_compressed.
func TestMessageBackup_InvalidFrameEmpty(t *testing.T) {
	assertFrameRejected(t, "messagebackup/cases/invalid_frame/empty_input.json")
}

// assertFrameRejected drives DecryptFrames on invalid-frame fixtures and
// confirms an error is returned.
func assertFrameRejected(t *testing.T, fixturePath string) {
	t.Helper()
	raw := loader.MustRead(fixturePath)
	var fix mbCaseFixture
	if err := json.Unmarshal(raw, &fix); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if fix.ExpectedOutcome != "rejected_frame" {
		t.Fatalf("fixture expected_outcome = %q; want rejected_frame", fix.ExpectedOutcome)
	}

	var input []byte
	if fix.InputBytesHex != "" {
		var err error
		input, err = hex.DecodeString(fix.InputBytesHex)
		if err != nil {
			t.Fatalf("decode input_bytes_hex: %v", err)
		}
	}

	key := mbKeyFromFixture(t, &fix)
	defer key.Zeroize()

	dec := backup.NewFrameDecryptor(key)
	_, decErr := dec.DecryptFrames(bytes.NewReader(input))
	if decErr == nil {
		t.Fatalf("DecryptFrames succeeded on malformed frame; want error (source: %s)", fix.Source)
	}

	// Must be ErrDataTooShort for under-minimum inputs.
	var shortErr *backup.ErrDataTooShort
	if !errors.As(decErr, &shortErr) {
		t.Fatalf("DecryptFrames returned %T (%v); want *backup.ErrDataTooShort", decErr, decErr)
	}
	t.Logf("Correctly rejected with ErrDataTooShort (source: %s)", fix.Source)
}
