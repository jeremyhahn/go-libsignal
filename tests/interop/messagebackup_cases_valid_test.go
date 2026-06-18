// Interop tests for valid message-backup encrypted frame cases.
//
// Source: rust/message-backup/tests/res/test-cases/valid-encrypted/*.binproto.encrypted
// at Rust libsignal commit 98915c442d.
//
// The Rust test encrypted_proto_matches_source (test_cases.rs:287) verifies
// that BackupReader::new_encrypted_compressed succeeds for each of these files
// using the standard test key material:
//
//	AEP  = "mmm...m" (64 chars)
//	ACI  = [0x11; 16]
//	FST  = [0xAB; 32] (forward secrecy token, omitted for legacy cases)
//
// Here we drive pkg/backup.FrameDecryptor against the legacy CBC+HMAC format
// (legacy-account.binproto.encrypted). The decoder must accept the bucketed
// zero-padding that Rust's pad_gzipped_bucketed appends after the gzip stream
// (see pkg/backup/frame.go for the gzip Multistream(false) hand-off).
// The newer SBACKUP\x01 format is documented but not yet implemented in Go;
// that fixture is loaded and its magic header is asserted to distinguish the
// two formats.
package interop

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/backup"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

// mbCaseFixture mirrors the JSON schema for messagebackup/cases/*/*.json.
type mbCaseFixture struct {
	Source          string `json:"source"`
	RustRev         string `json:"rust_rev"`
	Purpose         string `json:"purpose"`
	InputBytesHex   string `json:"input_bytes_hex"`
	ExpectedOutcome string `json:"expected_outcome"`
	HMACKeyHex      string `json:"hmac_key_hex"`
	AESKeyHex       string `json:"aes_key_hex"`
}

// mbKeyFromFixture builds a pkg/backup.MessageBackupKey from hex fields in a
// fixture. The caller is responsible for calling key.Zeroize().
func mbKeyFromFixture(t *testing.T, fix *mbCaseFixture) *backup.MessageBackupKey {
	t.Helper()
	hmacBytes, err := hex.DecodeString(fix.HMACKeyHex)
	if err != nil {
		t.Fatalf("decode hmac_key_hex: %v", err)
	}
	aesBytes, err := hex.DecodeString(fix.AESKeyHex)
	if err != nil {
		t.Fatalf("decode aes_key_hex: %v", err)
	}
	// secret.New consumes the slice (move semantics); copy first.
	hmacCopy := make([]byte, len(hmacBytes))
	copy(hmacCopy, hmacBytes)
	aesCopy := make([]byte, len(aesBytes))
	copy(aesCopy, aesBytes)

	hmacSec, err := secret.New(hmacCopy)
	if err != nil {
		t.Fatalf("secret.New(hmac): %v", err)
	}
	aesSec, err := secret.New(aesCopy)
	if err != nil {
		hmacSec.Destroy()
		t.Fatalf("secret.New(aes): %v", err)
	}
	return &backup.MessageBackupKey{
		HMACKey: hmacSec,
		AESKey:  aesSec,
	}
}

// TestMessageBackup_ValidLegacyEncrypted verifies that the Rust-generated
// legacy CBC+HMAC backup (legacy-account.binproto.encrypted) passes HMAC
// verification in Go.
//
// Mirrors Rust's is_valid_encrypted_proto for legacy-account.binproto.encrypted
// in rust/message-backup/tests/test_cases.rs:287.
//
// NOTE: The Rust format includes bucketed zero-padding (PadGzippedBucketed)
// inside the AES-CBC region after the gzip stream. Go's FrameDecryptor
// uses a simpler format without this padding. The HMAC therefore passes,
// but full frame decoding fails at the gzip layer due to the trailing zeros
// being interpreted as a second (invalid) gzip stream. This divergence is
// documented: Go generates non-padded backups and reads non-padded backups.
func TestMessageBackup_ValidLegacyEncrypted(t *testing.T) {
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

	// HMAC verification must succeed.
	if err := backup.VerifyHMAC(key, bytes.NewReader(input)); err != nil {
		t.Fatalf("VerifyHMAC failed for valid Rust-generated legacy backup: %v", err)
	}

	// Full decryption must succeed end-to-end against the Rust padded format.
	dec := backup.NewFrameDecryptor(key)
	frames, err := dec.DecryptFrames(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("DecryptFrames failed on Rust-padded backup: %v", err)
	}
	if len(frames) == 0 {
		t.Fatalf("DecryptFrames returned 0 frames; expected at least 1 (BackupInfo)")
	}
	t.Logf("Decoded %d frames from Rust legacy-format backup (source: %s)", len(frames), fix.Source)
}

// TestMessageBackup_ValidNewAccountFormat documents the newer SBACKUP\x01
// backup format. The Go pkg/backup FrameDecryptor implements the legacy
// CBC+HMAC format only; this test asserts the magic header is present so
// any future FrameDecryptor extension can be verified.
//
// Mirrors Rust's is_valid_encrypted_proto for new-account.binproto.encrypted
// in rust/message-backup/tests/test_cases.rs:287.
func TestMessageBackup_ValidNewAccountFormat(t *testing.T) {
	raw := loader.MustRead("messagebackup/cases/valid/new_account_encrypted.json")
	var fix mbCaseFixture
	if err := json.Unmarshal(raw, &fix); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	input, err := hex.DecodeString(fix.InputBytesHex)
	if err != nil {
		t.Fatalf("decode input_bytes_hex: %v", err)
	}

	// The newer format starts with the magic header "SBACKUP\x01".
	sbackupBytes := []byte{0x53, 0x42, 0x41, 0x43, 0x4b, 0x55, 0x50, 0x01}
	if !bytes.HasPrefix(input, sbackupBytes) {
		t.Fatalf("new-account fixture does not start with SBACKUP\\x01 magic (got %x)", input[:8])
	}
	t.Logf("Confirmed SBACKUP\\x01 magic header; newer format not yet in Go FrameDecryptor (source: %s)", fix.Source)
}
