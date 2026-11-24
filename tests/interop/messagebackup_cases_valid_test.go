// Valid encrypted message-backup cases from rust/message-backup/tests/res/test-cases/valid-encrypted, with Rust's test keys (AEP "m"*64, ACI 0x11*16, FST 0xAB*32). FrameDecryptor reads the legacy CBC+HMAC case; for the SBACKUP\x01 format only the magic header is checked.
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

// TestMessageBackup_ValidLegacyEncrypted checks the Rust legacy backup passes HMAC verification; Go neither writes nor reads Rust's bucketed padding after the gzip stream.
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

// TestMessageBackup_ValidNewAccountFormat checks the new-account backup starts with SBACKUP\x01, a format FrameDecryptor does not read.
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
