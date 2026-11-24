// Message-backup HMAC-SHA256 against the Rust mac_read.rs vector, with a pinned digest.
package interop

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

// frameHMACFixture mirrors the JSON schema for messagebackup/frame_hmac.json.
type frameHMACFixture struct {
	Source  string         `json:"source"`
	RustRev string         `json:"rust_rev"`
	Purpose string         `json:"purpose"`
	Vectors []frameHMACVec `json:"vectors"`
}

type frameHMACVec struct {
	Name   string       `json:"name"`
	Inputs frameHMACIn  `json:"inputs"`
	Expect frameHMACOut `json:"expected"`
}

type frameHMACIn struct {
	HMACKeyHex   string `json:"hmac_key_hex"`
	PlaintextHex string `json:"plaintext_hex"`
}

type frameHMACOut struct {
	MACHex string `json:"mac_hex"`
}

// TestMessageBackupFrameHMAC asserts that Go's stdlib HMAC-SHA256 (which is
// what pkg/backup uses verbatim) produces the expected MAC for every vector
// extracted from the Rust mac_read module tests.
func TestMessageBackupFrameHMAC(t *testing.T) {
	raw := loader.MustRead("messagebackup/frame_hmac.json")

	var fix frameHMACFixture
	if err := json.Unmarshal(raw, &fix); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if len(fix.Vectors) == 0 {
		t.Fatal("fixture contains no vectors")
	}

	for _, vec := range fix.Vectors {
		vec := vec
		t.Run(vec.Name, func(t *testing.T) {
			key, err := hex.DecodeString(vec.Inputs.HMACKeyHex)
			if err != nil {
				t.Fatalf("decode hmac_key_hex: %v", err)
			}
			plaintext, err := hex.DecodeString(vec.Inputs.PlaintextHex)
			if err != nil {
				t.Fatalf("decode plaintext_hex: %v", err)
			}
			wantMAC, err := hex.DecodeString(vec.Expect.MACHex)
			if err != nil {
				t.Fatalf("decode mac_hex: %v", err)
			}

			// This is the exact computation pkg/backup.FrameEncryptor and
			// pkg/backup.VerifyHMAC perform; see pkg/backup/frame.go.
			mac := hmac.New(sha256.New, key)
			mac.Write(plaintext)
			gotMAC := mac.Sum(nil)

			if !bytes.Equal(gotMAC, wantMAC) {
				t.Fatalf("HMAC mismatch:\n  got  %x\n  want %x", gotMAC, wantMAC)
			}
		})
	}
}
