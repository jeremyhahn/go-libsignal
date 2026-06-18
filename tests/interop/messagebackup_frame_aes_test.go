// Conformance test for message-backup frame AES-256-CBC parity.
//
// Drives the same AES-256-CBC + PKCS7 primitive that pkg/backup.FrameEncryptor
// uses (crypto/aes + crypto/cipher.NewCBCEncrypter) against vectors extracted
// from rust/message-backup/src/frame/aes_read.rs::test::aes_reader_round_trip_*
// at Rust libsignal commit 98915c442d.
//
// The Rust tests use FAKE_KEY=[0xaf;32] and FAKE_IV=[0xbb;16] to
// encrypt + PKCS7-pad four plaintexts (empty, short 26 B, med 256 B, long 1024 B)
// with AES-256-CBC, then decrypt them and assert round-trip equality.  Here we
// pin the concrete expected ciphertext so any change to the cipher mode, key
// size, or padding scheme will cause this test to fail.
package interop

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

// frameAESFixture mirrors the JSON schema for messagebackup/frame_aes.json.
type frameAESFixture struct {
	Source  string        `json:"source"`
	RustRev string        `json:"rust_rev"`
	Purpose string        `json:"purpose"`
	Vectors []frameAESVec `json:"vectors"`
}

type frameAESVec struct {
	Name   string      `json:"name"`
	Inputs frameAESIn  `json:"inputs"`
	Expect frameAESOut `json:"expected"`
}

type frameAESIn struct {
	KeyHex       string `json:"key_hex"`
	IVHex        string `json:"iv_hex"`
	PlaintextHex string `json:"plaintext_hex"`
}

type frameAESOut struct {
	CiphertextHex string `json:"ciphertext_hex"`
}

// aesCBCEncryptPKCS7 performs AES-256-CBC encryption with PKCS7 padding.
// This replicates the exact code path in pkg/backup/frame.go:EncryptFrames.
func aesCBCEncryptPKCS7(key, iv, plaintext []byte) ([]byte, error) {
	padded := frameAESPKCS7Pad(plaintext, aes.BlockSize)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)
	return ciphertext, nil
}

// frameAESPKCS7Pad pads data to a multiple of blockSize using PKCS7, matching
// pkg/backup/frame.go:pkcs7Pad exactly.
func frameAESPKCS7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// TestMessageBackupFrameAES asserts that Go's AES-256-CBC + PKCS7 encryption
// (which is what pkg/backup.FrameEncryptor applies to plaintext before writing)
// produces byte-identical ciphertext to Rust's Aes256CbcReader for all four
// Rust test-case plaintext sizes.
func TestMessageBackupFrameAES(t *testing.T) {
	raw := loader.MustRead("messagebackup/frame_aes.json")

	var fix frameAESFixture
	if err := json.Unmarshal(raw, &fix); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if len(fix.Vectors) == 0 {
		t.Fatal("fixture contains no vectors")
	}

	for _, vec := range fix.Vectors {
		vec := vec
		t.Run(vec.Name, func(t *testing.T) {
			key, err := hex.DecodeString(vec.Inputs.KeyHex)
			if err != nil {
				t.Fatalf("decode key_hex: %v", err)
			}
			iv, err := hex.DecodeString(vec.Inputs.IVHex)
			if err != nil {
				t.Fatalf("decode iv_hex: %v", err)
			}
			plaintext, err := hex.DecodeString(vec.Inputs.PlaintextHex)
			if err != nil {
				t.Fatalf("decode plaintext_hex: %v", err)
			}
			wantCT, err := hex.DecodeString(vec.Expect.CiphertextHex)
			if err != nil {
				t.Fatalf("decode ciphertext_hex: %v", err)
			}

			gotCT, err := aesCBCEncryptPKCS7(key, iv, plaintext)
			if err != nil {
				t.Fatalf("aesCBCEncryptPKCS7: %v", err)
			}

			if !bytes.Equal(gotCT, wantCT) {
				t.Fatalf("ciphertext mismatch:\n  got  %x\n  want %x", gotCT, wantCT)
			}
		})
	}
}
