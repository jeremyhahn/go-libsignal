// Interop test for zkgroup ProfileKeyEncryptionDomain parity.
//
// Source: rust/zkgroup/src/crypto/profile_key_encryption.rs:119-215
// at Rust libsignal commit 98915c442d.
//
// Rust's test_profile_key_encryption() derives a KeyPair from
// TEST_ARRAY_32_1 via Sho(HMAC-SHA256, b"Test_Profile_Key_Encryption"),
// encrypts (profile_key=TEST_ARRAY_32_1, uid=TEST_ARRAY_16_1), and pins
// the 64-byte ciphertext bytes.
//
// Go equivalent: zkcredential.DeriveKeyPair + kp.Encrypt(ProfileKeyStruct).
//
// NOTE: Profile-key decrypt (ProfileKeyEncryptionDomain::decrypt) is
// internal to pkg/zkgroup and is not exported at the interop boundary; only
// the higher-level GroupSecretParams.{Encrypt,Decrypt}ProfileKey are public.
// This test verifies:
//  1. DeriveKeyPair + Encrypt produce a 64-byte ciphertext (correct shape).
//  2. EncodeCiphertext → DecodeCiphertext is a lossless round-trip.
//  3. The encoded bytes match the Rust pinned value (logged; not a hard failure
//     because SHO ratcheting divergence would produce a different but equally
//     valid ciphertext).
package interop

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

type zkPKEFixture struct {
	Source  string     `json:"source"`
	RustRev string     `json:"rust_rev"`
	Purpose string     `json:"purpose"`
	Vectors []zkPKEVec `json:"vectors"`
}

type zkPKEVec struct {
	Name   string      `json:"name"`
	Inputs zkPKEInputs `json:"inputs"`
	Expect zkPKEExpect `json:"expected"`
}

type zkPKEInputs struct {
	ShoLabel      string `json:"sho_label"`
	ShoKeyHex     string `json:"sho_key_hex"`
	ProfileKeyHex string `json:"profile_key_hex"`
	UIDHex        string `json:"uid_hex"`
}

type zkPKEExpect struct {
	CiphertextHex string `json:"ciphertext_hex"`
}

// TestZKGroup_CryptoProfileKeyEncryption verifies that
// zkcredential.DeriveKeyPair + kp.Encrypt(ProfileKeyStruct) produces a
// structurally valid 64-byte ciphertext and that EncodeCiphertext →
// DecodeCiphertext is lossless.
//
// Mirrors rust/zkgroup/src/crypto/profile_key_encryption.rs:test_profile_key_encryption.
func TestZKGroup_CryptoProfileKeyEncryption(t *testing.T) {
	raw := loader.MustRead("zkgroup/crypto/profile_key_encryption.json")
	var fix zkPKEFixture
	if err := json.Unmarshal(raw, &fix); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if len(fix.Vectors) == 0 {
		t.Fatal("fixture has no vectors")
	}

	for _, vec := range fix.Vectors {
		vec := vec
		t.Run(vec.Name, func(t *testing.T) {
			sho := zkcredential.NewShoHmacSha256Ext(vec.Inputs.ShoLabel)
			if vec.Inputs.ShoKeyHex != "" {
				shoKey, err := hex.DecodeString(vec.Inputs.ShoKeyHex)
				if err != nil {
					t.Fatalf("decode sho_key_hex: %v", err)
				}
				sho.AbsorbAndRatchet(shoKey)
			}

			domain := zkgroup.ProfileKeyEncryptionDomain{}
			kp, err := zkcredential.DeriveKeyPair(sho, domain)
			if err != nil {
				t.Fatalf("DeriveKeyPair: %v", err)
			}

			profileKeyBytes, err := hex.DecodeString(vec.Inputs.ProfileKeyHex)
			if err != nil {
				t.Fatalf("decode profile_key_hex: %v", err)
			}
			uidBytes, err := hex.DecodeString(vec.Inputs.UIDHex)
			if err != nil {
				t.Fatalf("decode uid_hex: %v", err)
			}

			var pkArr [32]byte
			var uidArr [16]byte
			copy(pkArr[:], profileKeyBytes)
			copy(uidArr[:], uidBytes)

			profileKeyStruct := zkgroup.NewProfileKeyStruct(pkArr, uidArr)
			ct := kp.Encrypt(profileKeyStruct)

			// Must produce exactly 64 bytes.
			gotBytes := zkcredential.EncodeCiphertext(ct)
			if len(gotBytes) != 64 {
				t.Fatalf("EncodeCiphertext length = %d; want 64", len(gotBytes))
			}

			// Encode → Decode must be lossless.
			ct2, err := zkcredential.DecodeCiphertext(gotBytes)
			if err != nil {
				t.Fatalf("DecodeCiphertext: %v", err)
			}
			reEncoded := zkcredential.EncodeCiphertext(ct2)
			if !bytes.Equal(gotBytes, reEncoded) {
				t.Fatalf("EncodeCiphertext round-trip mismatch")
			}

			// Byte-level parity vs Rust pinned ciphertext.
			wantBytes, parseErr := hex.DecodeString(vec.Expect.CiphertextHex)
			if parseErr != nil {
				t.Fatalf("decode ciphertext_hex: %v", parseErr)
			}
			if !bytes.Equal(gotBytes, wantBytes) {
				t.Fatalf("ciphertext bytes differ from Rust pinned value:\n  got  %x\n  want %x", gotBytes, wantBytes)
			}
		})
	}
}
