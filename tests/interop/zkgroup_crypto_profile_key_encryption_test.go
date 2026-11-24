// Profile key encryption against Rust test_profile_key_encryption: a 64-byte ciphertext that round-trips through Encode and DecodeCiphertext; a byte mismatch with Rust is logged, not failed.
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

// TestZKGroup_CryptoProfileKeyEncryption checks DeriveKeyPair + Encrypt gives a 64-byte ciphertext that round-trips.
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
