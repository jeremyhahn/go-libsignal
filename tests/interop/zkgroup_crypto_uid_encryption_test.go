// Interop test for zkgroup UidEncryptionDomain parity.
//
// Source: rust/zkgroup/src/crypto/uid_encryption.rs:112-181
// at Rust libsignal commit 98915c442d.
//
// Rust's test_uid_encryption() derives a KeyPair from TEST_ARRAY_32 via
// Sho(HMAC-SHA256, b"Test_Uid_Encryption"), encrypts an ACI built from
// TEST_ARRAY_16, and pins the 64-byte ciphertext.
//
// test_pni_encryption() is property-based only (no pinned ciphertext).
//
// Go equivalent: zkcredential.DeriveKeyPair + kp.Encrypt(UIDStruct).
// Byte-identity requires matching SHO ratcheting; divergence is logged only.
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

type zkUIDEncFixture struct {
	Source  string        `json:"source"`
	RustRev string        `json:"rust_rev"`
	Purpose string        `json:"purpose"`
	Vectors []zkUIDEncVec `json:"vectors"`
}

type zkUIDEncVec struct {
	Name   string         `json:"name"`
	Inputs zkUIDEncInputs `json:"inputs"`
	Expect zkUIDEncExpect `json:"expected"`
}

type zkUIDEncInputs struct {
	ShoLabel   string `json:"sho_label"`
	ShoKeyHex  string `json:"sho_key_hex"`
	ACIUUIDHex string `json:"aci_uuid_hex"`
	PNIUUIDHex string `json:"pni_uuid_hex"`
}

type zkUIDEncExpect struct {
	CiphertextHex string `json:"ciphertext_hex"`
	ServiceIDType string `json:"service_id_type"`
	VerifyResult  string `json:"verify_result"`
}

// TestZKGroup_CryptoUIDEncryption drives zkcredential.DeriveKeyPair +
// kp.Encrypt(UIDStruct) against the UIDEncryptionDomain and asserts
// EncodeCiphertext produces a 64-byte value with a lossless round-trip.
//
// Mirrors rust/zkgroup/src/crypto/uid_encryption.rs:test_uid_encryption.
func TestZKGroup_CryptoUIDEncryption(t *testing.T) {
	raw := loader.MustRead("zkgroup/crypto/uid_encryption.json")
	var fix zkUIDEncFixture
	if err := json.Unmarshal(raw, &fix); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if len(fix.Vectors) == 0 {
		t.Fatal("fixture has no vectors")
	}

	for _, vec := range fix.Vectors {
		vec := vec
		t.Run(vec.Name, func(t *testing.T) {
			// Determine UUID source and service-ID type from the fixture.
			// ACI vectors have aci_uuid_hex; PNI vectors have pni_uuid_hex.
			var uidHex string
			var isPNI bool
			switch {
			case vec.Inputs.ACIUUIDHex != "":
				uidHex = vec.Inputs.ACIUUIDHex
			case vec.Inputs.PNIUUIDHex != "":
				uidHex = vec.Inputs.PNIUUIDHex
				isPNI = true
			default:
				t.Fatal("fixture vector has neither aci_uuid_hex nor pni_uuid_hex")
			}

			sho := zkcredential.NewShoHmacSha256Ext(vec.Inputs.ShoLabel)
			if vec.Inputs.ShoKeyHex != "" {
				shoKey, err := hex.DecodeString(vec.Inputs.ShoKeyHex)
				if err != nil {
					t.Fatalf("decode sho_key_hex: %v", err)
				}
				sho.AbsorbAndRatchet(shoKey)
			}

			domain := zkgroup.UIDEncryptionDomain{}
			kp, err := zkcredential.DeriveKeyPair(sho, domain)
			if err != nil {
				t.Fatalf("DeriveKeyPair: %v", err)
			}

			uidBytes, err := hex.DecodeString(uidHex)
			if err != nil {
				t.Fatalf("decode uuid hex: %v", err)
			}

			var uuidArr [16]byte
			copy(uuidArr[:], uidBytes)
			var sid zkgroup.ServiceID
			if isPNI {
				sid = zkgroup.NewPNI(uuidArr)
			} else {
				sid = zkgroup.NewACI(uuidArr)
			}
			uid := zkgroup.NewUIDStructFromServiceID(sid)

			ct := kp.Encrypt(uid)
			gotBytes := zkcredential.EncodeCiphertext(ct)

			// Must be 64 bytes.
			if len(gotBytes) != 64 {
				t.Fatalf("EncodeCiphertext length = %d; want 64", len(gotBytes))
			}

			// Encode → Decode round-trip.
			ct2, decErr := zkcredential.DecodeCiphertext(gotBytes)
			if decErr != nil {
				t.Fatalf("DecodeCiphertext: %v", decErr)
			}
			reEncoded := zkcredential.EncodeCiphertext(ct2)
			if !bytes.Equal(gotBytes, reEncoded) {
				t.Fatalf("EncodeCiphertext round-trip mismatch")
			}

			// Byte-level parity vs Rust pinned ciphertext (when fixture pins one).
			if vec.Expect.CiphertextHex != "" {
				wantBytes, parseErr := hex.DecodeString(vec.Expect.CiphertextHex)
				if parseErr != nil {
					t.Fatalf("decode ciphertext_hex: %v", parseErr)
				}
				if !bytes.Equal(gotBytes, wantBytes) {
					t.Fatalf("ciphertext bytes differ from Rust pinned:\n  got  %x\n  want %x", gotBytes, wantBytes)
				}
			}
		})
	}
}
