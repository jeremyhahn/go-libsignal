// Conformance test: zkgroup profile-key encryption byte-identical to Rust.
//
// Mirrors rust/zkgroup/src/crypto/profile_key_encryption.rs::tests::test_profile_key_encryption:
//
//   1. let mut sho = Sho::new(b"Test_Profile_Key_Encryption", &TEST_ARRAY_32_1);
//   2. let key_pair = KeyPair::derive_from(sho.as_mut());
//   3. let profile_key = ProfileKeyStruct::new(TEST_ARRAY_32_1, TEST_ARRAY_16_1);
//   4. let ciphertext = key_pair.encrypt(&profile_key);
//   5. assert bincode::serialize(&ciphertext) == 64-byte expected hex.

package interop

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

type profileKeyEncryptionFixture struct {
	ShoLabel              string `json:"sho_label"`
	ExpectedCiphertextHex string `json:"expected_ciphertext_hex"`
}

// TestZkgroup_ProfileKeyEncryption_KAT proves Go's profile-key encryption
// keypair encrypts a ProfileKeyStruct(TEST_ARRAY_32_1, TEST_ARRAY_16_1)
// to a 64-byte ciphertext byte-identical to Rust libsignal.
func TestZkgroup_ProfileKeyEncryption_KAT(t *testing.T) {
	raw := loader.MustRead("zkgroup/profile_key_encryption_known_answers.json")
	var fx profileKeyEncryptionFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	want, err := hex.DecodeString(strings.ReplaceAll(fx.ExpectedCiphertextHex, " ", ""))
	if err != nil {
		t.Fatalf("decode expected ciphertext: %v", err)
	}
	if len(want) != 64 {
		t.Fatalf("expected 64-byte ciphertext, got %d bytes", len(want))
	}

	// TEST_ARRAY_32_1 = 100..131 → fillRange(100).
	// TEST_ARRAY_16_1 = 100..115 → fillRange16(100).
	masterKey := fillRange(100)
	profileKeyBytes := fillRange(100)
	uidBytes := fillRange16(100)

	// Step 1: SHO("Test_Profile_Key_Encryption", TEST_ARRAY_32_1).
	sho := zkcredential.NewShoHmacSha256Ext(fx.ShoLabel)
	sho.AbsorbAndRatchet(masterKey[:])

	// Step 2: derive profile-key encryption keypair.
	pkDomain := zkgroup.ProfileKeyEncryptionDomain{}
	kp, err := zkcredential.DeriveKeyPair(sho, pkDomain)
	if err != nil {
		t.Fatalf("DeriveKeyPair(ProfileKeyEncryptionDomain): %v", err)
	}

	// Step 3: build ProfileKeyStruct.
	pk := zkgroup.NewProfileKeyStruct(profileKeyBytes, uidBytes)

	// Step 4: encrypt and serialize.
	ct := kp.Encrypt(pk)
	got := zkcredential.EncodeCiphertext(ct)

	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("ProfileKey ciphertext mismatch:\n  got  %s\n  want %s",
			hex.EncodeToString(got), hex.EncodeToString(want))
	}

	// Round-trip via DecodeCiphertext.
	parsed, err := zkcredential.DecodeCiphertext(got)
	if err != nil {
		t.Fatalf("DecodeCiphertext: %v", err)
	}
	if !ct.Equal(parsed) {
		t.Fatal("DecodeCiphertext produced different points")
	}
}
