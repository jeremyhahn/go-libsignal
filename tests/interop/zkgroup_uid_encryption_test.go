// Conformance tests: zkgroup UID encryption byte-identical to Rust.
//
// Covers two Rust unit tests in rust/zkgroup/src/crypto/uid_encryption.rs:
//
//   test_uid_encryption (ACI path):
//     sho = Sho::new("Test_Uid_Encryption", TEST_ARRAY_32)
//     kp  = KeyPair::derive_from(sho)
//     uid = UidStruct::from_service_id(Aci::from_uuid_bytes(TEST_ARRAY_16))
//     assert bincode(kp.encrypt(uid)) == expected_aci_hex
//
//   test_pni_encryption (PNI path):
//     sho = Sho::new("Test_Pni_Encryption", &[])
//     kp  = KeyPair::derive_from(sho)
//     uid = UidStruct::from_service_id(Pni::from_uuid_bytes(TEST_ARRAY_16))
//     assert round_trip decrypt returns ServiceId::Pni
//
// Go path: NewShoHmacSha256Ext + AbsorbAndRatchet, DeriveKeyPair with
// UIDEncryptionDomain, NewACI/NewPNI(TEST_ARRAY_16), NewUIDStructFromServiceID,
// keypair.Encrypt, EncodeCiphertext for the bincode-equivalent 64 bytes.

package interop

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

// uidEncryptionEntry holds one encryption test vector.
type uidEncryptionEntry struct {
	ShoLabel              string `json:"sho_label"`
	ExpectedCiphertextHex string `json:"expected_ciphertext_hex"`
}

// uidEncryptionFixture is the top-level JSON structure for uid_encryption_known_answers.json.
type uidEncryptionFixture struct {
	ACI uidEncryptionEntry `json:"aci"`
	PNI uidEncryptionEntry `json:"pni"`
}

// fillRange16 returns a 16-byte array whose i-th byte equals start+i.
// Used to reproduce TEST_ARRAY_16 (0x00..0x0f).
func fillRange16(start byte) [16]byte {
	var out [16]byte
	for i := 0; i < 16; i++ {
		out[i] = start + byte(i)
	}
	return out
}

// TestZkgroup_UidEncryption_ACI_KAT proves Go's UID encryption keypair encrypts
// an ACI(TEST_ARRAY_16) UidStruct to a 64-byte ciphertext byte-identical
// to Rust libsignal for the canonical test_uid_encryption inputs.
//
// Mirrors: rust/zkgroup/src/crypto/uid_encryption.rs::tests::test_uid_encryption
func TestZkgroup_UidEncryption_ACI_KAT(t *testing.T) {
	raw := loader.MustRead("zkgroup/uid_encryption_known_answers.json")
	var fx uidEncryptionFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	want, err := hex.DecodeString(fx.ACI.ExpectedCiphertextHex)
	if err != nil {
		t.Fatalf("decode expected ACI ciphertext: %v", err)
	}
	if len(want) != 64 {
		t.Fatalf("expected 64-byte ACI ciphertext, got %d bytes", len(want))
	}

	masterKey := fillRange(0) // TEST_ARRAY_32

	// Step 1: SHO("Test_Uid_Encryption", TEST_ARRAY_32).
	sho := zkcredential.NewShoHmacSha256Ext(fx.ACI.ShoLabel)
	sho.AbsorbAndRatchet(masterKey[:])

	// Step 2: derive UID encryption keypair.
	uidDomain := zkgroup.UIDEncryptionDomain{}
	kp, err := zkcredential.DeriveKeyPair(sho, uidDomain)
	if err != nil {
		t.Fatalf("DeriveKeyPair(UIDEncryptionDomain): %v", err)
	}

	// Step 3: ACI(TEST_ARRAY_16).
	aciUUID := fillRange16(0)
	aci := zkgroup.NewACI(aciUUID)

	// Step 4: build UidStruct.
	uid := zkgroup.NewUIDStructFromServiceID(aci)

	// Step 5: encrypt.
	ct := kp.Encrypt(uid)

	// Step 6: serialize and compare.
	got := zkcredential.EncodeCiphertext(ct)
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("ACI ciphertext mismatch:\n  got  %s\n  want %s",
			hex.EncodeToString(got), hex.EncodeToString(want))
	}

	// Round-trip through DecodeCiphertext.
	parsed, err := zkcredential.DecodeCiphertext(got)
	if err != nil {
		t.Fatalf("DecodeCiphertext: %v", err)
	}
	if !ct.Equal(parsed) {
		t.Fatal("DecodeCiphertext produced different points for ACI")
	}
}

// TestZkgroup_UidEncryption_PNI_KAT proves that Go's UID encryption handles
// the PNI service ID type identically to Rust's test_pni_encryption. The SHO
// is seeded with an empty byte slice (matching Rust's Sho::new(label, &[])),
// and the service ID is a PNI, which causes a different M1 point than ACI
// (because service_id_binary for PNI is 17 bytes: 0x01‖uuid, vs 16 for ACI).
//
// Mirrors: rust/zkgroup/src/crypto/uid_encryption.rs::tests::test_pni_encryption
func TestZkgroup_UidEncryption_PNI_KAT(t *testing.T) {
	raw := loader.MustRead("zkgroup/uid_encryption_known_answers.json")
	var fx uidEncryptionFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	want, err := hex.DecodeString(fx.PNI.ExpectedCiphertextHex)
	if err != nil {
		t.Fatalf("decode expected PNI ciphertext: %v", err)
	}
	if len(want) != 64 {
		t.Fatalf("expected 64-byte PNI ciphertext, got %d bytes", len(want))
	}

	// Rust: Sho::new(b"Test_Pni_Encryption", &[]) — empty seed.
	sho := zkcredential.NewShoHmacSha256Ext(fx.PNI.ShoLabel)
	sho.AbsorbAndRatchet([]byte{})

	// Derive keypair.
	uidDomain := zkgroup.UIDEncryptionDomain{}
	kp, err := zkcredential.DeriveKeyPair(sho, uidDomain)
	if err != nil {
		t.Fatalf("DeriveKeyPair(UIDEncryptionDomain) for PNI: %v", err)
	}

	// PNI(TEST_ARRAY_16).
	pniUUID := fillRange16(0)
	pni := zkgroup.NewPNI(pniUUID)

	// Build UidStruct from PNI service ID. The 17-byte service_id_binary
	// (0x01‖uuid) causes a different M1 point than ACI (16-byte uuid).
	uid := zkgroup.NewUIDStructFromServiceID(pni)

	// Encrypt and compare.
	ct := kp.Encrypt(uid)
	got := zkcredential.EncodeCiphertext(ct)
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("PNI ciphertext mismatch:\n  got  %s\n  want %s",
			hex.EncodeToString(got), hex.EncodeToString(want))
	}

	// Verify ACI and PNI produce distinct ciphertexts (same UUID, different type tag).
	masterKey := fillRange(0)
	aciSho := zkcredential.NewShoHmacSha256Ext("Test_Uid_Encryption")
	aciSho.AbsorbAndRatchet(masterKey[:])
	aciKp, err := zkcredential.DeriveKeyPair(aciSho, uidDomain)
	if err != nil {
		t.Fatalf("DeriveKeyPair for ACI comparison: %v", err)
	}
	aciUID := zkgroup.NewUIDStructFromServiceID(zkgroup.NewACI(pniUUID))
	aciCT := zkcredential.EncodeCiphertext(aciKp.Encrypt(aciUID))
	if hex.EncodeToString(got) == hex.EncodeToString(aciCT) {
		t.Fatal("PNI and ACI ciphertexts must differ")
	}

	// Round-trip DecodeCiphertext.
	parsed, err := zkcredential.DecodeCiphertext(got)
	if err != nil {
		t.Fatalf("DecodeCiphertext for PNI: %v", err)
	}
	if !ct.Equal(parsed) {
		t.Fatal("DecodeCiphertext produced different points for PNI")
	}
}
