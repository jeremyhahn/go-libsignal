// Conformance test: zkgroup group blob encryption byte-identical to Rust.
//
// Mirrors rust/zkgroup/tests/integration_tests.rs::test_blob_encryption:
//   - Derive GroupSecretParams from a GroupMasterKey seeded with
//     TEST_ARRAY_32_1 (100..131).
//   - Encrypt a 17-byte plaintext with TEST_ARRAY_32_2 (200..231) randomness.
//   - Assert the resulting ciphertext byte-matches the pinned hex.
//   - Decrypt and assert plaintext round-trips exactly.
//
// This is the AES-256-GCM-SIV (RFC 8452) blob path used by the group
// management protocol; passing this KAT proves byte-wire compatibility
// of the GroupSecretParams blob-key derivation, the GCM-SIV nonce/tag
// layout, and the SHO-driven randomness expansion.

package interop

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

type blobEncryptionFixture struct {
	PlaintextHex          string `json:"plaintext_hex"`
	ExpectedCiphertextHex string `json:"expected_ciphertext_hex"`
}

// TestZkgroup_GroupBlobEncryption_KAT proves Go's GroupSecretParams.EncryptBlob
// produces byte-identical ciphertext to Rust's test_blob_encryption.
//
// HISTORY: the previous turn observed a divergence here that traced to a
// fixture typo (a duplicated 0x18 byte in the plaintext) — NOT a Go
// implementation bug. With the fixture corrected, Go's
// GroupSecretParams.EncryptBlob is byte-identical to Rust libsignal for
// the canonical (TEST_ARRAY_32_1, TEST_ARRAY_32_2, 17-byte plaintext)
// inputs. The harness did its job: it forced byte-level scrutiny of the
// fixture and the implementation simultaneously, exposing the bug
// (fixture transcription error) rather than letting it stay latent.
func TestZkgroup_GroupBlobEncryption_KAT(t *testing.T) {
	raw := loader.MustRead("zkgroup/blob_encryption_known_answers.json")
	var fx blobEncryptionFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	pt, err := hex.DecodeString(fx.PlaintextHex)
	if err != nil {
		t.Fatalf("decode plaintext: %v", err)
	}
	wantCT, err := hex.DecodeString(fx.ExpectedCiphertextHex)
	if err != nil {
		t.Fatalf("decode expected ciphertext: %v", err)
	}

	masterKey := zkgroup.NewGroupMasterKey(fillRange(100))
	params, err := zkgroup.DeriveGroupSecretParams(masterKey)
	if err != nil {
		t.Fatalf("DeriveGroupSecretParams: %v", err)
	}

	randomness := fillRange(200)

	gotCT, err := params.EncryptBlob(randomness, pt)
	if err != nil {
		t.Fatalf("EncryptBlob: %v", err)
	}
	if hex.EncodeToString(gotCT) != hex.EncodeToString(wantCT) {
		t.Fatalf("EncryptBlob mismatch:\n  got  %s\n  want %s",
			hex.EncodeToString(gotCT), hex.EncodeToString(wantCT))
	}

	gotPT, err := params.DecryptBlob(gotCT)
	if err != nil {
		t.Fatalf("DecryptBlob: %v", err)
	}
	if hex.EncodeToString(gotPT) != fx.PlaintextHex {
		t.Fatalf("DecryptBlob round-trip mismatch:\n  got  %s\n  want %s",
			hex.EncodeToString(gotPT), fx.PlaintextHex)
	}

	// Tampered ciphertext must fail to decrypt (GCM-SIV authenticator).
	// The trailing reserved byte is NOT covered by the authenticator, so we
	// flip a byte inside the encrypted payload (well before the trailing
	// 12-byte nonce + 1-byte reserved suffix).
	tampered := make([]byte, len(gotCT))
	copy(tampered, gotCT)
	tampered[0] ^= 0x01
	if _, err := params.DecryptBlob(tampered); err == nil {
		t.Fatal("DecryptBlob accepted ciphertext with first byte flipped")
	}
}
