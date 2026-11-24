// Conformance: GroupSecretParams blob encryption (AES-256-GCM-SIV) against Rust test_blob_encryption, byte for byte and round trip.

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

// TestZkgroup_GroupBlobEncryption_KAT checks EncryptBlob matches Rust test_blob_encryption.
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
