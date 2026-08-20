//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 1 test in this file exercises AES-256-GCM under a vector-supplied nonce.
// FIPS 140-3 does not approve that, but the Rust-emitted fixture pinned by
// /RUST_REV fixes the nonce, so the fips140only build tag drops this file
// from the FIPS gate. `make test` and `make coverage` still run it.

// Conformance test: AES-256-GCM smoke vs Rust signal_crypto::Aes256GcmEncryption.
//
// Mirrors rust/crypto/tests/aes_gcm.rs::aes_gcm_smoke_test (NIST GCM
// "Test Case 4" derivative). The fixture pins every hex literal; the
// drift detector greps the upstream source.
//
// The test drives pkg/cipher.AESGCMEncrypt / AESGCMDecrypt.

package interop

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/cipher"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

type aesGcmSmokeFixture struct {
	KeyHex           string `json:"key_hex"`
	NonceHex         string `json:"nonce_hex"`
	ADHex            string `json:"ad_hex"`
	PlaintextHex     string `json:"plaintext_hex"`
	ExpectedCTAndTag string `json:"expected_ct_with_tag_hex"`
}

// TestAESGCM_Smoke_KAT asserts that Go's stdlib AES-GCM Seal output (which
// returns ciphertext || tag concatenated, matching Rust's Aes256GcmEncryption
// + compute_tag and append) is byte-identical to the Rust expected value
// from aes_gcm_smoke_test.
func TestAESGCM_Smoke_KAT(t *testing.T) {
	raw := loader.MustRead("crypto/aes_gcm_smoke.json")
	var fx aesGcmSmokeFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	key, err := hex.DecodeString(fx.KeyHex)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	nonce, err := hex.DecodeString(fx.NonceHex)
	if err != nil {
		t.Fatalf("decode nonce: %v", err)
	}
	ad, err := hex.DecodeString(fx.ADHex)
	if err != nil {
		t.Fatalf("decode ad: %v", err)
	}
	pt, err := hex.DecodeString(fx.PlaintextHex)
	if err != nil {
		t.Fatalf("decode pt: %v", err)
	}
	want, err := hex.DecodeString(fx.ExpectedCTAndTag)
	if err != nil {
		t.Fatalf("decode expected: %v", err)
	}

	got, err := cipher.AESGCMEncrypt(key, nonce, pt, ad)
	if err != nil {
		t.Fatalf("AESGCMEncrypt: %v", err)
	}
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("AES-GCM smoke mismatch:\n  got  %s\n  want %s", hex.EncodeToString(got), hex.EncodeToString(want))
	}

	// Round-trip: decrypt and verify pt.
	pt2, err := cipher.AESGCMDecrypt(key, nonce, got, ad)
	if err != nil {
		t.Fatalf("AESGCMDecrypt: %v", err)
	}
	if hex.EncodeToString(pt2) != fx.PlaintextHex {
		t.Fatalf("AESGCMDecrypt round-trip mismatch:\n  got  %s\n  want %s", hex.EncodeToString(pt2), fx.PlaintextHex)
	}
}
