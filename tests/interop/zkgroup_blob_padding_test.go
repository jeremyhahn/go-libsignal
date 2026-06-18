// Conformance test: zkgroup EncryptBlobWithPadding byte-identical to Rust.
//
// Mirrors rust/zkgroup/src/api/groups/group_params.rs::test_encrypt_with_padding:
//   - GroupSecretParams::generate with all-zero randomness (32 bytes).
//   - EncryptBlobWithPadding using all-zero randomness, plaintext "secret
//     team", padding_len = 0 then 8.
//   - Assert ciphertext byte-matches the Rust expected hex for both cases.
//   - Round-trip via DecryptBlobWithPadding and confirm the original
//     plaintext is recovered (padding_len bytes stripped).

package interop

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

type paddingVector struct {
	PaddingLen         int    `json:"padding_len"`
	ExpectedCiphertext string `json:"expected_ciphertext_hex"`
}

type paddingFixture struct {
	ParamsSeedHex string          `json:"params_seed_hex"`
	RandomnessHex string          `json:"randomness_hex"`
	Plaintext     string          `json:"plaintext"`
	Vectors       []paddingVector `json:"vectors"`
}

// TestZkgroup_EncryptBlobWithPadding_KAT proves Go's
// GroupSecretParams.EncryptBlobWithPadding produces byte-identical output
// to Rust libsignal for the canonical "secret team" inputs at two
// padding lengths.
func TestZkgroup_EncryptBlobWithPadding_KAT(t *testing.T) {
	raw := loader.MustRead("zkgroup/blob_padding_known_answers.json")
	var fx paddingFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	paramsSeedBytes, err := hex.DecodeString(fx.ParamsSeedHex)
	if err != nil {
		t.Fatalf("decode params seed: %v", err)
	}
	if len(paramsSeedBytes) != 32 {
		t.Fatalf("params seed must be 32 bytes; got %d", len(paramsSeedBytes))
	}
	var paramsSeed [32]byte
	copy(paramsSeed[:], paramsSeedBytes)

	randBytes, err := hex.DecodeString(fx.RandomnessHex)
	if err != nil {
		t.Fatalf("decode randomness: %v", err)
	}
	if len(randBytes) != 32 {
		t.Fatalf("randomness must be 32 bytes; got %d", len(randBytes))
	}
	var randomness [32]byte
	copy(randomness[:], randBytes)

	// Rust calls GroupSecretParams::generate with [0u8; RANDOMNESS_LEN]; Go
	// has DeriveGroupSecretParamsFromRandomness or analogous. Match the
	// Rust path: the params come from the SHO transform of the generate
	// randomness, not directly from a master key.
	params, err := zkgroup.GenerateGroupSecretParams(paramsSeed)
	if err != nil {
		t.Fatalf("GenerateGroupSecretParams: %v", err)
	}

	plaintext := []byte(fx.Plaintext)

	for _, v := range fx.Vectors {
		v := v
		want, err := hex.DecodeString(v.ExpectedCiphertext)
		if err != nil {
			t.Fatalf("decode expected hex (padding=%d): %v", v.PaddingLen, err)
		}

		got, err := params.EncryptBlobWithPadding(randomness, plaintext, v.PaddingLen)
		if err != nil {
			t.Fatalf("EncryptBlobWithPadding(padding=%d): %v", v.PaddingLen, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("padding=%d ciphertext mismatch:\n  got  %s\n  want %s",
				v.PaddingLen, hex.EncodeToString(got), hex.EncodeToString(want))
		}

		gotPT, err := params.DecryptBlobWithPadding(got)
		if err != nil {
			t.Fatalf("DecryptBlobWithPadding(padding=%d): %v", v.PaddingLen, err)
		}
		if !bytes.Equal(gotPT, plaintext) {
			t.Fatalf("padding=%d round-trip plaintext mismatch:\n  got  %q\n  want %q",
				v.PaddingLen, gotPT, plaintext)
		}
	}
}
