// Conformance test: AES-256-CTR-32-BE vs Rust signal_crypto::Aes256Ctr32.
//
// Mirrors the Rust test rust/crypto/tests/aes_ctr.rs::aes_ctr_smoke_test,
// which is itself a NIST SP 800-38A reference vector. The fixture
// at fixtures/crypto/aes_ctr_known_answers.json carries the same hex
// constants; the manifest's upstream_must_contain check fails CI if any
// of those hex literals disappear from the upstream source.
//
// The test drives pkg/cipher.NewAES256CTR, which mirrors Rust's
// Aes256Ctr32::from_key(key, nonce, init_ctr).
// Rust source: rust/crypto/src/aes_ctr.rs:35-45

package interop

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/cipher"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

type aesCtrVector struct {
	Name           string `json:"name"`
	KeyHex         string `json:"key_hex"`
	NonceHex       string `json:"nonce_hex"`
	InitCounterHex string `json:"init_counter_hex"`
	InputHex       string `json:"input_hex"`
	OutputHex      string `json:"output_hex"`
}

type aesCtrFixture struct {
	Vectors []aesCtrVector `json:"vectors"`
}

// TestAESCTR_Aes256Ctr32_KAT runs every vector in the fixture file through
// pkg/cipher.NewAES256CTR and asserts byte-identical output to the Rust
// signal_crypto::Aes256Ctr32 reference.
func TestAESCTR_Aes256Ctr32_KAT(t *testing.T) {
	raw := loader.MustRead("crypto/aes_ctr_known_answers.json")
	var fx aesCtrFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if len(fx.Vectors) == 0 {
		t.Fatal("fixture has no vectors")
	}

	for _, v := range fx.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			key, err := hex.DecodeString(v.KeyHex)
			if err != nil {
				t.Fatalf("decode key: %v", err)
			}
			nonce, err := hex.DecodeString(v.NonceHex)
			if err != nil {
				t.Fatalf("decode nonce: %v", err)
			}
			if len(nonce) != cipher.AES256CTRNonceSize {
				t.Fatalf("nonce must be %d bytes for CTR32BE; got %d",
					cipher.AES256CTRNonceSize, len(nonce))
			}
			initCtrBytes, err := hex.DecodeString(v.InitCounterHex)
			if err != nil {
				t.Fatalf("decode init counter: %v", err)
			}
			if len(initCtrBytes) != 4 {
				t.Fatalf("init counter must be 4 bytes (32-bit BE); got %d", len(initCtrBytes))
			}
			input, err := hex.DecodeString(v.InputHex)
			if err != nil {
				t.Fatalf("decode input: %v", err)
			}
			want, err := hex.DecodeString(v.OutputHex)
			if err != nil {
				t.Fatalf("decode output: %v", err)
			}
			if len(input) != len(want) {
				t.Fatalf("input length %d != output length %d", len(input), len(want))
			}

			initCtr := binary.BigEndian.Uint32(initCtrBytes)
			ctr, err := cipher.NewAES256CTR(key, nonce, initCtr)
			if err != nil {
				t.Fatalf("NewAES256CTR: %v", err)
			}

			got := make([]byte, len(input))
			copy(got, input)
			ctr.Process(got)

			if hex.EncodeToString(got) != hex.EncodeToString(want) {
				t.Fatalf("AES-CTR mismatch (vector %s):\n  got  %s\n  want %s",
					v.Name, hex.EncodeToString(got), hex.EncodeToString(want))
			}
		})
	}

	t.Logf("AES-CTR KAT: %s vectors pass byte-identical against Rust signal_crypto::Aes256Ctr32",
		strconv.Itoa(len(fx.Vectors)))
}
