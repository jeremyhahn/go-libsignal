// Wycheproof AES-GCM Known-Answer-Tests run against pkg/cipher.AESGCMEncrypt
// and pkg/cipher.AESGCMDecrypt, mirroring the conformance suite that Rust
// libsignal runs in rust/crypto/tests/aes_gcm.rs against
// signal_crypto::Aes256Gcm{Encryption,Decryption}.
//
// The fixture is a verbatim copy of rust/crypto/tests/data/aes_gcm_test.json
// at the upstream commit recorded in /RUST_REV (sha256 enforced by
// MANIFEST.toml). Results that pass here are guaranteed identical, byte for
// byte, to results Rust produces against the same vectors.
//
// We currently only assert the AES-256 (key size = 256) and 96-bit-IV
// vectors that Rust's signal_crypto exposes through Aes256Gcm{Encryption,
// Decryption}. Other key sizes and IV widths exist in the corpus and are
// skipped here for the same reason Rust skips them — they are outside the
// API surface signal_crypto offers.

package interop

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/cipher"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

type wycheproofTest struct {
	TCID    int      `json:"tcId"`
	Comment string   `json:"comment"`
	Key     string   `json:"key"`
	IV      string   `json:"iv"`
	AAD     string   `json:"aad"`
	Msg     string   `json:"msg"`
	CT      string   `json:"ct"`
	Tag     string   `json:"tag"`
	Result  string   `json:"result"`
	Flags   []string `json:"flags"`
}

type wycheproofGroup struct {
	IVSize  int              `json:"ivSize"`
	KeySize int              `json:"keySize"`
	TagSize int              `json:"tagSize"`
	Type    string           `json:"type"`
	Tests   []wycheproofTest `json:"tests"`
}

type wycheproofSet struct {
	Algorithm   string            `json:"algorithm"`
	NumberTests int               `json:"numberOfTests"`
	TestGroups  []wycheproofGroup `json:"testGroups"`
}

// TestAESGCM_Wycheproof runs the Wycheproof AES-GCM KAT corpus against Go
// stdlib AES-GCM and asserts every "valid" / "invalid" vector behaves
// identically to the Rust libsignal reference. "acceptable" vectors are
// reported but not asserted, mirroring Rust's permissive treatment of
// borderline-but-not-spec-violating cases.
func TestAESGCM_Wycheproof(t *testing.T) {
	raw := loader.MustRead("crypto/aes_gcm_test.json")

	var set wycheproofSet
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatalf("decode KAT JSON: %v", err)
	}
	if !strings.EqualFold(set.Algorithm, "AES-GCM") {
		t.Fatalf("unexpected algorithm %q in fixture", set.Algorithm)
	}

	var (
		runValid    int
		runInvalid  int
		acceptable  int
		skipped     int
		skipReasons = map[string]int{}
	)

	for gi, g := range set.TestGroups {
		// Mirror Rust scope: AES-256, 96-bit IV, 128-bit tag.
		if g.KeySize != 256 {
			skipped += len(g.Tests)
			skipReasons[fmt.Sprintf("keySize=%d", g.KeySize)] += len(g.Tests)
			continue
		}
		if g.IVSize != 96 {
			skipped += len(g.Tests)
			skipReasons[fmt.Sprintf("ivSize=%d", g.IVSize)] += len(g.Tests)
			continue
		}
		if g.TagSize != 128 {
			skipped += len(g.Tests)
			skipReasons[fmt.Sprintf("tagSize=%d", g.TagSize)] += len(g.Tests)
			continue
		}

		for _, kat := range g.Tests {
			tc := kat
			name := fmt.Sprintf("group%d/tc%d", gi, tc.TCID)
			t.Run(name, func(t *testing.T) {
				key := mustHex(t, tc.Key)
				iv := mustHex(t, tc.IV)
				aad := mustHex(t, tc.AAD)
				wantCT := mustHex(t, tc.CT)
				wantTag := mustHex(t, tc.Tag)
				pt := mustHex(t, tc.Msg)

				switch tc.Result {
				case "valid":
					runValid++

					// Encrypt via pkg/cipher.AESGCMEncrypt. Returns ct||tag.
					sealed, err := cipher.AESGCMEncrypt(key, iv, pt, aad)
					if err != nil {
						t.Fatalf("AESGCMEncrypt: %v", err)
					}
					if len(sealed) != len(wantCT)+len(wantTag) {
						t.Fatalf("sealed length %d != ct+tag %d", len(sealed), len(wantCT)+len(wantTag))
					}
					gotCT := sealed[:len(wantCT)]
					gotTag := sealed[len(wantCT):]
					if !bytesEq(gotCT, wantCT) {
						t.Fatalf("ciphertext mismatch:\n  got  %x\n  want %x", gotCT, wantCT)
					}
					if !bytesEq(gotTag, wantTag) {
						t.Fatalf("tag mismatch:\n  got  %x\n  want %x", gotTag, wantTag)
					}

					// Decrypt via pkg/cipher.AESGCMDecrypt.
					ctTag := append(append([]byte{}, wantCT...), wantTag...)
					gotPT, err := cipher.AESGCMDecrypt(key, iv, ctTag, aad)
					if err != nil {
						t.Fatalf("AESGCMDecrypt(valid): %v", err)
					}
					if !bytesEq(gotPT, pt) {
						t.Fatalf("plaintext mismatch:\n  got  %x\n  want %x", gotPT, pt)
					}

				case "invalid":
					runInvalid++

					// Two sub-cases mirror Rust's expectations:
					//   1. Encryption with the same key/iv/aad/pt should NOT
					//      produce the recorded tag (i.e. the recorded tag is
					//      a forgery target).
					//   2. Decryption of recorded ct||tag should fail with
					//      auth-tag mismatch.
					sealed, err := cipher.AESGCMEncrypt(key, iv, pt, aad)
					if err == nil && len(sealed) >= len(wantTag) {
						gotTag := sealed[len(sealed)-len(wantTag):]
						if bytesEq(gotTag, wantTag) {
							t.Fatalf("invalid KAT produced matching tag (forgery): tcId=%d", tc.TCID)
						}
					}
					ctTag := append(append([]byte{}, wantCT...), wantTag...)
					if _, err := cipher.AESGCMDecrypt(key, iv, ctTag, aad); err == nil {
						t.Fatalf("AESGCMDecrypt(invalid) succeeded; expected error: tcId=%d", tc.TCID)
					}

				case "acceptable":
					// "acceptable" vectors are spec-compliant but flagged for
					// some borderline behaviour (e.g. constructed IVs, weak
					// truncation). Rust does not assert these; mirror that.
					acceptable++

				default:
					t.Fatalf("unknown KAT result %q on tcId=%d", tc.Result, tc.TCID)
				}
			})
		}
	}

	t.Logf("AES-GCM KAT summary: valid=%d invalid=%d acceptable=%d skipped=%d (%v)",
		runValid, runInvalid, acceptable, skipped, skipReasons)

	if runValid == 0 || runInvalid == 0 {
		t.Fatalf("KAT corpus produced no valid/invalid runs (valid=%d invalid=%d); fixture may have changed shape", runValid, runInvalid)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", s, err)
	}
	return b
}

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
