// Package interop — Kyber-1024 Known-Answer Test (KAT).
//
// This test loads tests/interop/fixtures/kem/kyber1024_kat.json, which is
// emitted by the Rust wire_emitter binary (make interop-wire-emit), and
// verifies that the Go Kyber-1024 implementation produces the same shared
// secret when decapsulating the Rust-emitted ciphertext with the Rust-emitted
// secret key.
//
// If the fixture file is absent (pending regeneration), the test fails with a
// clear message. Run `make interop-wire-emit` to populate the fixture.
//
// Rust reference: rust/protocol/src/kem.rs — KeyPair::generate,
//
//	PublicKey::encapsulate, SecretKey::decapsulate
//	(libsignal v0.92.2, RUST_REV 98915c442d).
package interop

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/kem"
)

// katFixture mirrors the JSON schema emitted by wire_emitter emit_kyber1024_kat.
type katFixture struct {
	Vectors []struct {
		Name   string `json:"name"`
		Inputs struct {
			PkHex string `json:"pk_hex"`
			SkHex string `json:"sk_hex"`
			CtHex string `json:"ct_hex"`
		} `json:"inputs"`
		Expected struct {
			SsHex string `json:"ss_hex"`
		} `json:"expected"`
	} `json:"vectors"`
}

// kyber1024KATFixturePath returns the absolute path to the KAT fixture file.
func kyber1024KATFixturePath() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "fixtures", "wire", "kem", "kyber1024_kat.json")
}

// TestKyber1024KAT loads the Rust-emitted KAT fixture and asserts that the Go
// Kyber-1024 implementation produces the expected shared secret when
// decapsulating the Rust ciphertext with the Rust secret key.
//
// A missing fixture is a fatal error: run `make interop-wire-emit` to regenerate.
func TestKyber1024KAT(t *testing.T) {
	fixturePath := kyber1024KATFixturePath()
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			t.Fatalf("kyber1024_kat.json not found at %s — run `make interop-wire-emit` to regenerate", fixturePath)
		}
		t.Fatalf("reading kyber1024_kat.json: %v", err)
	}

	var fixture katFixture
	if jsonErr := json.Unmarshal(data, &fixture); jsonErr != nil {
		t.Fatalf("unmarshaling kyber1024_kat.json: %v", jsonErr)
	}
	if len(fixture.Vectors) == 0 {
		t.Fatal("kyber1024_kat.json contains no vectors")
	}

	for _, v := range fixture.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			// The Rust pk_hex includes the 0x08 Kyber1024 type-byte prefix.
			pkBytes, err := hex.DecodeString(v.Inputs.PkHex)
			if err != nil {
				t.Fatalf("decoding pk_hex: %v", err)
			}

			// The Rust sk_hex includes the 0x08 type-byte prefix; strip it
			// before passing to NewSecretKey which expects raw key material.
			skBytes, err := hex.DecodeString(v.Inputs.SkHex)
			if err != nil {
				t.Fatalf("decoding sk_hex: %v", err)
			}
			if len(skBytes) < 2 {
				t.Fatalf("sk_hex too short: %d bytes", len(skBytes))
			}
			skRaw := skBytes[1:] // strip type-byte prefix

			// The Rust ct_hex includes the 0x08 type-byte prefix.
			ctBytes, err := hex.DecodeString(v.Inputs.CtHex)
			if err != nil {
				t.Fatalf("decoding ct_hex: %v", err)
			}

			expectedSS, err := hex.DecodeString(v.Expected.SsHex)
			if err != nil {
				t.Fatalf("decoding ss_hex: %v", err)
			}

			// Deserialize public key (Rust serialization includes type-byte prefix).
			pk, pkErr := kem.DeserializePublicKey(pkBytes)
			if pkErr != nil {
				t.Fatalf("DeserializePublicKey: %v", pkErr)
			}
			if pk.Type() != kem.KeyTypeKyber1024 {
				t.Fatalf("public key type = 0x%02x, want 0x%02x (Kyber1024)", pk.Type(), kem.KeyTypeKyber1024)
			}

			// Reconstruct secret key from raw bytes (no type-byte prefix).
			sk, skErr := kem.NewSecretKey(kem.KeyTypeKyber1024, skRaw)
			if skErr != nil {
				t.Fatalf("NewSecretKey: %v", skErr)
			}

			// Deserialize ciphertext (Rust serialization includes type-byte prefix).
			ct, ctErr := kem.DeserializeCiphertext(ctBytes)
			if ctErr != nil {
				t.Fatalf("DeserializeCiphertext: %v", ctErr)
			}
			if ct.Type() != kem.KeyTypeKyber1024 {
				t.Fatalf("ciphertext type = 0x%02x, want 0x%02x (Kyber1024)", ct.Type(), kem.KeyTypeKyber1024)
			}

			// Decapsulate and assert equality with the Rust-emitted shared secret.
			kyber := kem.NewKyber1024KEM()
			ss, decErr := kyber.Decapsulate(sk, ct)
			if decErr != nil {
				t.Fatalf("Decapsulate: %v", decErr)
			}

			if len(expectedSS) != 32 {
				t.Fatalf("expected_ss length = %d, want 32", len(expectedSS))
			}
			for i, b := range expectedSS {
				if ss[i] != b {
					t.Errorf("shared secret mismatch at byte %d: got 0x%02x, want 0x%02x", i, ss[i], b)
				}
			}
		})
	}
}
