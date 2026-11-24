// zkgroup Schnorr signatures against Rust test_signature: sign and verify round-trip and a tampered message fails; a byte mismatch with Rust is logged, as the SHO schedule may differ.
package interop

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/poksho"
	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

type zkSigFixture struct {
	Source  string     `json:"source"`
	RustRev string     `json:"rust_rev"`
	Purpose string     `json:"purpose"`
	Vectors []zkSigVec `json:"vectors"`
}

type zkSigVec struct {
	Name   string      `json:"name"`
	Inputs zkSigInputs `json:"inputs"`
	Expect zkSigExpect `json:"expected"`
}

type zkSigInputs struct {
	ShoLabel   string `json:"sho_label"`
	ShoKeyHex  string `json:"sho_key_hex"`
	MessageHex string `json:"message_hex"`
}

type zkSigExpect struct {
	SignatureHex string `json:"signature_hex"`
	VerifyResult string `json:"verify_result"`
}

// TestZKGroup_CryptoSignature checks Sign and Verify round-trip and reject tampering, logging any byte difference from Rust.
func TestZKGroup_CryptoSignature(t *testing.T) {
	raw := loader.MustRead("zkgroup/crypto/signature.json")
	var fix zkSigFixture
	if err := json.Unmarshal(raw, &fix); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if len(fix.Vectors) == 0 {
		t.Fatal("fixture has no vectors")
	}

	for _, vec := range fix.Vectors {
		vec := vec
		t.Run(vec.Name, func(t *testing.T) {
			// Build the SHO matching Rust's Sho::new(label, key).
			sho := zkcredential.NewShoHmacSha256Ext(vec.Inputs.ShoLabel)
			if vec.Inputs.ShoKeyHex != "" {
				shoKey, err := hex.DecodeString(vec.Inputs.ShoKeyHex)
				if err != nil {
					t.Fatalf("decode sho_key_hex: %v", err)
				}
				sho.AbsorbAndRatchet(shoKey)
			}

			kp, err := zkgroup.GenerateSignatureKeyPair(sho)
			if err != nil {
				t.Fatalf("GenerateSignatureKeyPair: %v", err)
			}

			message, err := hex.DecodeString(vec.Inputs.MessageHex)
			if err != nil {
				t.Fatalf("decode message_hex: %v", err)
			}

			// Squeeze signing randomness from the shared SHO (mirrors
			// Rust's sho.squeeze_as_array::<RANDOMNESS_LEN>()).
			randomness := sho.SqueezeAndRatchet(32)

			switch vec.Expect.VerifyResult {
			case "success":
				sig, signErr := kp.Sign(message, randomness)
				if signErr != nil {
					t.Fatalf("Sign: %v", signErr)
				}

				// Verify succeeds.
				if err := kp.GetPublicKey().Verify(message, sig); err != nil {
					t.Fatalf("Verify(original message): %v", err)
				}

				// Byte-level parity vs Rust pinned signature.
				wantSig, parseErr := hex.DecodeString(vec.Expect.SignatureHex)
				if parseErr != nil {
					t.Fatalf("decode signature_hex: %v", parseErr)
				}
				if !bytes.Equal(sig, wantSig) {
					t.Fatalf("signature bytes differ from Rust pinned value:\n  got  %x\n  want %x", sig, wantSig)
				}
			case "failure":
				// Tampered message: verify must fail.
				wantSig, err := hex.DecodeString(vec.Expect.SignatureHex)
				if err != nil {
					t.Fatalf("decode signature_hex: %v", err)
				}
				verifyErr := kp.GetPublicKey().Verify(message, wantSig)
				if verifyErr == nil {
					t.Fatal("Verify succeeded on tampered message; expected failure")
				}
				// Confirm it's a proof-failure error, not something else.
				var proofErr *poksho.ErrPokshoVerificationFailure
				if !errors.As(verifyErr, &proofErr) {
					t.Fatalf("Verify returned %T (%v); expected poksho.ErrPokshoVerificationFailure", verifyErr, verifyErr)
				}
			}
		})
	}
}
