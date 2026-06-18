// Keytrans VRF negative-case conformance test.
//
// Asserts that VRFPublicKey.ProofToHash REJECTS every corrupted-proof vector
// in keytrans/vrf_negative_proofs.json. This mirrors Rust's
// test_proof_to_hash_fails (rust/keytrans/src/vrf.rs:230-242) which for
// each of the 3 RFC 9381 TAI test vectors:
//
//	(a) changes the message to "a" (0x61) and asserts error, and
//	(b) for every byte i, XORs it with 1 and asserts error.
//
// The fixture encodes a representative subset of (a) and (b) mutations
// (14 vectors total) to keep fixture size manageable while providing full
// coverage of each proof region: gamma (bytes 0-31), c scalar (32-47),
// and s scalar (48-79).
//
// Rust source: rust/keytrans/src/vrf.rs:230-242
// Upstream commit: 98915c44
package interop

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/keytrans"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

type vrfNegativeVector struct {
	Name          string `json:"name"`
	Description   string `json:"description"`
	ExpectedError string `json:"expected_error"`
	Inputs        struct {
		PublicKeyHex string `json:"public_key_hex"`
		MessageHex   string `json:"message_hex"`
		ProofHex     string `json:"proof_hex"`
	} `json:"inputs"`
}

type vrfNegativeFixture struct {
	Source  string              `json:"source"`
	RustRev string              `json:"rust_rev"`
	Purpose string              `json:"purpose"`
	Vectors []vrfNegativeVector `json:"vectors"`
}

// TestKeytransVRF_RejectsCorruptedProofs drives VRFPublicKey.ProofToHash against
// every corrupted-proof vector and asserts rejection with ErrInvalidVRFProof.
func TestKeytransVRF_RejectsCorruptedProofs(t *testing.T) {
	raw := loader.MustRead("keytrans/vrf_negative_proofs.json")

	var fix vrfNegativeFixture
	if err := json.Unmarshal(raw, &fix); err != nil {
		t.Fatalf("decode fixture JSON: %v", err)
	}
	if len(fix.Vectors) < 10 {
		t.Fatalf("fixture must contain at least 10 negative vectors, got %d", len(fix.Vectors))
	}

	for _, v := range fix.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			pkBytes, err := hex.DecodeString(v.Inputs.PublicKeyHex)
			if err != nil {
				t.Fatalf("decode public_key_hex: %v", err)
			}
			if len(pkBytes) != 32 {
				t.Fatalf("public key must be 32 bytes, got %d", len(pkBytes))
			}

			msgBytes, err := hex.DecodeString(v.Inputs.MessageHex)
			if err != nil {
				t.Fatalf("decode message_hex: %v", err)
			}

			proofBytes, err := hex.DecodeString(v.Inputs.ProofHex)
			if err != nil {
				t.Fatalf("decode proof_hex: %v", err)
			}
			if len(proofBytes) != 80 {
				t.Fatalf("proof must be 80 bytes, got %d", len(proofBytes))
			}

			var pkArr [32]byte
			copy(pkArr[:], pkBytes)
			var proofArr [80]byte
			copy(proofArr[:], proofBytes)

			pk, err := keytrans.NewVRFPublicKey(pkArr)
			if err != nil {
				// Corrupted gamma bytes may yield an invalid curve point.
				// That is also a correct rejection — the proof failed.
				if errors.Is(err, keytrans.ErrInvalidCurvePoint) {
					return
				}
				t.Fatalf("NewVRFPublicKey: unexpected error %v", err)
			}

			_, err = pk.ProofToHash(msgBytes, &proofArr)
			if err == nil {
				t.Fatalf("ProofToHash accepted corrupted proof %q; expected error", v.Name)
			}
			// The error must be ErrInvalidVRFProof (or wrapped around it).
			if !errors.Is(err, keytrans.ErrInvalidVRFProof) {
				t.Errorf("ProofToHash returned %v; want ErrInvalidVRFProof", err)
			}
		})
	}
}
