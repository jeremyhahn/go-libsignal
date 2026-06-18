// Keytrans VRF proof-to-hash conformance test.
//
// Drives pkg/keytrans.VRFPublicKey.ProofToHash against the three test vectors
// extracted from rust/keytrans/src/vrf.rs::tests::TEST_VECTORS (the same
// vectors exercised by test_proof_to_hash and test_encode_to_curve_try_and_increment).
//
// The Rust implementation is ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381 TAI
// variant). Each vector supplies a compressed Edwards25519 public key, a
// message (alpha), and an 80-byte proof (pi). ProofToHash must verify the proof
// and return the 32-byte VRF hash (beta) byte-for-byte identical to the Rust
// reference.
//
// Rust source: rust/keytrans/src/vrf.rs:158-243
// Upstream commit: 98915c442d
package interop

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/keytrans"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

type vrfVector struct {
	Name   string `json:"name"`
	Inputs struct {
		PublicKeyHex string `json:"public_key_hex"`
		MessageHex   string `json:"message_hex"`
		ProofHex     string `json:"proof_hex"`
	} `json:"inputs"`
	Expected struct {
		HashHex string `json:"hash_hex"`
	} `json:"expected"`
}

type vrfFixture struct {
	Source  string      `json:"source"`
	RustRev string      `json:"rust_rev"`
	Purpose string      `json:"purpose"`
	Vectors []vrfVector `json:"vectors"`
}

// TestKeytransVRF_ProofToHash verifies that VRFPublicKey.ProofToHash returns
// the expected 32-byte VRF hash for all three upstream Rust test vectors.
func TestKeytransVRF_ProofToHash(t *testing.T) {
	raw := loader.MustRead("keytrans/vrf_proofs.json")

	var fix vrfFixture
	if err := json.Unmarshal(raw, &fix); err != nil {
		t.Fatalf("decode fixture JSON: %v", err)
	}
	if len(fix.Vectors) == 0 {
		t.Fatal("fixture contains no vectors")
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

			wantHash, err := hex.DecodeString(v.Expected.HashHex)
			if err != nil {
				t.Fatalf("decode hash_hex: %v", err)
			}

			var pkArr [32]byte
			copy(pkArr[:], pkBytes)
			var proofArr [80]byte
			copy(proofArr[:], proofBytes)

			pk, err := keytrans.NewVRFPublicKey(pkArr)
			if err != nil {
				t.Fatalf("NewVRFPublicKey: %v", err)
			}

			gotHash, err := pk.ProofToHash(msgBytes, &proofArr)
			if err != nil {
				t.Fatalf("ProofToHash: %v", err)
			}

			if !bytesEq(gotHash[:], wantHash) {
				t.Fatalf("hash mismatch:\n  got  %x\n  want %x", gotHash, wantHash)
			}
		})
	}
}

// TestKeytransVRF_ProofToHash_WrongMessage confirms that ProofToHash rejects a
// valid proof when the message is altered, matching Rust's test_proof_to_hash_fails
// behaviour.
func TestKeytransVRF_ProofToHash_WrongMessage(t *testing.T) {
	raw := loader.MustRead("keytrans/vrf_proofs.json")

	var fix vrfFixture
	if err := json.Unmarshal(raw, &fix); err != nil {
		t.Fatalf("decode fixture JSON: %v", err)
	}

	for _, v := range fix.Vectors {
		v := v
		t.Run(v.Name+"/wrong_message", func(t *testing.T) {
			pkBytes, err := hex.DecodeString(v.Inputs.PublicKeyHex)
			if err != nil {
				t.Fatalf("decode public_key_hex: %v", err)
			}
			proofBytes, err := hex.DecodeString(v.Inputs.ProofHex)
			if err != nil {
				t.Fatalf("decode proof_hex: %v", err)
			}

			var pkArr [32]byte
			copy(pkArr[:], pkBytes)
			var proofArr [80]byte
			copy(proofArr[:], proofBytes)

			pk, err := keytrans.NewVRFPublicKey(pkArr)
			if err != nil {
				t.Fatalf("NewVRFPublicKey: %v", err)
			}

			// Using the wrong message must cause proof verification to fail.
			_, err = pk.ProofToHash([]byte("wrong message"), &proofArr)
			if err == nil {
				t.Fatal("expected error when message does not match proof, got nil")
			}
		})
	}
}
