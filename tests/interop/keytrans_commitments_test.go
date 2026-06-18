// Keytrans commitment conformance test.
//
// Drives pkg/keytrans.Commit against the four test vectors extracted from
// rust/keytrans/src/commitments.rs::test::test_commit.
//
// The commitment scheme is HMAC-SHA256 with a fixed 16-byte key baked into
// the implementation. The HMAC input is:
//
//	nonce (16 bytes) || BE-uint16(len(search_key)) || search_key
//	|| BE-uint32(len(data)) || data
//
// All four upstream vectors use a zero nonce. Go's Commit must reproduce the
// expected 32-byte output byte-for-byte.
//
// Rust source: rust/keytrans/src/commitments.rs:37-51
// Upstream commit: 98915c442d
package interop

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/keytrans"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

type commitmentVector struct {
	Name   string `json:"name"`
	Inputs struct {
		SearchKeyHex string `json:"search_key_hex"`
		DataHex      string `json:"data_hex"`
		NonceHex     string `json:"nonce_hex"`
	} `json:"inputs"`
	Expected struct {
		CommitmentHex string `json:"commitment_hex"`
	} `json:"expected"`
}

type commitmentFixture struct {
	Source  string             `json:"source"`
	RustRev string             `json:"rust_rev"`
	Purpose string             `json:"purpose"`
	Vectors []commitmentVector `json:"vectors"`
}

// TestKeytransCommitments_Commit verifies that keytrans.Commit produces the
// expected 32-byte HMAC-SHA256 commitment for all four upstream Rust test cases.
func TestKeytransCommitments_Commit(t *testing.T) {
	raw := loader.MustRead("keytrans/commitments.json")

	var fix commitmentFixture
	if err := json.Unmarshal(raw, &fix); err != nil {
		t.Fatalf("decode fixture JSON: %v", err)
	}
	if len(fix.Vectors) == 0 {
		t.Fatal("fixture contains no vectors")
	}

	for _, v := range fix.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			searchKey, err := hex.DecodeString(v.Inputs.SearchKeyHex)
			if err != nil {
				t.Fatalf("decode search_key_hex: %v", err)
			}

			data, err := hex.DecodeString(v.Inputs.DataHex)
			if err != nil {
				t.Fatalf("decode data_hex: %v", err)
			}

			nonceBytes, err := hex.DecodeString(v.Inputs.NonceHex)
			if err != nil {
				t.Fatalf("decode nonce_hex: %v", err)
			}
			if len(nonceBytes) != 16 {
				t.Fatalf("nonce must be 16 bytes, got %d", len(nonceBytes))
			}
			var nonce [16]byte
			copy(nonce[:], nonceBytes)

			want, err := hex.DecodeString(v.Expected.CommitmentHex)
			if err != nil {
				t.Fatalf("decode commitment_hex: %v", err)
			}

			got := keytrans.Commit(searchKey, data, &nonce)

			if !bytesEq(got, want) {
				t.Fatalf("commitment mismatch:\n  got  %x\n  want %x", got, want)
			}
		})
	}
}

// TestKeytransCommitments_Commit_TamperedInput confirms that Commit is
// sensitive to every field: changing search_key, data, or nonce must alter the
// output, so a single-byte mutation in any input causes a different result.
func TestKeytransCommitments_Commit_TamperedInput(t *testing.T) {
	raw := loader.MustRead("keytrans/commitments.json")

	var fix commitmentFixture
	if err := json.Unmarshal(raw, &fix); err != nil {
		t.Fatalf("decode fixture JSON: %v", err)
	}

	// Use the case_1 vector (non-empty key and data) for tamper testing.
	var base *commitmentVector
	for i := range fix.Vectors {
		if fix.Vectors[i].Name == "case_1" {
			base = &fix.Vectors[i]
			break
		}
	}
	if base == nil {
		t.Fatal("case_1 vector not found in fixture")
	}

	searchKey, _ := hex.DecodeString(base.Inputs.SearchKeyHex)
	data, _ := hex.DecodeString(base.Inputs.DataHex)
	nonceBytes, _ := hex.DecodeString(base.Inputs.NonceHex)
	var nonce [16]byte
	copy(nonce[:], nonceBytes)

	baseline := keytrans.Commit(searchKey, data, &nonce)

	t.Run("tampered_search_key", func(t *testing.T) {
		tampered := append([]byte{}, searchKey...)
		tampered[0] ^= 0x01
		got := keytrans.Commit(tampered, data, &nonce)
		if bytesEq(got, baseline) {
			t.Fatal("tampered search_key produced the same commitment")
		}
	})

	t.Run("tampered_data", func(t *testing.T) {
		tampered := append([]byte{}, data...)
		tampered[0] ^= 0x01
		got := keytrans.Commit(searchKey, tampered, &nonce)
		if bytesEq(got, baseline) {
			t.Fatal("tampered data produced the same commitment")
		}
	})

	t.Run("tampered_nonce", func(t *testing.T) {
		var tamperedNonce [16]byte
		copy(tamperedNonce[:], nonceBytes)
		tamperedNonce[0] ^= 0x01
		got := keytrans.Commit(searchKey, data, &tamperedNonce)
		if bytesEq(got, baseline) {
			t.Fatal("tampered nonce produced the same commitment")
		}
	})
}
