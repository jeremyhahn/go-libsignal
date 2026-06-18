// Usernames ZK proof and scalar hash KAT interop test.
//
// Drives pkg/usernames against known-answer fixtures extracted from
// rust/usernames/src/username.rs (inline tests at lines 135-266).
//
// scalar_kats: verify that Hash() for each fixture username produces the
// expected 32-byte hash byte-for-byte. The _z9_ vector anchors that
// nickname_scalar == 74656 (Rust valid_nickname_scalar test at line 355).
//
// proof_kats: verify that Proof(randomness) produces the exact bytes
// encoded in the fixture, and that VerifyProof(proof, hash) succeeds.
// Proof generation uses the same poksho ZK statement as Rust, so proof
// bytes must match regardless of platform.
//
// Rust source: rust/usernames/src/username.rs:135-266
// Upstream commit: 98915c44
package interop

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/usernames"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

// scalarKAT corresponds to a scalar_kats entry in proof_known_answers.json.
type scalarKAT struct {
	Name          string `json:"name"`
	Nickname      string `json:"nickname"`
	Discriminator uint64 `json:"discriminator"`
	SHAScalarHex  string `json:"sha_scalar_hex"`
	NickScalarHex string `json:"nickname_scalar_hex"`
	DiscScalarHex string `json:"discriminator_scalar_hex"`
	HashHex       string `json:"hash_hex"`
}

// proofKAT corresponds to a proof_kats entry in proof_known_answers.json.
type proofKAT struct {
	Name          string `json:"name"`
	Nickname      string `json:"nickname"`
	Discriminator uint64 `json:"discriminator"`
	RandomnessHex string `json:"randomness_hex"`
	HashHex       string `json:"hash_hex"`
	ProofHex      string `json:"proof_hex"`
}

type usernameKATFixture struct {
	Source     string      `json:"source"`
	RustRev    string      `json:"rust_rev"`
	Purpose    string      `json:"purpose"`
	ScalarKATs []scalarKAT `json:"scalar_kats"`
	ProofKATs  []proofKAT  `json:"proof_kats"`
}

// usernameStr formats a username from nickname and discriminator, using the
// same zero-padding as Rust's format_parts (at least 2 digits).
func usernameStr(nickname string, discriminator uint64) string {
	return fmt.Sprintf("%s.%02d", nickname, discriminator)
}

// TestUsernames_ScalarHash verifies that Hash() for each fixture username
// produces the expected 32-byte hash byte-for-byte.
// Also anchors that the _z9_ nickname encodes nickname_scalar = 74656 via
// its fixture hash, which was generated with that scalar value.
//
// Rust ref: username.rs valid_nickname_scalar (line 355), valid_usernames (line 365).
func TestUsernames_ScalarHash(t *testing.T) {
	raw := loader.MustRead("usernames/proof_known_answers.json")

	var fix usernameKATFixture
	if err := json.Unmarshal(raw, &fix); err != nil {
		t.Fatalf("decode fixture JSON: %v", err)
	}
	if len(fix.ScalarKATs) == 0 {
		t.Fatal("fixture contains no scalar_kats")
	}

	for _, v := range fix.ScalarKATs {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			wantHash, err := hex.DecodeString(v.HashHex)
			if err != nil {
				t.Fatalf("decode hash_hex: %v", err)
			}

			u, err := usernames.New(usernameStr(v.Nickname, v.Discriminator))
			if err != nil {
				t.Fatalf("New(%s): %v", usernameStr(v.Nickname, v.Discriminator), err)
			}

			gotHash := u.Hash()
			if !bytesEq(gotHash[:], wantHash) {
				t.Errorf("Hash mismatch for %s:\n  got  %x\n  want %x", v.Name, gotHash, wantHash)
			}
		})
	}
}

// TestUsernames_ProofAndVerify verifies that Proof(randomness) produces the
// exact bytes stored in the fixture, and that VerifyProof accepts them.
//
// Rust ref: username.rs valid_usernames_proof_and_verify (proptest, line 460+).
// Fixed randomness 0x01..0x20 used instead of random to make the KAT deterministic.
func TestUsernames_ProofAndVerify(t *testing.T) {
	raw := loader.MustRead("usernames/proof_known_answers.json")

	var fix usernameKATFixture
	if err := json.Unmarshal(raw, &fix); err != nil {
		t.Fatalf("decode fixture JSON: %v", err)
	}
	if len(fix.ProofKATs) == 0 {
		t.Fatal("fixture contains no proof_kats")
	}

	for _, v := range fix.ProofKATs {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			randBytes, err := hex.DecodeString(v.RandomnessHex)
			if err != nil {
				t.Fatalf("decode randomness_hex: %v", err)
			}
			if len(randBytes) != 32 {
				t.Fatalf("randomness must be 32 bytes, got %d", len(randBytes))
			}
			wantHash, err := hex.DecodeString(v.HashHex)
			if err != nil {
				t.Fatalf("decode hash_hex: %v", err)
			}
			wantProof, err := hex.DecodeString(v.ProofHex)
			if err != nil {
				t.Fatalf("decode proof_hex: %v", err)
			}

			u, err := usernames.New(usernameStr(v.Nickname, v.Discriminator))
			if err != nil {
				t.Fatalf("New(%s): %v", usernameStr(v.Nickname, v.Discriminator), err)
			}

			// Assert hash matches the scalar_kats fixture.
			gotHash := u.Hash()
			if !bytesEq(gotHash[:], wantHash) {
				t.Errorf("Hash mismatch:\n  got  %x\n  want %x", gotHash, wantHash)
			}

			var randomness [32]byte
			copy(randomness[:], randBytes)

			gotProof, err := u.Proof(randomness)
			if err != nil {
				t.Fatalf("Proof(): %v", err)
			}

			if !bytesEq(gotProof, wantProof) {
				t.Errorf("Proof bytes mismatch:\n  got  %x\n  want %x", gotProof, wantProof)
			}

			// Round-trip: VerifyProof must accept the proof we generated.
			var hashArr [32]byte
			copy(hashArr[:], gotHash[:])
			if err := usernames.VerifyProof(gotProof, hashArr); err != nil {
				t.Errorf("VerifyProof(generated proof): %v", err)
			}

			// Also verify using the fixture proof bytes directly.
			if err := usernames.VerifyProof(wantProof, hashArr); err != nil {
				t.Errorf("VerifyProof(fixture proof): %v", err)
			}
		})
	}
}

// TestUsernames_VerifyProof_RejectsCorrupted asserts that VerifyProof rejects
// a proof with a single flipped bit, confirming the ZK verification gates on
// proof bytes.
//
// Rust ref: username.rs valid_usernames_proof_and_verify (implicit property).
func TestUsernames_VerifyProof_RejectsCorrupted(t *testing.T) {
	raw := loader.MustRead("usernames/proof_known_answers.json")

	var fix usernameKATFixture
	if err := json.Unmarshal(raw, &fix); err != nil {
		t.Fatalf("decode fixture JSON: %v", err)
	}

	for _, v := range fix.ProofKATs {
		v := v
		t.Run(v.Name+"/corrupted_proof", func(t *testing.T) {
			wantProof, err := hex.DecodeString(v.ProofHex)
			if err != nil {
				t.Fatalf("decode proof_hex: %v", err)
			}
			wantHash, err := hex.DecodeString(v.HashHex)
			if err != nil {
				t.Fatalf("decode hash_hex: %v", err)
			}
			var hashArr [32]byte
			copy(hashArr[:], wantHash)

			// Flip byte[0] of the proof.
			corrupted := make([]byte, len(wantProof))
			copy(corrupted, wantProof)
			corrupted[0] ^= 0x01

			if err := usernames.VerifyProof(corrupted, hashArr); err == nil {
				t.Error("VerifyProof must reject a corrupted proof, but returned nil")
			}
		})
	}
}
