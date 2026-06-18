// Conformance test: distribution-ID to group-ID transform vs Rust libsignal-protocol.
//
// Mirrors rust/protocol/src/group_cipher.rs:16-73 where distribution_id is a
// uuid::Uuid formatted via Uuid::Display (standard hyphenated UUID string).
// The Go DistributionIDToGroupID function must produce byte-identical output.
//
// Rust reference: uuid crate Display impl produces "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
// (8-4-4-4-12 lowercase hex groups separated by hyphens), matching RFC 4122 §3.
// Go's DistributionIDToGroupID uses hex.EncodeToString + string slicing to
// produce the identical format from the same 16-byte input.

package interop

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/groups"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

type groupIDFixture struct {
	Source  string `json:"source"`
	RustRev string `json:"rust_rev"`
	Purpose string `json:"purpose"`
	Vectors []struct {
		Name   string `json:"name"`
		Inputs struct {
			DistributionIDHex string `json:"distribution_id_hex"`
		} `json:"inputs"`
		Expected struct {
			GroupID string `json:"group_id"`
		} `json:"expected"`
	} `json:"vectors"`
}

// TestGroupIDFromDistributionID verifies that Go's DistributionIDToGroupID
// produces the exact same UUID string as Rust's Uuid::Display for each
// fixed 16-byte distribution ID in the fixture.
func TestGroupIDFromDistributionID(t *testing.T) {
	raw := loader.MustRead("protocol/group_id_from_distribution_id.json")

	var fx groupIDFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if len(fx.Vectors) == 0 {
		t.Fatal("fixture contains no vectors")
	}

	for _, v := range fx.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			b, err := hex.DecodeString(v.Inputs.DistributionIDHex)
			if err != nil {
				t.Fatalf("decode distribution_id_hex: %v", err)
			}
			if len(b) != 16 {
				t.Fatalf("distribution_id must be 16 bytes, got %d", len(b))
			}

			var id [16]byte
			copy(id[:], b)

			got := groups.DistributionIDToGroupID(id)
			if got != v.Expected.GroupID {
				t.Errorf("DistributionIDToGroupID(%s):\n  got  %q\n  want %q",
					v.Inputs.DistributionIDHex, got, v.Expected.GroupID)
			}
		})
	}
}
