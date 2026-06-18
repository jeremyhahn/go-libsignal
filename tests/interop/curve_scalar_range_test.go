// Conformance test: Curve25519 scalar-range checks against Rust libsignal_core.
//
// Mirrors the inline tests in rust/core/src/curve.rs:
//   - keys_with_the_high_bit_set_are_out_of_range
//   - keys_above_the_prime_modulus_are_out_of_range
//
// Validates Go's DjbECPublicKey.ScalarIsInRange against the boundary
// cases that bracket the Curve25519 prime p = 2^255 - 19.

package interop

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

type scalarRangeVector struct {
	Name    string `json:"name"`
	KeyHex  string `json:"key_hex"`
	InRange bool   `json:"in_range"`
}

type scalarRangeFixture struct {
	Vectors []scalarRangeVector `json:"vectors"`
}

// TestCurve25519_ScalarRange_KAT runs every KAT vector from the upstream
// Rust scalar-range tests and asserts Go produces the identical
// in-range / out-of-range answer.
func TestCurve25519_ScalarRange_KAT(t *testing.T) {
	raw := loader.MustRead("curve/scalar_range_known_answers.json")
	var fx scalarRangeFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if len(fx.Vectors) == 0 {
		t.Fatal("fixture has no vectors")
	}

	for _, v := range fx.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			b, err := hex.DecodeString(v.KeyHex)
			if err != nil {
				t.Fatalf("decode hex: %v", err)
			}
			if len(b) != 32 {
				t.Fatalf("key must be 32 bytes; got %d", len(b))
			}
			var arr [32]byte
			copy(arr[:], b)

			pk := ecc.NewDjbECPublicKey(arr)
			got := pk.ScalarIsInRange()
			if got != v.InRange {
				t.Fatalf("ScalarIsInRange(%s) = %v, want %v\n  bytes: %x", v.Name, got, v.InRange, b)
			}
		})
	}
}
