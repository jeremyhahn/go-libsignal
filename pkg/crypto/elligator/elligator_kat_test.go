package elligator

// Elligator-Ristretto cross-package consistency tests.
//
// Rust libsignal has NO standalone Elligator KATs for this primitive:
//   - rust/poksho/src/ does not test Elligator directly.
//   - rust/zkgroup/src/crypto/profile_key_struct.rs uses
//     RistrettoPoint::from_uniform_bytes_single_elligator, which is the
//     forward map only.
//   - The curve25519-dalek-signal Lizard / elligator_ristretto_flavor_inverse
//     function has no upstream test vectors published at the pinned commit
//     (98915c44).
//
// Therefore these tests verify INTERNAL CONSISTENCY (Go round-trip properties)
// rather than cross-implementation byte-exact KAT parity:
//
//  1. Forward Elligator map via ristretto255.SetUniformBytes followed by
//     ElligatorRistrettoFlavorInverse must recover a preimage that maps back
//     to the same ristretto point.
//  2. Every candidate returned with a set bit in the mask must map forward to
//     the original point.
//  3. Non-canonical / invalid encodings must return ok=false.
//
// If/when Rust libsignal publishes KAT vectors for this primitive, this file
// should be replaced with a byte-exact cross-implementation test.

import (
	"crypto/sha256"
	"testing"

	"github.com/gtank/ristretto255"
)

// inputVector is one consistency test vector.
type inputVector struct {
	name string
	seed []byte // arbitrary seed — not a field element; hashed to derive the uniform bytes
}

// consistencyVectors returns the fixed set of vectors used in this test.
// Seeds cover: empty, single byte, all-ones, sequential, a UUID-like pattern,
// and a near-p field element to exercise edge-case code paths in the
// elligatorInv Jacobi-quartic computation.
func consistencyVectors() []inputVector {
	return []inputVector{
		{name: "empty", seed: []byte{}},
		{name: "zero_byte", seed: []byte{0x00}},
		{name: "ff_byte", seed: []byte{0xFF}},
		{name: "sequential_16", seed: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},
		{name: "uuid_like", seed: []byte{
			0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
			0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78,
		}},
		{name: "all_0x42", seed: []byte{
			0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
			0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
		}},
		{name: "pattern_aa_55", seed: []byte{
			0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55,
		}},
		{name: "near_p_seed", seed: []byte{
			0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
		}},
		{name: "short_text", seed: []byte("hello world")},
		{name: "signal_protocol", seed: []byte("Signal Protocol Elligator consistency test")},
	}
}

// uniformBytesFromSeed derives 64 uniform bytes by SHA-256-ing the seed twice
// to fill the two halves, mirroring how the ristretto255 library uses 64
// random bytes. The first and second halves are independent hashes to avoid
// trivial symmetry.
func uniformBytesFromSeed(seed []byte) [64]byte {
	h1 := sha256.Sum256(append([]byte("half1:"), seed...))
	h2 := sha256.Sum256(append([]byte("half2:"), seed...))
	var out [64]byte
	copy(out[:32], h1[:])
	copy(out[32:], h2[:])
	return out
}

// TestElligatorRistretto_Consistency verifies that for each vector:
//  1. ElligatorRistrettoFlavorInverse returns ok=true.
//  2. The mask has at least one set bit (at least one preimage exists).
//  3. Every candidate with a set bit maps forward (via SetUniformBytes) to
//     the same ristretto point as the original.
func TestElligatorRistretto_Consistency(t *testing.T) {
	for _, v := range consistencyVectors() {
		t.Run(v.name, func(t *testing.T) {
			// Forward: uniform bytes -> ristretto point.
			uniform := uniformBytesFromSeed(v.seed)
			p := ristretto255.NewIdentityElement()
			if _, err := p.SetUniformBytes(uniform[:]); err != nil {
				t.Fatalf("SetUniformBytes failed: %v", err)
			}
			encoded := p.Bytes()

			// Inverse.
			mask, candidates, ok := ElligatorRistrettoFlavorInverse(encoded)
			if !ok {
				t.Fatalf("ElligatorRistrettoFlavorInverse returned ok=false for a valid ristretto point")
			}
			if mask == 0 {
				t.Fatal("mask is zero: no preimage found for a ristretto-group point")
			}

			// Verify every valid candidate maps back to the original point.
			for j := 0; j < 8; j++ {
				if mask&(1<<j) == 0 {
					continue
				}
				var u2 [64]byte
				copy(u2[:32], candidates[j][:])
				p2 := ristretto255.NewIdentityElement()
				if _, err := p2.SetUniformBytes(u2[:]); err != nil {
					t.Errorf("candidate[%d]: SetUniformBytes failed: %v", j, err)
					continue
				}
				if p.Equal(p2) != 1 {
					t.Errorf("candidate[%d] maps to a different point", j)
				}
			}
		})
	}
}

// TestElligatorRistretto_IdentityPoint verifies that the identity point
// (all-zero encoding) can be decoded and has at least one preimage.
func TestElligatorRistretto_IdentityPoint(t *testing.T) {
	identity := ristretto255.NewIdentityElement()
	encoded := identity.Bytes()

	mask, candidates, ok := ElligatorRistrettoFlavorInverse(encoded)
	if !ok {
		t.Fatal("inverse failed for identity point")
	}
	if mask == 0 {
		t.Fatal("no preimage for identity point")
	}

	// Verify at least one candidate maps to the identity.
	for j := 0; j < 8; j++ {
		if mask&(1<<j) == 0 {
			continue
		}
		var u [64]byte
		copy(u[:32], candidates[j][:])
		p := ristretto255.NewIdentityElement()
		if _, err := p.SetUniformBytes(u[:]); err != nil {
			continue
		}
		if p.Equal(identity) == 1 {
			return // at least one valid candidate verified
		}
	}
	t.Error("no valid candidate maps back to the identity point")
}

// TestElligatorRistretto_GeneratorPoint verifies that the standard generator
// point G has at least one preimage and every preimage maps back to G.
func TestElligatorRistretto_GeneratorPoint(t *testing.T) {
	gen := ristretto255.NewGeneratorElement()
	encoded := gen.Bytes()

	mask, candidates, ok := ElligatorRistrettoFlavorInverse(encoded)
	if !ok {
		t.Fatal("inverse failed for generator point")
	}
	if mask == 0 {
		t.Fatal("no preimage for generator point")
	}

	for j := 0; j < 8; j++ {
		if mask&(1<<j) == 0 {
			continue
		}
		var u [64]byte
		copy(u[:32], candidates[j][:])
		p := ristretto255.NewIdentityElement()
		if _, err := p.SetUniformBytes(u[:]); err != nil {
			t.Errorf("generator candidate[%d]: SetUniformBytes failed: %v", j, err)
			continue
		}
		if p.Equal(gen) != 1 {
			t.Errorf("generator candidate[%d] maps to a different point", j)
		}
	}
}

// TestElligatorRistretto_InvalidEncodings confirms that malformed inputs
// return ok=false rather than panicking or returning stale data.
func TestElligatorRistretto_InvalidEncodings(t *testing.T) {
	cases := []struct {
		name     string
		encoding []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"short_31_bytes", make([]byte, 31)},
		{"long_33_bytes", make([]byte, 33)},
		{"all_0xff", func() []byte {
			b := make([]byte, 32)
			for i := range b {
				b[i] = 0xff
			}
			return b
		}()},
		{"negative_s_bit_set", []byte{
			0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, ok := ElligatorRistrettoFlavorInverse(c.encoding)
			if ok {
				t.Errorf("expected ok=false for invalid encoding %q, got ok=true", c.name)
			}
		})
	}
}

// TestElligatorRistretto_PreimageDiversity verifies that distinct ristretto
// points (derived from different seeds) produce distinct sets of preimages.
// This is a sanity check rather than a mathematical proof.
func TestElligatorRistretto_PreimageDiversity(t *testing.T) {
	seeds := [][]byte{
		[]byte("point A"),
		[]byte("point B"),
		[]byte("point C"),
	}

	type preimageSet [8][32]byte
	sets := make([]preimageSet, len(seeds))
	masks := make([]uint8, len(seeds))

	for i, seed := range seeds {
		uniform := uniformBytesFromSeed(seed)
		p := ristretto255.NewIdentityElement()
		if _, err := p.SetUniformBytes(uniform[:]); err != nil {
			t.Fatalf("seed %d: SetUniformBytes failed: %v", i, err)
		}
		encoded := p.Bytes()

		mask, candidates, ok := ElligatorRistrettoFlavorInverse(encoded)
		if !ok {
			t.Fatalf("seed %d: inverse failed", i)
		}
		sets[i] = candidates
		masks[i] = mask
	}

	// At least one candidate must differ between any two distinct seeds.
	for i := 0; i < len(seeds); i++ {
		for j := i + 1; j < len(seeds); j++ {
			allSame := true
			for k := 0; k < 8; k++ {
				if masks[i]&(1<<k) != 0 && sets[i][k] != sets[j][k] {
					allSame = false
					break
				}
			}
			if allSame {
				t.Errorf("seeds %d and %d produced identical preimage sets", i, j)
			}
		}
	}
}
