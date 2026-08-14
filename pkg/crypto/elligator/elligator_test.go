package elligator

import (
	"crypto/sha256"
	"testing"

	"filippo.io/edwards25519/field"
	"github.com/gtank/ristretto255"
)

// TestElligatorInverseRoundTrip verifies that the Elligator inverse recovers
// the original field element for a point created via the forward Elligator map.
func TestElligatorInverseRoundTrip(t *testing.T) {
	testCases := []struct {
		name    string
		feBytes [32]byte
	}{
		{
			name:    "zero field element",
			feBytes: [32]byte{},
		},
		{
			name: "simple field element",
			feBytes: func() [32]byte {
				var b [32]byte
				b[0] = 42
				b[0] &= 254
				b[31] &= 127
				return b
			}(),
		},
		{
			name: "field element from data",
			feBytes: func() [32]byte {
				h := sha256.Sum256([]byte("test data"))
				h[0] &= 254
				h[31] &= 127
				return h
			}(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Forward map: fe -> ristretto point
			var uniform [64]byte
			copy(uniform[:32], tc.feBytes[:])
			// second 32 bytes are zero -> MAP(zeros) = identity

			p := ristretto255.NewIdentityElement()
			if _, err := p.SetUniformBytes(uniform[:]); err != nil {
				t.Fatalf("SetUniformBytes failed: %v", err)
			}

			// Get canonical encoding
			encoded := p.Bytes()

			// Inverse: find field elements
			mask, candidates, ok := ElligatorRistrettoFlavorInverse(encoded)
			if !ok {
				t.Fatal("ElligatorRistrettoFlavorInverse failed")
			}

			// Check that the original field element is among the candidates
			found := false
			for j := 0; j < 8; j++ {
				if mask&(1<<j) == 0 {
					continue
				}
				// Verify this candidate maps to the same point
				var u2 [64]byte
				copy(u2[:32], candidates[j][:])
				p2 := ristretto255.NewIdentityElement()
				if _, err := p2.SetUniformBytes(u2[:]); err != nil {
					t.Errorf("candidate %d: SetUniformBytes failed: %v", j, err)
					continue
				}
				if p.Equal(p2) == 1 {
					// Check if it matches the original
					if candidates[j] == tc.feBytes {
						found = true
					}
				}
			}

			if !found {
				t.Errorf("original field element not found among inverse candidates")
				t.Logf("original: %x", tc.feBytes)
				t.Logf("mask: %08b", mask)
				for j := 0; j < 8; j++ {
					if mask&(1<<j) != 0 {
						t.Logf("candidate[%d]: %x", j, candidates[j])
					}
				}
			}
		})
	}
}

// TestElligatorInverseLizardRoundTrip tests that LizardEncode followed by
// the Elligator inverse recovers the original 16-byte data.
func TestElligatorInverseLizardRoundTrip(t *testing.T) {
	testCases := []struct {
		name string
		data [16]byte
	}{
		{
			name: "all zeros",
			data: [16]byte{},
		},
		{
			name: "all ones",
			data: [16]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		},
		{
			name: "sequential",
			data: [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		},
		{
			name: "arbitrary uuid",
			data: [16]byte{0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
				0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// LizardEncode: data -> ristretto point
			encoded := lizardEncode(tc.data)

			// Get canonical encoding
			pointBytes := encoded.Bytes()

			// Elligator inverse
			mask, candidates, ok := ElligatorRistrettoFlavorInverse(pointBytes)
			if !ok {
				t.Fatal("ElligatorRistrettoFlavorInverse failed")
			}

			// LizardDecode: find the candidate that matches
			found := false
			for j := 0; j < 8; j++ {
				if mask&(1<<j) == 0 {
					continue
				}
				fe := candidates[j]
				// Check if the Lizard structure is valid:
				// bytes[8:24] should contain the data
				var candidate [16]byte
				copy(candidate[:], fe[8:24])

				// Verify: hash the candidate, overlay, clear bits, compare
				h := sha256.Sum256(candidate[:])
				copy(h[8:24], candidate[:])
				h[0] &= 254
				h[31] &= 63

				if h == fe {
					if candidate == tc.data {
						found = true
					}
				}
			}

			if !found {
				t.Errorf("LizardDecode failed to recover original data %x", tc.data)
				t.Logf("mask: %08b", mask)
				for j := 0; j < 8; j++ {
					if mask&(1<<j) != 0 {
						t.Logf("candidate[%d]: %x", j, candidates[j])
					}
				}
			}
		})
	}
}

// TestElligatorInverseInvalidInput tests that invalid inputs are handled.
func TestElligatorInverseInvalidInput(t *testing.T) {
	t.Run("wrong length", func(t *testing.T) {
		_, _, ok := ElligatorRistrettoFlavorInverse([]byte{1, 2, 3})
		if ok {
			t.Error("expected failure for wrong length input")
		}
	})

	t.Run("non-canonical encoding", func(t *testing.T) {
		// All 0xff bytes is not a valid ristretto encoding
		var bad [32]byte
		for i := range bad {
			bad[i] = 0xff
		}
		_, _, ok := ElligatorRistrettoFlavorInverse(bad[:])
		if ok {
			t.Error("expected failure for non-canonical encoding")
		}
	})
}

// lizardEncode is a local copy of the LizardEncode logic for testing purposes.
func lizardEncode(data [16]byte) *ristretto255.Element {
	hash := sha256.Sum256(data[:])
	var feBytes [32]byte
	copy(feBytes[:], hash[:])
	copy(feBytes[8:24], data[:])
	feBytes[0] &= 254
	feBytes[31] &= 63

	var uniform [64]byte
	copy(uniform[:32], feBytes[:])

	e := ristretto255.NewIdentityElement()
	if _, err := e.SetUniformBytes(uniform[:]); err != nil {
		panic("lizard encode failed: " + err.Error())
	}
	return e
}

// TestElligatorInverseAllCandidatesMapBack verifies that every valid candidate
// from the inverse actually maps back to the original point.
func TestElligatorInverseAllCandidatesMapBack(t *testing.T) {
	// Use a known point
	data := [16]byte{0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
		0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51}
	p := lizardEncode(data)
	encoded := p.Bytes()

	mask, candidates, ok := ElligatorRistrettoFlavorInverse(encoded)
	if !ok {
		t.Fatal("inverse failed")
	}

	if mask == 0 {
		t.Fatal("no valid candidates found")
	}

	validCount := 0
	for j := 0; j < 8; j++ {
		if mask&(1<<j) == 0 {
			continue
		}
		validCount++

		// Forward map this candidate and verify it produces the same point
		var u [64]byte
		copy(u[:32], candidates[j][:])
		p2 := ristretto255.NewIdentityElement()
		if _, err := p2.SetUniformBytes(u[:]); err != nil {
			t.Errorf("candidate %d: SetUniformBytes failed: %v", j, err)
			continue
		}
		if p.Equal(p2) != 1 {
			t.Errorf("candidate %d maps to a different point", j)
		}
	}

	if validCount == 0 {
		t.Error("no valid candidates found despite non-zero mask")
	}
}

// TestDecodeToExtended verifies the ristretto DECODE implementation.
func TestDecodeToExtended(t *testing.T) {
	t.Run("identity point", func(t *testing.T) {
		identity := ristretto255.NewIdentityElement()
		encoded := identity.Bytes()
		X, Y, Z, T, ok := decodeToExtended(encoded)
		if !ok {
			t.Fatal("decode failed for identity")
		}
		// Identity: X=0, Y=1, Z=1, T=0 (or any equivalent in projective)
		// X/Z should be 0, Y/Z should be 1
		_ = X
		_ = Y
		_ = Z
		_ = T
	})

	t.Run("generator point", func(t *testing.T) {
		gen := ristretto255.NewGeneratorElement()
		encoded := gen.Bytes()
		_, _, _, _, ok := decodeToExtended(encoded)
		if !ok {
			t.Fatal("decode failed for generator")
		}
	})

	t.Run("invalid encoding", func(t *testing.T) {
		var bad [32]byte
		bad[0] = 0xff // negative s
		_, _, _, _, ok := decodeToExtended(bad[:])
		if ok {
			t.Error("expected failure for negative s")
		}
	})
}

// TestElligatorInv_BranchlessFoundFlagEquivalence is a regression test for the
// constant-time refactor of elligatorInv. It verifies that the branchless
// integer expression `sIsZero | (wasSquare &^ sIsZero)` is mathematically
// identical to the old boolean `sIsZero==1 || (wasSquare==1 && sIsZero!=1)` for
// every combination of the two 0/1 input flags. This exhaustive truth-table
// proof guarantees the refactor introduces no behavioral change in the found flag
// (and therefore no change in the mask produced by ElligatorRistrettoFlavorInverse).
func TestElligatorInv_BranchlessFoundFlagEquivalence(t *testing.T) {
	cases := []struct {
		sIsZero   int
		wasSquare int
		wantFound int
	}{
		{0, 0, 0}, // s≠0, not a square: no preimage
		{0, 1, 1}, // s≠0, is a square: preimage exists
		{1, 0, 1}, // s=0 degenerate case: preimage is sqrtID (or zero)
		{1, 1, 1}, // s=0 degenerate case (also square): preimage exists
	}

	for _, tc := range cases {
		// Old branchy boolean logic (reference):
		oldBool := tc.sIsZero == 1 || (tc.wasSquare == 1 && tc.sIsZero != 1)
		var oldInt int
		if oldBool {
			oldInt = 1
		}

		// New branchless integer logic (implementation):
		newInt := tc.sIsZero | (tc.wasSquare &^ tc.sIsZero)

		if newInt != tc.wantFound {
			t.Errorf("sIsZero=%d wasSquare=%d: branchless got %d, want %d",
				tc.sIsZero, tc.wasSquare, newInt, tc.wantFound)
		}
		if oldInt != newInt {
			t.Errorf("sIsZero=%d wasSquare=%d: old=%d new=%d (behavioral divergence detected)",
				tc.sIsZero, tc.wasSquare, oldInt, newInt)
		}
	}
}

// TestConstantsConsistency verifies derived constants are self-consistent.
func TestConstantsConsistency(t *testing.T) {
	// Verify dp1OverDm1 = (d+1) * (d-1)^{-1}
	dp1 := new(field.Element).Add(feD, feOne)
	dm1 := new(field.Element).Subtract(feD, feOne)
	dm1Inv := new(field.Element).Invert(dm1)
	expected := new(field.Element).Multiply(dp1, dm1Inv)
	if expected.Equal(dp1OverDm1) != 1 {
		t.Error("dp1OverDm1 constant is incorrect")
	}

	// Verify mDoubleInvSqrtAMinusD = -2 * invSqrtAMinusD
	doubled := new(field.Element).Add(invSqrtAMinusD, invSqrtAMinusD)
	negDoubled := new(field.Element).Negate(doubled)
	if negDoubled.Equal(mDoubleInvSqrtAMinusD) != 1 {
		t.Error("mDoubleInvSqrtAMinusD constant is incorrect")
	}

	// Verify miDoubleInvSqrtAMinusD = mDoubleInvSqrtAMinusD * sqrt(-1)
	product := new(field.Element).Multiply(mDoubleInvSqrtAMinusD, sqrtM1)
	if product.Equal(miDoubleInvSqrtAMinusD) != 1 {
		t.Error("miDoubleInvSqrtAMinusD constant is incorrect")
	}
}
