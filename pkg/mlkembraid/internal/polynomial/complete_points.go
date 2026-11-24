// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package polynomial

import "github.com/jeremyhahn/go-libsignal/pkg/mlkembraid/internal/gf"

// Lagrange basis polynomials for complete point sets (x = 0..N-1, y = 1) of sizes 1, 3, 5, 30, 34 and 36, computed at init as Rust does at compile time.

var (
	completePointsPolys1  [1]Poly
	completePointsPolys3  [3]Poly
	completePointsPolys5  [5]Poly
	completePointsPolys30 [30]Poly
	completePointsPolys34 [34]Poly
	completePointsPolys36 [36]Poly
)

func init() {
	fillCompletePoints(completePointsPolys1[:], 1)
	fillCompletePoints(completePointsPolys3[:], 3)
	fillCompletePoints(completePointsPolys5[:], 5)
	fillCompletePoints(completePointsPolys30[:], 30)
	fillCompletePoints(completePointsPolys34[:], 34)
	fillCompletePoints(completePointsPolys36[:], 36)
}

// fillCompletePoints populates out[i] with the Lagrange basis polynomial for
// the complete point set {(0,1), (1,1), ..., (n-1,1)}.
// Mirrors Rust's lagrange_polys_for_complete_points::<N>.
func fillCompletePoints(out []Poly, n int) {
	// Build the ones-point set: pts[i] = (i, 1).
	ones := make([]pt, n)
	for i := range ones {
		ones[i] = pt{x: gf.GF16{Value: uint16(i)}, y: gf.One}
	}
	for i := range out {
		out[i] = lagrangeInterpolatePt(ones, i)
	}
}
