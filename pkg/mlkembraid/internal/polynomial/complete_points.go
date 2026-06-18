// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package polynomial

import "github.com/jeremyhahn/go-libsignal/pkg/mlkembraid/internal/gf"

// This file contains the Lagrange basis polynomials for the "complete" point
// sets used by Protocol V1. In the Rust reference these are computed at
// compile time as const values; in Go we compute them once at package init
// using the same algorithm (lagrangeInterpolatePt on a set of ones-points).
//
// A "complete" point set of size N has x-values exactly {0, 1, ..., N-1}
// and y-values all 1. The N basis polynomials polys[i] satisfy:
//
//	polys[i](i) = 1
//	polys[i](j) = 0  for j != i, j in {0..N-1}
//
// Supported sizes in Protocol V1 (MLKEM-768): 1, 3, 5, 30, 34, 36.
// These are the only sizes dispatched to in fromCompletePoints.

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
