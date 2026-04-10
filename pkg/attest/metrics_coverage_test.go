// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package attest

import (
	"testing"
)

// TestAttestationMetrics_ValidEvidenceWithQEReport verifies that AttestationMetrics
// extracts QE report fields from parseable evidence.
func TestAttestationMetrics_ValidEvidenceWithQEReport(t *testing.T) {
	evidence := buildMinimalValidEvidence(t)
	metrics, err := AttestationMetrics(evidence, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if metrics == nil {
		t.Fatal("expected non-nil metrics")
	}
	// With minimal evidence, qeReportBody is set - qe_isvsvn and qe_isvprodid should be present.
	if _, ok := metrics["qe_isvsvn"]; !ok {
		t.Fatal("expected qe_isvsvn in metrics")
	}
	if _, ok := metrics["qe_isvprodid"]; !ok {
		t.Fatal("expected qe_isvprodid in metrics")
	}
}
