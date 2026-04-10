// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package attest

import (
	"testing"
	"time"
)

func TestForSGX_EmptyEvidence(t *testing.T) {
	mrenclave := make([]byte, MREnclaveSize)
	_, err := ForSGX(mrenclave, nil, []byte{1}, nil, time.Now(), PreQuantum)
	if err == nil {
		t.Fatal("expected error for empty evidence")
	}
}

func TestForSGX_EmptyEndorsements(t *testing.T) {
	mrenclave := make([]byte, MREnclaveSize)
	_, err := ForSGX(mrenclave, []byte{1}, nil, nil, time.Now(), PreQuantum)
	if err == nil {
		t.Fatal("expected error for empty endorsements")
	}
}

func TestForSGX_InvalidMREnclaveLength(t *testing.T) {
	tests := []struct {
		name      string
		mrenclave []byte
	}{
		{"too short", make([]byte, 16)},
		{"too long", make([]byte, 64)},
		{"empty", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ForSGX(tt.mrenclave, []byte{1}, []byte{1}, nil, time.Now(), PreQuantum)
			if err == nil {
				t.Fatal("expected error for invalid mrenclave length")
			}
		})
	}
}

func TestForSGX_InvalidEvidenceData(t *testing.T) {
	// Valid lengths but garbage data should fail during attestation verification
	mrenclave := make([]byte, MREnclaveSize)
	evidence := []byte{0x01, 0x02, 0x03, 0x04}
	endorsements := []byte{0x05, 0x06, 0x07, 0x08}

	_, err := ForSGX(mrenclave, evidence, endorsements, nil, time.Now(), PreQuantum)
	if err == nil {
		t.Fatal("expected error for garbage evidence/endorsement data")
	}
}

func TestForSGX_PostQuantumAndPreQuantumBothFailOnBadData(t *testing.T) {
	// Both PreQuantum (NK) and PostQuantum (NKhfs) should fail attestation
	// verification with invalid evidence/endorsement data, not panic.
	mrenclave := make([]byte, MREnclaveSize)

	_, err1 := ForSGX(mrenclave, []byte{1}, []byte{1}, nil, time.Now(), PreQuantum)
	_, err2 := ForSGX(mrenclave, []byte{1}, []byte{1}, nil, time.Now(), PostQuantum)

	if err1 == nil || err2 == nil {
		t.Fatal("both should fail with invalid attestation data")
	}
}
