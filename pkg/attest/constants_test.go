// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package attest

import (
	"testing"
)

func TestMustDecodeHex(t *testing.T) {
	tests := []struct {
		name string
		hex  string
		want []byte
	}{
		{
			name: "empty string",
			hex:  "",
			want: []byte{},
		},
		{
			name: "single byte",
			hex:  "ff",
			want: []byte{0xff},
		},
		{
			name: "multiple bytes lowercase",
			hex:  "deadbeef",
			want: []byte{0xde, 0xad, 0xbe, 0xef},
		},
		{
			name: "uppercase",
			hex:  "ABCD",
			want: []byte{0xab, 0xcd},
		},
		{
			name: "mixed case",
			hex:  "aAbBcC",
			want: []byte{0xaa, 0xbb, 0xcc},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mustDecodeHex(tt.hex)
			if len(got) != len(tt.want) {
				t.Fatalf("len = %d, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("byte[%d] = 0x%02x, want 0x%02x", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestMustDecodeHex_PanicsOnOddLength(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for odd-length hex string")
		}
	}()
	mustDecodeHex("abc")
}

func TestMustDecodeHex_PanicsOnInvalidChar(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for invalid hex char")
		}
	}()
	mustDecodeHex("zz")
}

func TestGetSWAdvisories_KnownMREnclave(t *testing.T) {
	advisories := GetSWAdvisories(EnclaveIDSVR2_2025Q3Prod)
	if len(advisories) != len(commonSWAdvisories) {
		t.Fatalf("expected %d advisories, got %d", len(commonSWAdvisories), len(advisories))
	}
	for i, a := range advisories {
		if a != commonSWAdvisories[i] {
			t.Errorf("advisory[%d] = %q, want %q", i, a, commonSWAdvisories[i])
		}
	}
}

func TestGetSWAdvisories_UnknownMREnclave(t *testing.T) {
	unknown := make([]byte, 32)
	advisories := GetSWAdvisories(unknown)
	if len(advisories) != len(DefaultSWAdvisories) {
		t.Fatalf("expected default advisories (len %d), got %d", len(DefaultSWAdvisories), len(advisories))
	}
}

func TestGetSWAdvisories_AllKnownEnclaves(t *testing.T) {
	// Every known enclave in acceptableSWAdvisories should return commonSWAdvisories.
	for _, entry := range acceptableSWAdvisories {
		got := GetSWAdvisories(entry.mrenclave)
		if len(got) != len(entry.advisories) {
			t.Errorf("mrenclave %x: got %d advisories, want %d", entry.mrenclave, len(got), len(entry.advisories))
		}
	}
}

func TestEnclaveIDsAre32Bytes(t *testing.T) {
	ids := []struct {
		name string
		val  []byte
	}{
		{"SVR2_2025Q3Prod", EnclaveIDSVR2_2025Q3Prod},
		{"SVRB_2025Q3Prod", EnclaveIDSVRB_2025Q3Prod},
		{"SVR2_2026Q1Staging", EnclaveIDSVR2_2026Q1Staging},
		{"SVR2_2026Q1Prod", EnclaveIDSVR2_2026Q1Prod},
		{"SVRB_2026Q1Staging", EnclaveIDSVRB_2026Q1Staging},
		{"SVRB_2026Q1Prod", EnclaveIDSVRB_2026Q1Prod},
		{"CDSIStaging", EnclaveIDCDSIStaging},
		{"CDSIProd", EnclaveIDCDSIProd},
	}
	for _, id := range ids {
		t.Run(id.name, func(t *testing.T) {
			if len(id.val) != MREnclaveSize {
				t.Errorf("len = %d, want %d", len(id.val), MREnclaveSize)
			}
		})
	}
}

func TestRaftConfigsNotNil(t *testing.T) {
	configs := []*RaftConfig{
		RaftConfigSVR2_2025Q3Prod,
		RaftConfigSVRB_2025Q3Prod,
		RaftConfigSVR2_2026Q1Staging,
		RaftConfigSVR2_2026Q1Prod,
		RaftConfigSVRB_2026Q1Staging,
		RaftConfigSVRB_2026Q1Prod,
	}
	for i, c := range configs {
		if c == nil {
			t.Errorf("config[%d] is nil", i)
			continue
		}
		if c.AttestationTimeout == 0 {
			t.Errorf("config[%d] has zero AttestationTimeout", i)
		}
	}
}
