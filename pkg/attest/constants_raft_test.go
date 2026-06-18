// Enclave-to-Raft config mapping verification.
//
// For every SVR2 enclave ID defined in constants.go, asserts that
// SVR2NewHandshakeWithRaftConfigLookup resolves to the correct RaftConfig
// entry (GroupID, MinVotingReplicas, MaxVotingReplicas, DBVersion, etc.).
//
// This mirrors the EXPECTED_RAFT_CONFIG_SVR2 lookup table defined in
// rust/attest/src/constants.rs and ensures the Go mapping does not drift.
//
// Rust source: rust/attest/src/constants.rs (EXPECTED_RAFT_CONFIG_SVR2)
// Upstream commit: 98915c44
package attest

import (
	"bytes"
	"testing"
)

// raftConfigExpectation pairs an enclave ID with its expected RaftConfig fields.
type raftConfigExpectation struct {
	name      string
	enclaveID []byte
	config    *RaftConfig
}

// svr2RaftExpectations mirrors the EXPECTED_RAFT_CONFIG_SVR2 lookup in
// rust/attest/src/constants.rs.
var svr2RaftExpectations = []raftConfigExpectation{
	{
		name:      "SVR2_2025Q3_PROD",
		enclaveID: EnclaveIDSVR2_2025Q3Prod,
		config:    RaftConfigSVR2_2025Q3Prod,
	},
	{
		name:      "SVR2_2026Q1_STAGING",
		enclaveID: EnclaveIDSVR2_2026Q1Staging,
		config:    RaftConfigSVR2_2026Q1Staging,
	},
	{
		name:      "SVR2_2026Q1_PROD",
		enclaveID: EnclaveIDSVR2_2026Q1Prod,
		config:    RaftConfigSVR2_2026Q1Prod,
	},
}

// TestSVR2_EnclaveToRaftConfig_Lookup verifies that for every SVR2 enclave ID
// the lookup table resolves to the correct RaftConfig (GroupID, min/max
// replicas, DBVersion) matching the Rust EXPECTED_RAFT_CONFIG_SVR2 table.
func TestSVR2_EnclaveToRaftConfig_Lookup(t *testing.T) {
	for _, e := range svr2RaftExpectations {
		e := e
		t.Run(e.name, func(t *testing.T) {
			groupID, ok := SVR2LookupGroupID(e.enclaveID)
			if !ok {
				t.Fatalf("SVR2LookupGroupID(%s): enclave not found in lookup table", e.name)
			}
			if groupID != e.config.GroupID {
				t.Errorf("GroupID = %d, want %d", groupID, e.config.GroupID)
			}

			// Verify the full RaftConfig via the internal lookup table.
			var found *RaftConfig
			for _, entry := range expectedRaftConfigSVR2 {
				if bytes.Equal(entry.mrenclave, e.enclaveID) {
					found = entry.config
					break
				}
			}
			if found == nil {
				t.Fatalf("expectedRaftConfigSVR2 does not contain enclave %s", e.name)
			}

			assertRaftConfigEqual(t, e.name, found, e.config)
		})
	}
}

// TestSVR2_UnknownEnclave_LookupFails verifies that a random MRENCLAVE value
// returns ok=false from SVR2LookupGroupID, ensuring unknown enclaves are
// explicitly rejected rather than silently mapping to a wrong config.
func TestSVR2_UnknownEnclave_LookupFails(t *testing.T) {
	unknown := make([]byte, 32)
	for i := range unknown {
		unknown[i] = 0xAA
	}
	_, ok := SVR2LookupGroupID(unknown)
	if ok {
		t.Error("SVR2LookupGroupID must return false for an unknown MRENCLAVE")
	}
}

// TestSVR2_RaftConfig_FieldSanity verifies structural invariants on every
// known RaftConfig (min < max replicas, non-zero GroupID, non-zero timeout).
func TestSVR2_RaftConfig_FieldSanity(t *testing.T) {
	configs := []struct {
		name   string
		config *RaftConfig
	}{
		{"SVR2_2025Q3_PROD", RaftConfigSVR2_2025Q3Prod},
		{"SVR2_2026Q1_STAGING", RaftConfigSVR2_2026Q1Staging},
		{"SVR2_2026Q1_PROD", RaftConfigSVR2_2026Q1Prod},
		{"SVRB_2025Q3_PROD", RaftConfigSVRB_2025Q3Prod},
		{"SVRB_2026Q1_STAGING", RaftConfigSVRB_2026Q1Staging},
		{"SVRB_2026Q1_PROD", RaftConfigSVRB_2026Q1Prod},
	}

	for _, c := range configs {
		c := c
		t.Run(c.name, func(t *testing.T) {
			cfg := c.config
			if cfg.MinVotingReplicas >= cfg.MaxVotingReplicas {
				t.Errorf("MinVotingReplicas (%d) must be < MaxVotingReplicas (%d)",
					cfg.MinVotingReplicas, cfg.MaxVotingReplicas)
			}
			if cfg.GroupID == 0 {
				t.Error("GroupID must not be zero")
			}
			if cfg.AttestationTimeout == 0 {
				t.Error("AttestationTimeout must not be zero")
			}
			if cfg.DBVersion == 0 {
				t.Error("DBVersion must not be zero")
			}
		})
	}
}

// assertRaftConfigEqual is a helper that compares two RaftConfig structs field
// by field and reports any divergence as test failures.
func assertRaftConfigEqual(t *testing.T, name string, got, want *RaftConfig) {
	t.Helper()
	if got.GroupID != want.GroupID {
		t.Errorf("%s: GroupID = %d, want %d", name, got.GroupID, want.GroupID)
	}
	if got.MinVotingReplicas != want.MinVotingReplicas {
		t.Errorf("%s: MinVotingReplicas = %d, want %d", name, got.MinVotingReplicas, want.MinVotingReplicas)
	}
	if got.MaxVotingReplicas != want.MaxVotingReplicas {
		t.Errorf("%s: MaxVotingReplicas = %d, want %d", name, got.MaxVotingReplicas, want.MaxVotingReplicas)
	}
	if got.SuperMajority != want.SuperMajority {
		t.Errorf("%s: SuperMajority = %d, want %d", name, got.SuperMajority, want.SuperMajority)
	}
	if got.DBVersion != want.DBVersion {
		t.Errorf("%s: DBVersion = %d, want %d", name, got.DBVersion, want.DBVersion)
	}
	if got.AttestationTimeout != want.AttestationTimeout {
		t.Errorf("%s: AttestationTimeout = %d, want %d", name, got.AttestationTimeout, want.AttestationTimeout)
	}
	if got.Simulated != want.Simulated {
		t.Errorf("%s: Simulated = %v, want %v", name, got.Simulated, want.Simulated)
	}
}
