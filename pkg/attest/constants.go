// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package attest

// Enclave IDs (MRENCLAVE values) for known Signal enclaves.
var (
	EnclaveIDSVR2_2025Q3Prod    = mustDecodeHex("29cd63c87bea751e3bfd0fbd401279192e2e5c99948b4ee9437eafc4968355fb")
	EnclaveIDSVRB_2025Q3Prod    = mustDecodeHex("aa906dbc85965d37accb660b65a8c224f037b0e7cfd034532acada3592e5b446")
	EnclaveIDSVR2_2026Q1Staging = mustDecodeHex("97f151f6ed078edbbfd72fa9cae694dcc08353f1f5e8d9ccd79a971b10ffc535")
	EnclaveIDSVR2_2026Q1Prod    = mustDecodeHex("1240acbd4aa26974184844c8a46b1022d3957ac8a76c1fd8f5b1a15141ee0708")
	EnclaveIDSVRB_2026Q1Staging = mustDecodeHex("97f151f6ed078edbbfd72fa9cae694dcc08353f1f5e8d9ccd79a971b10ffc535")
	EnclaveIDSVRB_2026Q1Prod    = mustDecodeHex("bee62050df1072e3d9fdf7660bfaf4e4b71f5622db9de8b30fc5f4b9852d8359")
	EnclaveIDCDSIStaging        = mustDecodeHex("3a1ac5e5b07c3f01d0b8074687616082a618e0a7f69a2f558e0f6fe4965db4e1")
	EnclaveIDCDSIProd           = mustDecodeHex("ee9503070127120074612b6688e593b67e486b1541449f54d71e387484eb40a3")
)

// Common SW advisories known to be mitigated.
var commonSWAdvisories = []string{"INTEL-SA-00615", "INTEL-SA-00657"}

// DefaultSWAdvisories are SW advisories known to be mitigated by default.
var DefaultSWAdvisories = []string{}

// acceptableSWAdvisories maps MRENCLAVE values to their known mitigated advisories.
var acceptableSWAdvisories = []struct {
	mrenclave  []byte
	advisories []string
}{
	{EnclaveIDSVR2_2025Q3Prod, commonSWAdvisories},
	{EnclaveIDSVRB_2025Q3Prod, commonSWAdvisories},
	{EnclaveIDSVR2_2026Q1Staging, commonSWAdvisories},
	{EnclaveIDSVR2_2026Q1Prod, commonSWAdvisories},
	{EnclaveIDSVRB_2026Q1Staging, commonSWAdvisories},
	{EnclaveIDSVRB_2026Q1Prod, commonSWAdvisories},
	{EnclaveIDCDSIStaging, commonSWAdvisories},
	{EnclaveIDCDSIProd, commonSWAdvisories},
}

// GetSWAdvisories returns the list of acceptable SW advisories for a given MRENCLAVE.
func GetSWAdvisories(mrenclave []byte) []string {
	for _, entry := range acceptableSWAdvisories {
		if bytesEqualSlice(entry.mrenclave, mrenclave) {
			return entry.advisories
		}
	}
	return DefaultSWAdvisories
}

// Raft configurations for known SVR2 enclaves.
var (
	RaftConfigSVR2_2025Q3Prod = &RaftConfig{
		MinVotingReplicas:  4,
		MaxVotingReplicas:  13,
		SuperMajority:      2,
		GroupID:            10263621230883829694,
		DBVersion:          2,
		AttestationTimeout: 604800,
		Simulated:          false,
	}

	RaftConfigSVRB_2025Q3Prod = &RaftConfig{
		MinVotingReplicas:  4,
		MaxVotingReplicas:  13,
		SuperMajority:      2,
		GroupID:            17845984565043772621,
		DBVersion:          4,
		AttestationTimeout: 604800,
		Simulated:          false,
	}

	RaftConfigSVR2_2026Q1Staging = &RaftConfig{
		MinVotingReplicas:  3,
		MaxVotingReplicas:  9,
		SuperMajority:      0,
		GroupID:            2330628069874851020,
		DBVersion:          2,
		AttestationTimeout: 604800,
		Simulated:          false,
	}

	RaftConfigSVR2_2026Q1Prod = &RaftConfig{
		MinVotingReplicas:  4,
		MaxVotingReplicas:  13,
		SuperMajority:      2,
		GroupID:            2076725645304009823,
		DBVersion:          2,
		AttestationTimeout: 604800,
		Simulated:          false,
	}

	RaftConfigSVRB_2026Q1Staging = &RaftConfig{
		MinVotingReplicas:  3,
		MaxVotingReplicas:  9,
		SuperMajority:      0,
		GroupID:            1416305463306398324,
		DBVersion:          4,
		AttestationTimeout: 604800,
		Simulated:          false,
	}

	RaftConfigSVRB_2026Q1Prod = &RaftConfig{
		MinVotingReplicas:  4,
		MaxVotingReplicas:  13,
		SuperMajority:      2,
		GroupID:            16652830871035963553,
		DBVersion:          4,
		AttestationTimeout: 604800,
		Simulated:          false,
	}
)

// expectedRaftConfigSVR2 maps MRENCLAVE values to their expected raft configs
// for SVR2 bridging code.
var expectedRaftConfigSVR2 = []struct {
	mrenclave []byte
	config    *RaftConfig
}{
	{EnclaveIDSVR2_2025Q3Prod, RaftConfigSVR2_2025Q3Prod},
	{EnclaveIDSVR2_2026Q1Staging, RaftConfigSVR2_2026Q1Staging},
	{EnclaveIDSVR2_2026Q1Prod, RaftConfigSVR2_2026Q1Prod},
}

func mustDecodeHex(s string) []byte {
	if len(s)%2 != 0 {
		panic("hex string has odd length")
	}
	b := make([]byte, len(s)/2)
	for i := 0; i < len(b); i++ {
		hi, err := hexNibble(s[i*2])
		if err != nil {
			panic(err)
		}
		lo, err := hexNibble(s[i*2+1])
		if err != nil {
			panic(err)
		}
		b[i] = hi<<4 | lo
	}
	return b
}
