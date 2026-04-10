// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package attest

import (
	"time"
)

const (
	invalidEvidence  = "Evidence does not fit expected format"
	invalidEndorsement = "Endorsement does not fit expected format"
	invalidMREnclave = "MREnclave value does not fit expected format"

	// skewAdjustment is how much to offset when checking for time-based validity
	// checks to adjust for clock skew on clients (24 hours).
	skewAdjustment = 24 * time.Hour
)

// MREnclaveSize is the size of an MRENCLAVE value in bytes.
const MREnclaveSize = 32

// MREnclave is a 32-byte MRENCLAVE value that identifies an enclave binary.
type MREnclave [MREnclaveSize]byte

// ForSGX creates a new handshake for an SGX enclave using DCAP attestation.
//
// Parameters:
//   - mrenclave: expected MRENCLAVE value (32 bytes)
//   - evidence: DCAP evidence bytes
//   - endorsements: DCAP endorsement bytes
//   - acceptableSWAdvisories: list of Intel SW advisory IDs known to be mitigated
//   - currentTime: current system time for validity checks
//   - handshakeType: PreQuantum or PostQuantum
func ForSGX(
	mrenclave []byte,
	evidence []byte,
	endorsements []byte,
	acceptableSWAdvisories []string,
	currentTime time.Time,
	handshakeType HandshakeType,
) (*UnvalidatedHandshake, error) {
	if len(evidence) == 0 {
		return nil, newAttestationDataError(invalidEvidence)
	}
	if len(endorsements) == 0 {
		return nil, newAttestationDataError(invalidEndorsement)
	}
	if len(mrenclave) != MREnclaveSize {
		return nil, newAttestationDataError(invalidMREnclave)
	}

	var expectedMREnclave MREnclave
	copy(expectedMREnclave[:], mrenclave)

	// Verify the remote attestation and extract the custom claims.
	// The skew adjustment is added to current time for certificate validity checks.
	adjustedTime := currentTime.Add(skewAdjustment)
	customClaims, err := VerifyRemoteAttestation(
		evidence,
		endorsements,
		&expectedMREnclave,
		acceptableSWAdvisories,
		adjustedTime,
	)
	if err != nil {
		return nil, newAttestationError(err)
	}

	claims, err := ClaimsFromCustomClaims(customClaims)
	if err != nil {
		return nil, err
	}

	return newHandshakeWithClaims(claims, handshakeType)
}
