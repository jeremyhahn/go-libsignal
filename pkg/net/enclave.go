// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package net

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/attest"
)

// EnclaveKind identifies the type of enclave service.
type EnclaveKind int

const (
	// EnclaveKindCDSI represents the Contact Discovery Service enclave.
	EnclaveKindCDSI EnclaveKind = iota
	// EnclaveKindSvrSgx represents the Secure Value Recovery SGX enclave.
	EnclaveKindSvrSgx
)

// URLPath returns the WebSocket endpoint path for the given enclave kind
// and MR_ENCLAVE value.
func (k EnclaveKind) URLPath(mrEnclave []byte) string {
	enclaveHex := hex.EncodeToString(mrEnclave)
	switch k {
	case EnclaveKindCDSI:
		return fmt.Sprintf("/v1/%s/discovery", enclaveHex)
	case EnclaveKindSvrSgx:
		return fmt.Sprintf("/v1/%s", enclaveHex)
	default:
		return fmt.Sprintf("/v1/%s", enclaveHex)
	}
}

// MrEnclave wraps an MRENCLAVE measurement value for an SGX enclave.
type MrEnclave struct {
	// Value is the raw MRENCLAVE bytes (typically 32 bytes).
	Value []byte
	// Kind identifies the type of enclave this measurement is for.
	Kind EnclaveKind
}

// EndpointParams contains the attestation parameters for connecting to a
// specific enclave endpoint.
type EndpointParams struct {
	// MrEnclave is the expected MRENCLAVE measurement.
	MrEnclave MrEnclave
	// RaftConfig is the expected Raft configuration for SVR enclaves.
	// This is nil for CDSI enclaves.
	RaftConfig *attest.RaftConfig
}

// EnclaveEndpoint describes a complete endpoint for connecting to an enclave
// service, combining domain configuration, WebSocket settings, and
// attestation parameters.
type EnclaveEndpoint struct {
	// DomainConfig contains the connection configuration for this endpoint.
	DomainConfig DomainConfig
	// WSConfig contains WebSocket-specific configuration.
	WSConfig WSConfig
	// Params contains the attestation parameters.
	Params EndpointParams
}

// NewHandshaker creates an attestation handshake for the enclave endpoint.
// It dispatches to the appropriate attest package function based on the
// enclave kind.
type NewHandshaker interface {
	// NewHandshake creates a new attestation handshake from the endpoint
	// parameters and the attestation message received from the server.
	NewHandshake(params *EndpointParams, attestationMessage []byte) (*attest.Handshake, error)
}

// CDSIHandshaker creates CDSI attestation handshakes.
type CDSIHandshaker struct{}

// NewHandshake creates a new CDS2 handshake.
func (h *CDSIHandshaker) NewHandshake(params *EndpointParams, attestationMessage []byte) (*attest.Handshake, error) {
	return attest.CDS2NewHandshake(
		params.MrEnclave.Value,
		attestationMessage,
		time.Now(),
	)
}

// SvrSgxHandshaker creates SVR SGX attestation handshakes.
type SvrSgxHandshaker struct{}

// NewHandshake creates a new SVR2 handshake.
func (h *SvrSgxHandshaker) NewHandshake(params *EndpointParams, attestationMessage []byte) (*attest.Handshake, error) {
	if params.RaftConfig == nil {
		return nil, &ErrMissingRaftConfig{}
	}
	return attest.SVR2NewHandshake(
		params.MrEnclave.Value,
		attestationMessage,
		time.Now(),
		params.RaftConfig,
	)
}
