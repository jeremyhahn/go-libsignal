// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package attest

import (
	"encoding/binary"
	"fmt"

	"github.com/flynn/noise"
)

// HandshakeType represents whether to use pre-quantum or post-quantum handshake.
type HandshakeType int

const (
	// PreQuantum uses the standard Noise_NK_25519_ChaChaPoly_SHA256 pattern.
	PreQuantum HandshakeType = iota
	// PostQuantum uses the Noise_NKhfs_25519+Kyber1024_ChaChaPoly_SHA256 pattern,
	// providing hybrid forward secrecy against quantum adversaries.
	PostQuantum
)

// Claims represents verified claims extracted from an attestation.
type Claims struct {
	PublicKey       []byte
	RaftGroupConfig *RaftConfig
	Custom          map[string][]byte
}

// RaftConfig mirrors the protobuf RaftGroupConfig message.
// It represents a Raft configuration that can be checked against the attested remote config.
type RaftConfig struct {
	MinVotingReplicas  uint32
	MaxVotingReplicas  uint32
	SuperMajority      uint32
	GroupID            uint64
	DBVersion          int32
	AttestationTimeout uint32
	Simulated          bool
}

// ClaimsFromCustomClaims creates Claims from a custom claims map.
func ClaimsFromCustomClaims(customClaims map[string][]byte) (*Claims, error) {
	pk, ok := customClaims["pk"]
	if !ok {
		return nil, newAttestationDataError("pk field is missing from the claims")
	}
	delete(customClaims, "pk")

	var raftConfig *RaftConfig
	if configBytes, ok := customClaims["config"]; ok {
		delete(customClaims, "config")
		var err error
		raftConfig, err = decodeRaftGroupConfig(configBytes)
		if err != nil {
			return nil, &RaftConfigDecodeError{Err: err}
		}
	}

	return &Claims{
		PublicKey:       pk,
		RaftGroupConfig: raftConfig,
		Custom:          customClaims,
	}, nil
}

// ClaimsFromAttestationData creates Claims from an AttestationData protobuf.
func ClaimsFromAttestationData(publicKey []byte, groupConfig *RaftConfig) (*Claims, error) {
	if groupConfig == nil {
		return nil, newAttestationDataError("RaftGroupConfig is missing from the AttestationData")
	}
	return &Claims{
		PublicKey:       publicKey,
		RaftGroupConfig: groupConfig,
		Custom:          make(map[string][]byte),
	}, nil
}

// decodeRaftGroupConfig decodes a protobuf-encoded RaftGroupConfig.
// This is a simplified decoder that reads the protobuf wire format directly.
func decodeRaftGroupConfig(data []byte) (*RaftConfig, error) {
	config := &RaftConfig{}
	// Field numbers from the .proto file:
	// 1: group_id (fixed64)
	// 2: min_voting_replicas (uint32)
	// 3: max_voting_replicas (uint32)
	// 4: super_majority (uint32)
	// 5: db_version (enum/int32)
	// 6: attestation_timeout (uint32)
	// 7: simulated (bool)
	offset := 0
	for offset < len(data) {
		tag, n := binary.Uvarint(data[offset:])
		if n <= 0 {
			return nil, &ProtobufDecodeError{Detail: "failed to decode protobuf tag"}
		}
		offset += n
		fieldNumber := tag >> 3
		wireType := tag & 0x7

		switch wireType {
		case 0: // varint
			val, n := binary.Uvarint(data[offset:])
			if n <= 0 {
				return nil, &ProtobufDecodeError{Detail: "failed to decode varint"}
			}
			offset += n
			switch fieldNumber {
			case 2:
				config.MinVotingReplicas = uint32(val)
			case 3:
				config.MaxVotingReplicas = uint32(val)
			case 4:
				config.SuperMajority = uint32(val)
			case 5:
				config.DBVersion = int32(val)
			case 6:
				config.AttestationTimeout = uint32(val)
			case 7:
				config.Simulated = val != 0
			}
		case 1: // 64-bit (fixed64)
			if offset+8 > len(data) {
				return nil, &ProtobufDecodeError{Detail: "not enough data for fixed64"}
			}
			val := binary.LittleEndian.Uint64(data[offset : offset+8])
			offset += 8
			if fieldNumber == 1 {
				config.GroupID = val
			}
		case 2: // length-delimited
			length, n := binary.Uvarint(data[offset:])
			if n <= 0 {
				return nil, &ProtobufDecodeError{Detail: "failed to decode length"}
			}
			offset += n
			offset += int(length)
		case 5: // 32-bit
			offset += 4
		default:
			return nil, &ProtobufWireTypeError{WireType: wireType, FieldNumber: fieldNumber}
		}
	}
	return config, nil
}

// Handshake is a noise handshaker that can be used to build a ClientConnection.
//
// Callers provide an attestation that must contain the remote enclave's public key.
// If the attestation is valid, this public key will be used to generate a noise NK
// handshake (with the caller acting as the initiator) via Handshake.InitialRequest().
// When a handshake response is received the handshake can be completed with
// Handshake.Complete() to build a ClientConnection that can be used to exchange
// arbitrary encrypted payloads with the remote enclave.
type Handshake struct {
	// hs is set for pre-quantum (NK) handshakes.
	hs *noise.HandshakeState
	// nkhfs is set for post-quantum (NKhfs) handshakes.
	nkhfs          *NKhfsHandshake
	initialRequest []byte
	claims         *Claims
}

// InitialRequest returns the initial message from client for noise handshake.
func (h *Handshake) InitialRequest() []byte {
	return h.initialRequest
}

// Complete completes client connection initiation, returns a valid client connection.
func (h *Handshake) Complete(initialReceived []byte) (*ClientConnection, error) {
	if h.nkhfs != nil {
		return h.completeNKhfs(initialReceived)
	}
	return h.completePreQuantum(initialReceived)
}

// completePreQuantum completes a pre-quantum NK handshake.
func (h *Handshake) completePreQuantum(initialReceived []byte) (*ClientConnection, error) {
	// ReadMessage returns cipher states when the handshake is complete.
	// For NK pattern: message 0 is initiator->responder (WriteMessage),
	// message 1 is responder->initiator (ReadMessage completes the handshake).
	_, cs0, cs1, err := h.hs.ReadMessage(nil, initialReceived)
	if err != nil {
		return nil, newNoiseHandshakeError(err)
	}

	if cs0 == nil || cs1 == nil {
		return nil, newNoiseHandshakeError(&HandshakeIncompleteError{})
	}

	return &ClientConnection{
		HandshakeHash: h.hs.ChannelBinding(),
		sendCipher:    &preQuantumCipher{cs: cs0},
		recvCipher:    &preQuantumCipher{cs: cs1},
	}, nil
}

// completeNKhfs completes a post-quantum NKhfs handshake.
func (h *Handshake) completeNKhfs(initialReceived []byte) (*ClientConnection, error) {
	_, cs0, cs1, handshakeHash, err := h.nkhfs.state.readMessage2(initialReceived)
	if err != nil {
		return nil, err
	}

	return &ClientConnection{
		HandshakeHash: handshakeHash,
		sendCipher:    cs0,
		recvCipher:    cs1,
	}, nil
}

// UnvalidatedHandshake wraps a Handshake that has not yet been validated
// against an expected RaftConfig.
type UnvalidatedHandshake struct {
	handshake *Handshake
}

// Validate validates the handshake against the expected raft config.
func (u *UnvalidatedHandshake) Validate(expected *RaftConfig) (*Handshake, error) {
	actual := u.handshake.claims.RaftGroupConfig
	if actual == nil {
		return nil, newAttestationDataError("Claims must contain a raft group config")
	}
	if !raftConfigEqual(expected, actual) {
		return nil, newAttestationDataError(
			fmt.Sprintf("Unexpected raft config %+v (expected %+v)", actual, expected),
		)
	}
	return u.handshake, nil
}

// SkipRaftValidation skips raft config validation and returns the handshake directly.
func (u *UnvalidatedHandshake) SkipRaftValidation() *Handshake {
	return u.handshake
}

// raftConfigEqual compares a RaftConfig with another RaftConfig for equality.
func raftConfigEqual(expected, actual *RaftConfig) bool {
	return expected.MinVotingReplicas == actual.MinVotingReplicas &&
		expected.MaxVotingReplicas == actual.MaxVotingReplicas &&
		expected.SuperMajority == actual.SuperMajority &&
		expected.GroupID == actual.GroupID &&
		expected.DBVersion == actual.DBVersion &&
		expected.AttestationTimeout == actual.AttestationTimeout &&
		expected.Simulated == actual.Simulated
}

// newHandshakeWithClaims creates a new Handshake from verified claims.
// For PostQuantum, uses Noise_NKhfs_25519+Kyber1024_ChaChaPoly_SHA256.
// For PreQuantum, uses Noise_NK_25519_ChaChaPoly_SHA256.
func newHandshakeWithClaims(claims *Claims, hsType HandshakeType) (*UnvalidatedHandshake, error) {
	if hsType == PostQuantum {
		return newNKhfsHandshakeWithClaims(claims)
	}

	cs := noiseCipherSuite()

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cs,
		Pattern:     noise.HandshakeNK,
		Initiator:   true,
		PeerStatic:  claims.PublicKey,
	})
	if err != nil {
		return nil, newAttestationDataError("invalid public key")
	}

	// Write the initial handshake message (empty payload for NK pattern).
	initialRequest, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, newNoiseHandshakeError(err)
	}

	return &UnvalidatedHandshake{
		handshake: &Handshake{
			hs:             hs,
			initialRequest: initialRequest,
			claims:         claims,
		},
	}, nil
}
