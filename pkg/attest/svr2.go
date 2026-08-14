// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package attest

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"time"
)

// SVR2LookupGroupID returns the group ID associated with the given mrenclave, if known.
func SVR2LookupGroupID(mrenclave []byte) (uint64, bool) {
	for _, entry := range expectedRaftConfigSVR2 {
		if bytesEqualSlice(entry.mrenclave, mrenclave) {
			return entry.config.GroupID, true
		}
	}
	return 0, false
}

// SVR2NewHandshakeWithRaftConfigLookup creates a new SVR2 handshake using a built-in
// raft config lookup table. This is primarily for bridging code that does not expose
// the notion of environment to the clients.
func SVR2NewHandshakeWithRaftConfigLookup(
	mrenclave []byte,
	attestationMsg []byte,
	currentTime time.Time,
) (*Handshake, error) {
	var expectedConfig *RaftConfig
	for _, entry := range expectedRaftConfigSVR2 {
		if bytesEqualSlice(entry.mrenclave, mrenclave) {
			expectedConfig = entry.config
			break
		}
	}
	if expectedConfig == nil {
		return nil, newAttestationDataError(fmt.Sprintf("unknown mrenclave %x", mrenclave))
	}

	return SVR2NewHandshake(mrenclave, attestationMsg, currentTime, expectedConfig)
}

// SVR2NewHandshake creates a new SVR2 handshake with the given raft config.
func SVR2NewHandshake(
	mrenclave []byte,
	attestationMsg []byte,
	currentTime time.Time,
	expectedRaftConfig *RaftConfig,
) (*Handshake, error) {
	return svr2NewHandshakeWithConstants(
		mrenclave,
		attestationMsg,
		currentTime,
		GetSWAdvisories(mrenclave),
		expectedRaftConfig,
		PostQuantum,
	)
}

func svr2NewHandshakeWithConstants(
	mrenclave []byte,
	attestationMsg []byte,
	currentTime time.Time,
	acceptableSWAdvisories []string,
	expectedRaftConfig *RaftConfig,
	handshakeType HandshakeType,
) (*Handshake, error) {
	// Deserialize the SVR ClientHandshakeStart protobuf message.
	evidence, endorsement, err := decodeSVRClientHandshakeStart(attestationMsg)
	if err != nil {
		return nil, newAttestationDataError(fmt.Sprintf("failed to decode attestation message: %v", err))
	}

	unvalidated, err := ForSGX(
		mrenclave,
		evidence,
		endorsement,
		acceptableSWAdvisories,
		currentTime,
		handshakeType,
	)
	if err != nil {
		return nil, err
	}

	return unvalidated.Validate(expectedRaftConfig)
}

// decodeSVRClientHandshakeStart decodes a protobuf-encoded SVR ClientHandshakeStart message.
// Returns (evidence, endorsement, error).
//
// The protobuf message has the following fields:
//
//	message ClientHandshakeStart {
//	  reserved 1;
//	  bytes evidence = 2;
//	  bytes endorsement = 3;
//	}
func decodeSVRClientHandshakeStart(data []byte) ([]byte, []byte, error) {
	var evidence, endorsement []byte
	offset := 0
	for offset < len(data) {
		tag, n := binary.Uvarint(data[offset:])
		if n <= 0 {
			return nil, nil, &ProtobufDecodeError{Detail: "failed to decode protobuf tag"}
		}
		offset += n
		fieldNumber := tag >> 3
		wireType := tag & 0x7

		if wireType != 2 { // all fields are length-delimited (bytes)
			return nil, nil, &ProtobufWireTypeError{WireType: wireType, FieldNumber: fieldNumber}
		}

		length, n := binary.Uvarint(data[offset:])
		if n <= 0 {
			return nil, nil, &ProtobufDecodeError{Detail: "failed to decode length"}
		}
		offset += n

		// Validate length before int() cast.  A crafted varint can encode values
		// ≥ 2^63; casting to int wraps negative, defeating the bounds check, then
		// make([]byte, length) panics.  Check in uint64 arithmetic instead.
		if offset > len(data) || length > uint64(len(data)-offset) {
			return nil, nil, &ProtobufDecodeError{Detail: "data underflow"}
		}

		fieldData := make([]byte, length)
		copy(fieldData, data[offset:offset+int(length)])
		offset += int(length)

		switch fieldNumber {
		case 2:
			evidence = fieldData
		case 3:
			endorsement = fieldData
		}
	}

	return evidence, endorsement, nil
}

func bytesEqualSlice(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}
