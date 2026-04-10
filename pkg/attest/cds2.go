// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package attest

import (
	"encoding/binary"
	"fmt"
	"time"
)

// CDS2NewHandshake creates a new handshake for Contact Discovery Service v2.
//
// Parameters:
//   - mrenclave: expected MRENCLAVE value (32 bytes)
//   - attestationMsg: protobuf-encoded ClientHandshakeStart message
//   - currentTime: current system time for validity checks
func CDS2NewHandshake(
	mrenclave []byte,
	attestationMsg []byte,
	currentTime time.Time,
) (*Handshake, error) {
	// Deserialize the ClientHandshakeStart protobuf message.
	evidence, endorsement, err := decodeCDS2ClientHandshakeStart(attestationMsg)
	if err != nil {
		return nil, newAttestationDataError(fmt.Sprintf("failed to decode attestation message: %v", err))
	}

	swAdvisories := GetSWAdvisories(mrenclave)

	unvalidated, err := ForSGX(
		mrenclave,
		evidence,
		endorsement,
		swAdvisories,
		currentTime,
		PostQuantum,
	)
	if err != nil {
		return nil, err
	}

	return unvalidated.SkipRaftValidation(), nil
}

// CDS2ExtractMetrics extracts attestation metrics from a ClientHandshakeStart message.
func CDS2ExtractMetrics(attestationMsg []byte) (map[string]int64, error) {
	evidence, endorsement, err := decodeCDS2ClientHandshakeStart(attestationMsg)
	if err != nil {
		return nil, newAttestationDataError(fmt.Sprintf("failed to decode attestation message: %v", err))
	}

	return AttestationMetrics(evidence, endorsement)
}

// decodeCDS2ClientHandshakeStart decodes a protobuf-encoded CDS2 ClientHandshakeStart message.
// Returns (evidence, endorsement, error).
//
// The protobuf message has the following fields:
//
//	message ClientHandshakeStart {
//	  bytes pubkey = 1;
//	  bytes evidence = 2;
//	  bytes endorsement = 3;
//	}
func decodeCDS2ClientHandshakeStart(data []byte) ([]byte, []byte, error) {
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

		if offset+int(length) > len(data) {
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
