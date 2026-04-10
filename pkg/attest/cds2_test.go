// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package attest

import (
	"encoding/binary"
	"testing"
	"time"
)

// buildProtobufBytesField creates a protobuf length-delimited field.
func buildProtobufBytesField(fieldNumber int, data []byte) []byte {
	tag := uint64(fieldNumber<<3) | 2
	var buf []byte
	tagBytes := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(tagBytes, tag)
	buf = append(buf, tagBytes[:n]...)

	lenBytes := make([]byte, binary.MaxVarintLen64)
	n = binary.PutUvarint(lenBytes, uint64(len(data)))
	buf = append(buf, lenBytes[:n]...)
	buf = append(buf, data...)
	return buf
}

func TestDecodeCDS2ClientHandshakeStart_HappyPath(t *testing.T) {
	evidenceData := []byte("evidence_bytes")
	endorsementData := []byte("endorsement_bytes")

	var msg []byte
	msg = append(msg, buildProtobufBytesField(1, []byte("pubkey_data"))...)
	msg = append(msg, buildProtobufBytesField(2, evidenceData)...)
	msg = append(msg, buildProtobufBytesField(3, endorsementData)...)

	evidence, endorsement, err := decodeCDS2ClientHandshakeStart(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(evidence) != "evidence_bytes" {
		t.Errorf("evidence = %q, want %q", evidence, "evidence_bytes")
	}
	if string(endorsement) != "endorsement_bytes" {
		t.Errorf("endorsement = %q, want %q", endorsement, "endorsement_bytes")
	}
}

func TestDecodeCDS2ClientHandshakeStart_EmptyMessage(t *testing.T) {
	evidence, endorsement, err := decodeCDS2ClientHandshakeStart([]byte{})
	if err != nil {
		t.Fatalf("empty message should not error: %v", err)
	}
	if evidence != nil || endorsement != nil {
		t.Error("expected nil evidence and endorsement for empty message")
	}
}

func TestDecodeCDS2ClientHandshakeStart_OnlyPubkey(t *testing.T) {
	msg := buildProtobufBytesField(1, []byte("just_pubkey"))

	evidence, endorsement, err := decodeCDS2ClientHandshakeStart(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if evidence != nil {
		t.Error("evidence should be nil when only pubkey present")
	}
	if endorsement != nil {
		t.Error("endorsement should be nil when only pubkey present")
	}
}

func TestDecodeCDS2ClientHandshakeStart_InvalidTag(t *testing.T) {
	_, _, err := decodeCDS2ClientHandshakeStart([]byte{0x80}) // truncated varint
	if err == nil {
		t.Fatal("expected error for truncated varint tag")
	}
}

func TestDecodeCDS2ClientHandshakeStart_WrongWireType(t *testing.T) {
	// Wire type 0 (varint) for field 1 instead of wire type 2 (bytes)
	_, _, err := decodeCDS2ClientHandshakeStart([]byte{0x08, 0x01}) // field 1, varint
	if err == nil {
		t.Fatal("expected error for wrong wire type")
	}
}

func TestDecodeCDS2ClientHandshakeStart_TruncatedLength(t *testing.T) {
	// Valid tag for field 2 (bytes), but truncated length
	_, _, err := decodeCDS2ClientHandshakeStart([]byte{0x12, 0x80}) // field 2, truncated length
	if err == nil {
		t.Fatal("expected error for truncated length")
	}
}

func TestDecodeCDS2ClientHandshakeStart_DataUnderflow(t *testing.T) {
	// Field 2, length = 10, but only 3 bytes of data
	msg := []byte{0x12, 0x0a, 0x01, 0x02, 0x03}
	_, _, err := decodeCDS2ClientHandshakeStart(msg)
	if err == nil {
		t.Fatal("expected error for data underflow")
	}
}

func TestCDS2NewHandshake_InvalidAttestation(t *testing.T) {
	mrenclave := make([]byte, MREnclaveSize)

	// Build a valid protobuf structure but with garbage evidence/endorsement data
	var msg []byte
	msg = append(msg, buildProtobufBytesField(2, []byte("fake_evidence"))...)
	msg = append(msg, buildProtobufBytesField(3, []byte("fake_endorsement"))...)

	_, err := CDS2NewHandshake(mrenclave, msg, time.Now())
	if err == nil {
		t.Fatal("expected error for invalid attestation data")
	}
}

func TestCDS2NewHandshake_EmptyAttestationMsg(t *testing.T) {
	mrenclave := make([]byte, MREnclaveSize)
	_, err := CDS2NewHandshake(mrenclave, []byte{}, time.Now())
	if err == nil {
		t.Fatal("expected error: empty attestation message should have no evidence")
	}
}

func TestCDS2NewHandshake_MalformedProtobuf(t *testing.T) {
	mrenclave := make([]byte, MREnclaveSize)
	_, err := CDS2NewHandshake(mrenclave, []byte{0x80}, time.Now())
	if err == nil {
		t.Fatal("expected error for malformed protobuf")
	}
}

func TestCDS2ExtractMetrics_HappyPath(t *testing.T) {
	var msg []byte
	msg = append(msg, buildProtobufBytesField(2, []byte("evidence"))...)
	msg = append(msg, buildProtobufBytesField(3, []byte("endorsement"))...)

	metrics, err := CDS2ExtractMetrics(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if metrics == nil {
		t.Fatal("metrics should not be nil")
	}
}

func TestCDS2ExtractMetrics_InvalidProtobuf(t *testing.T) {
	_, err := CDS2ExtractMetrics([]byte{0x80})
	if err == nil {
		t.Fatal("expected error for invalid protobuf")
	}
}
