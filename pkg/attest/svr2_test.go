// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package attest

import (
	"testing"
	"time"
)

func TestDecodeSVRClientHandshakeStart_HappyPath(t *testing.T) {
	evidenceData := []byte("svr_evidence")
	endorsementData := []byte("svr_endorsement")

	var msg []byte
	msg = append(msg, buildProtobufBytesField(2, evidenceData)...)
	msg = append(msg, buildProtobufBytesField(3, endorsementData)...)

	evidence, endorsement, err := decodeSVRClientHandshakeStart(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(evidence) != "svr_evidence" {
		t.Errorf("evidence = %q, want %q", evidence, "svr_evidence")
	}
	if string(endorsement) != "svr_endorsement" {
		t.Errorf("endorsement = %q, want %q", endorsement, "svr_endorsement")
	}
}

func TestDecodeSVRClientHandshakeStart_EmptyMessage(t *testing.T) {
	evidence, endorsement, err := decodeSVRClientHandshakeStart([]byte{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if evidence != nil || endorsement != nil {
		t.Error("expected nil fields for empty message")
	}
}

func TestDecodeSVRClientHandshakeStart_InvalidTag(t *testing.T) {
	_, _, err := decodeSVRClientHandshakeStart([]byte{0x80})
	if err == nil {
		t.Fatal("expected error for truncated varint tag")
	}
}

func TestDecodeSVRClientHandshakeStart_WrongWireType(t *testing.T) {
	// Wire type 0 (varint) for field 2
	_, _, err := decodeSVRClientHandshakeStart([]byte{0x10, 0x01})
	if err == nil {
		t.Fatal("expected error for wrong wire type")
	}
}

func TestDecodeSVRClientHandshakeStart_TruncatedLength(t *testing.T) {
	_, _, err := decodeSVRClientHandshakeStart([]byte{0x12, 0x80})
	if err == nil {
		t.Fatal("expected error for truncated length")
	}
}

func TestDecodeSVRClientHandshakeStart_DataUnderflow(t *testing.T) {
	msg := []byte{0x12, 0x0a, 0x01, 0x02}
	_, _, err := decodeSVRClientHandshakeStart(msg)
	if err == nil {
		t.Fatal("expected error for data underflow")
	}
}

func TestDecodeSVRClientHandshakeStart_SkipsUnknownFields(t *testing.T) {
	// Include a field 5 (unknown) with data, plus fields 2 and 3
	var msg []byte
	msg = append(msg, buildProtobufBytesField(5, []byte("unknown"))...)
	msg = append(msg, buildProtobufBytesField(2, []byte("ev"))...)
	msg = append(msg, buildProtobufBytesField(3, []byte("end"))...)

	evidence, endorsement, err := decodeSVRClientHandshakeStart(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(evidence) != "ev" {
		t.Errorf("evidence = %q, want %q", evidence, "ev")
	}
	if string(endorsement) != "end" {
		t.Errorf("endorsement = %q, want %q", endorsement, "end")
	}
}

func TestBytesEqualSlice(t *testing.T) {
	tests := []struct {
		name string
		a, b []byte
		want bool
	}{
		{"equal", []byte{1, 2, 3}, []byte{1, 2, 3}, true},
		{"different content", []byte{1, 2, 3}, []byte{1, 2, 4}, false},
		{"different lengths", []byte{1, 2}, []byte{1, 2, 3}, false},
		{"both empty", []byte{}, []byte{}, true},
		{"both nil", nil, nil, true},
		{"nil vs empty", nil, []byte{}, true},
		{"one element match", []byte{42}, []byte{42}, true},
		{"one element differ", []byte{42}, []byte{43}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bytesEqualSlice(tt.a, tt.b); got != tt.want {
				t.Errorf("bytesEqualSlice(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestSVR2LookupGroupID_KnownMREnclave(t *testing.T) {
	groupID, ok := SVR2LookupGroupID(EnclaveIDSVR2_2025Q3Prod)
	if !ok {
		t.Fatal("expected known mrenclave to be found")
	}
	if groupID != RaftConfigSVR2_2025Q3Prod.GroupID {
		t.Errorf("GroupID = %d, want %d", groupID, RaftConfigSVR2_2025Q3Prod.GroupID)
	}
}

func TestSVR2LookupGroupID_UnknownMREnclave(t *testing.T) {
	unknown := make([]byte, 32)
	_, ok := SVR2LookupGroupID(unknown)
	if ok {
		t.Fatal("expected unknown mrenclave to not be found")
	}
}

func TestSVR2NewHandshakeWithRaftConfigLookup_UnknownMREnclave(t *testing.T) {
	unknown := make([]byte, MREnclaveSize)
	var msg []byte
	msg = append(msg, buildProtobufBytesField(2, []byte("evidence"))...)
	msg = append(msg, buildProtobufBytesField(3, []byte("endorsement"))...)

	_, err := SVR2NewHandshakeWithRaftConfigLookup(unknown, msg, time.Now())
	if err == nil {
		t.Fatal("expected error for unknown mrenclave")
	}
}

func TestSVR2NewHandshakeWithRaftConfigLookup_KnownButInvalidAttestation(t *testing.T) {
	// Use a known MRENCLAVE so the lookup succeeds, but attestation data is still garbage
	mrenclave := EnclaveIDSVR2_2025Q3Prod
	var msg []byte
	msg = append(msg, buildProtobufBytesField(2, []byte("fake_evidence"))...)
	msg = append(msg, buildProtobufBytesField(3, []byte("fake_endorsement"))...)

	_, err := SVR2NewHandshakeWithRaftConfigLookup(mrenclave, msg, time.Now())
	if err == nil {
		t.Fatal("expected error for invalid attestation despite known mrenclave")
	}
}

func TestSVR2NewHandshake_InvalidAttestation(t *testing.T) {
	mrenclave := make([]byte, MREnclaveSize)
	var msg []byte
	msg = append(msg, buildProtobufBytesField(2, []byte("fake"))...)
	msg = append(msg, buildProtobufBytesField(3, []byte("fake"))...)

	config := &RaftConfig{MinVotingReplicas: 4}
	_, err := SVR2NewHandshake(mrenclave, msg, time.Now(), config)
	if err == nil {
		t.Fatal("expected error for invalid attestation")
	}
}

func TestSVR2NewHandshake_MalformedProtobuf(t *testing.T) {
	mrenclave := make([]byte, MREnclaveSize)
	config := &RaftConfig{}
	_, err := SVR2NewHandshake(mrenclave, []byte{0x80}, time.Now(), config)
	if err == nil {
		t.Fatal("expected error for malformed protobuf")
	}
}

func TestSVR2NewHandshake_EmptyAttestationMsg(t *testing.T) {
	mrenclave := make([]byte, MREnclaveSize)
	config := &RaftConfig{}
	_, err := SVR2NewHandshake(mrenclave, []byte{}, time.Now(), config)
	if err == nil {
		t.Fatal("expected error for empty attestation message")
	}
}

func TestSvr2NewHandshakeWithConstants_MalformedProtobuf(t *testing.T) {
	mrenclave := make([]byte, MREnclaveSize)
	config := &RaftConfig{}
	_, err := svr2NewHandshakeWithConstants(mrenclave, []byte{0x80}, time.Now(), nil, config, PreQuantum)
	if err == nil {
		t.Fatal("expected error for malformed protobuf")
	}
}
