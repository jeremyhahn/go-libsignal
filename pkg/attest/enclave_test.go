//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 10 tests in this file exercise X25519. FIPS 140-3 does not approve that,
// but the Noise_NK_25519_ChaChaPoly_SHA256 pattern Signal uses to reach its
// SGX and HSM enclaves requires it, so the fips140only build tag drops this
// file from the FIPS gate. `make test` and `make coverage` still run it.

// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package attest

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/flynn/noise"
)

func TestClaimsFromCustomClaims_HappyPath(t *testing.T) {
	pk := make([]byte, 32)
	pk[0] = 0x42
	customClaims := map[string][]byte{
		"pk":    pk,
		"extra": {1, 2, 3},
	}

	claims, err := ClaimsFromCustomClaims(customClaims)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.PublicKey[0] != 0x42 {
		t.Error("public key not preserved")
	}
	if _, ok := claims.Custom["pk"]; ok {
		t.Error("pk should be removed from Custom map")
	}
	if v, ok := claims.Custom["extra"]; !ok || len(v) != 3 {
		t.Error("extra field should be preserved in Custom")
	}
}

func TestClaimsFromCustomClaims_WithConfigField(t *testing.T) {
	pk := make([]byte, 32)
	// Build a minimal protobuf for RaftGroupConfig: field 2 (varint) = 4
	configBytes := []byte{0x10, 0x04} // field 2, varint 4
	customClaims := map[string][]byte{
		"pk":     pk,
		"config": configBytes,
	}

	claims, err := ClaimsFromCustomClaims(customClaims)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.RaftGroupConfig == nil {
		t.Fatal("expected RaftGroupConfig to be set")
	}
	if claims.RaftGroupConfig.MinVotingReplicas != 4 {
		t.Errorf("MinVotingReplicas = %d, want 4", claims.RaftGroupConfig.MinVotingReplicas)
	}
	if _, ok := claims.Custom["config"]; ok {
		t.Error("config should be removed from Custom map")
	}
}

func TestClaimsFromCustomClaims_MissingPK(t *testing.T) {
	customClaims := map[string][]byte{
		"other": {1},
	}
	_, err := ClaimsFromCustomClaims(customClaims)
	if err == nil {
		t.Fatal("expected error for missing pk")
	}
}

func TestClaimsFromAttestationData_HappyPath(t *testing.T) {
	pk := make([]byte, 32)
	config := &RaftConfig{MinVotingReplicas: 3}
	claims, err := ClaimsFromAttestationData(pk, config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.RaftGroupConfig != config {
		t.Error("RaftGroupConfig not set correctly")
	}
	if claims.Custom == nil {
		t.Error("Custom map should be initialized")
	}
}

func TestClaimsFromAttestationData_NilConfig(t *testing.T) {
	pk := make([]byte, 32)
	_, err := ClaimsFromAttestationData(pk, nil)
	if err == nil {
		t.Fatal("expected error for nil config")
	}
}

func TestDecodeRaftGroupConfig_FullMessage(t *testing.T) {
	// Build a hand-crafted protobuf with all fields:
	// field 1 (fixed64) = 123456789, field 2 (varint) = 4, field 3 (varint) = 13,
	// field 4 (varint) = 2, field 5 (varint) = 2, field 6 (varint) = 604800, field 7 (varint) = 1
	var buf []byte

	// field 1: fixed64 (wire type 1) -> tag = (1<<3)|1 = 0x09
	buf = append(buf, 0x09)
	b8 := make([]byte, 8)
	binary.LittleEndian.PutUint64(b8, 123456789)
	buf = append(buf, b8...)

	// field 2: varint (wire type 0) -> tag = (2<<3)|0 = 0x10
	buf = append(buf, 0x10, 0x04)

	// field 3: varint -> tag = (3<<3)|0 = 0x18
	buf = append(buf, 0x18, 0x0d)

	// field 4: varint -> tag = (4<<3)|0 = 0x20
	buf = append(buf, 0x20, 0x02)

	// field 5: varint -> tag = (5<<3)|0 = 0x28
	buf = append(buf, 0x28, 0x02)

	// field 6: varint -> tag = (6<<3)|0 = 0x30
	// 604800 = 0x93A00 -> varint encoding
	buf = append(buf, 0x30)
	v := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(v, 604800)
	buf = append(buf, v[:n]...)

	// field 7: varint -> tag = (7<<3)|0 = 0x38
	buf = append(buf, 0x38, 0x01)

	config, err := decodeRaftGroupConfig(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if config.GroupID != 123456789 {
		t.Errorf("GroupID = %d, want 123456789", config.GroupID)
	}
	if config.MinVotingReplicas != 4 {
		t.Errorf("MinVotingReplicas = %d, want 4", config.MinVotingReplicas)
	}
	if config.MaxVotingReplicas != 13 {
		t.Errorf("MaxVotingReplicas = %d, want 13", config.MaxVotingReplicas)
	}
	if config.SuperMajority != 2 {
		t.Errorf("SuperMajority = %d, want 2", config.SuperMajority)
	}
	if config.DBVersion != 2 {
		t.Errorf("DBVersion = %d, want 2", config.DBVersion)
	}
	if config.AttestationTimeout != 604800 {
		t.Errorf("AttestationTimeout = %d, want 604800", config.AttestationTimeout)
	}
	if !config.Simulated {
		t.Error("Simulated = false, want true")
	}
}

func TestDecodeRaftGroupConfig_EmptyData(t *testing.T) {
	config, err := decodeRaftGroupConfig([]byte{})
	if err != nil {
		t.Fatalf("empty data should succeed with default config: %v", err)
	}
	if config.GroupID != 0 {
		t.Errorf("GroupID should be 0 for empty data")
	}
}

func TestDecodeRaftGroupConfig_InvalidTag(t *testing.T) {
	// A buffer that will fail uvarint decoding (0x80 with no continuation)
	_, err := decodeRaftGroupConfig([]byte{0x80})
	if err == nil {
		t.Fatal("expected error for truncated varint tag")
	}
}

func TestDecodeRaftGroupConfig_TruncatedVarint(t *testing.T) {
	// Valid tag for field 2 (varint), but no value follows
	// tag = 0x10, then 0x80 which needs continuation
	_, err := decodeRaftGroupConfig([]byte{0x10, 0x80})
	if err == nil {
		t.Fatal("expected error for truncated varint value")
	}
}

func TestDecodeRaftGroupConfig_TruncatedFixed64(t *testing.T) {
	// tag for field 1 (fixed64) = 0x09, but only 4 bytes of data
	_, err := decodeRaftGroupConfig([]byte{0x09, 0x01, 0x02, 0x03, 0x04})
	if err == nil {
		t.Fatal("expected error for truncated fixed64")
	}
}

func TestDecodeRaftGroupConfig_LengthDelimitedField(t *testing.T) {
	// Unknown length-delimited field (wire type 2), field 10
	// tag = (10<<3)|2 = 0x52, length = 3, data = "abc"
	data := []byte{0x52, 0x03, 0x61, 0x62, 0x63}
	config, err := decodeRaftGroupConfig(data)
	if err != nil {
		t.Fatalf("should skip unknown length-delimited field: %v", err)
	}
	if config == nil {
		t.Fatal("config should not be nil")
	}
}

func TestDecodeRaftGroupConfig_Fixed32Field(t *testing.T) {
	// Unknown fixed32 field (wire type 5), field 10
	// tag = (10<<3)|5 = 0x55
	data := []byte{0x55, 0x01, 0x02, 0x03, 0x04}
	config, err := decodeRaftGroupConfig(data)
	if err != nil {
		t.Fatalf("should skip unknown fixed32 field: %v", err)
	}
	if config == nil {
		t.Fatal("config should not be nil")
	}
}

func TestDecodeRaftGroupConfig_UnknownWireType(t *testing.T) {
	// Wire type 3 is not handled
	// tag = (1<<3)|3 = 0x0b
	_, err := decodeRaftGroupConfig([]byte{0x0b})
	if err == nil {
		t.Fatal("expected error for unknown wire type")
	}
}

func TestRaftConfigEqual(t *testing.T) {
	a := &RaftConfig{
		MinVotingReplicas:  4,
		MaxVotingReplicas:  13,
		SuperMajority:      2,
		GroupID:            12345,
		DBVersion:          2,
		AttestationTimeout: 604800,
		Simulated:          false,
	}
	b := &RaftConfig{
		MinVotingReplicas:  4,
		MaxVotingReplicas:  13,
		SuperMajority:      2,
		GroupID:            12345,
		DBVersion:          2,
		AttestationTimeout: 604800,
		Simulated:          false,
	}
	if !raftConfigEqual(a, b) {
		t.Error("identical configs should be equal")
	}

	b.MinVotingReplicas = 5
	if raftConfigEqual(a, b) {
		t.Error("different MinVotingReplicas should not be equal")
	}
}

func TestRaftConfigEqual_AllFieldsDiffer(t *testing.T) {
	base := &RaftConfig{
		MinVotingReplicas:  4,
		MaxVotingReplicas:  13,
		SuperMajority:      2,
		GroupID:            12345,
		DBVersion:          2,
		AttestationTimeout: 604800,
		Simulated:          false,
	}

	tests := []struct {
		name   string
		modify func(c *RaftConfig)
	}{
		{"MaxVotingReplicas", func(c *RaftConfig) { c.MaxVotingReplicas = 99 }},
		{"SuperMajority", func(c *RaftConfig) { c.SuperMajority = 99 }},
		{"GroupID", func(c *RaftConfig) { c.GroupID = 99 }},
		{"DBVersion", func(c *RaftConfig) { c.DBVersion = 99 }},
		{"AttestationTimeout", func(c *RaftConfig) { c.AttestationTimeout = 99 }},
		{"Simulated", func(c *RaftConfig) { c.Simulated = true }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			other := *base
			tt.modify(&other)
			if raftConfigEqual(base, &other) {
				t.Errorf("configs differing in %s should not be equal", tt.name)
			}
		})
	}
}

func TestNewHandshakeWithClaims_HappyPath(t *testing.T) {
	// Generate a valid X25519 key pair for the "remote enclave" public key
	cs := noiseCipherSuite()
	kp, err := cs.GenerateKeypair(nil)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	claims := &Claims{
		PublicKey: kp.Public,
		Custom:    make(map[string][]byte),
	}

	unvalidated, err := newHandshakeWithClaims(claims, PreQuantum)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if unvalidated == nil {
		t.Fatal("unvalidated should not be nil")
	}
	if unvalidated.handshake == nil {
		t.Fatal("handshake should not be nil")
	}
	if len(unvalidated.handshake.InitialRequest()) == 0 {
		t.Error("initial request should not be empty")
	}
}

func TestNewHandshakeWithClaims_InvalidPublicKey(t *testing.T) {
	claims := &Claims{
		PublicKey: []byte{0x01, 0x02}, // too short for X25519
		Custom:    make(map[string][]byte),
	}

	// flynn/noise accepts any 32-byte key for DH25519, so a 2-byte key should fail
	_, err := newHandshakeWithClaims(claims, PreQuantum)
	if err == nil {
		t.Fatal("expected error for invalid public key")
	}
}

func TestHandshake_InitialRequest(t *testing.T) {
	cs := noiseCipherSuite()
	kp, _ := cs.GenerateKeypair(nil)

	claims := &Claims{PublicKey: kp.Public, Custom: make(map[string][]byte)}
	unvalidated, err := newHandshakeWithClaims(claims, PreQuantum)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := unvalidated.handshake.InitialRequest()
	if len(req) == 0 {
		t.Error("InitialRequest should not be empty")
	}
	// For NK pattern, initiator message is 32 (ephemeral public) + 0 (empty payload) + 0 (no encryption in msg 0)
	// But there's poly overhead. Just check it's reasonable.
	if len(req) < 32 {
		t.Errorf("InitialRequest too short: %d bytes", len(req))
	}
}

func TestHandshake_Complete_HappyPath(t *testing.T) {
	// Set up a full NK handshake between initiator and responder
	cs := noiseCipherSuite()
	responderKP, _ := cs.GenerateKeypair(nil)

	// Initiator side
	claims := &Claims{PublicKey: responderKP.Public, Custom: make(map[string][]byte)}
	unvalidated, err := newHandshakeWithClaims(claims, PreQuantum)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Responder side
	responderHS, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Pattern:       noise.HandshakeNK,
		Initiator:     false,
		StaticKeypair: responderKP,
	})
	if err != nil {
		t.Fatalf("failed to create responder handshake: %v", err)
	}

	// Responder reads initiator message
	_, _, _, err = responderHS.ReadMessage(nil, unvalidated.handshake.InitialRequest())
	if err != nil {
		t.Fatalf("responder ReadMessage failed: %v", err)
	}

	// Responder writes response
	respMsg, _, _, err := responderHS.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("responder WriteMessage failed: %v", err)
	}

	// Initiator completes handshake
	conn, err := unvalidated.handshake.Complete(respMsg)
	if err != nil {
		t.Fatalf("Complete failed: %v", err)
	}
	if conn == nil {
		t.Fatal("connection should not be nil")
	}
	if len(conn.HandshakeHash) == 0 {
		t.Error("HandshakeHash should not be empty")
	}
}

func TestHandshake_Complete_InvalidData(t *testing.T) {
	cs := noiseCipherSuite()
	kp, _ := cs.GenerateKeypair(nil)

	claims := &Claims{PublicKey: kp.Public, Custom: make(map[string][]byte)}
	unvalidated, err := newHandshakeWithClaims(claims, PreQuantum)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = unvalidated.handshake.Complete([]byte{0x00, 0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for invalid handshake data")
	}
}

func TestUnvalidatedHandshake_Validate_HappyPath(t *testing.T) {
	cs := noiseCipherSuite()
	kp, _ := cs.GenerateKeypair(nil)

	config := &RaftConfig{MinVotingReplicas: 4, GroupID: 123}
	claims := &Claims{
		PublicKey:       kp.Public,
		RaftGroupConfig: config,
		Custom:          make(map[string][]byte),
	}
	unvalidated, err := newHandshakeWithClaims(claims, PreQuantum)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hs, err := unvalidated.Validate(config)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if hs == nil {
		t.Fatal("handshake should not be nil")
	}
}

func TestUnvalidatedHandshake_Validate_NilRaftConfig(t *testing.T) {
	cs := noiseCipherSuite()
	kp, _ := cs.GenerateKeypair(nil)

	claims := &Claims{
		PublicKey:       kp.Public,
		RaftGroupConfig: nil,
		Custom:          make(map[string][]byte),
	}
	unvalidated, err := newHandshakeWithClaims(claims, PreQuantum)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = unvalidated.Validate(&RaftConfig{})
	if err == nil {
		t.Fatal("expected error for nil raft config in claims")
	}
}

func TestUnvalidatedHandshake_Validate_Mismatch(t *testing.T) {
	cs := noiseCipherSuite()
	kp, _ := cs.GenerateKeypair(nil)

	claims := &Claims{
		PublicKey:       kp.Public,
		RaftGroupConfig: &RaftConfig{MinVotingReplicas: 4},
		Custom:          make(map[string][]byte),
	}
	unvalidated, err := newHandshakeWithClaims(claims, PreQuantum)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = unvalidated.Validate(&RaftConfig{MinVotingReplicas: 99})
	if err == nil {
		t.Fatal("expected error for mismatched raft config")
	}
}

func TestUnvalidatedHandshake_SkipRaftValidation(t *testing.T) {
	cs := noiseCipherSuite()
	kp, _ := cs.GenerateKeypair(nil)

	claims := &Claims{
		PublicKey: kp.Public,
		Custom:    make(map[string][]byte),
	}
	unvalidated, err := newHandshakeWithClaims(claims, PreQuantum)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hs := unvalidated.SkipRaftValidation()
	if hs == nil {
		t.Fatal("SkipRaftValidation should return non-nil handshake")
	}
}

func TestPostQuantumHandshakeSucceeds(t *testing.T) {
	// PostQuantum now uses NKhfs; provide a valid 32-byte X25519 public key.
	cs := noiseCipherSuite()
	kp, err := cs.GenerateKeypair(nil)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	claims := &Claims{
		PublicKey: kp.Public,
		Custom:    make(map[string][]byte),
	}

	uv, err := newHandshakeWithClaims(claims, PostQuantum)
	if err != nil {
		t.Fatalf("PostQuantum handshake should succeed with valid key: %v", err)
	}
	if uv == nil {
		t.Fatal("expected non-nil UnvalidatedHandshake")
	}
	req := uv.handshake.InitialRequest()
	// NKhfs msg1: e.pub(32) + EncryptAndHash(e1.pub)(1568+16) + EncryptAndHash(nil)(16) = 1632 bytes.
	if len(req) != NoiseHandshakeOverheadHFS {
		t.Errorf("NKhfs initial request: got %d bytes, want %d", len(req), NoiseHandshakeOverheadHFS)
	}
}

func TestPostQuantumHandshakeInvalidKey(t *testing.T) {
	// A 2-byte key is invalid for X25519.
	claims := &Claims{
		PublicKey: []byte{0x01, 0x02},
		Custom:    make(map[string][]byte),
	}
	_, err := newHandshakeWithClaims(claims, PostQuantum)
	if err == nil {
		t.Fatal("expected error for invalid 2-byte public key")
	}
}

func TestPreQuantumHandshakeStillWorks(t *testing.T) {
	cs := noiseCipherSuite()
	kp, err := cs.GenerateKeypair(nil)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	claims := &Claims{
		PublicKey: kp.Public,
		Custom:    make(map[string][]byte),
	}

	unvalidated, err := newHandshakeWithClaims(claims, PreQuantum)
	if err != nil {
		t.Fatalf("PreQuantum should succeed: %v", err)
	}
	if unvalidated == nil {
		t.Fatal("unvalidated should not be nil for PreQuantum")
	}
}

// TestDecodeRaftGroupConfig_GiantVarintLength is a regression test for Finding 3
// (pre-auth DoS via crafted varint in the length-delimited protobuf branch).
// Before the fix, a varint encoding 2^63 caused int(length) to be negative,
// bypassing the "offset += int(length)" bounds, triggering a panic or data
// corruption.  The fix validates length in uint64 arithmetic before the int()
// cast and returns ProtobufDecodeError.
//
// The crafted input: tag 0x52 (field 10, wire type 2) followed by the 10-byte
// varint for 2^63 = {0x80 × 9, 0x01}.
func TestDecodeRaftGroupConfig_GiantVarintLength(t *testing.T) {
	// varint encoding of 2^63: nine 0x80 continuation bytes then 0x01.
	tag := byte(0x52) // field 10, wire type 2 (length-delimited)
	giantVarint := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}
	data := append([]byte{tag}, giantVarint...)

	_, err := decodeRaftGroupConfig(data)
	if err == nil {
		t.Fatal("must return error for giant varint length, not panic (regression for Finding 3)")
	}
	var pbErr *ProtobufDecodeError
	if !errors.As(err, &pbErr) {
		t.Errorf("expected ProtobufDecodeError, got %T: %v", err, err)
	}
}

// TestDecodeRaftGroupConfig_GiantVarintLengthFieldOne verifies the same panic-safe
// behaviour on a different wire-type-2 field number.
func TestDecodeRaftGroupConfig_GiantVarintLengthFieldOne(t *testing.T) {
	// tag = (100<<3)|2 = 0x322 — multi-byte tag, but encode as two bytes.
	// Actually use a single-byte tag for simplicity: field 1 wire type 2 = 0x0A.
	tag := byte(0x0A)
	giantVarint := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}
	data := append([]byte{tag}, giantVarint...)

	_, err := decodeRaftGroupConfig(data)
	if err == nil {
		t.Fatal("must return error for giant varint length on field 1 wire type 2")
	}
	var pbErr *ProtobufDecodeError
	if !errors.As(err, &pbErr) {
		t.Errorf("expected ProtobufDecodeError, got %T: %v", err, err)
	}
}
