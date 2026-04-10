package spqr

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// ============================================================================
// V1/V2 Deserialize: skipped key loop body
// ============================================================================

// buildV2StateWithSkippedKey builds a V2 serialized state with one skipped key entry.
// This exercises the skipped key loop body in Deserialize (lines ~621-637).
func buildV2StateWithSkippedKey(t *testing.T) []byte {
	t.Helper()
	rootKeyBytes := make([]byte, keyLen)
	for i := range rootKeyBytes {
		rootKeyBytes[i] = byte(i + 1)
	}

	chainEpoch := uint64(0)
	buf := []byte{}
	buf = append(buf, serializeVersion) // V2
	buf = append(buf, byte(DirectionA2B))

	epochB := make([]byte, 8)
	binary.BigEndian.PutUint64(epochB, chainEpoch)
	buf = append(buf, epochB...) // epoch
	buf = append(buf, epochB...) // sendEpoch

	buf = append(buf, rootKeyBytes...)

	mjump := make([]byte, 4)
	binary.BigEndian.PutUint32(mjump, 25000)
	buf = append(buf, mjump...) // maxJump

	numChains := make([]byte, 4)
	binary.BigEndian.PutUint32(numChains, 1)
	buf = append(buf, numChains...) // numChains=1

	// Chain entry: epoch(8) + sendCounter(4) + recvCounter(4) + hasSend(1) + hasRecv(1)
	chainEntry := make([]byte, chainFixedSize)
	binary.BigEndian.PutUint64(chainEntry[0:8], chainEpoch)
	buf = append(buf, chainEntry...)

	// numSkipped = 1
	numSkipped := make([]byte, 4)
	binary.BigEndian.PutUint32(numSkipped, 1)
	buf = append(buf, numSkipped...)

	// Skipped key entry: epoch(8) + counter(4) + key(32)
	skEpoch := make([]byte, 8)
	binary.BigEndian.PutUint64(skEpoch, 0)
	buf = append(buf, skEpoch...)

	skCounter := make([]byte, 4)
	binary.BigEndian.PutUint32(skCounter, 1)
	buf = append(buf, skCounter...)

	skKey := make([]byte, keyLen)
	for i := range skKey {
		skKey[i] = byte(i + 42)
	}
	buf = append(buf, skKey...)

	return buf
}

// TestDeserializeV2WithSkippedKeys verifies the V1/V2 skipped key loop body
// is executed when the serialized state contains skipped keys.
func TestDeserializeV2WithSkippedKeys(t *testing.T) {
	data := buildV2StateWithSkippedKey(t)

	s, err := Deserialize(data)
	if err != nil {
		t.Fatalf("Deserialize V2 with skipped keys: %v", err)
	}
	defer s.Zeroize()

	if len(s.skippedKeys) != 1 {
		t.Errorf("expected 1 skipped key, got %d", len(s.skippedKeys))
	}

	skID := SkippedKeyID{Epoch: 0, Counter: 1}
	sk, ok := s.skippedKeys[skID]
	if !ok {
		t.Fatal("skipped key {epoch=0, counter=1} not found")
	}
	if sk == nil || sk.IsDestroyed() {
		t.Error("skipped key secret is nil or destroyed")
	}
}

// TestDeserializeV2TrailingData verifies that V1/V2 trailing data is rejected.
func TestDeserializeV2TrailingData(t *testing.T) {
	data := buildV2StateWithSkippedKey(t)
	// Append a trailing byte.
	data = append(data, 0xFF)
	_, err := Deserialize(data)
	if err == nil {
		t.Fatal("expected error for V2 trailing data")
	}
	var e *ErrDeserialize
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// ============================================================================
// V3 resolved Deserialize: skipped key loop body
// ============================================================================

// buildV3ResolvedWithSkippedKey builds a V3 resolved state with one skipped key.
func buildV3ResolvedWithSkippedKey(t *testing.T) []byte {
	t.Helper()
	rootKeyBytes := make([]byte, keyLen)
	for i := range rootKeyBytes {
		rootKeyBytes[i] = byte(i + 2)
	}

	buf := []byte{}
	buf = append(buf, serializeVersionV3) // V3
	buf = append(buf, 0x01)               // negotiated=resolved
	buf = append(buf, byte(VersionV1))    // resolvedVersion=V1

	buf = append(buf, byte(DirectionA2B)) // direction

	epochB := make([]byte, 8)
	binary.BigEndian.PutUint64(epochB, 0)
	buf = append(buf, epochB...) // epoch
	buf = append(buf, epochB...) // sendEpoch

	buf = append(buf, rootKeyBytes...)

	mjump := make([]byte, 4)
	binary.BigEndian.PutUint32(mjump, 25000)
	buf = append(buf, mjump...) // maxJump

	numChains := make([]byte, 4)
	binary.BigEndian.PutUint32(numChains, 1)
	buf = append(buf, numChains...) // numChains=1

	// Chain entry
	chainEntry := make([]byte, chainFixedSize)
	// epoch=0, sendCounter=0, recvCounter=1 (we received one message)
	binary.BigEndian.PutUint64(chainEntry[0:8], 0)
	binary.BigEndian.PutUint32(chainEntry[8:12], 0)
	binary.BigEndian.PutUint32(chainEntry[12:16], 1)
	// hasSend=0, hasRecv=0
	buf = append(buf, chainEntry...)

	// numSkipped = 1
	numSkipped := make([]byte, 4)
	binary.BigEndian.PutUint32(numSkipped, 1)
	buf = append(buf, numSkipped...)

	// Skipped key: epoch(8) + counter(4) + key(32)
	skEpoch := make([]byte, 8)
	binary.BigEndian.PutUint64(skEpoch, 0)
	buf = append(buf, skEpoch...)

	skCounter := make([]byte, 4)
	binary.BigEndian.PutUint32(skCounter, 3)
	buf = append(buf, skCounter...)

	skKey := make([]byte, keyLen)
	for i := range skKey {
		skKey[i] = byte(i + 77)
	}
	buf = append(buf, skKey...)

	return buf
}

// TestDeserializeV3ResolvedWithSkippedKeys exercises the V3 resolved skipped key loop body.
func TestDeserializeV3ResolvedWithSkippedKeys(t *testing.T) {
	data := buildV3ResolvedWithSkippedKey(t)

	s, err := Deserialize(data)
	if err != nil {
		t.Fatalf("Deserialize V3 resolved with skipped keys: %v", err)
	}
	defer s.Zeroize()

	if len(s.skippedKeys) != 1 {
		t.Errorf("expected 1 skipped key, got %d", len(s.skippedKeys))
	}
	skID := SkippedKeyID{Epoch: 0, Counter: 3}
	sk, ok := s.skippedKeys[skID]
	if !ok {
		t.Fatal("skipped key {epoch=0, counter=3} not found in V3 resolved")
	}
	if sk == nil || sk.IsDestroyed() {
		t.Error("V3 resolved skipped key secret is nil or destroyed")
	}
}

// TestDeserializeV3ResolvedWithSkippedKeysTrailingData verifies V3 resolved trailing data is rejected.
func TestDeserializeV3ResolvedWithSkippedKeysTrailingData(t *testing.T) {
	data := buildV3ResolvedWithSkippedKey(t)
	data = append(data, 0xFF)
	_, err := Deserialize(data)
	if err == nil {
		t.Fatal("expected error for V3 resolved trailing data")
	}
	var e *ErrDeserialize
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// TestDeserializeV3InvalidNegotiationByteV5 exercises the default case in deserializeV3.
func TestDeserializeV3InvalidNegotiationByteV5(t *testing.T) {
	buf := []byte{serializeVersionV3, 0xFF} // invalid negotiation byte
	_, err := Deserialize(buf)
	if err == nil {
		t.Fatal("expected error for V3 invalid negotiation byte")
	}
	var e *ErrDeserialize
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// TestDeserializeV3UnsupportedResolvedVersion tests V3 resolved with unknown version.
func TestDeserializeV3UnsupportedResolvedVersion(t *testing.T) {
	buf := []byte{serializeVersionV3, 0x01, 0xFF} // resolved=0x01, version=0xFF
	_, err := Deserialize(buf)
	if err == nil {
		t.Fatal("expected error for V3 unsupported resolved version")
	}
	var e *ErrDeserialize
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// ============================================================================
// V4 resolved Deserialize: skipped key loop body
// ============================================================================

// buildV4ResolvedWithSkippedKey builds a V4 resolved state with one skipped key and no braid.
func buildV4ResolvedWithSkippedKey(t *testing.T) []byte {
	t.Helper()
	rootKeyBytes := make([]byte, keyLen)
	for i := range rootKeyBytes {
		rootKeyBytes[i] = byte(i + 3)
	}

	buf := []byte{}
	buf = append(buf, serializeVersionV4) // V4
	buf = append(buf, 0x01)               // negotiated=resolved
	buf = append(buf, byte(VersionV1))    // resolvedVersion=V1

	buf = append(buf, byte(DirectionB2A)) // direction

	epochB := make([]byte, 8)
	binary.BigEndian.PutUint64(epochB, 0)
	buf = append(buf, epochB...) // epoch
	buf = append(buf, epochB...) // sendEpoch

	buf = append(buf, rootKeyBytes...)

	mjump := make([]byte, 4)
	binary.BigEndian.PutUint32(mjump, 25000)
	buf = append(buf, mjump...) // maxJump

	numChains := make([]byte, 4)
	binary.BigEndian.PutUint32(numChains, 1)
	buf = append(buf, numChains...) // numChains=1

	// Chain entry
	chainEntry := make([]byte, chainFixedSize)
	binary.BigEndian.PutUint64(chainEntry[0:8], 0)
	binary.BigEndian.PutUint32(chainEntry[8:12], 0)
	binary.BigEndian.PutUint32(chainEntry[12:16], 1) // recvCounter=1
	buf = append(buf, chainEntry...)

	// numSkipped = 1
	numSkipped := make([]byte, 4)
	binary.BigEndian.PutUint32(numSkipped, 1)
	buf = append(buf, numSkipped...)

	// Skipped key: epoch(8) + counter(4) + key(32)
	skEpoch := make([]byte, 8)
	binary.BigEndian.PutUint64(skEpoch, 0)
	buf = append(buf, skEpoch...)

	skCounter := make([]byte, 4)
	binary.BigEndian.PutUint32(skCounter, 5)
	buf = append(buf, skCounter...)

	skKey := make([]byte, keyLen)
	for i := range skKey {
		skKey[i] = byte(i + 55)
	}
	buf = append(buf, skKey...)

	// No braid: hasBraid=0x00
	buf = append(buf, 0x00)

	return buf
}

// TestDeserializeV4ResolvedWithSkippedKeys exercises V4 resolved skipped key loop body.
func TestDeserializeV4ResolvedWithSkippedKeys(t *testing.T) {
	data := buildV4ResolvedWithSkippedKey(t)

	s, err := Deserialize(data)
	if err != nil {
		t.Fatalf("Deserialize V4 resolved with skipped keys: %v", err)
	}
	defer s.Zeroize()

	if len(s.skippedKeys) != 1 {
		t.Errorf("expected 1 skipped key, got %d", len(s.skippedKeys))
	}
	skID := SkippedKeyID{Epoch: 0, Counter: 5}
	sk, ok := s.skippedKeys[skID]
	if !ok {
		t.Fatal("skipped key {epoch=0, counter=5} not found in V4 resolved")
	}
	if sk == nil || sk.IsDestroyed() {
		t.Error("V4 resolved skipped key secret is nil or destroyed")
	}
}

// TestDeserializeV4ResolvedWithSkippedKeysTrailingData verifies V4 resolved trailing data is rejected.
func TestDeserializeV4ResolvedWithSkippedKeysTrailingData(t *testing.T) {
	data := buildV4ResolvedWithSkippedKey(t)
	data = append(data, 0xFF)
	_, err := Deserialize(data)
	if err == nil {
		t.Fatal("expected error for V4 resolved trailing data")
	}
	var e *ErrDeserialize
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// TestDeserializeV4InvalidNegotiationByteV5 exercises the default case in deserializeV4.
func TestDeserializeV4InvalidNegotiationByteV5(t *testing.T) {
	buf := []byte{serializeVersionV4, 0xFF} // invalid negotiation byte
	_, err := Deserialize(buf)
	if err == nil {
		t.Fatal("expected error for V4 invalid negotiation byte")
	}
	var e *ErrDeserialize
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// TestDeserializeV4UnsupportedResolvedVersion tests V4 resolved with unsupported version.
func TestDeserializeV4UnsupportedResolvedVersion(t *testing.T) {
	buf := []byte{serializeVersionV4, 0x01, 0xFF}
	_, err := Deserialize(buf)
	if err == nil {
		t.Fatal("expected error for V4 unsupported resolved version")
	}
	var e *ErrDeserialize
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// TestDeserializeV4ResolvedSkippedKeysTooMany tests V4 resolved with too many skipped keys.
func TestDeserializeV4ResolvedSkippedKeysTooMany(t *testing.T) {
	data := buildV4ResolvedWithSkippedKey(t)
	// The numSkipped field is after the chain data.
	// Find it: offset = 3 (header) + 1 (dir) + 8 (epoch) + 8 (sendEpoch) + 32 (rk) + 4 (maxJump) + 4 (numChains) + chainFixedSize
	off := 3 + 1 + 8 + 8 + keyLen + 4 + 4 + chainFixedSize
	binary.BigEndian.PutUint32(data[off:], uint32(maxDeserializedSkippedKeys+1))
	_, err := Deserialize(data)
	if err == nil {
		t.Fatal("expected error for V4 resolved too many skipped keys")
	}
	var e *ErrDeserialize
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// ============================================================================
// V4 resolved skipped key count missing (no data for skipped count)
// ============================================================================

// TestDeserializeV4ResolvedSkippedCountMissing builds V4 resolved with 0 chains but
// no bytes for numSkipped — exercises the "V4 data too short for skipped keys count" path.
func TestDeserializeV4ResolvedSkippedCountMissing(t *testing.T) {
	rootKeyBytes := make([]byte, keyLen)
	buf := []byte{}
	buf = append(buf, serializeVersionV4)
	buf = append(buf, 0x01)
	buf = append(buf, byte(VersionV1))
	buf = append(buf, byte(DirectionA2B))

	epochB := make([]byte, 8)
	buf = append(buf, epochB...) // epoch=0
	buf = append(buf, epochB...) // sendEpoch=0
	buf = append(buf, rootKeyBytes...)

	mjump := make([]byte, 4)
	binary.BigEndian.PutUint32(mjump, 25000)
	buf = append(buf, mjump...) // maxJump
	numChains := make([]byte, 4)
	// numChains=0
	buf = append(buf, numChains...)
	// No numSkipped bytes — truncated here.

	_, err := Deserialize(buf)
	if err == nil {
		t.Fatal("expected error for V4 resolved missing skipped key count")
	}
	var e *ErrDeserialize
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// ============================================================================
// V3 resolved skipped key count missing
// ============================================================================

func TestDeserializeV3ResolvedSkippedCountMissing(t *testing.T) {
	rootKeyBytes := make([]byte, keyLen)
	buf := []byte{}
	buf = append(buf, serializeVersionV3)
	buf = append(buf, 0x01)
	buf = append(buf, byte(VersionV1))
	buf = append(buf, byte(DirectionA2B))

	epochB := make([]byte, 8)
	buf = append(buf, epochB...)
	buf = append(buf, epochB...)
	buf = append(buf, rootKeyBytes...)

	mjump := make([]byte, 4)
	binary.BigEndian.PutUint32(mjump, 25000)
	buf = append(buf, mjump...)
	numChains := make([]byte, 4)
	buf = append(buf, numChains...) // 0 chains, no numSkipped follows

	_, err := Deserialize(buf)
	if err == nil {
		t.Fatal("expected error for V3 resolved missing skipped key count")
	}
	var e *ErrDeserialize
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// ============================================================================
// KDF functions: direct tests for normal success and error paths
// ============================================================================

// TestKdfSckaInitSuccess verifies KdfSckaInit derives three distinct non-nil keys.
func TestKdfSckaInitSuccess(t *testing.T) {
	ss := make([]byte, 32)
	for i := range ss {
		ss[i] = byte(i + 1)
	}

	rk, cks, ckr, err := KdfSckaInit(ss)
	if err != nil {
		t.Fatalf("KdfSckaInit: %v", err)
	}
	defer rk.Destroy()
	defer cks.Destroy()
	defer ckr.Destroy()

	if rk == nil || rk.IsDestroyed() {
		t.Error("rk should not be nil or destroyed")
	}
	if cks == nil || cks.IsDestroyed() {
		t.Error("cks should not be nil or destroyed")
	}
	if ckr == nil || ckr.IsDestroyed() {
		t.Error("ckr should not be nil or destroyed")
	}
	if len(rk.Bytes()) != keyLen {
		t.Errorf("rk length = %d, want %d", len(rk.Bytes()), keyLen)
	}

	// All three keys should be distinct.
	if bytes.Equal(rk.Bytes(), cks.Bytes()) {
		t.Error("rk and cks should be distinct")
	}
	if bytes.Equal(rk.Bytes(), ckr.Bytes()) {
		t.Error("rk and ckr should be distinct")
	}
	if bytes.Equal(cks.Bytes(), ckr.Bytes()) {
		t.Error("cks and ckr should be distinct")
	}
}

// TestKdfSckaInitEmptySharedSecretV5 verifies KdfSckaInit rejects empty input.
func TestKdfSckaInitEmptySharedSecretV5(t *testing.T) {
	_, _, _, err := KdfSckaInit(nil)
	if err == nil {
		t.Fatal("expected error for nil shared secret")
	}
	var e *ErrInvalidInput
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrInvalidInput, got %T: %v", err, err)
	}

	_, _, _, err = KdfSckaInit([]byte{})
	if err == nil {
		t.Fatal("expected error for empty shared secret")
	}
}

// TestKdfSckaRKSuccess verifies KdfSckaRK derives new keys from root key + SCKA output.
func TestKdfSckaRKSuccess(t *testing.T) {
	rkBytes := make([]byte, keyLen)
	for i := range rkBytes {
		rkBytes[i] = byte(i + 10)
	}
	rkSecret, err := secret.New(rkBytes)
	if err != nil {
		t.Fatalf("secret.New: %v", err)
	}
	defer rkSecret.Destroy()

	sckaOut := make([]byte, 32)
	for i := range sckaOut {
		sckaOut[i] = byte(i + 20)
	}

	newRK, newCKs, newCKr, err := KdfSckaRK(rkSecret, sckaOut)
	if err != nil {
		t.Fatalf("KdfSckaRK: %v", err)
	}
	defer newRK.Destroy()
	defer newCKs.Destroy()
	defer newCKr.Destroy()

	if newRK == nil || newRK.IsDestroyed() {
		t.Error("newRK should not be nil or destroyed")
	}
	if newCKs == nil || newCKs.IsDestroyed() {
		t.Error("newCKs should not be nil or destroyed")
	}
	if newCKr == nil || newCKr.IsDestroyed() {
		t.Error("newCKr should not be nil or destroyed")
	}
}

// TestKdfSckaRKNilRootKey verifies KdfSckaRK rejects nil root key.
func TestKdfSckaRKNilRootKey(t *testing.T) {
	_, _, _, err := KdfSckaRK(nil, []byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for nil root key")
	}
	var e *ErrInvalidInput
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrInvalidInput, got %T: %v", err, err)
	}
}

// TestKdfSckaRKEmptySckaOutputV5 verifies KdfSckaRK rejects empty SCKA output.
func TestKdfSckaRKEmptySckaOutputV5(t *testing.T) {
	rkBytes := make([]byte, keyLen)
	rk, err := secret.New(rkBytes)
	if err != nil {
		t.Fatalf("secret.New: %v", err)
	}
	defer rk.Destroy()

	_, _, _, err = KdfSckaRK(rk, []byte{})
	if err == nil {
		t.Fatal("expected error for empty SCKA output")
	}
	var e *ErrInvalidInput
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrInvalidInput, got %T: %v", err, err)
	}
}

// TestKdfSckaCKSuccess verifies KdfSckaCK derives mk and nextCK from chain key.
func TestKdfSckaCKSuccess(t *testing.T) {
	ckBytes := make([]byte, keyLen)
	for i := range ckBytes {
		ckBytes[i] = byte(i + 5)
	}
	ck, err := secret.New(ckBytes)
	if err != nil {
		t.Fatalf("secret.New: %v", err)
	}
	defer ck.Destroy()

	mk, nextCK, err := KdfSckaCK(ck, 1)
	if err != nil {
		t.Fatalf("KdfSckaCK: %v", err)
	}
	defer mk.Destroy()
	defer nextCK.Destroy()

	if mk == nil || mk.IsDestroyed() {
		t.Error("mk should not be nil or destroyed")
	}
	if nextCK == nil || nextCK.IsDestroyed() {
		t.Error("nextCK should not be nil or destroyed")
	}
	if len(mk.Bytes()) != keyLen {
		t.Errorf("mk length = %d, want %d", len(mk.Bytes()), keyLen)
	}
	// mk and nextCK should be distinct (different HKDF outputs).
	if bytes.Equal(mk.Bytes(), nextCK.Bytes()) {
		t.Error("mk and nextCK should be distinct")
	}
}

// TestKdfSckaCKNilChainKey verifies KdfSckaCK rejects nil chain key.
func TestKdfSckaCKNilChainKey(t *testing.T) {
	_, _, err := KdfSckaCK(nil, 1)
	if err == nil {
		t.Fatal("expected error for nil chain key")
	}
	var e *ErrInvalidInput
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrInvalidInput, got %T: %v", err, err)
	}
}

// ============================================================================
// Send API: braid-integrated path
// ============================================================================

// TestSendAPIWithBraid exercises the Send() package function on a braid-attached state,
// covering the braid delegation path in Send (lines ~297-307 in session_api.go).
//
// Strategy: create Alice and Bob braid structs directly (resolved), serialize them,
// then use the Send/Recv API. This avoids the pending state issue.
func TestSendAPIWithBraid(t *testing.T) {
	ss := randomBytes(t, 32)
	ssCopy := make([]byte, 32)
	copy(ssCopy, ss)

	kemAlice := mlkembraid.NewMLKEM768IncrementalKEM()
	kemBob := mlkembraid.NewMLKEM768IncrementalKEM()

	braidAlice, err := mlkembraid.InitAlice(ss, kemAlice, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}
	braidBob, err := mlkembraid.InitBob(ssCopy, kemBob, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitBob: %v", err)
	}

	// Create resolved braid states directly via InitWithBraid.
	alice, err := InitWithBraid(ss, DirectionA2B, uint32(maxJump), braidAlice)
	if err != nil {
		t.Fatalf("InitWithBraid alice: %v", err)
	}
	bob, err := InitWithBraid(ssCopy, DirectionB2A, uint32(maxJump), braidBob)
	if err != nil {
		t.Fatalf("InitWithBraid bob: %v", err)
	}

	// Serialize for use with the API.
	aliceSerialized, err := alice.Serialize()
	alice.Zeroize()
	if err != nil {
		t.Fatalf("alice.Serialize: %v", err)
	}
	bobSerialized, err := bob.Serialize()
	bob.Zeroize()
	if err != nil {
		t.Fatalf("bob.Serialize: %v", err)
	}

	// Alice sends via the Send API (braid path).
	aliceState2, pqrMsg, aliceMK, sendErr := Send(aliceSerialized)
	if sendErr != nil {
		t.Fatalf("Send alice: %v", sendErr)
	}
	if len(aliceState2) == 0 {
		t.Error("Send returned empty new state")
	}
	if len(pqrMsg) == 0 {
		t.Error("Send returned empty pqrMsg")
	}
	if len(aliceMK) == 0 {
		t.Error("Send returned empty message key")
	}

	// Bob receives via the Recv API (braid path).
	bobState2, bobMK, recvErr := Recv(bobSerialized, pqrMsg)
	if recvErr != nil {
		t.Fatalf("Recv bob: %v", recvErr)
	}
	if len(bobState2) == 0 {
		t.Error("Recv returned empty new state")
	}
	_ = bobMK
}

// TestSendAPIDisabled exercises the Send() function on a V0-disabled state.
func TestSendAPIDisabled(t *testing.T) {
	// Build a V3 disabled state.
	buf := []byte{serializeVersionV3, 0x01, byte(VersionV0)}
	s, err := Deserialize(buf)
	if err != nil {
		t.Fatalf("Deserialize V3 disabled: %v", err)
	}
	serialized, err := s.Serialize()
	s.Zeroize()
	if err != nil {
		t.Fatalf("Serialize disabled: %v", err)
	}

	newState, pqrMsg, mk, err := Send(serialized)
	if err != nil {
		t.Fatalf("Send disabled: %v", err)
	}
	if len(newState) == 0 {
		t.Error("expected non-empty new state")
	}
	if len(pqrMsg) != 0 {
		t.Error("expected empty pqrMsg for disabled state")
	}
	if mk != nil {
		t.Error("expected nil message key for disabled state")
	}
}

// TestRecvAPIDisabled exercises the Recv() function on a V0-disabled state.
func TestRecvAPIDisabled(t *testing.T) {
	buf := []byte{serializeVersionV3, 0x01, byte(VersionV0)}
	s, err := Deserialize(buf)
	if err != nil {
		t.Fatalf("Deserialize V3 disabled: %v", err)
	}
	serialized, err := s.Serialize()
	s.Zeroize()
	if err != nil {
		t.Fatalf("Serialize disabled: %v", err)
	}

	newState, mk, err := Recv(serialized, []byte{})
	if err != nil {
		t.Fatalf("Recv disabled: %v", err)
	}
	if len(newState) == 0 {
		t.Error("expected non-empty new state")
	}
	if mk != nil {
		t.Error("expected nil message key for disabled state")
	}
}

// ============================================================================
// Send API: pending state with minVersion < V1 (sends empty msg without resolving)
// ============================================================================

// TestSendAPIPendingMinVersionV0 exercises the pending state path in Send()
// where minVersion < V1 (returns empty pqrMsg without resolving).
func TestSendAPIPendingMinVersionV0(t *testing.T) {
	serialized, err := InitialStateWithParams(Params{
		AuthKey:    randomBytes(t, 32),
		Version:    VersionV1,
		Direction:  DirectionA2B,
		MinVersion: VersionV0,
		MaxJump:    25000,
		MaxOOOKeys: maxSkippedKeys,
	})
	if err != nil {
		t.Fatalf("InitialStateWithParams: %v", err)
	}

	newState, pqrMsg, mk, err := Send(serialized)
	if err != nil {
		t.Fatalf("Send pending V0: %v", err)
	}
	if len(newState) == 0 {
		t.Error("expected non-empty new state")
	}
	// Pending with minVersion=V0: returns empty message.
	if len(pqrMsg) != 0 {
		t.Errorf("expected empty pqrMsg for pending V0, got %d bytes", len(pqrMsg))
	}
	if mk != nil {
		t.Error("expected nil message key for pending V0")
	}
}

// ============================================================================
// Send API: pending state with minVersion = V1 (auto-resolves and sends)
// ============================================================================

// TestSendAPIPendingMinVersionV1 exercises the Send() path that auto-resolves
// pending state when minVersion >= V1.
func TestSendAPIPendingMinVersionV1(t *testing.T) {
	serialized, err := InitialStateWithParams(Params{
		AuthKey:    randomBytes(t, 32),
		Version:    VersionV1,
		Direction:  DirectionA2B,
		MinVersion: VersionV1,
		MaxJump:    25000,
		MaxOOOKeys: maxSkippedKeys,
	})
	if err != nil {
		t.Fatalf("InitialStateWithParams: %v", err)
	}

	newState, pqrMsg, mk, err := Send(serialized)
	if err != nil {
		t.Fatalf("Send pending V1: %v", err)
	}
	if len(newState) == 0 {
		t.Error("expected non-empty new state")
	}
	if len(pqrMsg) != pqrMsgSize {
		t.Errorf("expected %d-byte pqrMsg for resolved V1, got %d", pqrMsgSize, len(pqrMsg))
	}
	if len(mk) == 0 {
		t.Error("expected non-nil message key for resolved V1 Send")
	}
}

// ============================================================================
// Recv API: pending state resolves to V0 (disabled) via empty pqrMsg
// ============================================================================

// TestRecvAPIPendingResolvesV0 exercises the Recv() path where pending state
// resolves to disabled (V0) via an empty or byte{0x00} pqrMsg.
func TestRecvAPIPendingResolvesV0(t *testing.T) {
	serialized, err := InitialState(randomBytes(t, 32), DirectionB2A, false)
	if err != nil {
		t.Fatalf("InitialState: %v", err)
	}

	// Empty pqrMsg resolves to V0 (disabled).
	newState, mk, err := Recv(serialized, []byte{})
	if err != nil {
		t.Fatalf("Recv pending resolve V0: %v", err)
	}
	if len(newState) == 0 {
		t.Error("expected non-empty new state")
	}
	if mk != nil {
		t.Error("expected nil message key for V0 resolved state")
	}
}

// ============================================================================
// Recv API: wrong message size for legacy resolved path
// ============================================================================

// TestRecvAPIWrongMsgSize exercises the ErrPQRMessage path in Recv() when
// a resolved V1 (non-braid) state receives a message that is neither 0 nor 12 bytes.
func TestRecvAPIWrongMsgSize(t *testing.T) {
	// Use a resolved V1 state: create with MinVersion=V1 so Send auto-resolves it.
	// The resolved state from Send can be used directly as receiver input.
	ss := randomBytes(t, 32)
	senderState, err := InitialStateWithParams(Params{
		AuthKey:    ss,
		Version:    VersionV1,
		Direction:  DirectionA2B,
		MinVersion: VersionV1,
		MaxJump:    25000,
		MaxOOOKeys: maxSkippedKeys,
	})
	if err != nil {
		t.Fatalf("InitialStateWithParams sender: %v", err)
	}

	// Auto-resolve and get a resolved sender state.
	resolvedSenderState, _, _, sendErr := Send(senderState)
	if sendErr != nil {
		t.Fatalf("Send: %v", sendErr)
	}

	// The resolved sender state (DirectionA2B) is good for sending but not for Recv.
	// We need a receiver state. Create a matching receiver (DirectionB2A, same authKey).
	// After resolution, both sides have chains derived from the same authKey.
	// The receiver state after resolution has the same root key derived from ss.
	// Use Send on DirectionB2A state (same authKey) to get a resolved receiver state.
	receiverState, err := InitialStateWithParams(Params{
		AuthKey:    ss,
		Version:    VersionV1,
		Direction:  DirectionB2A,
		MinVersion: VersionV1,
		MaxJump:    25000,
		MaxOOOKeys: maxSkippedKeys,
	})
	if err != nil {
		t.Fatalf("InitialStateWithParams receiver: %v", err)
	}
	resolvedReceiverState, _, _, sendErr2 := Send(receiverState)
	if sendErr2 != nil {
		t.Fatalf("Send receiver: %v", sendErr2)
	}
	_ = resolvedSenderState

	// Pass a wrong-size message (3 bytes, not 12) to the resolved receiver.
	_, _, recvErr := Recv(resolvedReceiverState, []byte{0x01, 0x02, 0x03})
	if recvErr == nil {
		t.Fatal("expected error for wrong message size in resolved V1 Recv")
	}
	var e *ErrPQRMessage
	if !errors.As(recvErr, &e) {
		t.Errorf("expected *ErrPQRMessage, got %T: %v", recvErr, recvErr)
	}
}

// ============================================================================
// Recv API: braid-integrated path (stateful)
// ============================================================================

// TestRecvAPIWithBraid exercises the Recv() package function on a braid-attached state,
// covering the braid delegation path in Recv (lines ~607-617 in session_api.go).
// Uses InitWithBraid to create resolved states directly, avoiding the pending state issue.
func TestRecvAPIWithBraid(t *testing.T) {
	ss := randomBytes(t, 32)
	ssCopy := make([]byte, 32)
	copy(ssCopy, ss)

	kemAlice := mlkembraid.NewMLKEM768IncrementalKEM()
	kemBob := mlkembraid.NewMLKEM768IncrementalKEM()

	braidAlice, err := mlkembraid.InitAlice(ss, kemAlice, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}
	braidBob, err := mlkembraid.InitBob(ssCopy, kemBob, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitBob: %v", err)
	}

	// Create resolved SPQR structs directly and serialize them for the API.
	alice, err := InitWithBraid(ss, DirectionA2B, uint32(maxJump), braidAlice)
	if err != nil {
		t.Fatalf("InitWithBraid alice: %v", err)
	}
	bob, err := InitWithBraid(ssCopy, DirectionB2A, uint32(maxJump), braidBob)
	if err != nil {
		t.Fatalf("InitWithBraid bob: %v", err)
	}

	aliceSerialized, err := alice.Serialize()
	alice.Zeroize()
	if err != nil {
		t.Fatalf("alice.Serialize: %v", err)
	}
	bobSerialized, err := bob.Serialize()
	bob.Zeroize()
	if err != nil {
		t.Fatalf("bob.Serialize: %v", err)
	}

	// Alice sends via the API — exercises Send's braid delegation path.
	aliceState2, alicePQR, aliceMK, sendErr := Send(aliceSerialized)
	if sendErr != nil {
		t.Fatalf("Send alice: %v", sendErr)
	}
	_ = aliceMK
	if len(alicePQR) == 0 {
		t.Error("expected non-empty pqrMsg from alice")
	}

	// Bob receives via Recv API — exercises Recv's braid delegation path.
	bobState2, bobMK, recvErr := Recv(bobSerialized, alicePQR)
	if recvErr != nil {
		t.Fatalf("Recv bob from alice: %v", recvErr)
	}
	if len(bobState2) == 0 {
		t.Error("expected non-empty bob state after Recv")
	}
	_ = bobMK

	// Alice sends a second time to ensure ongoing braid path works.
	_, alicePQR2, _, sendErr2 := Send(aliceState2)
	if sendErr2 != nil {
		t.Fatalf("Send alice 2: %v", sendErr2)
	}
	if len(alicePQR2) == 0 {
		t.Error("expected non-empty pqrMsg from alice 2")
	}

	// Bob receives the second message via the resolved braid path.
	_, bobMK2, recvErr2 := Recv(bobState2, alicePQR2)
	if recvErr2 != nil {
		t.Fatalf("Recv bob from alice 2: %v", recvErr2)
	}
	_ = bobMK2
}

// ============================================================================
// Recv API: pending with braid resolves to V1 path
// ============================================================================

// TestRecvAPIPendingWithBraidResolvesToV1 exercises the Recv() path where
// a braid-attached pending state receives a non-empty message and resolves to V1,
// then calls RecvBraid (lines ~607-617 in session_api.go).
func TestRecvAPIPendingWithBraidResolvesToV1(t *testing.T) {
	ss := randomBytes(t, 32)
	ssCopy := make([]byte, 32)
	copy(ssCopy, ss)

	kemAlice := mlkembraid.NewMLKEM768IncrementalKEM()
	kemBob := mlkembraid.NewMLKEM768IncrementalKEM()

	braidAlice, err := mlkembraid.InitAlice(ss, kemAlice, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}
	braidBob, err := mlkembraid.InitBob(ssCopy, kemBob, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitBob: %v", err)
	}

	// Create Alice's struct directly (resolved with braid).
	alice, err := InitWithBraid(ss, DirectionA2B, uint32(maxJump), braidAlice)
	if err != nil {
		t.Fatalf("InitWithBraid alice: %v", err)
	}
	defer alice.Zeroize()

	// Create Bob's serialized pending state with braid via InitialStateWithBraid.
	bobSerialized, err := InitialStateWithBraid(ssCopy, DirectionB2A, false, braidBob)
	if err != nil {
		t.Fatalf("InitialStateWithBraid bob: %v", err)
	}

	// Alice sends.
	pqrMsg, _, sendErr := alice.SendBraid()
	if sendErr != nil {
		t.Fatalf("alice.SendBraid: %v", sendErr)
	}

	// Bob (pending, braid attached) receives — this exercises the
	// Recv() -> pending -> resolveNegotiation -> s.braid != nil -> RecvBraid path.
	newBobState, bobMK, recvErr := Recv(bobSerialized, pqrMsg)
	if recvErr != nil {
		t.Fatalf("Recv bob pending->resolved: %v", recvErr)
	}
	if len(newBobState) == 0 {
		t.Error("expected non-empty bob state")
	}
	_ = bobMK
}

// ============================================================================
// InitialStateWithBraidResolved: error path
// ============================================================================

// TestInitialStateWithBraidResolvedInvalidInput exercises the error path
// in InitialStateWithBraidResolved when sharedSecret is empty.
func TestInitialStateWithBraidResolvedInvalidInput(t *testing.T) {
	kem := mlkembraid.NewMLKEM768IncrementalKEM()
	braid, err := mlkembraid.InitAlice(randomBytes(t, 32), kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}
	defer braid.Zeroize()

	_, err = InitialStateWithBraidResolved(nil, DirectionA2B, false, braid)
	if err == nil {
		t.Fatal("expected error for nil sharedSecret in InitialStateWithBraidResolved")
	}
}

// TestInitialStateWithBraidResolvedSuccess exercises the success path of
// InitialStateWithBraidResolved, covering the InitWithBraid success path (line 188+).
func TestInitialStateWithBraidResolvedSuccess(t *testing.T) {
	ss := randomBytes(t, 32)
	kem := mlkembraid.NewMLKEM768IncrementalKEM()
	braid, err := mlkembraid.InitAlice(ss, kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}

	serialized, err := InitialStateWithBraidResolved(ss, DirectionA2B, false, braid)
	if err != nil {
		t.Fatalf("InitialStateWithBraidResolved: %v", err)
	}
	if len(serialized) == 0 {
		t.Error("expected non-empty serialized state")
	}

	s, err := Deserialize(serialized)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	defer s.Zeroize()

	if !s.IsNegotiated() {
		t.Error("expected negotiated state from InitialStateWithBraidResolved")
	}
	if s.braid == nil {
		t.Error("expected braid to be attached")
	}
}

// ============================================================================
// serializeV4Resolved: nil/destroyed root key (serialization error path)
// ============================================================================

// TestSerializeV4ResolvedNilRootKey exercises the serializeV4Resolved error path
// when the root key is nil — triggers ErrSerialize from serializeV4Resolved.
func TestSerializeV4ResolvedNilRootKey(t *testing.T) {
	ss := randomBytes(t, 32)
	kem := mlkembraid.NewMLKEM768IncrementalKEM()
	braid, err := mlkembraid.InitAlice(ss, kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}
	defer braid.Zeroize()

	s := &SPQR{
		chains:      make(map[uint64]*EpochChain),
		skippedKeys: make(map[SkippedKeyID]*secret.Secret),
		direction:   DirectionA2B,
		maxJump:     uint32(maxJump),
		negotiation: negotiationResolved,
		version:     VersionV1,
		minVersion:  VersionV0,
		rootKey:     nil, // nil root key
		braid:       braid,
	}
	// rootKey is nil — Serialize → serializeV4Resolved should error.
	_, err = s.Serialize()
	if err == nil {
		t.Fatal("expected error for nil root key in serializeV4Resolved")
	}
	var e *ErrSerialize
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrSerialize, got %T: %v", err, err)
	}
}

// ============================================================================
// serializeV4Pending: nil authKey (serialization error path)
// ============================================================================

// TestSerializeV4PendingNilAuthKey exercises the serializeV4Pending error path
// when authKey is empty.
func TestSerializeV4PendingNilAuthKey(t *testing.T) {
	ss := randomBytes(t, 32)
	kem := mlkembraid.NewMLKEM768IncrementalKEM()
	braid, err := mlkembraid.InitAlice(ss, kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}
	defer braid.Zeroize()

	s := &SPQR{
		chains:      make(map[uint64]*EpochChain),
		skippedKeys: make(map[SkippedKeyID]*secret.Secret),
		direction:   DirectionA2B,
		maxJump:     uint32(maxJump),
		negotiation: negotiationPending,
		version:     VersionV1,
		minVersion:  VersionV0,
		authKey:     nil, // nil authKey
		braid:       braid,
	}
	_, err = s.Serialize()
	if err == nil {
		t.Fatal("expected error for nil authKey in serializeV4Pending")
	}
	var e *ErrSerialize
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrSerialize, got %T: %v", err, err)
	}
}

// ============================================================================
// RecvBraid: braid epoch == 0 error path
// ============================================================================

// TestRecvBraidEpochZeroError exercises the braid epoch == 0 error check in RecvBraid.
// This is triggered by crafting a wire message where braidMsg.Epoch == 0.
func TestRecvBraidEpochZeroError(t *testing.T) {
	ss := randomBytes(t, 32)
	kem := mlkembraid.NewMLKEM768IncrementalKEM()
	braidAlice, err := mlkembraid.InitAlice(ss, kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}

	s, err := InitWithBraid(ss, DirectionA2B, uint32(maxJump), braidAlice)
	if err != nil {
		t.Fatalf("InitWithBraid: %v", err)
	}
	defer s.Zeroize()

	// Build a wire message with epoch=0 to trigger the braid epoch == 0 error.
	// SCKA wire format: wireVersion(1) + varint(epoch) + varint(counter) + msgType(1)
	// epoch=0 in varint = 0x00, counter=1 in varint = 0x01
	// msgType=MessageTypeNone=0x00
	pqrMsg := []byte{
		mlkembraid.SPQRVersion,
		0x00,              // varint epoch=0
		0x01,              // varint counter=1
		byte(mlkembraid.MessageTypeNone), // msgType
	}

	_, err = s.RecvBraid(pqrMsg)
	if err == nil {
		t.Fatal("expected error for braid epoch == 0 in RecvBraid")
	}
	var e *ErrPQRMessage
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrPQRMessage, got %T: %v", err, err)
	}
}
