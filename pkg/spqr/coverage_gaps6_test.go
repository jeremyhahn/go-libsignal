package spqr

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// ============================================================================
// Serialize: nil/destroyed skipped key in V4 resolved, V3 resolved, V2
// ============================================================================

// TestSerializeV4ResolvedNilSkippedKey exercises the serializeV3Resolved
// nil/destroyed skipped key error path (serialize.go lines ~441-443).
// Without a braid, a resolved V1 state uses V3 format.
func TestSerializeV4ResolvedNilSkippedKey(t *testing.T) {
	rkBytes := make([]byte, keyLen)
	for i := range rkBytes {
		rkBytes[i] = byte(i + 1)
	}
	rk, err := secret.New(rkBytes)
	if err != nil {
		t.Fatalf("secret.New: %v", err)
	}

	// Create a destroyed (not nil) skipped key to trigger the nil-or-destroyed check.
	skBytes := make([]byte, keyLen)
	sk, skErr := secret.New(skBytes)
	if skErr != nil {
		t.Fatalf("secret.New sk: %v", skErr)
	}
	sk.Destroy() // now destroyed

	ckBytes := make([]byte, keyLen)
	for i := range ckBytes {
		ckBytes[i] = byte(i + 2)
	}
	ck, cerr := secret.New(ckBytes)
	if cerr != nil {
		t.Fatalf("secret.New chain key: %v", cerr)
	}

	s := &SPQR{
		chains: map[uint64]*EpochChain{
			0: {sendKey: ck},
		},
		skippedKeys: map[SkippedKeyID]*secret.Secret{
			{Epoch: 0, Counter: 1}: sk, // destroyed key triggers error
		},
		direction:   DirectionA2B,
		maxJump:     uint32(maxJump),
		negotiation: negotiationResolved,
		version:     VersionV1,
		minVersion:  VersionV0,
		rootKey:     rk,
		braid:       nil, // no braid → V3 format
	}
	// Do not defer Zeroize: the destroyed skipped key would panic on Destroy().
	// Manually clean up.
	defer func() {
		rk.Destroy()
		ck.Destroy()
	}()

	_, serErr := s.Serialize()
	if serErr == nil {
		t.Fatal("expected error for destroyed skipped key in Serialize")
	}
	var e *ErrSerialize
	if !errors.As(serErr, &e) {
		t.Errorf("expected *ErrSerialize, got %T: %v", serErr, serErr)
	}
}

// TestSerializeV3PendingNilAuthKey exercises the serializeV3Pending nil authKey path.
// A pending state without a braid uses V3 format.
func TestSerializeV3PendingNilAuthKey(t *testing.T) {
	s := &SPQR{
		chains:      make(map[uint64]*EpochChain),
		skippedKeys: make(map[SkippedKeyID]*secret.Secret),
		direction:   DirectionA2B,
		maxJump:     uint32(maxJump),
		negotiation: negotiationPending,
		version:     VersionV1,
		minVersion:  VersionV0,
		authKey:     nil, // triggers error in serializeV3Pending
		braid:       nil, // no braid → uses V3 format
	}

	_, err := s.Serialize()
	if err == nil {
		t.Fatal("expected error for nil authKey in serializeV3Pending")
	}
	var e *ErrSerialize
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrSerialize, got %T: %v", err, err)
	}
}

// TestSerializeV2NilSkippedKey exercises serializeV3Resolved nil/destroyed skipped
// key error path in the resolved V1 state without braid (same code path as V4 resolved).
func TestSerializeV2NilSkippedKey(t *testing.T) {
	rkBytes := make([]byte, keyLen)
	for i := range rkBytes {
		rkBytes[i] = byte(i + 3)
	}
	rk, err := secret.New(rkBytes)
	if err != nil {
		t.Fatalf("secret.New: %v", err)
	}

	ckBytes := make([]byte, keyLen)
	for i := range ckBytes {
		ckBytes[i] = byte(i + 4)
	}
	ck, cerr := secret.New(ckBytes)
	if cerr != nil {
		t.Fatalf("secret.New chain: %v", cerr)
	}

	// Use a destroyed (not nil) secret so Zeroize() doesn't panic.
	skBytes := make([]byte, keyLen)
	sk, skErr := secret.New(skBytes)
	if skErr != nil {
		t.Fatalf("secret.New sk: %v", skErr)
	}
	sk.Destroy()

	s := &SPQR{
		chains: map[uint64]*EpochChain{
			0: {sendKey: ck},
		},
		skippedKeys: map[SkippedKeyID]*secret.Secret{
			{Epoch: 0, Counter: 1}: sk,
		},
		direction:   DirectionB2A,
		maxJump:     uint32(maxJump),
		negotiation: negotiationResolved,
		version:     VersionV1,
		minVersion:  VersionV0,
		rootKey:     rk,
		braid:       nil,
	}
	defer func() {
		rk.Destroy()
		ck.Destroy()
	}()

	_, serErr := s.Serialize()
	if serErr == nil {
		t.Fatal("expected error for destroyed skipped key in serializeV3Resolved")
	}
	var e *ErrSerialize
	if !errors.As(serErr, &e) {
		t.Errorf("expected *ErrSerialize, got %T: %v", serErr, serErr)
	}
}

// ============================================================================
// deserializeV3: too-short and resolved-too-short paths
// ============================================================================

// TestDeserializeV3TooShort tests that a 1-byte V3 buffer returns an error.
func TestDeserializeV3TooShort(t *testing.T) {
	data := []byte{serializeVersionV3} // only 1 byte
	_, err := Deserialize(data)
	if err == nil {
		t.Fatal("expected error for 1-byte V3 data")
	}
	var e *ErrDeserialize
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// TestDeserializeV3ResolvedVersionTooShort tests that a 2-byte V3 resolved buffer
// (negotiated=0x01 but no version byte) returns an error.
func TestDeserializeV3ResolvedVersionTooShort(t *testing.T) {
	data := []byte{serializeVersionV3, 0x01} // resolved but no version byte
	_, err := Deserialize(data)
	if err == nil {
		t.Fatal("expected error for 2-byte V3 resolved data (no version byte)")
	}
	var e *ErrDeserialize
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// ============================================================================
// deserializeV3Pending: trailing data path
// ============================================================================

// TestDeserializeV3PendingTrailingDataV6 tests V3 pending state with trailing bytes.
func TestDeserializeV3PendingTrailingDataV6(t *testing.T) {
	// Build a valid V3 pending state.
	authKey := make([]byte, keyLen)
	for i := range authKey {
		authKey[i] = byte(i + 5)
	}

	buf := make([]byte, v3NegotiationPendingSize+1) // extra trailing byte
	offset := 0
	buf[offset] = serializeVersionV3
	offset++
	buf[offset] = 0x00 // pending
	offset++
	copy(buf[offset:], authKey)
	offset += keyLen
	buf[offset] = byte(VersionV0) // minVersion
	offset++
	buf[offset] = byte(DirectionA2B) // direction
	offset++
	binary.BigEndian.PutUint32(buf[offset:], 25000) // maxJump
	offset += 4
	buf[offset] = 0xFF // trailing garbage byte

	_, err := Deserialize(buf)
	if err == nil {
		t.Fatal("expected error for V3 pending trailing data")
	}
	var e *ErrDeserialize
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// ============================================================================
// deserializeV3Resolved: invalid direction path
// ============================================================================

// TestDeserializeV3ResolvedInvalidDirectionInLoop tests the invalid direction path
// in deserializeV3Resolved (not the initial direction check, which IS covered,
// but the same code path invoked when direction byte > 1).
func TestDeserializeV3ResolvedInvalidDirectionV6(t *testing.T) {
	rootKeyBytes := make([]byte, keyLen)
	buf := []byte{}
	buf = append(buf, serializeVersionV3)
	buf = append(buf, 0x01)            // resolved
	buf = append(buf, byte(VersionV1)) // V1
	buf = append(buf, 0x05)            // invalid direction > 1

	// Add enough bytes to pass the minSize check (57+ bytes after offset=3).
	epochB := make([]byte, 8)
	buf = append(buf, epochB...)      // epoch
	buf = append(buf, epochB...)      // sendEpoch
	buf = append(buf, rootKeyBytes...) // rootKey
	mjump := make([]byte, 4)
	binary.BigEndian.PutUint32(mjump, 25000)
	buf = append(buf, mjump...)
	numChains := make([]byte, 4)
	buf = append(buf, numChains...) // 0 chains
	numSkipped := make([]byte, 4)
	buf = append(buf, numSkipped...)

	_, err := Deserialize(buf)
	if err == nil {
		t.Fatal("expected error for V3 resolved invalid direction")
	}
	var e *ErrDeserialize
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// ============================================================================
// V4 pending braid deserialization failure
// ============================================================================

// TestDeserializeV4PendingInvalidBraidData tests V4 pending with hasBraid=1 and
// invalid braid data, covering the braid deserialization failure path.
func TestDeserializeV4PendingInvalidBraidData(t *testing.T) {
	authKey := make([]byte, keyLen)
	for i := range authKey {
		authKey[i] = byte(i + 6)
	}

	// V4 pending: version(1) + negotiated(1) + authKey(32) + minVersion(1) + direction(1) + maxJump(4) + hasBraid(1) + braidLen(4) + braidData(N)
	invalidBraidData := []byte{0xFF, 0xFE, 0xFD} // 3 bytes of garbage braid data
	braidLen := uint32(len(invalidBraidData))

	buf := []byte{}
	buf = append(buf, serializeVersionV4)
	buf = append(buf, 0x00)                           // pending
	buf = append(buf, authKey...)                     // authKey
	buf = append(buf, byte(VersionV0))                // minVersion
	buf = append(buf, byte(DirectionA2B))             // direction
	mjump := make([]byte, 4)
	binary.BigEndian.PutUint32(mjump, 25000)
	buf = append(buf, mjump...)
	buf = append(buf, 0x01) // hasBraid=1
	braidLenB := make([]byte, 4)
	binary.BigEndian.PutUint32(braidLenB, braidLen)
	buf = append(buf, braidLenB...)
	buf = append(buf, invalidBraidData...)

	_, err := Deserialize(buf)
	if err == nil {
		t.Fatal("expected error for V4 pending invalid braid data")
	}
	var e *ErrDeserialize
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// ============================================================================
// V4 resolved braid deserialization failure
// ============================================================================

// TestDeserializeV4ResolvedInvalidBraidData tests V4 resolved with hasBraid=1 and
// invalid braid data, covering the braid deserialization failure path in
// deserializeV4Resolved (lines ~1211-1215 in serialize.go).
func TestDeserializeV4ResolvedInvalidBraidData(t *testing.T) {
	rootKeyBytes := make([]byte, keyLen)
	for i := range rootKeyBytes {
		rootKeyBytes[i] = byte(i + 7)
	}

	invalidBraidData := []byte{0xAB, 0xCD, 0xEF} // garbage braid data
	braidLen := uint32(len(invalidBraidData))

	buf := []byte{}
	buf = append(buf, serializeVersionV4)  // V4
	buf = append(buf, 0x01)                // resolved
	buf = append(buf, byte(VersionV1))     // V1
	buf = append(buf, byte(DirectionA2B))  // direction

	epochB := make([]byte, 8)
	buf = append(buf, epochB...)       // epoch=0
	buf = append(buf, epochB...)       // sendEpoch=0
	buf = append(buf, rootKeyBytes...) // rootKey

	mjump := make([]byte, 4)
	binary.BigEndian.PutUint32(mjump, 25000)
	buf = append(buf, mjump...) // maxJump

	numChains := make([]byte, 4)
	buf = append(buf, numChains...) // numChains=0

	numSkipped := make([]byte, 4)
	buf = append(buf, numSkipped...) // numSkipped=0

	// hasBraid=1 + invalid braid data
	buf = append(buf, 0x01) // hasBraid
	braidLenB := make([]byte, 4)
	binary.BigEndian.PutUint32(braidLenB, braidLen)
	buf = append(buf, braidLenB...)
	buf = append(buf, invalidBraidData...)

	_, err := Deserialize(buf)
	if err == nil {
		t.Fatal("expected error for V4 resolved invalid braid data")
	}
	var e *ErrDeserialize
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// ============================================================================
// Recv: pending legacy wrong size and decrypt error paths
// ============================================================================

// TestRecvPendingLegacyWrongSize tests the Recv() path where a pending non-braid
// state resolves to V1 (non-empty pqrMsg) but the message is not 12 bytes.
// This covers lines ~620-624 in session_api.go.
func TestRecvPendingLegacyWrongSize(t *testing.T) {
	// Create a pending state with minVersion=V0 (no auto-resolve on Send,
	// but a non-empty Recv message will resolve it to V1).
	ss := randomBytes(t, 32)
	serialized, err := InitialState(ss, DirectionB2A, false)
	if err != nil {
		t.Fatalf("InitialState: %v", err)
	}

	// Send a non-empty but wrong-size (not 12 bytes) message.
	// This triggers: resolveNegotiation (V1) → braid==nil → len(pqrMsg)!=12.
	_, _, recvErr := Recv(serialized, []byte{0xAA, 0xBB, 0xCC})
	if recvErr == nil {
		t.Fatal("expected error for pending→V1 wrong-size legacy message")
	}
	var e *ErrPQRMessage
	if !errors.As(recvErr, &e) {
		t.Errorf("expected *ErrPQRMessage, got %T: %v", recvErr, recvErr)
	}
}

// TestRecvPendingLegacyDecryptError tests the Recv() path where a pending non-braid
// state resolves to V1 and receives a 12-byte message but with an invalid epoch/counter.
// This covers lines ~629-632 in session_api.go.
func TestRecvPendingLegacyDecryptError(t *testing.T) {
	ss := randomBytes(t, 32)
	serialized, err := InitialState(ss, DirectionB2A, false)
	if err != nil {
		t.Fatalf("InitialState: %v", err)
	}

	// Build a 12-byte message with epoch=999 (unknown epoch after chain init).
	msg := make([]byte, 12)
	binary.BigEndian.PutUint64(msg[0:8], 999) // unknown epoch
	binary.BigEndian.PutUint32(msg[8:12], 1)  // counter=1

	// This triggers: resolveNegotiation (V1) → braid==nil → Decrypt(999, 1) → ErrUnknownEpoch.
	_, _, recvErr := Recv(serialized, msg)
	if recvErr == nil {
		t.Fatal("expected error for unknown epoch in pending→V1 legacy Recv")
	}
	// Should be ErrUnknownEpoch or similar
	if recvErr.Error() == "" {
		t.Error("error message should not be empty")
	}
}

// ============================================================================
// Recv: resolved legacy Decrypt error path
// ============================================================================

// TestRecvResolvedLegacyDecryptError tests the Recv() path where a resolved V1
// state (no braid) receives a 12-byte message with an unknown epoch.
// This covers lines ~678-681 in session_api.go.
func TestRecvResolvedLegacyDecryptError(t *testing.T) {
	// Create a resolved V1 state using Send() with MinVersion=V1.
	ss := randomBytes(t, 32)
	serialized, err := InitialStateWithParams(Params{
		AuthKey:    ss,
		Version:    VersionV1,
		Direction:  DirectionB2A,
		MinVersion: VersionV1,
		MaxJump:    25000,
		MaxOOOKeys: maxSkippedKeys,
	})
	if err != nil {
		t.Fatalf("InitialStateWithParams: %v", err)
	}

	// Auto-resolve via Send.
	resolvedState, _, _, sendErr := Send(serialized)
	if sendErr != nil {
		t.Fatalf("Send: %v", sendErr)
	}

	// Build a 12-byte message with epoch=999 (unknown epoch).
	msg := make([]byte, 12)
	binary.BigEndian.PutUint64(msg[0:8], 999) // unknown epoch
	binary.BigEndian.PutUint32(msg[8:12], 1)

	_, _, recvErr := Recv(resolvedState, msg)
	if recvErr == nil {
		t.Fatal("expected error for unknown epoch in resolved V1 Recv")
	}
}

// ============================================================================
// RecvBraid: Decrypt error path
// ============================================================================

// TestRecvBraidDecryptError tests the RecvBraid path where the Decrypt call
// fails because the counter is already consumed or the epoch is wrong.
// This covers lines ~537-540 in session_api.go.
func TestRecvBraidDecryptError(t *testing.T) {
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

	alice, err := InitWithBraid(ss, DirectionA2B, uint32(maxJump), braidAlice)
	if err != nil {
		t.Fatalf("InitWithBraid alice: %v", err)
	}
	defer alice.Zeroize()

	bob, err := InitWithBraid(ssCopy, DirectionB2A, uint32(maxJump), braidBob)
	if err != nil {
		t.Fatalf("InitWithBraid bob: %v", err)
	}
	defer bob.Zeroize()

	// Alice sends once — Bob receives correctly.
	pqrMsg1, _, err := alice.SendBraid()
	if err != nil {
		t.Fatalf("alice.SendBraid: %v", err)
	}
	_, err = bob.RecvBraid(pqrMsg1)
	if err != nil {
		t.Fatalf("bob.RecvBraid: %v", err)
	}

	// Alice sends again.
	pqrMsg2, _, err := alice.SendBraid()
	if err != nil {
		t.Fatalf("alice.SendBraid 2: %v", err)
	}

	// Bob receives correctly.
	_, err = bob.RecvBraid(pqrMsg2)
	if err != nil {
		t.Fatalf("bob.RecvBraid 2: %v", err)
	}

	// Now replay pqrMsg2 — this should fail with "key already requested".
	_, err = bob.RecvBraid(pqrMsg2)
	if err == nil {
		t.Fatal("expected error for replayed pqrMsg in RecvBraid")
	}
	// Should be ErrKeyAlreadyRequested or similar decrypt error.
	if err.Error() == "" {
		t.Error("error message should not be empty")
	}
}
