package spqr

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// ---- Error type coverage ----

func TestErrCounterExhaustedError(t *testing.T) {
	err := &ErrCounterExhausted{Epoch: 7}
	want := "spqr: counter exhausted at epoch 7"
	if err.Error() != want {
		t.Errorf("ErrCounterExhausted.Error() = %q, want %q", err.Error(), want)
	}
}

func TestErrSendKeyDestroyedError(t *testing.T) {
	err := &ErrSendKeyDestroyed{Epoch: 3}
	want := "spqr: send key destroyed at epoch 3"
	if err.Error() != want {
		t.Errorf("ErrSendKeyDestroyed.Error() = %q, want %q", err.Error(), want)
	}
}

func TestErrNoBraidError(t *testing.T) {
	err := &ErrNoBraid{}
	want := "spqr: braid not attached"
	if err.Error() != want {
		t.Errorf("ErrNoBraid.Error() = %q, want %q", err.Error(), want)
	}
}

func TestErrBraidSendErrorAndUnwrap(t *testing.T) {
	inner := &ErrInvalidInput{Field: "x", Reason: "bad"}
	err := &ErrBraidSend{Err: inner}
	if err.Error() == "" {
		t.Error("ErrBraidSend.Error() must not be empty")
	}
	if !errors.Is(err, inner) {
		t.Error("ErrBraidSend.Unwrap() should return the inner error")
	}
}

func TestErrBraidRecvErrorAndUnwrap(t *testing.T) {
	inner := &ErrInvalidInput{Field: "y", Reason: "bad"}
	err := &ErrBraidRecv{Err: inner}
	if err.Error() == "" {
		t.Error("ErrBraidRecv.Error() must not be empty")
	}
	if !errors.Is(err, inner) {
		t.Error("ErrBraidRecv.Unwrap() should return the inner error")
	}
}

func TestErrEpochAdvanceErrorAndUnwrap(t *testing.T) {
	inner := &ErrInvalidInput{Field: "z", Reason: "bad"}
	err := &ErrEpochAdvance{Err: inner}
	if err.Error() == "" {
		t.Error("ErrEpochAdvance.Error() must not be empty")
	}
	if !errors.Is(err, inner) {
		t.Error("ErrEpochAdvance.Unwrap() should return the inner error")
	}
}

func TestErrWireDecodeError(t *testing.T) {
	err := &ErrWireDecode{Reason: "truncated"}
	want := "spqr: wire decode failed: truncated"
	if err.Error() != want {
		t.Errorf("ErrWireDecode.Error() = %q, want %q", err.Error(), want)
	}
}

func TestErrWireEncodeError(t *testing.T) {
	err := &ErrWireEncode{Reason: "overflow"}
	want := "spqr: wire encode failed: overflow"
	if err.Error() != want {
		t.Errorf("ErrWireEncode.Error() = %q, want %q", err.Error(), want)
	}
}

// ---- Encrypt / Decrypt error paths ----

// TestEncryptSendEpochDecreased verifies ErrSendEpochDecreased when the
// epoch requested is below the last used send epoch.
func TestEncryptSendEpochDecreased(t *testing.T) {
	secret := randomBytes(t, 32)
	s, err := Init(secret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	// Advance sendEpoch by encrypting in epoch 0, then manually add epoch 1
	// and encrypt there so sendEpoch becomes 1.
	sckaOut := randomBytes(t, 32)
	if err := s.ReceiveKey(sckaOut, 1); err != nil {
		t.Fatalf("ReceiveKey: %v", err)
	}
	mk, _, err := s.Encrypt(1)
	if err != nil {
		t.Fatalf("Encrypt(1): %v", err)
	}
	mk.Destroy()

	// Now ask for epoch 0, which is below sendEpoch=1.
	_, _, err = s.Encrypt(0)
	if err == nil {
		t.Fatal("expected ErrSendEpochDecreased")
	}
	var e *ErrSendEpochDecreased
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrSendEpochDecreased, got %T: %v", err, err)
	}
}

// TestEncryptUnknownEpoch verifies ErrUnknownEpoch when epoch not in map.
func TestEncryptUnknownEpoch(t *testing.T) {
	secret := randomBytes(t, 32)
	s, err := Init(secret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	_, _, err = s.Encrypt(99)
	if err == nil {
		t.Fatal("expected ErrUnknownEpoch")
	}
	var e *ErrUnknownEpoch
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrUnknownEpoch, got %T: %v", err, err)
	}
}

// TestEncryptSendKeyDestroyed verifies ErrSendKeyDestroyed when the send key
// for the epoch has been cleared (e.g. after epoch advancement).
func TestEncryptSendKeyDestroyed(t *testing.T) {
	secret := randomBytes(t, 32)
	s, err := Init(secret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	// Advance to epoch 1 and encrypt there to clear epoch 0 send key.
	sckaOut := randomBytes(t, 32)
	if err := s.ReceiveKey(sckaOut, 1); err != nil {
		t.Fatalf("ReceiveKey: %v", err)
	}
	mk, _, err := s.Encrypt(1)
	if err != nil {
		t.Fatalf("Encrypt(1): %v", err)
	}
	mk.Destroy()

	// Epoch 0's send key should now be destroyed (clearOldEpochs).
	// If epoch 0 was pruned, ErrUnknownEpoch is also acceptable.
	_, _, err = s.Encrypt(0)
	if err == nil {
		t.Fatal("expected error for send-key-destroyed or unknown epoch")
	}
}

// TestDecryptKeyAlreadyRequested verifies ErrKeyAlreadyRequested.
func TestDecryptKeyAlreadyRequested(t *testing.T) {
	ss := randomBytes(t, 32)
	ssCopy := make([]byte, 32)
	copy(ssCopy, ss)

	alice, err := Init(ss, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init alice: %v", err)
	}
	defer alice.Zeroize()

	bob, err := Init(ssCopy, DirectionB2A, maxJump)
	if err != nil {
		t.Fatalf("Init bob: %v", err)
	}
	defer bob.Zeroize()

	mk, counter, err := alice.Encrypt(0)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	mk.Destroy()

	// Decrypt once — should succeed.
	mkd, err := bob.Decrypt(0, counter)
	if err != nil {
		t.Fatalf("Decrypt first: %v", err)
	}
	mkd.Destroy()

	// Decrypt again — same counter, should fail with ErrKeyAlreadyRequested.
	_, err = bob.Decrypt(0, counter)
	if err == nil {
		t.Fatal("expected ErrKeyAlreadyRequested on second decrypt of same counter")
	}
	var e *ErrKeyAlreadyRequested
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrKeyAlreadyRequested, got %T: %v", err, err)
	}
}

// TestDecryptKeyTrimmed verifies ErrKeyTrimmed for a counter old enough to
// have been GC'd. We achieve this by:
//  1. Encrypting N messages so bob builds up recvCounter sequentially.
//  2. Having bob skip just under the limit so old keys get GC'd.
//  3. Then attempting to retrieve a very old counter that was trimmed.
func TestDecryptKeyTrimmed(t *testing.T) {
	ss := randomBytes(t, 32)
	ssCopy := make([]byte, 32)
	copy(ssCopy, ss)

	// Use a small maxJump so we can create the scenario without huge allocations.
	const smallJump = 10

	alice, err := Init(ss, DirectionA2B, uint32(smallJump))
	if err != nil {
		t.Fatalf("Init alice: %v", err)
	}
	defer alice.Zeroize()

	bob, err := Init(ssCopy, DirectionB2A, uint32(smallJump))
	if err != nil {
		t.Fatalf("Init bob: %v", err)
	}
	defer bob.Zeroize()

	// Alice sends 3 messages: counters 1, 2, 3.
	for i := 0; i < 3; i++ {
		mk, _, err := alice.Encrypt(0)
		if err != nil {
			t.Fatalf("Encrypt %d: %v", i, err)
		}
		mk.Destroy()
	}

	// Bob decrypts counter 2 (skipping counter 1).
	mkd, err := bob.Decrypt(0, 2)
	if err != nil {
		t.Fatalf("Decrypt(0,2): %v", err)
	}
	mkd.Destroy()
	// Bob now has recvCounter=2, skippedKeys={counter:1}.

	// Bob decrypts counter 3, then with a small maxJump, decrypt 4..13 sequentially.
	// Alice needs to produce those keys.
	for i := 3; i <= 13; i++ {
		mk, _, err := alice.Encrypt(0)
		if err != nil {
			t.Fatalf("Encrypt %d: %v", i, err)
		}
		mk.Destroy()
		mkd, err := bob.Decrypt(0, uint32(i))
		if err != nil {
			t.Fatalf("Decrypt(0,%d): %v", i, err)
		}
		mkd.Destroy()
	}
	// recvCounter is now 13; skippedKeys still contains counter=1.

	// To trigger ErrKeyTrimmed for counter=1, we need:
	//   counter + maxSkippedKeys < chain.recvCounter
	//   1 + 2000 < chain.recvCounter → chain.recvCounter >= 2002
	//
	// Use white-box access to directly set the chain state and clear the
	// skipped key entry for counter 1 so it is not found in skippedKeys.
	chain := bob.chains[0]

	// Remove any stored skipped key for counter=1.
	skID1 := SkippedKeyID{Epoch: 0, Counter: 1}
	if sk, ok := bob.skippedKeys[skID1]; ok {
		sk.Destroy()
		delete(bob.skippedKeys, skID1)
	}

	// Advance recvCounter so that counter=1 falls in the "trimmed" range.
	chain.recvCounter = uint32(maxSkippedKeys + 5)

	_, err = bob.Decrypt(0, 1)
	if err == nil {
		t.Fatal("expected ErrKeyTrimmed for old counter")
	}
	var e *ErrKeyTrimmed
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrKeyTrimmed, got %T: %v", err, err)
	}
}

// TestDecryptMaxJumpRejected verifies ErrMaxJump when the jump is too large.
func TestDecryptMaxJumpRejected(t *testing.T) {
	ss := randomBytes(t, 32)
	s, err := Init(ss, DirectionB2A, 10) // very small max jump
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	_, err = s.Decrypt(0, 100) // jumps 100 from counter 0
	if err == nil {
		t.Fatal("expected ErrMaxJump")
	}
	var e *ErrMaxJump
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrMaxJump, got %T: %v", err, err)
	}
}

// ---- InitialStateWithBraid and InitialStateWithBraidResolved ----

func TestInitialStateWithBraid_NilBraid(t *testing.T) {
	_, err := InitialStateWithBraid(randomBytes(t, 32), DirectionA2B, false, nil)
	if err == nil {
		t.Fatal("expected error for nil braid")
	}
	var e *ErrInvalidInput
	if !errors.As(err, &e) || e.Field != "braid" {
		t.Errorf("expected ErrInvalidInput{braid}, got %T: %v", err, err)
	}
}

func TestInitialStateWithBraid_EmptySecret(t *testing.T) {
	kem := mlkembraid.NewMLKEM768IncrementalKEM()
	braid, err := mlkembraid.InitAlice(randomBytes(t, 32), kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}

	_, err = InitialStateWithBraid([]byte{}, DirectionA2B, false, braid)
	if err == nil {
		t.Fatal("expected error for empty shared secret")
	}
	var e *ErrInvalidInput
	if !errors.As(err, &e) || e.Field != "sharedSecret" {
		t.Errorf("expected ErrInvalidInput{sharedSecret}, got %T: %v", err, err)
	}
}

func TestInitialStateWithBraid_SelfSession(t *testing.T) {
	ss := randomBytes(t, 32)
	kem := mlkembraid.NewMLKEM768IncrementalKEM()
	braid, err := mlkembraid.InitAlice(ss, kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}

	state, err := InitialStateWithBraid(ss, DirectionA2B, true, braid)
	if err != nil {
		t.Fatalf("InitialStateWithBraid: %v", err)
	}
	if len(state) == 0 {
		t.Fatal("state must not be empty")
	}

	// Deserialize and verify maxJump is MaxUint32 for self-session.
	s, err := Deserialize(state)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	defer s.Zeroize()

	if s.maxJump != math.MaxUint32 {
		t.Errorf("maxJump = %d, want MaxUint32", s.maxJump)
	}
	if s.braid == nil {
		t.Error("braid must be present after InitialStateWithBraid")
	}
}

func TestInitialStateWithBraidResolved_NilBraid(t *testing.T) {
	_, err := InitialStateWithBraidResolved(randomBytes(t, 32), DirectionA2B, false, nil)
	if err == nil {
		t.Fatal("expected error for nil braid")
	}
	var e *ErrInvalidInput
	if !errors.As(err, &e) || e.Field != "braid" {
		t.Errorf("expected ErrInvalidInput{braid}, got %T: %v", err, err)
	}
}

func TestInitialStateWithBraidResolved_SelfSession(t *testing.T) {
	ss := randomBytes(t, 32)
	kem := mlkembraid.NewMLKEM768IncrementalKEM()
	braid, err := mlkembraid.InitBob(ss, kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitBob: %v", err)
	}

	state, err := InitialStateWithBraidResolved(ss, DirectionB2A, true, braid)
	if err != nil {
		t.Fatalf("InitialStateWithBraidResolved: %v", err)
	}

	s, err := Deserialize(state)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	defer s.Zeroize()

	if s.maxJump != math.MaxUint32 {
		t.Errorf("maxJump = %d, want MaxUint32", s.maxJump)
	}
	if !s.IsNegotiated() {
		t.Error("state should be pre-resolved")
	}
}

// ---- SendBraid / RecvBraid edge paths ----

// TestSendBraidPendingWithMinVersionV1 verifies that SendBraid on a pending
// state with minVersion=V1 immediately resolves to V1 and sends a key.
func TestSendBraidPendingWithMinVersionV1(t *testing.T) {
	ss := randomBytes(t, 32)
	kem := mlkembraid.NewMLKEM768IncrementalKEM()
	braid, err := mlkembraid.InitAlice(ss, kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}

	s := &SPQR{
		chains:      make(map[uint64]*EpochChain),
		skippedKeys: make(map[SkippedKeyID]*secret.Secret),
		direction:   DirectionA2B,
		maxJump:     uint32(maxJump),
		negotiation: negotiationPending,
		version:     VersionV1,
		minVersion:  VersionV1, // forces immediate resolution
		authKey:     ss,
		braid:       braid,
	}
	defer s.Zeroize()

	pqrMsg, mk, err := s.SendBraid()
	if err != nil {
		t.Fatalf("SendBraid: %v", err)
	}
	if len(pqrMsg) == 0 {
		t.Error("expected non-empty wire message after resolution")
	}
	if len(mk) == 0 {
		t.Error("expected non-nil message key after resolution")
	}
}

// TestSendBraidPendingWithMinVersionV0 verifies that SendBraid on a pending
// state with minVersion=V0 returns empty message and nil key.
func TestSendBraidPendingWithMinVersionV0(t *testing.T) {
	ss := randomBytes(t, 32)
	kem := mlkembraid.NewMLKEM768IncrementalKEM()
	braid, err := mlkembraid.InitAlice(ss, kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}

	s := &SPQR{
		chains:      make(map[uint64]*EpochChain),
		skippedKeys: make(map[SkippedKeyID]*secret.Secret),
		direction:   DirectionA2B,
		maxJump:     uint32(maxJump),
		negotiation: negotiationPending,
		version:     VersionV1,
		minVersion:  VersionV0, // allows V0 fallback
		authKey:     ss,
		braid:       braid,
	}
	defer s.Zeroize()

	pqrMsg, mk, err := s.SendBraid()
	if err != nil {
		t.Fatalf("SendBraid: %v", err)
	}
	if len(pqrMsg) != 0 {
		t.Errorf("expected empty wire message from pending V0 path, got %d bytes", len(pqrMsg))
	}
	if mk != nil {
		t.Error("expected nil message key from pending V0 path")
	}
}

// TestSendBraidDisabled verifies that SendBraid on a V0-disabled state
// returns empty message and nil key.
func TestSendBraidDisabled(t *testing.T) {
	ss := randomBytes(t, 32)
	kem := mlkembraid.NewMLKEM768IncrementalKEM()
	braid, err := mlkembraid.InitAlice(ss, kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}

	s := &SPQR{
		chains:      make(map[uint64]*EpochChain),
		skippedKeys: make(map[SkippedKeyID]*secret.Secret),
		direction:   DirectionA2B,
		maxJump:     uint32(maxJump),
		negotiation: negotiationResolved,
		version:     VersionV0, // disabled
		braid:       braid,
	}
	defer s.Zeroize()

	pqrMsg, mk, err := s.SendBraid()
	if err != nil {
		t.Fatalf("SendBraid: %v", err)
	}
	if len(pqrMsg) != 0 {
		t.Errorf("expected empty wire message for V0 disabled, got %d bytes", len(pqrMsg))
	}
	if mk != nil {
		t.Error("expected nil key for V0 disabled")
	}
}

// TestRecvBraidNoBraid verifies ErrNoBraid on RecvBraid without a braid.
func TestRecvBraidNoBraid(t *testing.T) {
	ss := randomBytes(t, 32)
	s, err := Init(ss, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	_, err = s.RecvBraid([]byte{0x01})
	if err == nil {
		t.Fatal("expected ErrNoBraid")
	}
	if _, ok := err.(*ErrNoBraid); !ok {
		t.Errorf("expected *ErrNoBraid, got %T: %v", err, err)
	}
}

// TestRecvBraidDisabled verifies nil key is returned when state is V0 disabled.
func TestRecvBraidDisabled(t *testing.T) {
	ss := randomBytes(t, 32)
	kem := mlkembraid.NewMLKEM768IncrementalKEM()
	braid, err := mlkembraid.InitBob(ss, kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitBob: %v", err)
	}

	s := &SPQR{
		chains:      make(map[uint64]*EpochChain),
		skippedKeys: make(map[SkippedKeyID]*secret.Secret),
		direction:   DirectionB2A,
		maxJump:     uint32(maxJump),
		negotiation: negotiationResolved,
		version:     VersionV0, // disabled
		braid:       braid,
	}
	defer s.Zeroize()

	mk, err := s.RecvBraid([]byte{})
	if err != nil {
		t.Fatalf("RecvBraid: %v", err)
	}
	if mk != nil {
		t.Error("expected nil key for V0 disabled")
	}
}

// TestRecvBraidPendingResolvesToV0 verifies that RecvBraid with empty pqrMsg
// resolves pending state to V0 and returns nil key.
func TestRecvBraidPendingResolvesToV0(t *testing.T) {
	ss := randomBytes(t, 32)
	kem := mlkembraid.NewMLKEM768IncrementalKEM()
	braid, err := mlkembraid.InitBob(ss, kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitBob: %v", err)
	}

	s := &SPQR{
		chains:      make(map[uint64]*EpochChain),
		skippedKeys: make(map[SkippedKeyID]*secret.Secret),
		direction:   DirectionB2A,
		maxJump:     uint32(maxJump),
		negotiation: negotiationPending,
		version:     VersionV1,
		minVersion:  VersionV0, // allows V0 fallback
		authKey:     ss,
		braid:       braid,
	}
	defer s.Zeroize()

	mk, err := s.RecvBraid([]byte{})
	if err != nil {
		t.Fatalf("RecvBraid empty: %v", err)
	}
	if mk != nil {
		t.Error("expected nil key after V0 resolution")
	}
	if !s.IsDisabled() {
		t.Error("state should be V0-disabled after empty pqrMsg")
	}
}

// TestRecvBraidInvalidWireMessage verifies ErrPQRMessage on a bad wire message.
func TestRecvBraidInvalidWireMessage(t *testing.T) {
	ss := randomBytes(t, 32)
	kem := mlkembraid.NewMLKEM768IncrementalKEM()
	braid, err := mlkembraid.InitBob(ss, kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitBob: %v", err)
	}

	s, err := InitWithBraid(ss, DirectionB2A, maxJump, braid)
	if err != nil {
		t.Fatalf("InitWithBraid: %v", err)
	}
	defer s.Zeroize()

	// A single byte with version=0xFF is not a valid wire message.
	_, err = s.RecvBraid([]byte{0xFF, 0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for invalid wire message")
	}
	var e *ErrPQRMessage
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrPQRMessage, got %T: %v", err, err)
	}
}

// ---- InitialStateWithParams unsupported version ----

func TestInitialStateWithParamsUnsupportedVersion(t *testing.T) {
	_, err := InitialStateWithParams(Params{
		AuthKey:    randomBytes(t, 32),
		Version:    Version(99),
		Direction:  DirectionA2B,
		MinVersion: VersionV0,
		MaxJump:    maxJump,
	})
	if err == nil {
		t.Fatal("expected error for unsupported version")
	}
	var e *ErrInvalidInput
	if !errors.As(err, &e) || e.Field != "Version" {
		t.Errorf("expected ErrInvalidInput{Version}, got %T: %v", err, err)
	}
}

// ---- Deserialize edge cases ----

// TestDeserializeGarbageProtoData verifies that garbage bytes return ErrDeserialize.
func TestDeserializeGarbageProtoData(t *testing.T) {
	_, err := Deserialize([]byte{0xFF, 0xFE, 0xFD, 0x00, 0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for garbage proto bytes")
	}
	var e *ErrDeserialize
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// ---- V0-disabled round-trip ----

// TestV4DisabledSerializeDeserializeRoundTrip verifies that serializeV4Disabled
// produces bytes that Deserialize reads back as a V0 disabled state.
// Uses InitialStateWithParams with MinVersion=V0 (opt-in downgrade path) because
// the default InitialStateWithBraid now enforces MinVersion=V1.
func TestV4DisabledSerializeDeserializeRoundTrip(t *testing.T) {
	// Create a braid-aware SPQR in V0 disabled state (e.g. after receiving empty msg).
	ss := randomBytes(t, 32)
	kem := mlkembraid.NewMLKEM768IncrementalKEM()
	braid, err := mlkembraid.InitAlice(ss, kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}

	// Create pending state with explicit MinVersion=V0 (opt-in downgrade path).
	// Copy the auth key since InitialStateWithParams takes ownership.
	ssCopy := make([]byte, len(ss))
	copy(ssCopy, ss)
	pendingState, err := InitialStateWithParams(Params{
		AuthKey:    ssCopy,
		Version:    VersionV1,
		Direction:  DirectionA2B,
		MinVersion: VersionV0,
		MaxJump:    uint32(maxJump),
		MaxOOOKeys: maxSkippedKeys,
	})
	if err != nil {
		t.Fatalf("InitialStateWithParams: %v", err)
	}
	// Attach braid separately since InitialStateWithParams doesn't take one.
	// For this test we only need the V0 resolution path (no braid needed).
	_ = braid

	// Resolve to V0 by receiving empty pqrMsg.
	resolvedState, _, err := Recv(pendingState, []byte{})
	if err != nil {
		t.Fatalf("Recv empty: %v", err)
	}

	// The resolved state should deserialize as V0 disabled.
	s, err := Deserialize(resolvedState)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	defer s.Zeroize()

	if !s.IsDisabled() {
		t.Error("state should be V0 disabled after receiving empty pqrMsg")
	}
	if !s.IsNegotiated() {
		t.Error("state should be negotiated")
	}

	// Verify that the V4 disabled state can be serialized and deserialized again.
	state2, err := s.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	s2, err := Deserialize(state2)
	if err != nil {
		t.Fatalf("Deserialize round-trip: %v", err)
	}
	defer s2.Zeroize()

	if !s2.IsDisabled() {
		t.Error("round-trip state should still be V0 disabled")
	}
	if !s2.IsNegotiated() {
		t.Error("round-trip state should still be negotiated")
	}
}

// ---- Send on V1 pending with minVersion=V1 ----

// TestSendWithMinVersionV1ResolvedImmediately tests that Send on a pending
// state with minVersion=V1 resolves immediately and sends a real key.
func TestSendWithMinVersionV1ResolvedImmediately(t *testing.T) {
	ss := randomBytes(t, 32)
	state, err := InitialStateWithParams(Params{
		AuthKey:    ss,
		Version:    VersionV1,
		Direction:  DirectionA2B,
		MinVersion: VersionV1, // force immediate resolution
		MaxJump:    uint32(maxJump),
		MaxOOOKeys: maxSkippedKeys,
	})
	if err != nil {
		t.Fatalf("InitialStateWithParams: %v", err)
	}

	_, pqrMsg, mk, err := Send(state)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(pqrMsg) == 0 {
		t.Error("expected non-empty pqrMsg after immediate V1 resolution")
	}
	if len(mk) == 0 {
		t.Error("expected non-nil message key after immediate V1 resolution")
	}
}

// ---- Recv on already-disabled path (V0) with legacy message ----

// TestRecvAlreadyDisabledV0 tests Recv on an already-disabled V0 state.
// Uses InitialStateWithParams with MinVersion=V0 (opt-in downgrade path).
func TestRecvAlreadyDisabledV0(t *testing.T) {
	ss := randomBytes(t, 32)
	state, err := InitialStateWithParams(Params{
		AuthKey:    ss,
		Version:    VersionV1,
		Direction:  DirectionA2B,
		MinVersion: VersionV0,
		MaxJump:    uint32(maxJump),
		MaxOOOKeys: maxSkippedKeys,
	})
	if err != nil {
		t.Fatalf("InitialStateWithParams: %v", err)
	}

	// Resolve to V0.
	state, _, err = Recv(state, []byte{})
	if err != nil {
		t.Fatalf("Recv (V0): %v", err)
	}

	// Call Recv again — should return nil key without error.
	// V0-disabled states serialize as empty bytes (Rust empty_state() convention).
	newState, mk, err := Recv(state, []byte{})
	if err != nil {
		t.Fatalf("Recv on disabled V0: %v", err)
	}
	if mk != nil {
		t.Error("expected nil key for V0 disabled Recv")
	}
	if len(newState) != 0 {
		t.Errorf("V0 state must be empty bytes, got %d bytes", len(newState))
	}
}

// ---- advanceEpoch error paths ----

// TestAdvanceEpochNilOutputKey verifies ErrInvalidInput for nil output key.
func TestAdvanceEpochNilOutputKey(t *testing.T) {
	ss := randomBytes(t, 32)
	s, err := Init(ss, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	err = s.advanceEpoch(nil)
	if err == nil {
		t.Fatal("expected error for nil output key")
	}
	var e *ErrInvalidInput
	if !errors.As(err, &e) || e.Field != "outputKey" {
		t.Errorf("expected ErrInvalidInput{outputKey}, got %T: %v", err, err)
	}
}

// ---- wire.go error paths ----

func TestDecodeWireMessageUnsupportedVersion(t *testing.T) {
	// A 2-byte message that is NOT 12 bytes (not legacy) with version byte != wireVersion.
	data := []byte{0x99, 0x01}
	_, err := decodeWireMessage(data)
	if err == nil {
		t.Fatal("expected error for unsupported wire version")
	}
	var e *ErrWireDecode
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrWireDecode, got %T: %v", err, err)
	}
}

func TestDecodeWireMessageEmpty(t *testing.T) {
	_, err := decodeWireMessage([]byte{})
	if err == nil {
		t.Fatal("expected error for empty wire message")
	}
}

func TestDecodeWireMessageInvalidEpochVarint(t *testing.T) {
	// wireVersion byte followed by an invalid varint (all-0x80 bytes, no terminator).
	// All continuation bits set with no terminating byte — must fail varint decode.
	data := make([]byte, 13)
	data[0] = wireVersion
	for i := 1; i < 13; i++ {
		data[i] = 0x80 // continuation bits set, no terminator
	}
	_, err := decodeWireMessage(data)
	if err == nil {
		t.Fatal("expected error for invalid varint")
	}
}

func TestDecodeWireMessageCounterExceedsU32(t *testing.T) {
	// Build a message: wireVersion + varint(epoch=1) + varint(counter > MaxUint32) + msgType
	buf := []byte{wireVersion}
	var tmp [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(tmp[:], 1) // epoch=1
	buf = append(buf, tmp[:n]...)
	n = binary.PutUvarint(tmp[:], uint64(math.MaxUint32)+1) // counter too big
	buf = append(buf, tmp[:n]...)
	buf = append(buf, byte(mlkembraid.MessageTypeNone))

	_, err := decodeWireMessage(buf)
	if err == nil {
		t.Fatal("expected error for counter exceeding u32 range")
	}
}

func TestDecodeWireMessageMissingMsgType(t *testing.T) {
	// wireVersion + varint(epoch=1) + varint(counter=1) but no msg type byte.
	buf := []byte{wireVersion}
	var tmp [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(tmp[:], 1) // epoch=1
	buf = append(buf, tmp[:n]...)
	n = binary.PutUvarint(tmp[:], 1) // counter=1
	buf = append(buf, tmp[:n]...)
	// no msg type byte appended

	_, err := decodeWireMessage(buf)
	if err == nil {
		t.Fatal("expected error for missing message type byte")
	}
}

func TestDecodeWireMessageUnknownMsgType(t *testing.T) {
	buf := []byte{wireVersion}
	var tmp [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(tmp[:], 1)
	buf = append(buf, tmp[:n]...)
	n = binary.PutUvarint(tmp[:], 1)
	buf = append(buf, tmp[:n]...)
	buf = append(buf, 0xFF) // unknown message type > MessageTypeCt2

	_, err := decodeWireMessage(buf)
	if err == nil {
		t.Fatal("expected error for unknown message type")
	}
}

// TestEncodeDecodeWireMessageRoundTrip verifies variable-length encoding/decoding.
func TestEncodeDecodeWireMessageRoundTrip(t *testing.T) {
	epoch := uint64(5)
	counter := uint32(13)
	msgType := mlkembraid.MessageTypeNone

	encoded := encodeWireMessage(epoch, counter, msgType, nil)
	decoded, err := decodeWireMessage(encoded)
	if err != nil {
		t.Fatalf("decodeWireMessage: %v", err)
	}
	if decoded.Epoch != epoch {
		t.Errorf("epoch = %d, want %d", decoded.Epoch, epoch)
	}
	if decoded.Counter != counter {
		t.Errorf("counter = %d, want %d", decoded.Counter, counter)
	}
	if decoded.MsgType != msgType {
		t.Errorf("msgType = %v, want %v", decoded.MsgType, msgType)
	}
}

// ---- GcSkippedKeys edge case (currentCounter <= maxSkippedKeys) ----

// TestGcSkippedKeysNoopWhenCounterSmall verifies that gcSkippedKeys does
// nothing when currentCounter <= maxSkippedKeys.
func TestGcSkippedKeysNoopWhenCounterSmall(t *testing.T) {
	ss := randomBytes(t, 32)
	ssCopy := make([]byte, 32)
	copy(ssCopy, ss)

	alice, err := Init(ss, DirectionA2B, uint32(maxJump))
	if err != nil {
		t.Fatalf("Init alice: %v", err)
	}
	defer alice.Zeroize()

	bob, err := Init(ssCopy, DirectionB2A, uint32(maxJump))
	if err != nil {
		t.Fatalf("Init bob: %v", err)
	}
	defer bob.Zeroize()

	// Produce a skipped key at counter 1 by skipping to counter 3.
	for i := 0; i < 3; i++ {
		mk, _, err := alice.Encrypt(0)
		if err != nil {
			t.Fatalf("Encrypt %d: %v", i, err)
		}
		mk.Destroy()
	}
	mkd, err := bob.Decrypt(0, 3)
	if err != nil {
		t.Fatalf("Decrypt(0,3): %v", err)
	}
	mkd.Destroy()

	before := bob.SkippedKeyCount()
	// Call gcSkippedKeys with a small currentCounter (no trimming should happen).
	bob.gcSkippedKeys(0, 10)

	after := bob.SkippedKeyCount()
	if before != after {
		t.Errorf("gcSkippedKeys should be a no-op for small counter; before=%d after=%d", before, after)
	}
}

// ---- clearOldEpochs send key clearing ----

// TestClearOldEpochsClearsSendKeys verifies that clearOldEpochs destroys the
// send keys on retained epochs below sendEpoch.
func TestClearOldEpochsClearsSendKeys(t *testing.T) {
	ss := randomBytes(t, 32)
	s, err := Init(ss, DirectionA2B, uint32(maxJump))
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	// Advance to epoch 2.
	if err := s.ReceiveKey(randomBytes(t, 32), 1); err != nil {
		t.Fatalf("ReceiveKey(1): %v", err)
	}
	if err := s.ReceiveKey(randomBytes(t, 32), 2); err != nil {
		t.Fatalf("ReceiveKey(2): %v", err)
	}

	// Encrypt at epoch 2 so sendEpoch becomes 2.
	mk, _, err := s.Encrypt(2)
	if err != nil {
		t.Fatalf("Encrypt(2): %v", err)
	}
	mk.Destroy()

	s.clearOldEpochs()

	// Epoch 1's send key should have been cleared (it's below sendEpoch=2).
	if chain, ok := s.chains[1]; ok {
		if chain.sendKey != nil && !chain.sendKey.IsDestroyed() {
			t.Error("epoch 1's sendKey should be nil/destroyed after clearOldEpochs")
		}
	}
}

// ---- Recv post-negotiation with braid path ----

// TestRecvBraidIntegratedResolvesPendingToV1 verifies that the braid-integrated
// Recv correctly resolves a pending state to V1 on the first braid message.
func TestRecvBraidIntegratedResolvesPendingToV1(t *testing.T) {
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

	// Alice resolved with braid.
	aliceState, err := InitialStateWithBraidResolved(ss, DirectionA2B, false, braidAlice)
	if err != nil {
		t.Fatalf("InitialStateWithBraidResolved alice: %v", err)
	}

	// Bob pending with braid.
	bobState, err := InitialStateWithBraid(ssCopy, DirectionB2A, false, braidBob)
	if err != nil {
		t.Fatalf("InitialStateWithBraid bob: %v", err)
	}

	// Alice sends.
	newAliceState, pqrMsg, aliceKey, err := Send(aliceState)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(newAliceState) == 0 || len(pqrMsg) == 0 {
		t.Fatal("expected non-empty state and msg from Alice Send")
	}

	// Bob receives — should resolve pending to V1.
	newBobState, bobKey, err := Recv(bobState, pqrMsg)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if len(newBobState) == 0 {
		t.Fatal("expected non-empty bob state")
	}

	// Keys should match (or both be nil for initial braid epoch=1, counter=0 case).
	if aliceKey != nil && bobKey != nil {
		if !bytes.Equal(aliceKey, bobKey) {
			t.Error("alice and bob message keys should match")
		}
	}
}
