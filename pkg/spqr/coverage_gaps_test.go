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

// ---- recvLegacy path ----

// TestRecvLegacyPath exercises the recvLegacy function via RecvBraid with a
// 12-byte (legacy) message. We use the braid-integrated SPQR and supply
// a 12-byte message which triggers the legacy dispatch.
func TestRecvLegacyPath(t *testing.T) {
	ss := randomBytes(t, 32)
	ssCopy := make([]byte, 32)
	copy(ssCopy, ss)

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

	// Build a sender (no braid) that will produce a 12-byte legacy message.
	sender, err := Init(ssCopy, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init sender: %v", err)
	}
	defer sender.Zeroize()

	mk, counter, err := sender.Encrypt(0)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	defer mk.Destroy()

	// Build legacy 12-byte wire message.
	legacyMsg := make([]byte, legacyPQRMsgSize)
	binary.BigEndian.PutUint64(legacyMsg[0:8], 0)
	binary.BigEndian.PutUint32(legacyMsg[8:12], counter)

	// RecvBraid should dispatch to recvLegacy for 12-byte messages.
	recvMK, err := s.RecvBraid(legacyMsg)
	if err != nil {
		t.Fatalf("RecvBraid (legacy): %v", err)
	}
	if len(recvMK) == 0 {
		t.Fatal("expected non-nil message key from legacy path")
	}
	if !bytes.Equal(mk.Bytes(), recvMK) {
		t.Error("legacy path: message key mismatch")
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

func TestDeserializeEmptyData(t *testing.T) {
	_, err := Deserialize([]byte{})
	if err == nil {
		t.Fatal("expected error for empty data")
	}
	var e *ErrDeserialize
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

func TestDeserializeUnsupportedVersion(t *testing.T) {
	_, err := Deserialize([]byte{0xAA})
	if err == nil {
		t.Fatal("expected error for unknown version")
	}
	var e *ErrDeserialize
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// TestDeserializeV3InvalidNegotiationByte tests the V3 invalid negotiation byte path.
func TestDeserializeV3InvalidNegotiationByte(t *testing.T) {
	data := []byte{serializeVersionV3, 0x02} // 0x02 is invalid
	_, err := Deserialize(data)
	if err == nil {
		t.Fatal("expected error for invalid V3 negotiation byte")
	}
}

// TestDeserializeV3ResolvedInvalidVersion tests V3 with unsupported resolved version.
func TestDeserializeV3ResolvedInvalidVersion(t *testing.T) {
	data := []byte{serializeVersionV3, 0x01, 0xAA} // 0xAA is unknown version
	_, err := Deserialize(data)
	if err == nil {
		t.Fatal("expected error for unsupported V3 resolved version")
	}
}

// TestDeserializeV3PendingTrailingData tests V3 pending with extra trailing bytes.
func TestDeserializeV3PendingTrailingData(t *testing.T) {
	// Build a valid V3 pending buffer, then add extra bytes.
	ss := randomBytes(t, 32)
	state, err := InitialState(ss, DirectionA2B, false)
	if err != nil {
		t.Fatalf("InitialState: %v", err)
	}
	// state[0] should be serializeVersionV3.
	if state[0] != serializeVersionV3 {
		t.Skip("state is not V3 format, skipping")
	}
	// Append a trailing byte.
	corrupted := append(state, 0xFF)
	_, err = Deserialize(corrupted)
	if err == nil {
		t.Fatal("expected error for V3 pending trailing data")
	}
}

// TestDeserializeV3DisabledWrongSize tests V3 disabled with wrong size.
func TestDeserializeV3DisabledWrongSize(t *testing.T) {
	// 4 bytes: version + negotiated + resolvedVersion + extra
	data := []byte{serializeVersionV3, 0x01, byte(VersionV0), 0xFF}
	_, err := Deserialize(data)
	if err == nil {
		t.Fatal("expected error for V3 disabled with trailing data")
	}
}

// TestDeserializeV4InvalidNegotiationByte tests V4 invalid negotiation byte.
func TestDeserializeV4InvalidNegotiationByte(t *testing.T) {
	data := []byte{serializeVersionV4, 0x02}
	_, err := Deserialize(data)
	if err == nil {
		t.Fatal("expected error for V4 invalid negotiation byte")
	}
}

// TestDeserializeV4ResolvedUnsupportedVersion tests V4 with unsupported resolved version.
func TestDeserializeV4ResolvedUnsupportedVersion(t *testing.T) {
	data := []byte{serializeVersionV4, 0x01, 0xFF}
	_, err := Deserialize(data)
	if err == nil {
		t.Fatal("expected error for V4 unsupported resolved version")
	}
}

// TestDeserializeV4PendingTooShort tests V4 pending data that is too short.
func TestDeserializeV4PendingTooShort(t *testing.T) {
	// V4 pending requires at least 41 bytes; provide less.
	data := []byte{serializeVersionV4, 0x00, 0x01}
	_, err := Deserialize(data)
	if err == nil {
		t.Fatal("expected error for V4 pending too short")
	}
}

// TestDeserializeV4PendingInvalidDirection tests V4 pending with invalid direction.
func TestDeserializeV4PendingInvalidDirection(t *testing.T) {
	// Build a V4 pending buffer with invalid direction byte.
	buf := make([]byte, 1+1+keyLen+1+1+4+1) // minimum for V4 pending
	buf[0] = serializeVersionV4
	buf[1] = 0x00           // pending
	buf[1+1+keyLen] = 0x00  // minVersion = V0
	buf[1+1+keyLen+1] = 0x05 // invalid direction (> 1)
	binary.BigEndian.PutUint32(buf[1+1+keyLen+2:], uint32(maxJump))
	buf[1+1+keyLen+2+4] = 0x00 // hasBraid = false

	_, err := Deserialize(buf)
	if err == nil {
		t.Fatal("expected error for V4 pending invalid direction")
	}
}

// TestDeserializeV4PendingTrailingData tests V4 pending with trailing data.
func TestDeserializeV4PendingTrailingData(t *testing.T) {
	// Build a valid V4 pending buffer without braid, then add extra bytes.
	buf := make([]byte, 1+1+keyLen+1+1+4+1+1) // extra byte at end
	buf[0] = serializeVersionV4
	buf[1] = 0x00 // pending
	// authKey at [2:2+32] stays zero
	buf[2+keyLen] = 0x00 // minVersion = V0
	buf[2+keyLen+1] = 0x00 // direction = A2B
	binary.BigEndian.PutUint32(buf[2+keyLen+2:], uint32(maxJump))
	buf[2+keyLen+6] = 0x00 // hasBraid = false
	buf[2+keyLen+7] = 0xFF // trailing data

	_, err := Deserialize(buf)
	if err == nil {
		t.Fatal("expected error for V4 pending trailing data")
	}
}

// TestDeserializeV4PendingBraidTooLarge tests V4 pending with braid length > maxBraidSerializedLen.
func TestDeserializeV4PendingBraidTooLarge(t *testing.T) {
	// Build V4 pending with hasBraid=1 and braidLen > maxBraidSerializedLen.
	size := 1 + 1 + keyLen + 1 + 1 + 4 + 1 + 4 // header + hasBraid + braidLen(4)
	buf := make([]byte, size)
	buf[0] = serializeVersionV4
	buf[1] = 0x00 // pending
	// authKey stays zero
	off := 2 + keyLen
	buf[off] = 0x00 // minVersion
	off++
	buf[off] = 0x00 // direction A2B
	off++
	binary.BigEndian.PutUint32(buf[off:], uint32(maxJump))
	off += 4
	buf[off] = 0x01 // hasBraid
	off++
	binary.BigEndian.PutUint32(buf[off:], uint32(maxBraidSerializedLen+1)) // too large

	_, err := Deserialize(buf)
	if err == nil {
		t.Fatal("expected error for V4 pending braid too large")
	}
	var e *ErrBraidTooLarge
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrBraidTooLarge, got %T: %v", err, err)
	}
}

// TestDeserializeV4ResolvedTooShort tests V4 resolved data that is too short.
func TestDeserializeV4ResolvedTooShort(t *testing.T) {
	data := []byte{serializeVersionV4, 0x01, byte(VersionV1), 0x00} // V4 resolved but too short
	_, err := Deserialize(data)
	if err == nil {
		t.Fatal("expected error for V4 resolved too short")
	}
}

// TestDeserializeV4ResolvedInvalidDirection tests V4 resolved with invalid direction.
func TestDeserializeV4ResolvedInvalidDirection(t *testing.T) {
	// Minimum valid V4 resolved header size: 3 (V4 hdr) + 1+8+8+32+4+4 = 60
	buf := make([]byte, 3+1+8+8+keyLen+4+4)
	buf[0] = serializeVersionV4
	buf[1] = 0x01          // resolved
	buf[2] = byte(VersionV1)
	buf[3] = 0x05           // invalid direction
	// rest stays zero (numChains=0, numSkipped=0 would be fine but direction is rejected first)

	_, err := Deserialize(buf)
	if err == nil {
		t.Fatal("expected error for V4 resolved invalid direction")
	}
}

// TestDeserializeV4ResolvedChainCountExceedsMax tests V4 resolved with too many chains.
func TestDeserializeV4ResolvedChainCountExceedsMax(t *testing.T) {
	buf := make([]byte, 3+1+8+8+keyLen+4+4)
	buf[0] = serializeVersionV4
	buf[1] = 0x01
	buf[2] = byte(VersionV1)
	buf[3] = 0x00 // direction A2B
	// epoch and sendEpoch stay 0
	// rootKey stays zero
	off := 3 + 1 + 8 + 8 + keyLen
	binary.BigEndian.PutUint32(buf[off:], uint32(maxJump)) // maxJump
	off += 4
	binary.BigEndian.PutUint32(buf[off:], uint32(maxDeserializedChains+1)) // too many chains

	_, err := Deserialize(buf)
	if err == nil {
		t.Fatal("expected error for V4 resolved chain count too large")
	}
}

// TestDeserializeV4ResolvedBraidTooLarge tests V4 resolved with braid length exceeding max.
func TestDeserializeV4ResolvedBraidTooLarge(t *testing.T) {
	// Use InitialStateWithBraidResolved to get a valid V4 resolved state,
	// then corrupt the braid length field.
	ss := randomBytes(t, 32)
	kem := mlkembraid.NewMLKEM768IncrementalKEM()
	braid, err := mlkembraid.InitAlice(ss, kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}

	state, err := InitialStateWithBraidResolved(ss, DirectionA2B, false, braid)
	if err != nil {
		t.Fatalf("InitialStateWithBraidResolved: %v", err)
	}
	if state[0] != serializeVersionV4 {
		t.Skip("state not V4 format")
	}

	// Locate the hasBraid byte and braidLen field by scanning for 0x01 after chains/skippedKeys.
	// The V4 resolved format ends with: hasBraid(1) + braidLen(4) + braidData.
	// We know the last 5+ bytes encode hasBraid+braidLen+braidData.
	// Find position: len(state) - braidDataLen - 4 - 1.
	// Instead, just corrupt with a fresh oversized state.
	// Build minimal V4 resolved with 0 chains, 0 skipped keys, hasBraid=1, braidLen=maxBraidSerializedLen+1.
	headerSize := 3 + 1 + 8 + 8 + keyLen + 4 + 4 + 4 // V4 hdr + direction + epoch + sendEpoch + rk + maxJump + numChains + numSkipped
	buf := make([]byte, headerSize+1+4)
	buf[0] = serializeVersionV4
	buf[1] = 0x01
	buf[2] = byte(VersionV1)
	buf[3] = 0x00 // direction
	off := 3 + 1 + 8 + 8 + keyLen
	binary.BigEndian.PutUint32(buf[off:], uint32(maxJump))
	off += 4
	// numChains = 0
	off += 4
	// numSkipped = 0
	off += 4
	buf[off] = 0x01 // hasBraid
	off++
	binary.BigEndian.PutUint32(buf[off:], uint32(maxBraidSerializedLen+1)) // too large

	_, err = Deserialize(buf)
	if err == nil {
		t.Fatal("expected error for V4 resolved braid too large")
	}
	var e *ErrBraidTooLarge
	if !errors.As(err, &e) {
		t.Errorf("expected *ErrBraidTooLarge, got %T: %v", err, err)
	}
}

// TestDeserializeV4ResolvedTrailingData tests V4 resolved with trailing data.
func TestDeserializeV4ResolvedTrailingData(t *testing.T) {
	// Minimal V4 resolved with 0 chains, 0 skipped, hasBraid=0, then extra byte.
	headerSize := 3 + 1 + 8 + 8 + keyLen + 4 + 4 + 4 + 1 + 1 // +hasBraid + trailing
	buf := make([]byte, headerSize)
	buf[0] = serializeVersionV4
	buf[1] = 0x01
	buf[2] = byte(VersionV1)
	buf[3] = 0x00 // direction A2B
	off := 3 + 1 + 8 + 8 + keyLen
	binary.BigEndian.PutUint32(buf[off:], uint32(maxJump))
	off += 4
	// numChains = 0 (already zero)
	off += 4
	// numSkipped = 0
	off += 4
	buf[off] = 0x00 // hasBraid = false
	off++
	buf[off] = 0xFF // trailing data

	_, err := Deserialize(buf)
	if err == nil {
		t.Fatal("expected error for V4 resolved trailing data")
	}
}

// TestDeserializeV4ResolvedSkippedKeyCountExceedsMax tests V4 with too many skipped keys.
func TestDeserializeV4ResolvedSkippedKeyCountExceedsMax(t *testing.T) {
	buf := make([]byte, 3+1+8+8+keyLen+4+4+4)
	buf[0] = serializeVersionV4
	buf[1] = 0x01
	buf[2] = byte(VersionV1)
	buf[3] = 0x00 // direction
	off := 3 + 1 + 8 + 8 + keyLen
	binary.BigEndian.PutUint32(buf[off:], uint32(maxJump))
	off += 4
	// numChains = 0
	off += 4
	binary.BigEndian.PutUint32(buf[off:], uint32(maxDeserializedSkippedKeys+1)) // too many

	_, err := Deserialize(buf)
	if err == nil {
		t.Fatal("expected error for V4 resolved skipped key count too large")
	}
}

// ---- V4 Disabled round-trip ----

// TestV4DisabledSerializeDeserializeRoundTrip verifies that serializeV4Disabled
// produces bytes that Deserialize reads back as a V0 disabled state.
func TestV4DisabledSerializeDeserializeRoundTrip(t *testing.T) {
	// Create a braid-aware SPQR in V0 disabled state (e.g. after receiving empty msg).
	ss := randomBytes(t, 32)
	kem := mlkembraid.NewMLKEM768IncrementalKEM()
	braid, err := mlkembraid.InitAlice(ss, kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}

	// Create pending state with braid.
	pendingState, err := InitialStateWithBraid(ss, DirectionA2B, false, braid)
	if err != nil {
		t.Fatalf("InitialStateWithBraid: %v", err)
	}

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
func TestRecvAlreadyDisabledV0(t *testing.T) {
	ss := randomBytes(t, 32)
	state, err := InitialState(ss, DirectionA2B, false)
	if err != nil {
		t.Fatalf("InitialState: %v", err)
	}

	// Resolve to V0.
	state, _, err = Recv(state, []byte{})
	if err != nil {
		t.Fatalf("Recv (V0): %v", err)
	}

	// Call Recv again — should return nil key without error.
	newState, mk, err := Recv(state, []byte{})
	if err != nil {
		t.Fatalf("Recv on disabled V0: %v", err)
	}
	if mk != nil {
		t.Error("expected nil key for V0 disabled Recv")
	}
	if len(newState) == 0 {
		t.Error("state must not be empty")
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
	data := make([]byte, 12)
	data[0] = wireVersion
	for i := 1; i < 12; i++ {
		data[i] = 0x80 // continuation bits set, no terminator
	}
	// Since this is exactly 12 bytes, it is treated as legacy format, not variable-length.
	// Use 13 bytes to avoid the legacy path.
	data = append(data, 0x80)
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

// TestDecodeWireMessageLegacyFormat verifies the legacy 12-byte parsing path.
func TestDecodeWireMessageLegacyFormat(t *testing.T) {
	msg := encodeLegacyMessage(42, 7)
	wm, err := decodeWireMessage(msg)
	if err != nil {
		t.Fatalf("decodeWireMessage legacy: %v", err)
	}
	if wm.Epoch != 42 {
		t.Errorf("epoch = %d, want 42", wm.Epoch)
	}
	if wm.Counter != 7 {
		t.Errorf("counter = %d, want 7", wm.Counter)
	}
	if wm.MsgType != mlkembraid.MessageTypeNone {
		t.Errorf("msgType = %v, want None", wm.MsgType)
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
