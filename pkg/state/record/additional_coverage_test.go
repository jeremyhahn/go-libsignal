//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 11 tests in this file exercise X25519. FIPS 140-3 does not approve that,
// but the X3DH key agreement specification (section 2.1) requires it, so the
// fips140only build tag drops this file from the FIPS gate. `make test` and
// `make coverage` still run it.

package record_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/kem"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/message"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/session"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/util/optional"
)

// ================== Error types ==================

// TestKyberPreKeyDeserializeErrorWithCause verifies Error() with a wrapped error.
func TestKyberPreKeyDeserializeErrorWithCause(t *testing.T) {
	inner := errors.New("underlying error")
	e := &record.KyberPreKeyDeserializeError{Operation: "decode", Err: inner}

	msg := e.Error()
	if msg == "" {
		t.Fatal("Error() must return non-empty string")
	}
	if !errors.Is(e, inner) {
		t.Fatal("Unwrap() must return the wrapped error")
	}
}

// TestKyberPreKeyDeserializeErrorNilCause verifies Error() without a wrapped error.
func TestKyberPreKeyDeserializeErrorNilCause(t *testing.T) {
	e := &record.KyberPreKeyDeserializeError{Operation: "decode", Err: nil}

	msg := e.Error()
	if msg == "" {
		t.Fatal("Error() must return non-empty string when Err is nil")
	}
	if e.Unwrap() != nil {
		t.Fatal("Unwrap() should return nil when Err is nil")
	}
}

// TestReceiverChainNotFoundError verifies the typed error message.
func TestReceiverChainNotFoundError(t *testing.T) {
	e := &record.ReceiverChainNotFoundError{Operation: "SetReceiverChainKey"}

	msg := e.Error()
	if msg == "" {
		t.Fatal("Error() must return non-empty string")
	}

	// Verify it is usable with errors.As.
	var target *record.ReceiverChainNotFoundError
	if !errors.As(e, &target) {
		t.Fatal("errors.As should find *ReceiverChainNotFoundError in itself")
	}
}

// TestSessionCopyError verifies SessionCopyError.Error() and Unwrap().
func TestSessionCopyError(t *testing.T) {
	inner := errors.New("deep copy failed")
	e := &record.SessionCopyError{Err: inner}

	msg := e.Error()
	if msg == "" {
		t.Fatal("Error() must return non-empty string")
	}
	if !errors.Is(e, inner) {
		t.Fatal("Unwrap() must return the wrapped error")
	}
}

// ================== SessionRecord.MarkEstablished ==================

// TestMarkEstablished verifies that MarkEstablished transitions IsFresh from
// true to false, matching the first-use semantics of a session record.
func TestMarkEstablished(t *testing.T) {
	s := newSerializer()
	sess := record.NewSession(s.Session, s.State)

	if !sess.IsFresh() {
		t.Fatal("new session should be fresh")
	}

	sess.MarkEstablished()

	if sess.IsFresh() {
		t.Fatal("session should not be fresh after MarkEstablished")
	}
}

// TestMarkEstablishedIdempotent verifies calling MarkEstablished twice is safe.
func TestMarkEstablishedIdempotent(t *testing.T) {
	s := newSerializer()
	sess := record.NewSession(s.Session, s.State)
	sess.MarkEstablished()
	sess.MarkEstablished()

	if sess.IsFresh() {
		t.Fatal("session should not be fresh after double MarkEstablished")
	}
}

// ================== SessionRecord.Copy ==================

// TestSessionCopy verifies that Copy returns an independent deep copy of the
// session, with matching session state but no shared references.
func TestSessionCopy(t *testing.T) {
	s := newSerializer()
	structure := makeFullStateStructure(t)
	initialState, err := record.NewStateFromStructure(structure, s.State)
	if err != nil {
		t.Fatal(err)
	}
	sess := record.NewSessionFromState(initialState, s.Session)

	copied, err := sess.Copy()
	if err != nil {
		t.Fatalf("Copy() failed: %v", err)
	}
	if copied == nil {
		t.Fatal("Copy() returned nil")
	}

	// Version should match.
	if copied.SessionState().Version() != sess.SessionState().Version() {
		t.Fatal("version mismatch between original and copy")
	}

	// Mutating the copy must not affect the original.
	copied.SessionState().SetVersion(99)
	if sess.SessionState().Version() == 99 {
		t.Fatal("modifying copy should not affect original")
	}
}

// TestSessionCopyWithPreviousStates verifies that Copy also deep-copies
// all previous session states.
func TestSessionCopyWithPreviousStates(t *testing.T) {
	s := newSerializer()

	structure1 := makeFullStateStructure(t)
	state1, err := record.NewStateFromStructure(structure1, s.State)
	if err != nil {
		t.Fatal(err)
	}
	sess := record.NewSessionFromState(state1, s.Session)

	// Archive the current state and promote a new one twice.
	for i := 0; i < 2; i++ {
		newStruct := makeFullStateStructure(t)
		newState, err := record.NewStateFromStructure(newStruct, s.State)
		if err != nil {
			t.Fatal(err)
		}
		sess.PromoteState(newState)
	}

	if len(sess.PreviousSessionStates()) != 2 {
		t.Fatalf("expected 2 previous states, got %d", len(sess.PreviousSessionStates()))
	}

	copied, err := sess.Copy()
	if err != nil {
		t.Fatalf("Copy() failed: %v", err)
	}

	if len(copied.PreviousSessionStates()) != 2 {
		t.Fatalf("copy should have 2 previous states, got %d", len(copied.PreviousSessionStates()))
	}
}

// ================== SessionState.PqRatchetState / SetPqRatchetState ==================

// TestPqRatchetStateGetSet verifies the get/set accessor round-trip for the
// PQ ratchet state field.
func TestPqRatchetStateGetSet(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	// Initially nil.
	if mustCopy(state.PqRatchetState()) != nil {
		t.Fatal("PqRatchetState() should be nil on a new state")
	}

	// Set and retrieve. The setter moves the caller's slice into guarded
	// memory and zeroizes it, so the expectation is kept as its own copy.
	want := "serialized-spqr-state"
	payload := []byte(want)
	if err := state.SetPqRatchetState(payload); err != nil {
		t.Fatalf("SetPqRatchetState: %v", err)
	}

	got := mustCopy(state.PqRatchetState())
	if string(got) != want {
		t.Fatalf("PqRatchetState() = %q, want %q", got, want)
	}
	for _, b := range payload {
		if b != 0 {
			t.Fatal("SetPqRatchetState left the caller's plaintext slice intact")
		}
	}
}

// TestPqRatchetStateSetNil verifies that setting nil clears the field.
func TestPqRatchetStateSetNil(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	if err := state.SetPqRatchetState([]byte("data")); err != nil {
		t.Fatalf("SetPqRatchetState: %v", err)
	}
	if err := state.SetPqRatchetState(nil); err != nil {
		t.Fatalf("SetPqRatchetState(nil): %v", err)
	}

	if mustCopy(state.PqRatchetState()) != nil {
		t.Fatal("PqRatchetState() should be nil after setting nil")
	}
}

// ================== SessionState.UnacknowledgedTimestamp ==================

// TestUnacknowledgedTimestampNoPendingPreKey verifies that UnacknowledgedTimestamp
// returns 0 when there is no pending pre-key message.
func TestUnacknowledgedTimestampNoPendingPreKey(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	if state.UnacknowledgedTimestamp() != 0 {
		t.Fatal("UnacknowledgedTimestamp() should be 0 when no pending pre-key")
	}
}

// TestUnacknowledgedTimestampWithPendingPreKey verifies that UnacknowledgedTimestamp
// returns a non-zero value once a pending pre-key message has been set.
func TestUnacknowledgedTimestampWithPendingPreKey(t *testing.T) {
	state := makeFullState(t)

	kp := genKP(t)
	preKeyID := optional.NewOptionalUint32(42)
	state.SetUnacknowledgedPreKeyMessage(preKeyID, 1, kp.PublicKey())

	ts := state.UnacknowledgedTimestamp()
	if ts == 0 {
		t.Fatal("UnacknowledgedTimestamp() should be non-zero after setting pre-key message")
	}
}

// TestUnacknowledgedTimestampClearedAfterClear verifies that clearing the pending
// pre-key message causes UnacknowledgedTimestamp to return 0 again.
func TestUnacknowledgedTimestampClearedAfterClear(t *testing.T) {
	state := makeFullState(t)

	kp := genKP(t)
	preKeyID := optional.NewOptionalUint32(1)
	state.SetUnacknowledgedPreKeyMessage(preKeyID, 1, kp.PublicKey())

	if state.UnacknowledgedTimestamp() == 0 {
		t.Fatal("expected non-zero timestamp after setting pre-key")
	}

	state.ClearUnackPreKeyMessage()

	if state.UnacknowledgedTimestamp() != 0 {
		t.Fatal("expected 0 timestamp after clearing pre-key")
	}
}

// ================== KyberPreKey.GuardedKeyPair ==================

// TestKyberPreKeyGuardedKeyPair verifies that GuardedKeyPair returns a valid
// GuardedKeyPair with matching public key type and a non-nil secret.
func TestKyberPreKeyGuardedKeyPair(t *testing.T) {
	pubKey := kem.NewPublicKey(kem.KeyTypeKyber1024, make([]byte, 1568))
	kp := mustGuardedKyberKeyPair(t, pubKey, make([]byte, 3168))

	preKey := record.NewKyberPreKey(1, 0, kp, []byte("sig"), &kyberPreKeySerializer{})

	guarded, err := preKey.GuardedKeyPair()
	if err != nil {
		t.Fatalf("GuardedKeyPair() failed: %v", err)
	}
	if guarded == nil {
		t.Fatal("GuardedKeyPair() returned nil")
	}
	if guarded.Public == nil {
		t.Fatal("GuardedKeyPair().Public should not be nil")
	}
	if guarded.Secret == nil {
		t.Fatal("GuardedKeyPair().Secret should not be nil")
	}
	guarded.Secret.Destroy()
}

// ================== SessionWithSelf ==================

// TestSessionWithSelfSameKey verifies that SessionWithSelf returns true when
// local and remote identity keys are identical.
func TestSessionWithSelfSameKey(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	idKP := genIDKeyPair(t)
	state.SetLocalIdentityKey(idKP.PublicKey())
	state.SetRemoteIdentityKey(idKP.PublicKey())

	if !state.SessionWithSelf() {
		t.Fatal("SessionWithSelf() should return true for same key")
	}
}

// TestSessionWithSelfDifferentKeys verifies that SessionWithSelf returns false
// when local and remote identity keys differ.
func TestSessionWithSelfDifferentKeys(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	idKP1 := genIDKeyPair(t)
	idKP2 := genIDKeyPair(t)
	state.SetLocalIdentityKey(idKP1.PublicKey())
	state.SetRemoteIdentityKey(idKP2.PublicKey())

	if state.SessionWithSelf() {
		t.Fatal("SessionWithSelf() should return false for different keys")
	}
}

// TestSessionWithSelfNilLocalKey verifies that SessionWithSelf returns false
// when the local identity key is nil.
func TestSessionWithSelfNilLocalKey(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	idKP := genIDKeyPair(t)
	// Only set remote; local remains nil.
	state.SetRemoteIdentityKey(idKP.PublicKey())

	if state.SessionWithSelf() {
		t.Fatal("SessionWithSelf() should return false when local key is nil")
	}
}

// ================== SetMessageKeys error path ==================

// TestSetMessageKeysNoChain verifies that SetMessageKeys returns a typed
// ReceiverChainNotFoundError when no receiver chain exists for the key.
func TestSetMessageKeysNoChain(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	kp := genKP(t)
	// No chain added for this key.

	mk := message.NewKeys([]byte("c"), []byte("m"), []byte("i"), 0)
	err := state.SetMessageKeys(kp.PublicKey(), mk)
	if err == nil {
		t.Fatal("SetMessageKeys() should return error when no chain exists")
	}
	var chainErr *record.ReceiverChainNotFoundError
	if !errors.As(err, &chainErr) {
		t.Errorf("expected *ReceiverChainNotFoundError, got %T: %v", err, err)
	}
}

// ================== SetReceiverChainKey error path ==================

// TestSetReceiverChainKeyNoChain verifies that SetReceiverChainKey returns a
// ReceiverChainNotFoundError when no receiver chain exists for the key.
func TestSetReceiverChainKeyNoChain(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	kp := genKP(t)
	ck := makeChainKey(t)
	// No receiver chain exists for this key.
	err := state.SetReceiverChainKey(kp.PublicKey(), ck)
	if err == nil {
		t.Fatal("SetReceiverChainKey() should return error when no chain exists")
	}
	var chainErr *record.ReceiverChainNotFoundError
	if !errors.As(err, &chainErr) {
		t.Errorf("expected *ReceiverChainNotFoundError, got %T: %v", err, err)
	}
}

// TestSetReceiverChainKeyMatchingChain verifies that SetReceiverChainKey
// succeeds when a matching receiver chain exists.
func TestSetReceiverChainKeyMatchingChain(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	kp := genKP(t)
	ck1 := makeChainKey(t)
	state.AddReceiverChain(kp.PublicKey(), ck1)

	ck2 := makeChainKey(t)
	err := state.SetReceiverChainKey(kp.PublicKey(), ck2)
	if err != nil {
		t.Fatalf("SetReceiverChainKey() failed unexpectedly: %v", err)
	}
}

// ================== KyberPreKeyFromStructure error paths ==================

// TestNewKyberPreKeyFromStructureInvalidPrivateKey verifies that an invalid
// private key in the structure triggers a KyberPreKeyDeserializeError.
func TestNewKyberPreKeyFromStructureInvalidPrivateKey(t *testing.T) {
	pubKey := kem.NewPublicKey(kem.KeyTypeKyber1024, make([]byte, 1568))

	structure := record.KyberPreKeyStructure{
		ID:         1,
		PublicKey:  pubKey.Serialize(),
		PrivateKey: mustGuard(t, []byte{0xFF, 0x01}), // clearly invalid (too short) secret key
		Signature:  []byte("sig"),
		Timestamp:  0,
	}

	_, err := record.NewKyberPreKeyFromStructure(structure, &kyberPreKeySerializer{})
	if err == nil {
		t.Fatal("expected error for invalid private key")
	}
	var deserErr *record.KyberPreKeyDeserializeError
	if !errors.As(err, &deserErr) {
		t.Errorf("expected *KyberPreKeyDeserializeError, got %T: %v", err, err)
	}
}

// ================== HasMessageKeys nil chain path ==================

// TestHasMessageKeysNilChain verifies that HasMessageKeys returns false when
// no receiver chain exists for the given key.
func TestHasMessageKeysNilChain(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	kp := genKP(t)
	// No chain added.
	if state.HasMessageKeys(kp.PublicKey(), 0) {
		t.Fatal("HasMessageKeys() should return false when no receiver chain exists")
	}
}

// ================== SetRootKey / SetSenderBaseKey error handling ==================

// TestSetRootKeyRejectsForeignImplementation verifies that a RootKeyable that
// is not a *root.Key is refused with a typed error rather than being stored.
func TestSetRootKeyRejectsForeignImplementation(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	err := state.SetRootKey(foreignRootKey{})
	if err == nil {
		t.Fatal("SetRootKey should reject a foreign RootKeyable implementation")
	}

	var typeErr *record.RootKeyTypeError
	if !errors.As(err, &typeErr) {
		t.Fatalf("expected *RootKeyTypeError, got %T: %v", err, err)
	}
	if typeErr.Error() == "" {
		t.Error("RootKeyTypeError message should not be empty")
	}
	// The state must remain usable: a genuine root key still takes.
	if err := state.SetRootKey(makeRootKey(t)); err != nil {
		t.Fatalf("SetRootKey with a *root.Key: %v", err)
	}
	if !bytes.Equal(mustCopy(state.RootKey().Bytes()), make([]byte, 32)) {
		t.Error("the root key set after the rejection was not stored")
	}
}

// foreignRootKey is a RootKeyable implementation from outside the record
// package, used to exercise the type guard in SetRootKey.
type foreignRootKey struct{}

func (foreignRootKey) Bytes() ([]byte, error) { return make([]byte, 32), nil }

func (foreignRootKey) CreateChain(theirRatchetKey ecc.ECPublicKeyable, ourRatchetKey *ecc.ECKeyPair) (*session.KeyPair, error) {
	return nil, errors.New("not implemented")
}

// TestSetSenderBaseKeyInvalidInput verifies that absent and undecodable sender
// base key bytes both clear the stored key instead of being kept.
func TestSetSenderBaseKeyInvalidInput(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	state.SetSenderBaseKey(genKP(t).PublicKey().Serialize())
	if state.SenderBaseKey() == nil {
		t.Fatal("a valid sender base key should be stored")
	}

	state.SetSenderBaseKey(nil)
	if state.SenderBaseKey() != nil {
		t.Error("an empty sender base key should clear the stored key")
	}

	state.SetSenderBaseKey(genKP(t).PublicKey().Serialize())
	state.SetSenderBaseKey([]byte{0xFF, 0xFF})
	if state.SenderBaseKey() != nil {
		t.Error("an undecodable sender base key should clear the stored key")
	}
}
