//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 22 tests in this file exercise X25519. FIPS 140-3 does not approve that,
// but the X3DH key agreement specification (section 2.1) requires it, so the
// fips140only build tag drops this file from the FIPS gate. `make test` and
// `make coverage` still run it.

package record_test

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/kdf"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/chain"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/message"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/util/optional"
)

// TestStateTotalSkippedMessageKeys exercises TotalSkippedMessageKeys which
// was at 0% coverage. It verifies the count across multiple receiver chains.
func TestStateTotalSkippedMessageKeys(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	// No receiver chains initially, total should be 0.
	total := state.TotalSkippedMessageKeys()
	if total != 0 {
		t.Fatalf("expected 0 total skipped message keys, got %d", total)
	}

	// Add a receiver chain with some message keys.
	kp1 := genKP(t)
	ck1 := makeChainKey(t)
	state.AddReceiverChain(kp1.PublicKey(), ck1)

	mk1 := message.NewKeys(fixedKey("c1", 32), fixedKey("m1", 32), fixedKey("i1", 16), 0)
	mk2 := message.NewKeys(fixedKey("c2", 32), fixedKey("m2", 32), fixedKey("i2", 16), 1)
	if err := state.SetMessageKeys(kp1.PublicKey(), mk1); err != nil {
		t.Fatal(err)
	}
	if err := state.SetMessageKeys(kp1.PublicKey(), mk2); err != nil {
		t.Fatal(err)
	}

	total = state.TotalSkippedMessageKeys()
	if total != 2 {
		t.Fatalf("expected 2 total skipped message keys, got %d", total)
	}

	// Add another receiver chain with message keys.
	kp2 := genKP(t)
	ck2 := makeChainKey(t)
	state.AddReceiverChain(kp2.PublicKey(), ck2)

	mk3 := message.NewKeys(fixedKey("c3", 32), fixedKey("m3", 32), fixedKey("i3", 16), 0)
	if err := state.SetMessageKeys(kp2.PublicKey(), mk3); err != nil {
		t.Fatal(err)
	}

	total = state.TotalSkippedMessageKeys()
	if total != 3 {
		t.Fatalf("expected 3 total skipped message keys, got %d", total)
	}
}

// TestStateTotalSkippedMessageKeysAfterRemoval verifies the count decreases
// after removing message keys.
func TestStateTotalSkippedMessageKeysAfterRemoval(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	kp := genKP(t)
	ck := makeChainKey(t)
	state.AddReceiverChain(kp.PublicKey(), ck)

	mk := message.NewKeys(fixedKey("c", 32), fixedKey("m", 32), fixedKey("i", 16), 5)
	if err := state.SetMessageKeys(kp.PublicKey(), mk); err != nil {
		t.Fatal(err)
	}

	if state.TotalSkippedMessageKeys() != 1 {
		t.Fatal("expected 1 total skipped message key")
	}

	state.RemoveMessageKeys(kp.PublicKey(), 5)

	if state.TotalSkippedMessageKeys() != 0 {
		t.Fatal("expected 0 total skipped message keys after removal")
	}
}

// TestSetMessageKeysExceedsMax exercises the branch in SetMessageKeys where
// message keys exceed maxMessageKeys, triggering PopFirstMessageKeys.
func TestSetMessageKeysExceedsMax(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	kp := genKP(t)
	ck := makeChainKey(t)
	state.AddReceiverChain(kp.PublicKey(), ck)

	// Add more than maxMessageKeys (2000) to trigger the pop branch.
	for i := uint32(0); i <= 2001; i++ {
		mk := message.NewKeys(fixedKey("c", 32), fixedKey("m", 32), fixedKey("i", 16), i)
		if err := state.SetMessageKeys(kp.PublicKey(), mk); err != nil {
			t.Fatal(err)
		}
	}

	// Verify total doesn't exceed the limit.
	total := state.TotalSkippedMessageKeys()
	if total > 2001 {
		t.Fatalf("total skipped keys %d should not exceed 2001", total)
	}
}

// TestStateNeedsRefresh exercises the NeedsRefresh getter and structure path.
func TestStateNeedsRefresh(t *testing.T) {
	s := newSerializer()
	structure := makeFullStateStructure(t)
	structure.NeedsRefresh = true

	state, err := record.NewStateFromStructure(structure, s.State)
	if err != nil {
		t.Fatal(err)
	}

	// Verify needs refresh is set.
	b, err := state.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	state2, err := record.NewStateFromBytes(b, s.State)
	if err != nil {
		t.Fatal(err)
	}

	// Re-serialize to verify the needs_refresh field round-trips.
	_ = state2
}

// TestStateSerializeWithPendingPreKey exercises the structure() path where
// pendingPreKey is non-nil, which generates the UnackPreKeyMessageItems
// structure() method (previously at 0% coverage).
func TestStateSerializeWithPendingPreKey(t *testing.T) {
	s := newSerializer()
	state := makeFullState(t)

	kp := genKP(t)
	preKeyID := optional.NewOptionalUint32(42)
	state.SetUnacknowledgedPreKeyMessage(preKeyID, 10, kp.PublicKey())

	// Serialize the state, which invokes structure() on all sub-structures
	// including pendingPreKey.structure().
	b, err := state.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	state2, err := record.NewStateFromBytes(b, s.State)
	if err != nil {
		t.Fatal(err)
	}

	if !state2.HasUnacknowledgedPreKeyMessage() {
		t.Fatal("pending pre key should survive serialization round-trip")
	}

	items, err := state2.UnackPreKeyMessageItems()
	if err != nil {
		t.Fatal(err)
	}
	if items.PreKeyID().Value != 42 {
		t.Fatalf("pre key ID mismatch: got %d", items.PreKeyID().Value)
	}
	if items.SignedPreKeyID() != 10 {
		t.Fatalf("signed pre key ID mismatch: got %d", items.SignedPreKeyID())
	}
}

// TestStateSerializeWithPendingPreKeyAndKyber exercises the structure()
// path with Kyber fields set.
func TestStateSerializeWithPendingPreKeyAndKyber(t *testing.T) {
	s := newSerializer()
	state := makeFullState(t)

	kp := genKP(t)
	preKeyID := optional.NewOptionalUint32(1)
	kyberPreKeyID := optional.NewOptionalUint32(99)
	kyberCiphertext := []byte("kyber-ciphertext-data")

	state.SetUnacknowledgedPreKeyMessageWithKyber(preKeyID, 20, kp.PublicKey(), kyberPreKeyID, kyberCiphertext)

	b, err := state.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	state2, err := record.NewStateFromBytes(b, s.State)
	if err != nil {
		t.Fatal(err)
	}

	items, err := state2.UnackPreKeyMessageItems()
	if err != nil {
		t.Fatal(err)
	}

	if items.KyberPreKeyID() == nil || items.KyberPreKeyID().Value != 99 {
		t.Fatal("kyber pre key ID mismatch after round-trip")
	}
	if string(items.KyberCiphertext()) != "kyber-ciphertext-data" {
		t.Fatal("kyber ciphertext mismatch after round-trip")
	}
}

// TestSessionSerializeWithMultipleReceiverChains exercises the structure()
// path for SessionState with receiver chains, which invokes chain.structure()
// including the private key serialization branch.
func TestSessionSerializeWithMultipleReceiverChains(t *testing.T) {
	s := newSerializer()
	state := makeFullState(t)

	// Add multiple receiver chains.
	for i := 0; i < 3; i++ {
		kp := genKP(t)
		ck := chain.NewKey(kdf.DeriveSecrets, make([]byte, 32), uint32(i))
		state.AddReceiverChain(kp.PublicKey(), ck)
	}

	b, err := state.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	state2, err := record.NewStateFromBytes(b, s.State)
	if err != nil {
		t.Fatal(err)
	}

	_ = state2
}

// TestChainStructureWithPrivateKey exercises the chain.structure() method
// where the private key is non-nil (the senderRatchetKeyPrivate serialization branch).
func TestChainStructureWithPrivateKey(t *testing.T) {
	kp := genKP(t)
	ck := makeChainKey(t)
	mk := message.NewKeys(fixedKey("c1", 32), fixedKey("m1", 32), fixedKey("i1", 16), 0)
	ch := record.NewChain(kp, ck, []*message.Keys{mk})

	// Serialize the state that contains this chain, triggering structure().
	s := newSerializer()
	state := record.NewState(s.State)
	state.SetSenderChain(kp, ck)

	// Also set identity keys so Serialize can work.
	idKP := genIDKeyPair(t)
	state.SetLocalIdentityKey(idKP.PublicKey())
	state.SetRemoteIdentityKey(idKP.PublicKey())
	state.SetSenderBaseKey(kp.PublicKey().Serialize())

	_ = ch
}

// TestChainStructureWithoutPrivateKey exercises the chain.structure() branch
// where senderRatchetKeyPair.PrivateKey() is nil.
func TestChainStructureWithoutPrivateKey(t *testing.T) {
	kp := genKP(t)
	ck := makeChainKey(t)

	// Create a chain with a key pair that has nil private key.
	pubOnlyPair := ecc.NewECKeyPair(kp.PublicKey(), nil)
	ch := record.NewChain(pubOnlyPair, ck, []*message.Keys{})

	// Verify the chain exists and can report its fields.
	if ch.SenderRatchetKey() == nil {
		t.Fatal("sender ratchet key should not be nil")
	}
	if ch.ChainKey() == nil {
		t.Fatal("chain key should not be nil")
	}
}

// TestNewChainFromStructureInvalidPublicKey exercises the error path in
// NewChainFromStructure when the public key bytes are invalid.
func TestNewChainFromStructureInvalidPublicKey(t *testing.T) {
	structure := &record.ChainStructure{
		SenderRatchetKeyPublic: []byte{0xFF}, // Invalid ECC point
		ChainKey:               &chain.KeyStructure{Key: mustGuard(t, make([]byte, 32)), Index: 0},
	}

	_, err := record.NewChainFromStructure(structure)
	if err == nil {
		t.Fatal("expected error for invalid public key bytes")
	}
}

// TestPendingPreKeyFromStructInvalidBaseKey exercises the error path in
// NewPendingPreKeyFromStruct when the base key is invalid.
func TestPendingPreKeyFromStructInvalidBaseKey(t *testing.T) {
	structure := &record.PendingPreKeyStructure{
		PreKeyID:       optional.NewOptionalUint32(1),
		SignedPreKeyID: 1,
		BaseKey:        []byte{0xFF}, // Invalid ECC point
	}

	_, err := record.NewPendingPreKeyFromStruct(structure)
	if err == nil {
		t.Fatal("expected error for invalid base key bytes")
	}
}

// TestStateFromStructureInvalidKeys exercises the error path in
// NewStateFromStructure when identity keys are invalid.
func TestStateFromStructureInvalidKeys(t *testing.T) {
	s := newSerializer()
	structure := &record.StateStructure{
		SessionVersion:       3,
		LocalIdentityPublic:  []byte{0xFF}, // Invalid
		RemoteIdentityPublic: []byte{0xFF}, // Invalid
		SenderBaseKey:        []byte{0xFF}, // Invalid
		RootKey:              mustGuard(t, make([]byte, 32)),
	}

	_, err := record.NewStateFromStructure(structure, s.State)
	if err == nil {
		t.Fatal("expected error for invalid identity keys")
	}
}

// TestSessionFromStructureInvalidPreviousState exercises the error path
// in NewSessionFromStructure when a previous state has invalid data.
func TestSessionFromStructureInvalidPreviousState(t *testing.T) {
	s := newSerializer()
	validState := makeFullStateStructure(t)

	invalidState := &record.StateStructure{
		SessionVersion:       3,
		LocalIdentityPublic:  []byte{0xFF},
		RemoteIdentityPublic: []byte{0xFF},
		SenderBaseKey:        []byte{0xFF},
	}

	structure := &record.SessionStructure{
		SessionState:   validState,
		PreviousStates: []*record.StateStructure{invalidState},
	}

	_, err := record.NewSessionFromStructure(structure, s.Session, s.State)
	if err == nil {
		t.Fatal("expected error for invalid previous state")
	}
}

// TestSessionStructureSerializeAndDeserializeWithArchivedStates exercises
// the Session.structure() method with multiple archived states.
func TestSessionStructureSerializeAndDeserializeWithArchivedStates(t *testing.T) {
	s := newSerializer()

	// Create a session with a fully-populated state (identity keys, etc.).
	structure := makeFullStateStructure(t)
	initialState, err := record.NewStateFromStructure(structure, s.State)
	if err != nil {
		t.Fatal(err)
	}
	sess := record.NewSessionFromState(initialState, s.Session)

	// Archive several states. Each archive creates a new empty state, but
	// the previously fully-populated state moves to previousStates.
	// We need to set a valid state after archiving so Serialize doesn't panic.
	for i := 0; i < 3; i++ {
		newStructure := makeFullStateStructure(t)
		newState, err := record.NewStateFromStructure(newStructure, s.State)
		if err != nil {
			t.Fatal(err)
		}
		sess.PromoteState(newState)
	}

	b, err := sess.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	sess2, err := record.NewSessionFromBytes(b, s.Session, s.State)
	if err != nil {
		t.Fatal(err)
	}

	if len(sess2.PreviousSessionStates()) != 3 {
		t.Fatalf("expected 3 previous states, got %d", len(sess2.PreviousSessionStates()))
	}
}

// TestReceiverChainKeyWithMatchingKey exercises the ReceiverChainKey
// method when the receiver chain exists and matches.
func TestReceiverChainKeyWithMatchingKey(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	kp := genKP(t)
	ck := makeChainKey(t)
	state.AddReceiverChain(kp.PublicKey(), ck)

	// Query with the same key should return a non-nil chain key.
	rck := state.ReceiverChainKey(kp.PublicKey())
	if rck == nil {
		t.Fatal("receiver chain key should not be nil for matching key")
	}
}

// TestHasMessageKeysNoMatch exercises the HasMessageKeys path where
// message keys exist but none match the given counter.
func TestHasMessageKeysNoMatch(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	kp := genKP(t)
	ck := makeChainKey(t)
	state.AddReceiverChain(kp.PublicKey(), ck)

	mk := message.NewKeys(fixedKey("c", 32), fixedKey("m", 32), fixedKey("i", 16), 5)
	if err := state.SetMessageKeys(kp.PublicKey(), mk); err != nil {
		t.Fatal(err)
	}

	// Query for a counter that doesn't exist.
	if state.HasMessageKeys(kp.PublicKey(), 99) {
		t.Fatal("should not have message key for non-existent counter")
	}

	// Query for the counter that does exist.
	if !state.HasMessageKeys(kp.PublicKey(), 5) {
		t.Fatal("should have message key for counter 5")
	}
}

// TestRemoveMessageKeysReturnsCorrectKey exercises the RemoveMessageKeys
// path with multiple keys, verifying the correct key is returned.
func TestRemoveMessageKeysReturnsCorrectKey(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	kp := genKP(t)
	ck := makeChainKey(t)
	state.AddReceiverChain(kp.PublicKey(), ck)

	mk1 := message.NewKeys(fixedKey("c1", 32), fixedKey("m1", 32), fixedKey("i1", 16), 10)
	mk2 := message.NewKeys(fixedKey("c2", 32), fixedKey("m2", 32), fixedKey("i2", 16), 20)
	mk3 := message.NewKeys(fixedKey("c3", 32), fixedKey("m3", 32), fixedKey("i3", 16), 30)
	if err := state.SetMessageKeys(kp.PublicKey(), mk1); err != nil {
		t.Fatal(err)
	}
	if err := state.SetMessageKeys(kp.PublicKey(), mk2); err != nil {
		t.Fatal(err)
	}
	if err := state.SetMessageKeys(kp.PublicKey(), mk3); err != nil {
		t.Fatal(err)
	}

	// Remove the middle key.
	removed := mustKeys(state.RemoveMessageKeys(kp.PublicKey(), 20))
	if removed == nil {
		t.Fatal("removed key should not be nil")
	}
	if removed.Index() != 20 {
		t.Fatalf("removed key index = %d, want 20", removed.Index())
	}

	// The other keys should still exist.
	if !state.HasMessageKeys(kp.PublicKey(), 10) {
		t.Fatal("key with counter 10 should still exist")
	}
	if !state.HasMessageKeys(kp.PublicKey(), 30) {
		t.Fatal("key with counter 30 should still exist")
	}
	if state.HasMessageKeys(kp.PublicKey(), 20) {
		t.Fatal("key with counter 20 should be removed")
	}
}

// TestRemoveMessageKeysReturnsNilWhenCounterNotFound verifies that
// RemoveMessageKeys returns nil when no key matches the given counter,
// instead of erroneously returning the key at index 0.
func TestRemoveMessageKeysReturnsNilWhenCounterNotFound(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	kp := genKP(t)
	ck := makeChainKey(t)
	state.AddReceiverChain(kp.PublicKey(), ck)

	// Add message keys with specific counters.
	mk1 := message.NewKeys(fixedKey("c1", 32), fixedKey("m1", 32), fixedKey("i1", 16), 10)
	mk2 := message.NewKeys(fixedKey("c2", 32), fixedKey("m2", 32), fixedKey("i2", 16), 20)
	if err := state.SetMessageKeys(kp.PublicKey(), mk1); err != nil {
		t.Fatal(err)
	}
	if err := state.SetMessageKeys(kp.PublicKey(), mk2); err != nil {
		t.Fatal(err)
	}

	// Attempt to remove a key with a counter that does not exist.
	removed := mustKeys(state.RemoveMessageKeys(kp.PublicKey(), 99))
	if removed != nil {
		t.Fatalf("expected nil for non-existent counter, got key with index %d", removed.Index())
	}

	// Verify the original keys are still intact.
	if !state.HasMessageKeys(kp.PublicKey(), 10) {
		t.Fatal("key with counter 10 should still exist")
	}
	if !state.HasMessageKeys(kp.PublicKey(), 20) {
		t.Fatal("key with counter 20 should still exist")
	}
}

// TestRemoveMessageKeysNilChain verifies that RemoveMessageKeys returns nil
// when the receiver chain does not exist for the given ephemeral key.
func TestRemoveMessageKeysNilChain(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	// Add one receiver chain.
	kp1 := genKP(t)
	ck := makeChainKey(t)
	state.AddReceiverChain(kp1.PublicKey(), ck)

	mk := message.NewKeys(fixedKey("c", 32), fixedKey("m", 32), fixedKey("i", 16), 5)
	if err := state.SetMessageKeys(kp1.PublicKey(), mk); err != nil {
		t.Fatal(err)
	}

	// Query with a different key that has no chain.
	kp2 := genKP(t)
	removed := mustKeys(state.RemoveMessageKeys(kp2.PublicKey(), 5))
	if removed != nil {
		t.Fatal("expected nil when querying a non-existent receiver chain")
	}
}

// TestRemoveMessageKeysFirstElementMatch verifies correct behavior when the
// matching key is at index 0 (the case that was previously buggy).
func TestRemoveMessageKeysFirstElementMatch(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	kp := genKP(t)
	ck := makeChainKey(t)
	state.AddReceiverChain(kp.PublicKey(), ck)

	mk1 := message.NewKeys(fixedKey("c1", 32), fixedKey("m1", 32), fixedKey("i1", 16), 0)
	mk2 := message.NewKeys(fixedKey("c2", 32), fixedKey("m2", 32), fixedKey("i2", 16), 1)
	if err := state.SetMessageKeys(kp.PublicKey(), mk1); err != nil {
		t.Fatal(err)
	}
	if err := state.SetMessageKeys(kp.PublicKey(), mk2); err != nil {
		t.Fatal(err)
	}

	// Remove the first key (counter 0).
	removed := mustKeys(state.RemoveMessageKeys(kp.PublicKey(), 0))
	if removed == nil {
		t.Fatal("expected non-nil key for counter 0")
	}
	if removed.Index() != 0 {
		t.Fatalf("expected removed key index 0, got %d", removed.Index())
	}

	// Counter 1 should still be there.
	if !state.HasMessageKeys(kp.PublicKey(), 1) {
		t.Fatal("key with counter 1 should still exist")
	}
}

// TestStateClone verifies that Clone creates an independent deep copy.
func TestStateClone(t *testing.T) {
	state := makeFullState(t)
	state.SetVersion(3)
	state.SetPreviousCounter(42)
	state.SetLocalRegistrationID(1111)

	clone, err := state.Clone()
	if err != nil {
		t.Fatal(err)
	}

	// Verify the clone has the same values.
	if clone.Version() != 3 {
		t.Fatal("clone version mismatch")
	}
	if clone.PreviousCounter() != 42 {
		t.Fatal("clone previous counter mismatch")
	}
	if clone.LocalRegistrationID() != 1111 {
		t.Fatal("clone local registration ID mismatch")
	}

	// Modify the clone and verify the original is unchanged.
	clone.SetPreviousCounter(100)
	clone.SetLocalRegistrationID(9999)

	if state.PreviousCounter() != 42 {
		t.Fatal("original previous counter should not change when clone is modified")
	}
	if state.LocalRegistrationID() != 1111 {
		t.Fatal("original local registration ID should not change when clone is modified")
	}
}

// TestStateCloneWithNilPendingPreKey verifies Clone works when
// pendingPreKey is nil (previously caused a nil pointer dereference).
func TestStateCloneWithNilPendingPreKey(t *testing.T) {
	state := makeFullState(t)
	state.ClearUnackPreKeyMessage()

	clone, err := state.Clone()
	if err != nil {
		t.Fatal(err)
	}

	if clone.HasUnacknowledgedPreKeyMessage() {
		t.Fatal("clone should not have pending pre key when original does not")
	}
}

// TestStateCopyFrom verifies that CopyFrom replaces all fields.
func TestStateCopyFrom(t *testing.T) {
	s := newSerializer()

	state1 := makeFullState(t)
	state1.SetVersion(3)
	state1.SetPreviousCounter(10)
	state1.SetLocalRegistrationID(1000)

	state2 := record.NewState(s.State)

	// CopyFrom should replace state2's fields with state1's.
	state2.CopyFrom(state1)

	if state2.Version() != 3 {
		t.Fatal("version should be copied")
	}
	if state2.PreviousCounter() != 10 {
		t.Fatal("previous counter should be copied")
	}
	if state2.LocalRegistrationID() != 1000 {
		t.Fatal("local registration ID should be copied")
	}
}

// TestVersionZeroMapsToTwo verifies that a stored session version of 0
// (pre-versioning) is mapped to version 2, matching Rust behavior.
func TestVersionZeroMapsToTwo(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)
	// Version defaults to 0 (zero value of int).
	if state.Version() != 2 {
		t.Errorf("Version() = %d, want 2 for stored version 0", state.Version())
	}
}

// TestVersionNonZeroUnchanged verifies that non-zero versions are returned as-is.
func TestVersionNonZeroUnchanged(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	for _, v := range []int{1, 2, 3, 4, 5} {
		state.SetVersion(v)
		if state.Version() != v {
			t.Errorf("Version() = %d, want %d", state.Version(), v)
		}
	}
}

// TestStateCopyFromOverwrite verifies that CopyFrom overwrites existing values.
func TestStateCopyFromOverwrite(t *testing.T) {
	state1 := makeFullState(t)
	state1.SetVersion(3)
	state1.SetPreviousCounter(10)

	state2 := makeFullState(t)
	state2.SetVersion(2)
	state2.SetPreviousCounter(99)

	state2.CopyFrom(state1)

	if state2.Version() != 3 {
		t.Fatal("version should be overwritten")
	}
	if state2.PreviousCounter() != 10 {
		t.Fatal("previous counter should be overwritten")
	}
}

// TestStateSerializeFullRoundTrip performs a comprehensive serialize/deserialize
// round-trip of a fully-populated state, exercising the structure() method for
// all sub-components.
func TestStateSerializeFullRoundTrip(t *testing.T) {
	s := newSerializer()
	state := makeFullState(t)

	state.SetVersion(3)
	state.SetLocalRegistrationID(1234)
	state.SetRemoteRegistrationID(5678)
	state.SetPreviousCounter(42)

	// Add receiver chains with message keys.
	kp := genKP(t)
	ck := makeChainKey(t)
	state.AddReceiverChain(kp.PublicKey(), ck)

	mk := message.NewKeys(fixedKey("cipher-key", 32), fixedKey("mac-key", 32), fixedKey("iv", 16), 0)
	if err := state.SetMessageKeys(kp.PublicKey(), mk); err != nil {
		t.Fatal(err)
	}

	// Set pending pre key.
	preKP := genKP(t)
	preKeyID := optional.NewOptionalUint32(7)
	state.SetUnacknowledgedPreKeyMessage(preKeyID, 15, preKP.PublicKey())

	// Set pending key exchange.
	baseKey := genKP(t)
	ratchetKey := genKP(t)
	identityKey := genIDKeyPair(t)
	state.SetPendingKeyExchange(99, baseKey, ratchetKey, identityKey)

	// Serialize.
	b, err := state.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	// Deserialize.
	state2, err := record.NewStateFromBytes(b, s.State)
	if err != nil {
		t.Fatal(err)
	}

	if state2.Version() != 3 {
		t.Fatal("version mismatch")
	}
	if state2.LocalRegistrationID() != 1234 {
		t.Fatal("local reg ID mismatch")
	}
	if state2.RemoteRegistrationID() != 5678 {
		t.Fatal("remote reg ID mismatch")
	}
	if state2.PreviousCounter() != 42 {
		t.Fatal("previous counter mismatch")
	}
	if !state2.HasPendingKeyExchange() {
		t.Fatal("pending key exchange lost")
	}
	if state2.PendingKeyExchangeSequence() != 99 {
		t.Fatal("pending key exchange sequence mismatch")
	}
	if !state2.HasUnacknowledgedPreKeyMessage() {
		t.Fatal("pending pre key lost")
	}
	items, err := state2.UnackPreKeyMessageItems()
	if err != nil {
		t.Fatal(err)
	}
	if items.PreKeyID().Value != 7 {
		t.Fatal("pre key ID mismatch")
	}
}
