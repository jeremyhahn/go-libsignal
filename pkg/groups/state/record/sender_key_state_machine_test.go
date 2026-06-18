package record

// sender_key_state_machine_test.go — ports the remaining Rust sender-key state
// machine tests from rust/protocol/src/sender_keys.rs:461-629 that are not
// already covered by coverage_boost_test.go.
//
// Ported Rust tests (by Rust source line):
//   add_single_state             sender_keys.rs:461   → TestRust_AddSingleState
//   add_second_state             sender_keys.rs:476   → TestRust_AddSecondState
//   iteration                    sender_keys.rs:605   → TestRust_SenderChainKeyIteration
//   when_sender_chain_key_…      sender_keys.rs:629   → TestRust_SenderChainKeyIterationOverflow
//
// The following Rust tests are already ported in coverage_boost_test.go:
//   when_exceed_maximum_states_then_oldest_is_ejected (495) → TestAddSenderKeyState_ExceedsMaxOldestEjected
//   when_second_state_with_same_pk_and_chain_id_…_keeps_first_data (537) → TestAddSenderKeyState_ReinsertExisting
//   when_second_state_with_different_pk_but_same_chain_id_…_replaced (553) → TestAddSenderKeyState_DifferentSigningKey
//   when_second_state_with_same_pk_and_chain_id_…_becomes_most_recent (570) → TestAddSenderKeyState_ReinsertBecomesMostRecent

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/groups/ratchet"
)

// chainKeyFromSeed mirrors the Rust test helper chain_key(i) which produces a
// deterministic 4-byte big-endian seed from an integer.
// Rust source: rust/protocol/src/sender_keys.rs:375-381
func chainKeyFromSeed(i uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, i)
	return b
}

// deterministicECPublicKey generates a deterministic ECPublicKey from a seed
// byte, used to substitute for Rust's random_public_key() in tests that only
// need distinct keys (not actual random ones). The seed value must be in [1,
// 255] to avoid an all-zero key.
func deterministicECPublicKey(seed byte) ecc.ECPublicKeyable {
	var keyBytes [32]byte
	for i := range keyBytes {
		keyBytes[i] = seed + byte(i)
	}
	// Clamp per Curve25519 spec so ecc.DecodePoint accepts it.
	keyBytes[0] &= 248
	keyBytes[31] &= 127
	keyBytes[31] |= 64
	return ecc.NewDjbECPublicKey(keyBytes)
}

// newRecord returns a fresh, empty SenderKey record for testing.
func newRecord() *SenderKey {
	return NewSenderKey(newTestRecordSerializer(), newTestStateSerializer())
}

// assertStateCount checks the number of sender key states in the record.
func assertStateCount(t *testing.T, record *SenderKey, want int) {
	t.Helper()
	got := len(record.senderKeyStates)
	if got != want {
		t.Errorf("state count = %d, want %d", got, want)
	}
}

// assertChainKey checks that the chain key of the state identified by (keyID,
// signatureKey) equals expectedChainKey.
func assertChainKey(t *testing.T, record *SenderKey, keyID uint32, expectedChainKey []byte) {
	t.Helper()
	state, err := record.GetSenderKeyStateByID(keyID)
	if err != nil {
		t.Fatalf("GetSenderKeyStateByID(%d): %v", keyID, err)
	}
	got := state.SenderChainKey().Seed()
	// Compare the meaningful prefix: the input chain key may be shorter than the
	// guarded seed buffer. The first len(expectedChainKey) bytes must match.
	if len(got) < len(expectedChainKey) || !bytes.Equal(got[:len(expectedChainKey)], expectedChainKey) {
		t.Errorf("chain key mismatch for keyID=%d: got %x, want prefix %x", keyID, got, expectedChainKey)
	}
}

// TestRust_AddSingleState ports add_single_state (sender_keys.rs:461).
//
// Adding one state must result in exactly one state in the record and the
// chain key must be retrievable by ID.
func TestRust_AddSingleState(t *testing.T) {
	rec := newRecord()

	pub := deterministicECPublicKey(1)
	chainID := uint32(1)
	ck := chainKeyFromSeed(1)

	rec.AddSenderKeyState(1, chainID, 0, ck, pub)

	assertStateCount(t, rec, 1)
	assertChainKey(t, rec, chainID, ck)
}

// TestRust_AddSecondState ports add_second_state (sender_keys.rs:476).
//
// Adding two distinct states must result in exactly two states, each with its
// own chain key retrievable by ID.
func TestRust_AddSecondState(t *testing.T) {
	rec := newRecord()

	pub1 := deterministicECPublicKey(1)
	pub2 := deterministicECPublicKey(2)
	chainID1 := uint32(1)
	chainID2 := uint32(2)
	ck1 := chainKeyFromSeed(1)
	ck2 := chainKeyFromSeed(2)

	rec.AddSenderKeyState(1, chainID1, 0, ck1, pub1)
	rec.AddSenderKeyState(1, chainID2, 0, ck2, pub2)

	assertStateCount(t, rec, 2)
	assertChainKey(t, rec, chainID1, ck1)
	assertChainKey(t, rec, chainID2, ck2)
}

// TestRust_SenderChainKeyIteration ports the iteration test
// (sender_keys.rs:605-627).
//
// Each call to Next() must produce a strictly increasing iteration counter and
// a seed that has not been seen before (no duplicates over 10 steps).
// The iteration counter starts at INITIAL_ITERATION (0) and increments by 1.
//
// Rust source constants:
//
//	INITIAL_ITERATION: u32 = 0
//	INITIAL_SEED_KEY:  [u8; 4] = [1, 2, 3, 4]
func TestRust_SenderChainKeyIteration(t *testing.T) {
	const initialIteration = uint32(0)
	initialSeedKey := []byte{1, 2, 3, 4}

	key := ratchet.NewSenderChainKey(initialIteration, initialSeedKey)

	seen := make(map[string]bool)
	seen[string(key.Seed())] = true

	for i := uint32(1); i < 10; i++ {
		next, err := key.Next()
		if err != nil {
			t.Fatalf("Next() at iteration %d: %v", i, err)
		}
		seed := next.Seed()
		seedStr := string(seed)
		if seen[seedStr] {
			t.Errorf("duplicate seed at iteration %d", i)
		}
		seen[seedStr] = true
		if next.Iteration() != initialIteration+i {
			t.Errorf("Iteration() = %d, want %d", next.Iteration(), initialIteration+i)
		}
		key = next
	}
}

// TestRust_SenderChainKeyIterationOverflow ports when_sender_chain_key_iteration_overflows
// (sender_keys.rs:629-637).
//
// Next() at u32::MAX must return an error matching InvalidState (Go: ErrChainTooLong).
//
// Rust source:
//
//	SenderChainKey::new(u32::MAX, INITIAL_SEED_KEY.to_vec())
//	assert_matches!(sender_chain_key.next(), Err(SignalProtocolError::InvalidState { .. }))
func TestRust_SenderChainKeyIterationOverflow(t *testing.T) {
	initialSeedKey := []byte{1, 2, 3, 4}

	key := ratchet.NewSenderChainKey(^uint32(0), initialSeedKey) // u32::MAX

	_, err := key.Next()
	if err == nil {
		t.Fatal("Next() at u32::MAX should return an error")
	}
	var chainErr *ratchet.ErrChainTooLong
	if !isErrChainTooLong(err, &chainErr) {
		t.Errorf("Next() error = %T (%v), want *ratchet.ErrChainTooLong", err, err)
	}
}

func isErrChainTooLong(err error, target **ratchet.ErrChainTooLong) bool {
	e, ok := err.(*ratchet.ErrChainTooLong)
	if ok {
		*target = e
	}
	return ok
}
