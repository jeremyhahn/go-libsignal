//go:build !fips140only

// FIPS 140-3 exemption (docs/FIPS.md): the ported Rust test uses HMAC-SHA256 under the 4-byte INITIAL_SEED_KEY.

package record

// Ports of the Rust sender-key state machine tests (sender_keys.rs:461-629) not covered by coverage_boost_test.go.

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

// TestRust_SenderChainKeyIteration checks Next yields increasing iterations from 0 and unique seeds (sender_keys.rs:605).
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

// TestRust_SenderChainKeyIterationOverflow checks Next at u32::MAX returns ErrChainTooLong (sender_keys.rs:629).
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
