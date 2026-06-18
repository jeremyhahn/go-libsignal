package mlkembraid

// Tests for F3 and F4 epoch-guard fixes.
//
// F3: receiveCt2Sampled Transition 13 must trigger on ANY message type with
// epoch == state.epoch+1, not only MessageTypeHdr.
// Rust ref: src/v1/chunked/states.rs Ct2Sampled arm, Ordering::Greater branch.
//
// F4: All states except Ct2Sampled must reject msg.epoch > state.epoch with
// ErrEpochOutOfRange. The previous code allowed epoch+1 for every state.
// Rust ref: every non-Ct2Sampled arm uses Ordering::Greater => Err(EpochOutOfRange).

import (
	"encoding/binary"
	"testing"
)

// --- F3 tests ---

// TestCt2SampledTransition13AnyMessageType verifies that receiveCt2Sampled
// triggers the next-epoch transition for any message type, not just Hdr.
// Rust: Ordering::Greater (epoch+1) => Self::KeysUnsampled(state.recv_next_epoch(msg.epoch))
// for ALL payload types.
func TestCt2SampledTransition13AnyMessageType(t *testing.T) {
	tests := []struct {
		name    string
		msgType MessageType
	}{
		{"None", MessageTypeNone},
		{"Hdr", MessageTypeHdr},
		{"Ek", MessageTypeEk},
		{"EkCt1Ack", MessageTypeEkCt1Ack},
		{"Ct1Ack", MessageTypeCt1Ack},
		{"Ct1", MessageTypeCt1},
		{"Ct2", MessageTypeCt2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ss := randomSecret(t)
			auth, err := NewAuthenticator(1, ss)
			if err != nil {
				t.Fatal(err)
			}
			state := &State{
				kind:  StateCt2Sampled,
				epoch: 1,
				auth:  auth,
			}

			// epoch+1 = 2: must trigger Transition 13 regardless of type.
			msg := &Message{Epoch: 2, Type: tc.msgType}
			_, _, err = state.Receive(msg, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
			if err != nil {
				t.Fatalf("expected no error for Ct2Sampled receiving epoch+1 with type %s, got: %v", tc.msgType, err)
			}
			if state.kind != StateKeysUnsampled {
				t.Errorf("expected transition to KeysUnsampled, got %s (type=%s)", state.kind, tc.msgType)
			}
			if state.epoch != 2 {
				t.Errorf("expected epoch advanced to 2, got %d (type=%s)", state.epoch, tc.msgType)
			}
		})
	}
}

// TestCt2SampledSameEpochNoTransition verifies that a same-epoch message in
// Ct2Sampled does NOT advance the state machine.
func TestCt2SampledSameEpochNoTransition(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}
	state := &State{
		kind:  StateCt2Sampled,
		epoch: 3,
		auth:  auth,
	}

	msg := &Message{Epoch: 3, Type: MessageTypeNone}
	_, _, err = state.Receive(msg, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.kind != StateCt2Sampled {
		t.Errorf("expected state to remain Ct2Sampled, got %s", state.kind)
	}
}

// TestCt2SampledFuturePlusOneEpochOutOfRange verifies that epoch+2 in Ct2Sampled
// returns ErrEpochOutOfRange.
func TestCt2SampledFuturePlusOneEpochOutOfRange(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}
	state := &State{
		kind:  StateCt2Sampled,
		epoch: 1,
		auth:  auth,
	}

	msg := &Message{Epoch: 3, Type: MessageTypeHdr} // epoch+2: out of range
	_, _, err = state.Receive(msg, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err == nil {
		t.Fatal("expected ErrEpochOutOfRange for epoch+2 in Ct2Sampled")
	}
	if _, ok := err.(*ErrEpochOutOfRange); !ok {
		t.Errorf("expected *ErrEpochOutOfRange, got %T: %v", err, err)
	}
}

// --- F4 tests ---

// TestNonCt2SampledStatesFutureEpochRejected verifies that non-Ct2Sampled
// states reject msg.epoch > state.epoch with ErrEpochOutOfRange.
// Rust: all non-Ct2Sampled arms use Ordering::Greater => Err(EpochOutOfRange).
func TestNonCt2SampledStatesFutureEpochRejected(t *testing.T) {
	ss := randomSecret(t)

	states := []StateKind{
		StateKeysUnsampled,
		StateKeysSampled,
		StateHeaderSent,
		StateCt1Received,
		StateEkSentCt1Received,
		StateNoHeaderReceived,
		StateHeaderReceived,
		StateCt1Sampled,
		StateEkReceivedCt1Sampled,
		StateCt1Acknowledged,
	}

	for _, kind := range states {
		t.Run(kind.String(), func(t *testing.T) {
			a, err := NewAuthenticator(1, ss)
			if err != nil {
				t.Fatal(err)
			}
			state := &State{
				kind:  kind,
				epoch: 1,
				auth:  a,
			}

			// epoch+1 = 2: must be rejected for all non-Ct2Sampled states.
			msg := &Message{Epoch: 2, Type: MessageTypeNone}
			_, _, err = state.Receive(msg, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
			if err == nil {
				t.Fatalf("expected ErrEpochOutOfRange for future epoch in state %s, got nil", kind)
			}
			if _, ok := err.(*ErrEpochOutOfRange); !ok {
				t.Errorf("expected *ErrEpochOutOfRange, got %T: %v in state %s", err, err, kind)
			}
		})
	}
}

// --- LOW: varint wire vector (audit finding F7 / Rust encoding_varint test) ---

// TestVarintWireVector asserts the specific varint encoding used in SerializeSCKA
// matches the Rust reference vector from serialize.rs::test::encoding_varint:
// value 300 (0x012C) encodes to [0xAC, 0x02].
// This uses encoding/binary.PutUvarint which produces identical bytes to Rust's
// LEB128/protobuf varint encoding.
func TestVarintWireVector(t *testing.T) {
	const value uint64 = 300 // 0x012C
	want := []byte{0xAC, 0x02}

	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], value)
	got := buf[:n]

	if len(got) != len(want) {
		t.Fatalf("varint(300): want %v (len %d), got %v (len %d)", want, len(want), got, len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("varint(300) byte[%d]: want 0x%02X, got 0x%02X", i, want[i], got[i])
		}
	}

	// Round-trip: decode must recover original value.
	decoded, n2 := binary.Uvarint(got)
	if n2 <= 0 || decoded != value {
		t.Errorf("varint round-trip failed: decoded %d (n=%d), want %d", decoded, n2, value)
	}
}

// TestNonCt2SampledStatesSameEpochAccepted verifies that non-Ct2Sampled states
// accept msg.epoch == state.epoch without error (basic sanity check for the guard).
func TestNonCt2SampledStatesSameEpochAccepted(t *testing.T) {
	ss := randomSecret(t)

	// Only test states whose handlers do not require complex setup and
	// return cleanly on a None message at the current epoch.
	simpleSameEpochStates := []StateKind{
		StateKeysUnsampled,
		StateNoHeaderReceived,
	}

	for _, kind := range simpleSameEpochStates {
		t.Run(kind.String(), func(t *testing.T) {
			a, err := NewAuthenticator(1, ss)
			if err != nil {
				t.Fatal(err)
			}
			state := &State{
				kind:  kind,
				epoch: 1,
				auth:  a,
			}

			msg := &Message{Epoch: 1, Type: MessageTypeNone}
			_, _, err = state.Receive(msg, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
			if err != nil {
				t.Fatalf("unexpected error for same-epoch None in state %s: %v", kind, err)
			}
		})
	}
}
