package mlkembraid

import (
	"math"
	"testing"
)

// ================== ErrEpochOverflow ==================

// TestErrEpochOverflowError verifies ErrEpochOverflow.Error() returns a non-empty string.
func TestErrEpochOverflowError(t *testing.T) {
	e := &ErrEpochOverflow{}
	msg := e.Error()
	if msg == "" {
		t.Fatal("ErrEpochOverflow.Error() must return non-empty string")
	}
}

// TestReceiveCt2SampledEpochOverflow exercises the ErrEpochOverflow path in
// receiveCt2Sampled when s.epoch == MaxUint64 and Transition 13 is triggered.
func TestReceiveCt2SampledEpochOverflow(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:  StateCt2Sampled,
		epoch: math.MaxUint64,
		auth:  auth,
	}

	// Trigger Transition 13 with epoch+1, but epoch is MaxUint64 so addition overflows.
	// math.MaxUint64 + 1 wraps to 0, so msg.Epoch = 0, but state.epoch+1 = 0 (overflow).
	// This should trigger the ErrEpochOverflow guard.
	// Any message type at epoch+1 triggers Transition 13 (F3 fix: type gate removed).
	msg := &Message{Epoch: 0, Type: MessageTypeHdr} // 0 == MaxUint64+1 (wrapped)
	_, _, err = state.Receive(msg, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	// Top-level guard for Ct2Sampled: msg.Epoch(0) > s.epoch+1(0 wrapped) is false.
	// receiveCt2Sampled: msg.Epoch(0) == s.epoch+1(0 wrapped) -> true.
	// s.epoch == MaxUint64 -> return ErrEpochOverflow.
	if err == nil {
		t.Fatal("expected ErrEpochOverflow for MaxUint64 epoch")
	}
	if _, ok := err.(*ErrEpochOverflow); !ok {
		t.Errorf("expected *ErrEpochOverflow, got %T: %v", err, err)
	}
}

// ================== readOptionalDecoder error paths ==================

// TestReadOptionalDecoderTooShort exercises the branch where data has the
// present flag but is too short for the decoder header.
func TestReadOptionalDecoderTooShort(t *testing.T) {
	// Flag=0x01 but only 3 bytes total (need 11 for the header).
	data := []byte{0x01, 0x00, 0x01}
	_, _, err := readOptionalDecoder(data)
	if err == nil {
		t.Fatal("expected error for data too short for decoder header")
	}
	if _, ok := err.(*ErrDeserialize); !ok {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// TestReadOptionalDecoderTooShortForData exercises the branch where the
// data is too short for a decoder chunk entry.
func TestReadOptionalDecoderTooShortForData(t *testing.T) {
	// flag(1) + expectedSize(4) + totalChunks(2) + numReceived(4) = 11 bytes.
	// Then one chunk entry is claimed but not present.
	buf := make([]byte, 11+1) // header OK, but then only 1 byte for chunk (need 2+32)
	buf[0] = 0x01             // hasDecoder=true
	// expectedSize = 1, totalChunks = 1, numReceived = 1
	buf[1], buf[2], buf[3], buf[4] = 0, 0, 0, 1  // expectedSize=1
	buf[5], buf[6] = 0, 1                        // totalChunks=1
	buf[7], buf[8], buf[9], buf[10] = 0, 0, 0, 1 // numReceived=1
	// Only 1 byte for chunk data (need 34: 2 index + 32 data)
	buf[11] = 0x00

	_, _, err := readOptionalDecoder(buf)
	if err == nil {
		t.Fatal("expected error for data too short for decoder chunk entry")
	}
}

// TestReadOptionalDecoderChunkCountExceedsMax exercises the bounds check for
// numReceived exceeding MaxChunkIndex+1.
func TestReadOptionalDecoderChunkCountExceedsMax(t *testing.T) {
	buf := make([]byte, 11)
	buf[0] = 0x01 // hasDecoder=true
	// numReceived = MaxChunkIndex+2 (exceeds maximum)
	overflow := uint32(MaxChunkIndex + 2)
	buf[7] = byte(overflow >> 24)
	buf[8] = byte(overflow >> 16)
	buf[9] = byte(overflow >> 8)
	buf[10] = byte(overflow)

	_, _, err := readOptionalDecoder(buf)
	if err == nil {
		t.Fatal("expected error for chunk count exceeding maximum")
	}
	if _, ok := err.(*ErrDeserialize); !ok {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// ================== NewDecoder: expectedSize too large path ==================

// TestNewDecoderTooLargeExpectedSize verifies that NewDecoder with an
// expectedSize requiring more than MaxChunkIndex+1 chunks returns an error.
func TestNewDecoderTooLargeExpectedSize(t *testing.T) {
	// (MaxChunkIndex+2) * ChunkDataSize bytes would require MaxChunkIndex+2 chunks.
	hugeSz := (MaxChunkIndex + 2) * ChunkDataSize
	_, err := NewDecoder(hugeSz, DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for expectedSize requiring too many chunks")
	}
	if _, ok := err.(*ErrChunkCount); !ok {
		t.Errorf("expected *ErrChunkCount, got %T: %v", err, err)
	}
}

// ================== NewEncoder: data too large path ==================

// TestNewEncoderTooLargeData verifies that NewEncoder with data requiring
// more than MaxChunkIndex+1 chunks returns an ErrChunkCount.
func TestNewEncoderTooLargeData(t *testing.T) {
	hugeData := make([]byte, (MaxChunkIndex+2)*ChunkDataSize)
	_, err := NewEncoder(hugeData, DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for data requiring too many chunks")
	}
	if _, ok := err.(*ErrChunkCount); !ok {
		t.Errorf("expected *ErrChunkCount, got %T: %v", err, err)
	}
}

// ================== Receive: nil message path ==================

// TestBraidReceiveNilMsg verifies that receiving a nil message returns ErrInvalidInput.
func TestBraidReceiveNilMsg(t *testing.T) {
	ss := randomSecret(t)
	bob, err := InitBob(ss, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = bob.Receive(nil)
	if err == nil {
		t.Fatal("expected error for nil message")
	}
	if _, ok := err.(*ErrInvalidInput); !ok {
		t.Errorf("expected *ErrInvalidInput, got %T: %v", err, err)
	}
}

// ================== Receive: past epoch path ==================

// TestBraidReceivePastEpochRejected verifies that receiving a message with an
// epoch behind lastReceivedEpoch is rejected.
func TestBraidReceivePastEpochRejected(t *testing.T) {
	ss := randomSecret(t)
	bob, err := InitBob(ss, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	// Receive a message at epoch=1 to advance lastReceivedEpoch.
	_, _, _ = bob.Receive(&Message{Epoch: 1, Type: MessageTypeNone})

	// Now try to receive a message at epoch=0 (past).
	_, _, err = bob.Receive(&Message{Epoch: 0, Type: MessageTypeNone})
	if err == nil {
		t.Fatal("expected error for past epoch message")
	}
	if _, ok := err.(*ErrInvalidEpoch); !ok {
		t.Errorf("expected *ErrInvalidEpoch, got %T: %v", err, err)
	}
}

// ================== DeserializeSCKA: chain index overflow ==================

// TestDeserializeSCKAChainIndexOverflow verifies that a chain_index exceeding
// uint32 range is rejected.
func TestDeserializeSCKAChainIndexOverflow(t *testing.T) {
	// Build a message with a very large chainIndex varint (> uint32 max).
	// Encode epoch=1 (varint: 0x01), then a 5-byte varint for MaxUint64 as chainIndex.
	buf := make([]byte, 1+1+10+1)
	buf[0] = SPQRVersion
	buf[1] = 0x01 // epoch = 1

	// Encode uint64 value > MaxUint32 as varint for chain_index.
	// 0x1_0000_0000 = 2^32, encoded as: 0x80, 0x80, 0x80, 0x80, 0x10
	at := 2
	// varint encoding of 0x100000000 (> MaxUint32)
	val := uint64(0x100000000)
	for val >= 0x80 {
		buf[at] = byte(val) | 0x80
		val >>= 7
		at++
	}
	buf[at] = byte(val)
	at++
	buf[at] = byte(MessageTypeNone)

	_, _, err := DeserializeSCKA(buf[:at+1])
	if err == nil {
		t.Fatal("expected error for chain_index overflow")
	}
	if _, ok := err.(*ErrSCKADecode); !ok {
		t.Errorf("expected *ErrSCKADecode, got %T: %v", err, err)
	}
}

// ================== Serialize nil KEM (Braid.Serialize) ==================

// TestSerializeBraidNilKEMIsOK verifies that Serialize works even when the
// braid has a valid state (ensures no regression in the serialize path).
func TestSerializeBraidRoundTripAfterSend(t *testing.T) {
	ss := randomSecret(t)
	alice, err := InitAlice(ss, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	// Advance Alice to KeysSampled by sending.
	_, _, _, err = alice.Send()
	if err != nil {
		t.Fatal(err)
	}

	data, err := alice.Serialize()
	if err != nil {
		t.Fatalf("Serialize after Send failed: %v", err)
	}

	restored, err := DeserializeBraid(data)
	if err != nil {
		t.Fatalf("DeserializeBraid after Send failed: %v", err)
	}

	if restored.StateKind() != alice.StateKind() {
		t.Errorf("state kind mismatch: got %s, want %s", restored.StateKind(), alice.StateKind())
	}
}

// ================== DeserializeSCKA: chunk index > 65535 ==================

// TestDeserializeSCKAChunkIndexTooLarge verifies that a chunk index exceeding
// 65535 is rejected by DeserializeSCKA. Matches Rust's serialize.rs:196
// decode_chunk check: index > 65535 → MsgDecode error.
func TestDeserializeSCKAChunkIndexTooLarge(t *testing.T) {
	// Build a MessageTypeHdr wire message with a chunk index of 65536 (> 65535).
	// Wire format: [ver(1)][varint(epoch)][varint(chainIdx)][msgType(1)][varint(chunkIdx)][data(32)]
	buf := make([]byte, 0, 60)
	var tmp [10]byte

	// Version
	buf = append(buf, SPQRVersion)
	// Epoch = 1
	n := putUvarint(tmp[:], 1)
	buf = append(buf, tmp[:n]...)
	// Chain index = 0
	n = putUvarint(tmp[:], 0)
	buf = append(buf, tmp[:n]...)
	// MessageType = Hdr (has chunk)
	buf = append(buf, byte(MessageTypeHdr))
	// Chunk index = 65536 (> 65535) encoded as varint
	// 65536 = 0x10000 → LEB128: 0x80, 0x80, 0x04
	n = putUvarint(tmp[:], 65536)
	buf = append(buf, tmp[:n]...)
	// 32 bytes of chunk data (zero)
	buf = append(buf, make([]byte, ChunkDataSize)...)

	_, _, err := DeserializeSCKA(buf)
	if err == nil {
		t.Fatal("expected error for chunk index > 65535, got nil")
	}
	if _, ok := err.(*ErrSCKADecode); !ok {
		t.Errorf("expected *ErrSCKADecode, got %T: %v", err, err)
	}
}

// TestDeserializeSCKAChunkIndexAtLimit verifies that a chunk index of exactly
// 65535 is accepted by DeserializeSCKA (boundary: just within the Rust limit).
func TestDeserializeSCKAChunkIndexAtLimit(t *testing.T) {
	buf := make([]byte, 0, 60)
	var tmp [10]byte

	buf = append(buf, SPQRVersion)
	n := putUvarint(tmp[:], 1) // epoch = 1
	buf = append(buf, tmp[:n]...)
	n = putUvarint(tmp[:], 0) // chain index = 0
	buf = append(buf, tmp[:n]...)
	buf = append(buf, byte(MessageTypeHdr))
	n = putUvarint(tmp[:], 65535) // chunk index at limit
	buf = append(buf, tmp[:n]...)
	buf = append(buf, make([]byte, ChunkDataSize)...)

	_, _, err := DeserializeSCKA(buf)
	if err != nil {
		t.Fatalf("unexpected error for chunk index = 65535: %v", err)
	}
}

// putUvarint is a test helper that encodes v as a uvarint into buf and
// returns the number of bytes written.
func putUvarint(buf []byte, v uint64) int {
	i := 0
	for v >= 0x80 {
		buf[i] = byte(v) | 0x80
		v >>= 7
		i++
	}
	buf[i] = byte(v)
	return i + 1
}
