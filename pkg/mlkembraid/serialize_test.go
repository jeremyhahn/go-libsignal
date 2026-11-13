package mlkembraid

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret/secrettest"
)

func TestSerializeBraidAlice_RoundTrip(t *testing.T) {
	ss := randomSecret(t)
	// Copy for Bob since secret.New will zeroize
	ssCopy := make([]byte, len(ss))
	copy(ssCopy, ss)

	alice, err := InitAlice(ss, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}

	data, err := alice.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	restored, err := DeserializeBraid(data)
	if err != nil {
		t.Fatalf("DeserializeBraid: %v", err)
	}

	if restored.StateKind() != alice.StateKind() {
		t.Errorf("state kind mismatch: got %s, want %s", restored.StateKind(), alice.StateKind())
	}
	if restored.Epoch() != alice.Epoch() {
		t.Errorf("epoch mismatch: got %d, want %d", restored.Epoch(), alice.Epoch())
	}
	if restored.chunkSize != alice.chunkSize {
		t.Errorf("chunkSize mismatch: got %d, want %d", restored.chunkSize, alice.chunkSize)
	}
	if restored.state.ct1Ack != alice.state.ct1Ack {
		t.Errorf("ct1Ack mismatch: got %v, want %v", restored.state.ct1Ack, alice.state.ct1Ack)
	}

	// Authenticator root keys should match.
	if !bytes.Equal(secrettest.Bytes(restored.state.auth.rootKey), secrettest.Bytes(alice.state.auth.rootKey)) {
		t.Error("authenticator rootKey mismatch after round trip")
	}
}

func TestSerializeBraidBob_RoundTrip(t *testing.T) {
	ss := randomSecret(t)

	bob, err := InitBob(ss, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitBob: %v", err)
	}

	data, err := bob.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	restored, err := DeserializeBraid(data)
	if err != nil {
		t.Fatalf("DeserializeBraid: %v", err)
	}

	if restored.StateKind() != bob.StateKind() {
		t.Errorf("state kind mismatch: got %s, want %s", restored.StateKind(), bob.StateKind())
	}
	if restored.Epoch() != bob.Epoch() {
		t.Errorf("epoch mismatch: got %d, want %d", restored.Epoch(), bob.Epoch())
	}

	// Bob should have a header decoder.
	if restored.state.headerDecoder == nil {
		t.Error("restored Bob should have a headerDecoder")
	}
	if bob.state.headerDecoder == nil {
		t.Fatal("original Bob should have a headerDecoder")
	}
	if restored.state.headerDecoder.originalLen != bob.state.headerDecoder.originalLen {
		t.Errorf("headerDecoder originalLen mismatch: got %d, want %d",
			restored.state.headerDecoder.originalLen, bob.state.headerDecoder.originalLen)
	}
	if restored.state.headerDecoder.TotalChunks() != bob.state.headerDecoder.TotalChunks() {
		t.Errorf("headerDecoder TotalChunks mismatch: got %d, want %d",
			restored.state.headerDecoder.TotalChunks(), bob.state.headerDecoder.TotalChunks())
	}
}

func TestSerializeBraid_AfterSendRecv(t *testing.T) {
	alice, bob := newAliceBob(t)

	// Run a few rounds to advance state.
	for i := 0; i < 5; i++ {
		msg, _, _, err := alice.Send()
		if err != nil {
			t.Fatalf("round %d: Alice.Send: %v", i, err)
		}
		if _, _, err := bob.Receive(msg); err != nil {
			t.Fatalf("round %d: Bob.Receive: %v", i, err)
		}

		msg, _, _, err = bob.Send()
		if err != nil {
			t.Fatalf("round %d: Bob.Send: %v", i, err)
		}
		if _, _, err := alice.Receive(msg); err != nil {
			t.Fatalf("round %d: Alice.Receive: %v", i, err)
		}
	}

	// Serialize and restore Alice.
	aliceData, err := alice.Serialize()
	if err != nil {
		t.Fatalf("Alice.Serialize: %v", err)
	}
	restoredAlice, err := DeserializeBraid(aliceData)
	if err != nil {
		t.Fatalf("DeserializeBraid(alice): %v", err)
	}

	if restoredAlice.StateKind() != alice.StateKind() {
		t.Errorf("Alice state kind mismatch: got %s, want %s", restoredAlice.StateKind(), alice.StateKind())
	}
	if restoredAlice.Epoch() != alice.Epoch() {
		t.Errorf("Alice epoch mismatch: got %d, want %d", restoredAlice.Epoch(), alice.Epoch())
	}

	// Serialize and restore Bob.
	bobData, err := bob.Serialize()
	if err != nil {
		t.Fatalf("Bob.Serialize: %v", err)
	}
	restoredBob, err := DeserializeBraid(bobData)
	if err != nil {
		t.Fatalf("DeserializeBraid(bob): %v", err)
	}

	if restoredBob.StateKind() != bob.StateKind() {
		t.Errorf("Bob state kind mismatch: got %s, want %s", restoredBob.StateKind(), bob.StateKind())
	}
	if restoredBob.Epoch() != bob.Epoch() {
		t.Errorf("Bob epoch mismatch: got %d, want %d", restoredBob.Epoch(), bob.Epoch())
	}
}

func TestDeserializeBraid_InvalidData(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "empty",
			data: []byte{},
		},
		{
			name: "too short",
			data: []byte{0x01, 0x00},
		},
		{
			name: "wrong version",
			data: []byte{0xFF, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "unsupported KEM type",
			data: []byte{0x01, 0xFF, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "truncated state",
			data: []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0xFF},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DeserializeBraid(tc.data)
			if err == nil {
				t.Fatal("expected error for invalid data")
			}
			if _, ok := err.(*ErrDeserialize); !ok {
				t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
			}
		})
	}
}

func TestSerializeBraid_ProtocolContinuesAfterDeserialize(t *testing.T) {
	alice, bob := newAliceBob(t)

	// Run a few rounds to move state machines forward.
	for i := 0; i < 10; i++ {
		msg, _, _, err := alice.Send()
		if err != nil {
			t.Fatalf("phase1 round %d: Alice.Send: %v", i, err)
		}
		if _, _, err := bob.Receive(msg); err != nil {
			t.Fatalf("phase1 round %d: Bob.Receive: %v", i, err)
		}

		msg, _, _, err = bob.Send()
		if err != nil {
			t.Fatalf("phase1 round %d: Bob.Send: %v", i, err)
		}
		if _, _, err := alice.Receive(msg); err != nil {
			t.Fatalf("phase1 round %d: Alice.Receive: %v", i, err)
		}
	}

	// Serialize both parties.
	aliceData, err := alice.Serialize()
	if err != nil {
		t.Fatalf("Alice.Serialize: %v", err)
	}
	bobData, err := bob.Serialize()
	if err != nil {
		t.Fatalf("Bob.Serialize: %v", err)
	}

	// Deserialize into new instances.
	restoredAlice, err := DeserializeBraid(aliceData)
	if err != nil {
		t.Fatalf("DeserializeBraid(alice): %v", err)
	}
	restoredBob, err := DeserializeBraid(bobData)
	if err != nil {
		t.Fatalf("DeserializeBraid(bob): %v", err)
	}

	// Continue the protocol from restored state until completion.
	aliceKey, bobKey := runProtocol(t, restoredAlice, restoredBob, 200)

	if aliceKey == nil {
		t.Fatal("restored Alice did not produce an output key")
	}
	if bobKey == nil {
		t.Fatal("restored Bob did not produce an output key")
	}

	// The output keys from both parties must agree.
	if !bytes.Equal(secrettest.Bytes(aliceKey.Key), secrettest.Bytes(bobKey.Key)) {
		t.Errorf("output keys do not match after deserialization:\n  Alice: %x\n  Bob:   %x",
			secrettest.Bytes(aliceKey.Key), secrettest.Bytes(bobKey.Key))
	}

	t.Logf("Protocol completed after deserialization: Alice state=%s epoch=%d, Bob state=%s epoch=%d",
		restoredAlice.StateKind(), restoredAlice.Epoch(),
		restoredBob.StateKind(), restoredBob.Epoch())
}

func TestSerializeBraid_NilState(t *testing.T) {
	b := &Braid{state: nil}
	_, err := b.Serialize()
	if err == nil {
		t.Fatal("expected error for nil state")
	}
	if serErr, ok := err.(*ErrSerialize); !ok {
		t.Errorf("expected *ErrSerialize, got %T: %v", err, err)
	} else if serErr.Reason != "nil state" {
		t.Errorf("unexpected reason: %s", serErr.Reason)
	}
}

func TestSerializeBraid_Deterministic(t *testing.T) {
	ss := randomSecret(t)
	alice, err := InitAlice(ss, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}

	data1, err := alice.Serialize()
	if err != nil {
		t.Fatalf("first Serialize: %v", err)
	}
	data2, err := alice.Serialize()
	if err != nil {
		t.Fatalf("second Serialize: %v", err)
	}

	if !bytes.Equal(data1, data2) {
		t.Error("consecutive serializations should produce identical output for initial state")
	}
}

func TestSerializeState_EncoderPreservation(t *testing.T) {
	// Create an encoder with some data and advance it.
	data := make([]byte, 100)
	for i := range data {
		data[i] = byte(i)
	}

	enc, err := NewEncoder(data, DefaultChunkSize)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}

	// Advance the encoder by producing some chunks.
	for i := 0; i < 2; i++ {
		enc.NextChunk()
	}

	// Serialize the encoder via appendOptionalEncoder.
	buf := appendOptionalEncoder(nil, enc)

	// Deserialize.
	restored, consumed, err := readOptionalEncoder(buf)
	if err != nil {
		t.Fatalf("readOptionalEncoder: %v", err)
	}
	if consumed != len(buf) {
		t.Errorf("consumed %d bytes, expected %d", consumed, len(buf))
	}

	// Verify the restored encoder produces the same chunks as the original
	// from their current position onward.
	if restored.TotalChunks() != enc.TotalChunks() {
		t.Errorf("encoder TotalChunks mismatch: got %d, want %d", restored.TotalChunks(), enc.TotalChunks())
	}
	if restored.sent != enc.sent {
		t.Errorf("encoder sent mismatch: got %d, want %d", restored.sent, enc.sent)
	}
	if restored.HasMore() != enc.HasMore() {
		t.Errorf("encoder HasMore mismatch: got %v, want %v", restored.HasMore(), enc.HasMore())
	}
	// Both encoders should emit the same next chunk.
	nextRestored := restored.NextChunk()
	nextOrig := enc.NextChunk()
	if !bytes.Equal(nextRestored, nextOrig) {
		t.Errorf("next chunk mismatch after round-trip: restored=%x orig=%x", nextRestored, nextOrig)
	}
}

func TestSerializeState_DecoderPreservation(t *testing.T) {
	dec, err := NewDecoder(HeaderSize+MacSize, DefaultChunkSize)
	if err != nil {
		t.Fatalf("NewDecoder: %v", err)
	}

	// Create an encoder to produce valid chunks.
	data := make([]byte, HeaderSize+MacSize)
	for i := range data {
		data[i] = byte(i)
	}
	enc, err := NewEncoder(data, DefaultChunkSize)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}

	// Add one chunk to the decoder.
	chunk := enc.NextChunk()
	if err := dec.AddChunk(chunk); err != nil {
		t.Fatalf("AddChunk: %v", err)
	}

	// Serialize the decoder.
	buf := appendOptionalDecoder(nil, dec)

	// Deserialize.
	restored, consumed, err := readOptionalDecoder(buf)
	if err != nil {
		t.Fatalf("readOptionalDecoder: %v", err)
	}
	if consumed != len(buf) {
		t.Errorf("consumed %d bytes, expected %d", consumed, len(buf))
	}

	if restored.originalLen != dec.originalLen {
		t.Errorf("originalLen mismatch: got %d, want %d", restored.originalLen, dec.originalLen)
	}
	if restored.TotalChunks() != dec.TotalChunks() {
		t.Errorf("TotalChunks mismatch: got %d, want %d", restored.TotalChunks(), dec.TotalChunks())
	}
	if restored.ReceivedCount() != dec.ReceivedCount() {
		t.Errorf("ReceivedCount mismatch: got %d, want %d", restored.ReceivedCount(), dec.ReceivedCount())
	}
}

func TestSerializeState_NilEncoder(t *testing.T) {
	buf := appendOptionalEncoder(nil, nil)
	if len(buf) != 1 || buf[0] != 0x00 {
		t.Errorf("nil encoder should serialize to [0x00], got %x", buf)
	}

	restored, consumed, err := readOptionalEncoder(buf)
	if err != nil {
		t.Fatalf("readOptionalEncoder: %v", err)
	}
	if consumed != 1 {
		t.Errorf("consumed %d bytes, expected 1", consumed)
	}
	if restored != nil {
		t.Error("expected nil encoder after deserializing nil")
	}
}

func TestSerializeState_NilDecoder(t *testing.T) {
	buf := appendOptionalDecoder(nil, nil)
	if len(buf) != 1 || buf[0] != 0x00 {
		t.Errorf("nil decoder should serialize to [0x00], got %x", buf)
	}

	restored, consumed, err := readOptionalDecoder(buf)
	if err != nil {
		t.Fatalf("readOptionalDecoder: %v", err)
	}
	if consumed != 1 {
		t.Errorf("consumed %d bytes, expected 1", consumed)
	}
	if restored != nil {
		t.Error("expected nil decoder after deserializing nil")
	}
}

func TestDeserializeBraid_TruncatedEncoder(t *testing.T) {
	// Build a valid serialized braid, then truncate it in the encoder region.
	ss := randomSecret(t)
	alice, err := InitAlice(ss, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}

	// Advance to get an encoder.
	_, _, _, sendErr := alice.Send()
	if sendErr != nil {
		t.Fatalf("Send: %v", sendErr)
	}

	data, err := alice.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	// Truncate the last 20 bytes to corrupt encoder/decoder data.
	truncated := data[:len(data)-20]
	// Fix the state length field to match truncated data.
	stateLen := uint32(len(truncated) - 10) // header is 10 bytes (1+1+4+4)
	truncated[6] = byte(stateLen >> 24)
	truncated[7] = byte(stateLen >> 16)
	truncated[8] = byte(stateLen >> 8)
	truncated[9] = byte(stateLen)

	_, err = DeserializeBraid(truncated)
	if err == nil {
		t.Fatal("expected error for truncated data")
	}
}

func TestErrSerialize_Error(t *testing.T) {
	err := &ErrSerialize{Reason: "test reason"}
	expected := "mlkembraid: serialize failed: test reason"
	if err.Error() != expected {
		t.Errorf("got %q, want %q", err.Error(), expected)
	}
}

func TestErrDeserialize_Error(t *testing.T) {
	err := &ErrDeserialize{Reason: "test reason"}
	expected := "mlkembraid: deserialize failed: test reason"
	if err.Error() != expected {
		t.Errorf("got %q, want %q", err.Error(), expected)
	}
}
