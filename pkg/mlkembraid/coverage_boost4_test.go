package mlkembraid

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret/secrettest"
)

// ================== bobCompleteEncapsulationDeferred: no ek_vector path ==================

// TestBobCompleteEncapsulationDeferredNoEkVector exercises the ErrInvalidState
// path when bobEkVector is nil and ekDecoder is also nil.
func TestBobCompleteEncapsulationDeferredCt1SampledNoEkVector(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}

	kemImpl := NewMLKEM768IncrementalKEM()
	_, ekSeed, _, err := kemImpl.KeyGen()
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:      StateCt1Sampled,
		epoch:     5,
		auth:      auth,
		bobEkSeed: mustSecret(t, ekSeed),
		bobHek:    mustEmptySecret(t, 32),
		// No bobEkVector and no ekDecoder.
	}

	_, _, err = state.bobCompleteEncapsulationDeferred(kemImpl, DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for missing ek_vector")
	}
	if _, ok := err.(*ErrInvalidState); !ok {
		t.Errorf("expected *ErrInvalidState, got %T: %v", err, err)
	}
}

// TestBobCompleteEncapsulationDeferredFromEkDecoder exercises the path where
// ek_vector is retrieved from a complete ekDecoder (not bobEkVector).
func TestBobCompleteEncapsulationDeferredFromEkDecoder(t *testing.T) {
	ss := randomSecret(t)
	kemImpl := NewMLKEM768IncrementalKEM()
	_, ekSeed, ekVector, err := kemImpl.KeyGen()
	if err != nil {
		t.Fatal(err)
	}

	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}

	// Build a complete ekDecoder with the full ek_vector.
	testChunkSize := 256
	ekEnc, err := NewEncoder(ekVector, testChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	ekDec, err := NewDecoder(len(ekVector), testChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	for ekEnc.HasMore() {
		if err := ekDec.AddChunk(ekEnc.NextChunk()); err != nil {
			t.Fatal(err)
		}
	}

	hek := computeHEK(ekSeed, ekVector)

	state := &State{
		kind:      StateCt1Sampled,
		epoch:     5,
		auth:      auth,
		bobEkSeed: mustSecret(t, ekSeed),
		bobHek:    mustSecret(t, hek),
		ekDecoder: ekDec,
		chunkSize: testChunkSize,
		// bobEkVector is nil - should be populated from ekDecoder.
	}

	receivingEpoch, outputKey, err := state.bobCompleteEncapsulationDeferred(kemImpl, testChunkSize)
	if err != nil {
		t.Fatalf("bobCompleteEncapsulationDeferred from ekDecoder failed: %v", err)
	}
	if outputKey == nil {
		t.Fatal("expected output key")
	}
	if receivingEpoch != 4 {
		t.Errorf("expected receivingEpoch=4, got %d", receivingEpoch)
	}
	if state.kind != StateCt2Sampled {
		t.Errorf("expected Ct2Sampled, got %s", state.kind)
	}
	outputKey.Key.Destroy()
}

// ================== receiveHeaderSent: full completion path ==================

// TestReceiveHeaderSentCompleteCt1 exercises the path in receiveHeaderSent
// where ct1_decoder.HasMessage() becomes true, transitioning to Ct1Received.
func TestReceiveHeaderSentCompleteCt1(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}

	// We need to send a complete ct1. MLKEM768CT1Size = 1088 bytes.
	// With DefaultChunkSize=32 and the fixed 32-byte wire payload, we need
	// ceil(1088/32)=34 chunks. Use a smaller test payload for speed:
	// Build a fake ct1 that fits in 1 chunk.
	testChunkSize := 256
	fakeCt1 := make([]byte, MLKEM768CT1Size)
	ct1Enc, err := NewEncoder(fakeCt1, testChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:      StateHeaderSent,
		epoch:     5,
		auth:      auth,
		chunkSize: testChunkSize,
	}

	kemImpl := NewMLKEM768IncrementalKEM()

	// Feed all ct1 chunks.
	for ct1Enc.HasMore() {
		chunk := ct1Enc.NextChunk()
		if _, _, err := state.Receive(&Message{Epoch: 5, Type: MessageTypeCt1, Data: chunk}, kemImpl, testChunkSize); err != nil {
			t.Fatalf("receiveHeaderSent failed: %v", err)
		}
	}

	// After all chunks received, should transition to Ct1Received.
	if state.kind != StateCt1Received {
		t.Errorf("expected Ct1Received after complete ct1, got %s", state.kind)
	}
}

// ================== receiveCt1Received: complete Ct2 path ==================

// TestReceiveCt1ReceivedCompleteCt2 exercises the path in receiveCt1Received
// where ct2_decoder.HasMessage() becomes true, triggering aliceCompleteCt2.
// This uses the complete protocol flow to construct valid ct1/ct2.
func TestReceiveCt1ReceivedCompleteCt2(t *testing.T) {
	ss := randomSecret(t)
	ssCopy := make([]byte, len(ss))
	copy(ssCopy, ss)

	kemImpl := NewMLKEM768IncrementalKEM()
	alice, err := InitAlice(ss, kemImpl, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := InitBob(ssCopy, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	// Run the protocol to get both parties to produce output keys.
	aliceKey, bobKey := runProtocol(t, alice, bob, 500)

	if aliceKey == nil || bobKey == nil {
		t.Fatal("both parties should produce output keys")
	}
	if !bytes.Equal(secrettest.Bytes(aliceKey.Key), secrettest.Bytes(bobKey.Key)) {
		t.Error("output keys should match")
	}
	aliceKey.Key.Destroy()
	bobKey.Key.Destroy()
}

// ================== AddChunk: polynomial redundancy index ==================

// TestAddChunkRedundancyIndex verifies that a chunk index beyond TotalChunks()
// is accepted as a valid polynomial redundancy chunk. With polynomial encoding
// any distinct chunk index reconstructs the original message.
func TestAddChunkRedundancyIndex(t *testing.T) {
	// Encoder for 32 bytes (1 first-pass chunk). The second NextChunk call
	// emits a redundancy chunk with index=1.
	data := make([]byte, 32)
	for i := range data {
		data[i] = byte(i)
	}
	enc, err := NewEncoder(data, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	_ = enc.NextChunk()           // index 0 — discard
	redundancy := enc.NextChunk() // index 1 — polynomial redundancy

	dec, err := NewDecoder(32, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	// Index 1 is beyond TotalChunks() (==1) but is a valid polynomial chunk.
	if err := dec.AddChunk(redundancy); err != nil {
		t.Fatalf("AddChunk(redundancy): unexpected error: %v", err)
	}
	if !dec.HasMessage() {
		t.Fatal("decoder should reconstruct from a single redundancy chunk")
	}
}
