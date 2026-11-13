package mlkembraid

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret/secrettest"
)

// --- Transition 10: Ct1Sampled receives Ek -> EkReceivedCt1Sampled ---

func TestTransition10_Ct1SampledEkComplete(t *testing.T) {
	// When all ek chunks arrive via Ek messages, Bob transitions to
	// EkReceivedCt1Sampled with verified hek.
	secret := randomSecret(t)
	kemImpl := NewMLKEM768IncrementalKEM()

	_, ekSeed, ekVector, err := kemImpl.KeyGen()
	if err != nil {
		t.Fatal(err)
	}

	hek := computeHEK(ekSeed, ekVector)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:      StateCt1Sampled,
		epoch:     1,
		auth:      auth,
		bobEkSeed: mustSecret(t, ekSeed),
		bobHek:    mustSecret(t, hek),
		chunkSize: DefaultChunkSize,
	}

	// Encode the ek_vector and feed all chunks.
	enc, err := NewEncoder(ekVector, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	for enc.HasMore() {
		chunk := enc.NextChunk()
		_, out, err := state.Receive(
			&Message{Epoch: 1, Type: MessageTypeEk, Data: chunk},
			kemImpl, DefaultChunkSize,
		)
		if err != nil {
			t.Fatalf("Ek chunk delivery failed: %v", err)
		}
		if out != nil {
			t.Error("should not produce output key from Ek")
		}
	}

	if state.kind != StateEkReceivedCt1Sampled {
		t.Errorf("expected EkReceivedCt1Sampled, got %s", state.kind)
	}
	if state.bobEkVector == nil || state.bobEkVector.Size() == 0 {
		t.Error("bobEkVector should be stored after transition 10")
	}
}

func TestTransition10_Ct1SampledEkBadHek(t *testing.T) {
	// When ek_vector completes but hek does not match, error is returned.
	secret := randomSecret(t)
	kemImpl := NewMLKEM768IncrementalKEM()

	_, ekSeed, ekVector, err := kemImpl.KeyGen()
	if err != nil {
		t.Fatal(err)
	}

	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	// Wrong hek (all zeros).
	state := &State{
		kind:      StateCt1Sampled,
		epoch:     1,
		auth:      auth,
		bobEkSeed: mustSecret(t, ekSeed),
		bobHek:    mustEmptySecret(t, 32),
		chunkSize: DefaultChunkSize,
	}

	enc, err := NewEncoder(ekVector, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	var lastErr error
	for enc.HasMore() {
		chunk := enc.NextChunk()
		_, _, lastErr = state.Receive(
			&Message{Epoch: 1, Type: MessageTypeEk, Data: chunk},
			kemImpl, DefaultChunkSize,
		)
		if lastErr != nil {
			break
		}
	}

	if lastErr == nil {
		t.Fatal("expected hek verification error")
	}
	if _, ok := lastErr.(*ErrHeaderFormat); !ok {
		t.Errorf("expected ErrHeaderFormat, got %T: %v", lastErr, lastErr)
	}
}

// --- Transition 8: Ct1Sampled receives EkCt1Ack (ek incomplete) -> Ct1Acknowledged ---

func TestTransition8_Ct1SampledEkCt1AckPartial(t *testing.T) {
	secret := randomSecret(t)
	kemImpl := NewMLKEM768IncrementalKEM()

	_, ekSeed, ekVector, err := kemImpl.KeyGen()
	if err != nil {
		t.Fatal(err)
	}

	hek := computeHEK(ekSeed, ekVector)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:      StateCt1Sampled,
		epoch:     1,
		auth:      auth,
		bobEkSeed: mustSecret(t, ekSeed),
		bobHek:    mustSecret(t, hek),
		chunkSize: DefaultChunkSize,
	}

	// Send just one EkCt1Ack chunk (not enough to complete ek_decoder).
	enc, err := NewEncoder(ekVector, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	firstChunk := enc.NextChunk()
	_, out, err := state.Receive(
		&Message{Epoch: 1, Type: MessageTypeEkCt1Ack, Data: firstChunk},
		kemImpl, DefaultChunkSize,
	)
	if err != nil {
		t.Fatalf("EkCt1Ack failed: %v", err)
	}
	if out != nil {
		t.Error("should not produce output key with partial ek")
	}
	if state.kind != StateCt1Acknowledged {
		t.Errorf("expected Ct1Acknowledged, got %s", state.kind)
	}
	if !state.ct1Ack {
		t.Error("ct1Ack should be set")
	}
}

// --- Transition 9: Ct1Sampled receives EkCt1Ack (ek complete) -> Ct2Sampled ---

func TestTransition9_Ct1SampledEkCt1AckComplete(t *testing.T) {
	secret := randomSecret(t)
	kemImpl := NewMLKEM768IncrementalKEM()

	_, ekSeed, ekVector, err := kemImpl.KeyGen()
	if err != nil {
		t.Fatal(err)
	}

	hek := computeHEK(ekSeed, ekVector)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:      StateCt1Sampled,
		epoch:     1,
		auth:      auth,
		bobEkSeed: mustSecret(t, ekSeed),
		bobHek:    mustSecret(t, hek),
		chunkSize: DefaultChunkSize,
	}

	// Send all ek chunks via Ek first (not acknowledging ct1 yet).
	enc, err := NewEncoder(ekVector, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	// Deliver all but the last chunk as Ek.
	totalChunks := enc.TotalChunks()
	for i := 0; i < totalChunks-1; i++ {
		chunk := enc.NextChunk()
		_, _, err := state.Receive(
			&Message{Epoch: 1, Type: MessageTypeEk, Data: chunk},
			kemImpl, DefaultChunkSize,
		)
		if err != nil {
			t.Fatalf("Ek chunk %d failed: %v", i, err)
		}
	}

	// State should still be Ct1Sampled (ek not yet complete).
	if state.kind != StateCt1Sampled {
		t.Fatalf("expected Ct1Sampled before final chunk, got %s", state.kind)
	}

	// Deliver the last chunk as EkCt1Ack -> ek completes + ct1 acknowledged.
	lastChunk := enc.NextChunk()
	_, outKey, err := state.Receive(
		&Message{Epoch: 1, Type: MessageTypeEkCt1Ack, Data: lastChunk},
		kemImpl, DefaultChunkSize,
	)
	if err != nil {
		t.Fatalf("final EkCt1Ack failed: %v", err)
	}

	if state.kind != StateCt2Sampled {
		t.Errorf("expected Ct2Sampled, got %s", state.kind)
	}
	if outKey == nil {
		t.Fatal("expected output key from encapsulation")
	}
	if secrettest.Len(t, outKey.Key) != 32 {
		t.Errorf("output key length = %d, want 32", secrettest.Len(t, outKey.Key))
	}
	if state.ct2Encoder == nil {
		t.Error("ct2Encoder should be created")
	}
	if state.ct1Encoder == nil {
		t.Error("ct1Encoder should be created")
	}
}

// --- EkReceivedCt1Sampled + Ct1Ack -> Ct2Sampled (via encapsulation) ---

func TestEkReceivedCt1Sampled_Ct1AckTriggersEncaps(t *testing.T) {
	secret := randomSecret(t)
	kemImpl := NewMLKEM768IncrementalKEM()

	_, ekSeed, ekVector, err := kemImpl.KeyGen()
	if err != nil {
		t.Fatal(err)
	}

	hek := computeHEK(ekSeed, ekVector)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	// Set up state as if transition 10 already occurred.
	state := &State{
		kind:        StateEkReceivedCt1Sampled,
		epoch:       1,
		auth:        auth,
		bobEkSeed:   mustSecret(t, ekSeed),
		bobHek:      mustSecret(t, hek),
		bobEkVector: mustSecret(t, ekVector),
		chunkSize:   DefaultChunkSize,
	}

	_, outKey, err := state.Receive(
		&Message{Epoch: 1, Type: MessageTypeCt1Ack},
		kemImpl, DefaultChunkSize,
	)
	if err != nil {
		t.Fatalf("Ct1Ack in EkReceivedCt1Sampled failed: %v", err)
	}
	if state.kind != StateCt2Sampled {
		t.Errorf("expected Ct2Sampled, got %s", state.kind)
	}
	if outKey == nil {
		t.Fatal("expected output key")
	}
	if state.ct2Encoder == nil {
		t.Error("ct2Encoder should be created")
	}
}

func TestEkReceivedCt1Sampled_EkCt1AckTriggersEncaps(t *testing.T) {
	secret := randomSecret(t)
	kemImpl := NewMLKEM768IncrementalKEM()

	_, ekSeed, ekVector, err := kemImpl.KeyGen()
	if err != nil {
		t.Fatal(err)
	}

	hek := computeHEK(ekSeed, ekVector)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:        StateEkReceivedCt1Sampled,
		epoch:       1,
		auth:        auth,
		bobEkSeed:   mustSecret(t, ekSeed),
		bobHek:      mustSecret(t, hek),
		bobEkVector: mustSecret(t, ekVector),
		chunkSize:   DefaultChunkSize,
	}

	_, outKey, err := state.Receive(
		&Message{Epoch: 1, Type: MessageTypeEkCt1Ack},
		kemImpl, DefaultChunkSize,
	)
	if err != nil {
		t.Fatalf("EkCt1Ack in EkReceivedCt1Sampled failed: %v", err)
	}
	if state.kind != StateCt2Sampled {
		t.Errorf("expected Ct2Sampled, got %s", state.kind)
	}
	if outKey == nil {
		t.Fatal("expected output key")
	}
}

// --- Ct1Acknowledged + remaining Ek -> Ct2Sampled ---

func TestCt1Acknowledged_EkCompleteTriggersEncaps(t *testing.T) {
	secret := randomSecret(t)
	kemImpl := NewMLKEM768IncrementalKEM()

	_, ekSeed, ekVector, err := kemImpl.KeyGen()
	if err != nil {
		t.Fatal(err)
	}

	hek := computeHEK(ekSeed, ekVector)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	// Pre-initialize ek_decoder with all but one chunk.
	enc, err := NewEncoder(ekVector, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	ekDec, err := NewDecoder(MLKEM768EKSize, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	totalChunks := enc.TotalChunks()
	for i := 0; i < totalChunks-1; i++ {
		chunk := enc.NextChunk()
		if err := ekDec.AddChunk(chunk); err != nil {
			t.Fatal(err)
		}
	}

	state := &State{
		kind:      StateCt1Acknowledged,
		epoch:     1,
		auth:      auth,
		bobEkSeed: mustSecret(t, ekSeed),
		bobHek:    mustSecret(t, hek),
		ekDecoder: ekDec,
		ct1Ack:    true,
		chunkSize: DefaultChunkSize,
	}

	// Deliver the last ek chunk -> completes ek and triggers encapsulation.
	lastChunk := enc.NextChunk()
	_, outKey, err := state.Receive(
		&Message{Epoch: 1, Type: MessageTypeEk, Data: lastChunk},
		kemImpl, DefaultChunkSize,
	)
	if err != nil {
		t.Fatalf("final Ek in Ct1Acknowledged failed: %v", err)
	}
	if state.kind != StateCt2Sampled {
		t.Errorf("expected Ct2Sampled, got %s", state.kind)
	}
	if outKey == nil {
		t.Fatal("expected output key")
	}
	if secrettest.Len(t, outKey.Key) != 32 {
		t.Errorf("output key length = %d, want 32", secrettest.Len(t, outKey.Key))
	}
}

// --- sendCt1Acknowledged with ct1Encoder ---

func TestSendCt1AcknowledgedCt1Chunks(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	ct1Enc, err := NewEncoder(make([]byte, 64), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:       StateCt1Acknowledged,
		epoch:      1,
		auth:       auth,
		ct1Encoder: ct1Enc,
	}

	msg, _, _, err := state.Send(NewMLKEM768IncrementalKEM())
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != MessageTypeCt1 {
		t.Errorf("expected Ct1, got %s", msg.Type)
	}
}

func TestSendCt1AcknowledgedWraparound(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	ct1Enc, err := NewEncoder(make([]byte, 32), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	// Drain encoder.
	for ct1Enc.HasMore() {
		ct1Enc.NextChunk()
	}

	state := &State{
		kind:       StateCt1Acknowledged,
		epoch:      1,
		auth:       auth,
		ct1Encoder: ct1Enc,
	}

	// After draining, should wrap around.
	msg, _, _, err := state.Send(NewMLKEM768IncrementalKEM())
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != MessageTypeCt1 {
		t.Errorf("expected Ct1 (wraparound), got %s", msg.Type)
	}
}

// --- Error paths ---

func TestReceiveCt1SampledEkMissingBobEkSeed(t *testing.T) {
	// verifyEkVector fails when bobEkSeed is not set.
	secret := randomSecret(t)
	kemImpl := NewMLKEM768IncrementalKEM()

	_, _, ekVector, err := kemImpl.KeyGen()
	if err != nil {
		t.Fatal(err)
	}

	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:      StateCt1Sampled,
		epoch:     1,
		auth:      auth,
		bobEkSeed: nil,
		bobHek:    mustEmptySecret(t, 32),
		chunkSize: DefaultChunkSize,
	}

	enc, err := NewEncoder(ekVector, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	var lastErr error
	for enc.HasMore() {
		chunk := enc.NextChunk()
		_, _, lastErr = state.Receive(
			&Message{Epoch: 1, Type: MessageTypeEk, Data: chunk},
			kemImpl, DefaultChunkSize,
		)
		if lastErr != nil {
			break
		}
	}

	if lastErr == nil {
		t.Fatal("expected error for missing bobEkSeed")
	}
	if _, ok := lastErr.(*ErrInvalidState); !ok {
		t.Errorf("expected ErrInvalidState, got %T: %v", lastErr, lastErr)
	}
}

func TestReceiveCt1AcknowledgedWrongMessageType(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:      StateCt1Acknowledged,
		epoch:     1,
		auth:      auth,
		chunkSize: DefaultChunkSize,
	}

	_, _, err = state.Receive(
		&Message{Epoch: 1, Type: MessageTypeCt1},
		NewMLKEM768IncrementalKEM(), DefaultChunkSize,
	)
	if err == nil {
		t.Fatal("expected error for wrong message type")
	}
	if _, ok := err.(*ErrInvalidMessageType); !ok {
		t.Errorf("expected ErrInvalidMessageType, got %T", err)
	}
}

func TestBobCompleteEncapsulationDeferredNoEkVector(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:      StateEkReceivedCt1Sampled,
		epoch:     1,
		auth:      auth,
		chunkSize: DefaultChunkSize,
	}

	_, _, err = state.bobCompleteEncapsulationDeferred(NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for missing ek_vector")
	}
	if _, ok := err.(*ErrInvalidState); !ok {
		t.Errorf("expected ErrInvalidState, got %T: %v", err, err)
	}
}

// --- Full protocol flow exercising new transitions ---

func TestFullProtocolExchangeNewTransitions(t *testing.T) {
	// Verify the full protocol still works end-to-end with the new transition logic.
	alice, bob := newAliceBob(t)

	aliceKey, bobKey := runProtocol(t, alice, bob, 200)

	if aliceKey == nil {
		t.Fatal("Alice did not produce an output key")
	}
	if bobKey == nil {
		t.Fatal("Bob did not produce an output key")
	}
	if !secrettest.Same(t, aliceKey.Key, bobKey.Key) {
		t.Error("output keys should match")
	}
	if aliceKey.Epoch != bobKey.Epoch {
		t.Errorf("epochs should match: Alice=%d, Bob=%d", aliceKey.Epoch, bobKey.Epoch)
	}
}

func TestTransition10ThenCt1Ack(t *testing.T) {
	// Full flow: Ek chunks complete (transition 10) -> EkReceivedCt1Sampled,
	// then Ct1Ack -> Ct2Sampled.
	secret := randomSecret(t)
	kemImpl := NewMLKEM768IncrementalKEM()

	_, ekSeed, ekVector, err := kemImpl.KeyGen()
	if err != nil {
		t.Fatal(err)
	}

	hek := computeHEK(ekSeed, ekVector)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:      StateCt1Sampled,
		epoch:     1,
		auth:      auth,
		bobEkSeed: mustSecret(t, ekSeed),
		bobHek:    mustSecret(t, hek),
		chunkSize: DefaultChunkSize,
	}

	// Phase 1: Send all ek chunks as Ek -> transition 10.
	enc, err := NewEncoder(ekVector, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	for enc.HasMore() {
		chunk := enc.NextChunk()
		_, _, err := state.Receive(
			&Message{Epoch: 1, Type: MessageTypeEk, Data: chunk},
			kemImpl, DefaultChunkSize,
		)
		if err != nil {
			t.Fatalf("Ek delivery failed: %v", err)
		}
	}

	if state.kind != StateEkReceivedCt1Sampled {
		t.Fatalf("expected EkReceivedCt1Sampled, got %s", state.kind)
	}

	// Phase 2: Ct1Ack -> triggers encapsulation -> Ct2Sampled.
	_, outKey, err := state.Receive(
		&Message{Epoch: 1, Type: MessageTypeCt1Ack},
		kemImpl, DefaultChunkSize,
	)
	if err != nil {
		t.Fatalf("Ct1Ack failed: %v", err)
	}
	if state.kind != StateCt2Sampled {
		t.Errorf("expected Ct2Sampled, got %s", state.kind)
	}
	if outKey == nil {
		t.Fatal("expected output key")
	}
}

func TestTransition8ThenEkComplete(t *testing.T) {
	// Flow: partial EkCt1Ack (transition 8) -> Ct1Acknowledged,
	// then remaining Ek chunks -> Ct2Sampled.
	secret := randomSecret(t)
	kemImpl := NewMLKEM768IncrementalKEM()

	_, ekSeed, ekVector, err := kemImpl.KeyGen()
	if err != nil {
		t.Fatal(err)
	}

	hek := computeHEK(ekSeed, ekVector)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:      StateCt1Sampled,
		epoch:     1,
		auth:      auth,
		bobEkSeed: mustSecret(t, ekSeed),
		bobHek:    mustSecret(t, hek),
		chunkSize: DefaultChunkSize,
	}

	enc, err := NewEncoder(ekVector, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	// Phase 1: Deliver first chunk as EkCt1Ack (partial) -> transition 8.
	firstChunk := enc.NextChunk()
	_, _, err = state.Receive(
		&Message{Epoch: 1, Type: MessageTypeEkCt1Ack, Data: firstChunk},
		kemImpl, DefaultChunkSize,
	)
	if err != nil {
		t.Fatalf("EkCt1Ack failed: %v", err)
	}
	if state.kind != StateCt1Acknowledged {
		t.Fatalf("expected Ct1Acknowledged, got %s", state.kind)
	}

	// Phase 2: Deliver remaining chunks as Ek in Ct1Acknowledged state.
	var outKey *OutputKey
	for enc.HasMore() {
		chunk := enc.NextChunk()
		_, outKey, err = state.Receive(
			&Message{Epoch: 1, Type: MessageTypeEk, Data: chunk},
			kemImpl, DefaultChunkSize,
		)
		if err != nil {
			t.Fatalf("Ek delivery in Ct1Acknowledged failed: %v", err)
		}
	}

	if state.kind != StateCt2Sampled {
		t.Errorf("expected Ct2Sampled, got %s", state.kind)
	}
	if outKey == nil {
		t.Fatal("expected output key from completed encapsulation")
	}
}
