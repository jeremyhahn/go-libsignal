package mlkembraid

import (
	"testing"
)

// ================== Authenticator.Clone with non-nil macKey ==================

// TestAuthenticatorCloneWithMacKey verifies that Clone succeeds when macKey is
// set (after at least one Update call), covering the a.macKey != nil branch.
func TestAuthenticatorCloneWithMacKey(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}
	// After NewAuthenticator, macKey is set (Update was called internally).
	// Now clone it.
	cloned, err := auth.Clone()
	if err != nil {
		t.Fatalf("Clone with non-nil macKey failed: %v", err)
	}
	if cloned == nil {
		t.Fatal("Clone returned nil")
	}
	if cloned.Epoch() != auth.Epoch() {
		t.Errorf("cloned epoch = %d, want %d", cloned.Epoch(), auth.Epoch())
	}
	auth.Zeroize()
	cloned.Zeroize()
}

// TestAuthenticatorClonePreservesEpoch verifies that Clone copies the epoch value.
func TestAuthenticatorClonePreservesEpoch(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(42, ss)
	if err != nil {
		t.Fatal(err)
	}
	cloned, err := auth.Clone()
	if err != nil {
		t.Fatalf("Clone failed: %v", err)
	}
	if cloned.Epoch() != 42 {
		t.Errorf("cloned epoch = %d, want 42", cloned.Epoch())
	}
	auth.Zeroize()
	cloned.Zeroize()
}

// ================== Receive: unknown state kind → ErrInvalidState ==================

// TestReceiveUnknownStateKind verifies that Receive returns ErrInvalidState
// when the state's kind is not in the receiveHandlers dispatch map.
func TestReceiveUnknownStateKind(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}

	// Use a StateKind value that is not in receiveHandlers (255 is out of range).
	const unknownKind StateKind = 255
	state := &State{
		kind:  unknownKind,
		epoch: 1,
		auth:  auth,
	}

	_, _, err = state.Receive(&Message{Epoch: 1, Type: MessageTypeNone}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err == nil {
		t.Fatal("expected ErrInvalidState for unknown state kind")
	}
	if _, ok := err.(*ErrInvalidState); !ok {
		t.Errorf("expected *ErrInvalidState, got %T: %v", err, err)
	}
}

// ================== receiveHeaderSent: invalid message type ==================

// TestReceiveHeaderSentInvalidType verifies that receiveHeaderSent returns
// ErrInvalidMessageType when receiving a non-None, non-Ct1 message.
func TestReceiveHeaderSentInvalidType(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:      StateHeaderSent,
		epoch:     5,
		auth:      auth,
		chunkSize: DefaultChunkSize,
	}

	_, _, err = state.Receive(&Message{Epoch: 5, Type: MessageTypeHdr}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err == nil {
		t.Fatal("expected ErrInvalidMessageType for Hdr in HeaderSent state")
	}
	if _, ok := err.(*ErrInvalidMessageType); !ok {
		t.Errorf("expected *ErrInvalidMessageType, got %T: %v", err, err)
	}
}

// ================== bobCompleteEncapsulationDeferred: two-phase path ==================

// TestBobCompleteEncapsulationDeferredTwoPhase exercises the CompleteEncaps2 path
// in bobCompleteEncapsulationDeferred where bobEncapSecret is non-nil (Encaps1
// was called in sendHeaderReceived before ek_vector arrived).
func TestBobCompleteEncapsulationDeferredTwoPhase(t *testing.T) {
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

	hek := computeHEK(ekSeed, ekVector)

	// Call Encaps1 to produce the bobEncapSecret token, simulating what
	// sendHeaderReceived does.
	encapsSecretBytes, _, _, err := kemImpl.Encaps1(ekSeed, hek)
	if err != nil {
		t.Fatal(err)
	}
	encapsSecret := mustSecret(t, encapsSecretBytes)

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

	state := &State{
		kind:           StateCt1Sampled,
		epoch:          5,
		auth:           auth,
		bobEkSeed:      mustSecret(t, ekSeed),
		bobHek:         mustSecret(t, hek),
		bobEncapSecret: encapsSecret,
		ekDecoder:      ekDec,
		chunkSize:      testChunkSize,
	}

	receivingEpoch, outputKey, err := state.bobCompleteEncapsulationDeferred(kemImpl, testChunkSize)
	if err != nil {
		t.Fatalf("bobCompleteEncapsulationDeferred two-phase failed: %v", err)
	}
	if outputKey == nil {
		t.Fatal("expected non-nil output key")
	}
	if receivingEpoch != 4 {
		t.Errorf("receivingEpoch = %d, want 4", receivingEpoch)
	}
	if state.kind != StateCt2Sampled {
		t.Errorf("expected StateCt2Sampled, got %s", state.kind)
	}
	outputKey.Key.Destroy()
}

// ================== receiveKeysSampled: invalid message type ==================

// TestReceiveKeysSampledInvalidMessageType verifies that receiveKeysSampled returns
// ErrInvalidMessageType when receiving a non-None, non-Ct1 message.
func TestReceiveKeysSampledInvalidMessageType(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:      StateKeysSampled,
		epoch:     5,
		auth:      auth,
		chunkSize: DefaultChunkSize,
	}

	_, _, err = state.Receive(&Message{Epoch: 5, Type: MessageTypeHdr}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err == nil {
		t.Fatal("expected ErrInvalidMessageType for Hdr in KeysSampled state")
	}
	if _, ok := err.(*ErrInvalidMessageType); !ok {
		t.Errorf("expected *ErrInvalidMessageType, got %T: %v", err, err)
	}
}

// ================== receiveCt1SampledCt1Ack: bobEkVector path ==================

// TestReceiveCt1SampledCt1AckWithEkVector exercises the path in
// receiveCt1SampledCt1Ack where bobEkVector is already set (transition 10
// completed), triggering bobCompleteEncapsulationDeferred immediately.
func TestReceiveCt1SampledCt1AckWithEkVector(t *testing.T) {
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

	hek := computeHEK(ekSeed, ekVector)

	state := &State{
		kind:        StateCt1Sampled,
		epoch:       5,
		auth:        auth,
		bobEkSeed:   mustSecret(t, ekSeed),
		bobHek:      mustSecret(t, hek),
		bobEkVector: mustSecret(t, ekVector),
		chunkSize:   DefaultChunkSize,
	}

	_, outputKey, err := state.Receive(&Message{Epoch: 5, Type: MessageTypeCt1Ack}, kemImpl, DefaultChunkSize)
	if err != nil {
		t.Fatalf("receiveCt1SampledCt1Ack with ekVector failed: %v", err)
	}
	if outputKey == nil {
		t.Fatal("expected output key after Ct1Ack with complete ek_vector")
	}
	if state.kind != StateCt2Sampled {
		t.Errorf("expected Ct2Sampled, got %s", state.kind)
	}
	outputKey.Key.Destroy()
}
