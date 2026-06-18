package mlkembraid

import (
	"math"
	"testing"
)

// ================== aliceCompleteCt2: Decaps failure ==================

// TestAliceCompleteCt2DecapsFail verifies that aliceCompleteCt2 returns an error
// when Decaps fails due to wrong dk size. This exercises state.go:507-509.
func TestAliceCompleteCt2DecapsFail(t *testing.T) {
	kemImpl := NewMLKEM768IncrementalKEM()

	_, ekSeed, ekVector, err := kemImpl.KeyGen()
	if err != nil {
		t.Fatal(err)
	}

	ct1, ct2, _, err := kemImpl.FullEncaps(ekSeed, ekVector)
	if err != nil {
		t.Fatal(err)
	}

	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}

	// Build a valid ct2WithMAC payload.
	badMAC := make([]byte, MacSize)
	ct2WithMAC := append(ct2, badMAC...)

	testChunkSize := 256
	ct2Enc, err := NewEncoder(ct2WithMAC, testChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	ct2Dec, err := NewDecoder(len(ct2WithMAC), testChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	for ct2Enc.HasMore() {
		if err := ct2Dec.AddChunk(ct2Enc.NextChunk()); err != nil {
			t.Fatal(err)
		}
	}

	// Use a 1-byte dk which causes Decaps to fail with ErrInvalidInput.
	shortDK := []byte{0x01}
	state := &State{
		kind:        StateEkSentCt1Received,
		epoch:       2,
		auth:        auth,
		dk:          mustSecret(t, shortDK),
		receivedCt1: mustSecret(t, ct1),
		ct2Decoder:  ct2Dec,
		chunkSize:   testChunkSize,
	}

	_, _, err = state.aliceCompleteCt2(&Message{}, kemImpl)
	if err == nil {
		t.Fatal("expected error for wrong dk in Decaps")
	}
}

// ================== receiveCt2Sampled: epoch overflow ==================

// TestReceiveCt2SampledEpochOverflowMaxEpoch verifies that receiveCt2Sampled
// returns ErrEpochOverflow when s.epoch == math.MaxUint64 and a next-epoch
// message arrives (msg.Epoch == s.epoch+1 wraps to 0 for MaxUint64).
// This exercises state.go:1185-1187.
func TestReceiveCt2SampledEpochOverflowMaxEpoch(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:      StateCt2Sampled,
		epoch:     math.MaxUint64, // s.epoch+1 wraps to 0
		auth:      auth,
		chunkSize: DefaultChunkSize,
	}

	// msg.Epoch = 0 == math.MaxUint64 + 1 (wraps), triggering the epoch
	// overflow branch inside receiveCt2Sampled.
	_, _, err = state.receiveCt2Sampled(&Message{
		Epoch: 0,
		Type:  MessageTypeNone,
	}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err == nil {
		t.Fatal("expected ErrEpochOverflow for MaxUint64 epoch in receiveCt2Sampled")
	}
	if _, ok := err.(*ErrEpochOverflow); !ok {
		t.Errorf("expected *ErrEpochOverflow, got %T: %v", err, err)
	}
}

// ================== sendHeaderReceived: Encaps1 failure ==================

// TestSendHeaderReceivedEncaps1Fail verifies that sendHeaderReceived returns an
// error when Encaps1 fails due to bobEkSeed having the wrong length.
// This exercises state.go:598-600.
func TestSendHeaderReceivedEncaps1Fail(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}

	// Use a 1-byte bobEkSeed so Encaps1 returns ErrInvalidInput (wrong length).
	// A 1-byte bobHek also, since Encaps1 checks both sizes.
	shortSeed := []byte{0x01}
	shortHek := []byte{0x02}

	state := &State{
		kind:      StateHeaderReceived,
		epoch:     2,
		auth:      auth,
		bobEkSeed: mustSecret(t, shortSeed),
		bobHek:    mustSecret(t, shortHek),
		chunkSize: DefaultChunkSize,
	}

	// bobEncapSecret is nil so Encaps1 will be called.
	_, _, _, err = state.sendHeaderReceived(NewMLKEM768IncrementalKEM())
	if err == nil {
		t.Fatal("expected error from Encaps1 with wrong ekSeed length")
	}
}

// ================== receiveEkSentCt1Received: AddChunk failure ==================

// TestReceiveEkSentCt1ReceivedAddChunkFail verifies that receiveEkSentCt1Received
// returns an error when AddChunk fails due to malformed chunk data.
// This exercises state.go:482-484.
func TestReceiveEkSentCt1ReceivedAddChunkFail(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}

	ct2Dec, err := NewDecoder(MLKEM768CT2Size+MacSize, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:       StateEkSentCt1Received,
		epoch:      2,
		auth:       auth,
		ct2Decoder: ct2Dec,
		chunkSize:  DefaultChunkSize,
	}

	malformed := []byte{0x00} // index=0, 0 data bytes instead of 32
	_, _, err = state.receiveEkSentCt1Received(&Message{
		Epoch: 2,
		Type:  MessageTypeCt2,
		Data:  malformed,
	}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for malformed chunk in receiveEkSentCt1Received")
	}
}

// ================== receiveNoHeaderReceived: AddChunk failure ==================

// TestReceiveNoHeaderReceivedAddChunkFail verifies that receiveNoHeaderReceived
// returns an error when AddChunk fails due to malformed chunk data.
// This exercises state.go:714-716.
func TestReceiveNoHeaderReceivedAddChunkFail(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}

	hdrDec, err := NewDecoder(HeaderSize+MacSize, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:          StateNoHeaderReceived,
		epoch:         1,
		auth:          auth,
		headerDecoder: hdrDec,
		chunkSize:     DefaultChunkSize,
	}

	malformed := []byte{0x00} // index=0, 0 data bytes instead of 32
	_, _, err = state.receiveNoHeaderReceived(&Message{
		Epoch: 1,
		Type:  MessageTypeHdr,
		Data:  malformed,
	}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for malformed chunk in receiveNoHeaderReceived")
	}
}

// TestReceiveNoHeaderReceivedBadMAC verifies that receiveNoHeaderReceived
// returns ErrMACVerification when the header MAC does not match.
// This exercises state.go:732-734.
func TestReceiveNoHeaderReceivedBadMAC(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}

	// Build a valid-size header payload with a bad MAC (all zeros).
	// HeaderSize=64 bytes of header + MacSize=32 bytes of (wrong) MAC.
	payload := make([]byte, HeaderSize+MacSize)
	// payload[:64] = header data (all zeros), payload[64:96] = bad MAC

	enc, err := NewEncoder(payload, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	hdrDec, err := NewDecoder(HeaderSize+MacSize, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	for enc.HasMore() {
		if err := hdrDec.AddChunk(enc.NextChunk()); err != nil {
			t.Fatal(err)
		}
	}

	state := &State{
		kind:          StateNoHeaderReceived,
		epoch:         1,
		auth:          auth,
		headerDecoder: hdrDec,
		chunkSize:     DefaultChunkSize,
	}

	// headerDecoder is already complete; send a None message which returns early.
	// Instead, call the method directly with a dummy Hdr message.
	// Since headerDecoder.HasMessage() is already true, we need to call it
	// with any Hdr message for the current epoch to trigger MAC verification.
	_, _, err = state.receiveNoHeaderReceived(&Message{
		Epoch: 1,
		Type:  MessageTypeHdr,
		Data:  makeWireChunk(0), // duplicate of an already-seen chunk; returns nil from AddChunk
	}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err == nil {
		t.Fatal("expected ErrMACVerification for bad header MAC")
	}
	if _, ok := err.(*ErrMACVerification); !ok {
		t.Errorf("expected *ErrMACVerification, got %T: %v", err, err)
	}
}

// ================== receiveHeaderReceived: AddChunk failure ==================

// TestReceiveHeaderReceivedAddChunkFail verifies that receiveHeaderReceived
// returns an error when AddChunk fails due to malformed chunk data.
// This exercises state.go:778-780.
func TestReceiveHeaderReceivedAddChunkFail(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}

	ekDec, err := NewDecoder(MLKEM768EKSize, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:      StateHeaderReceived,
		epoch:     2,
		auth:      auth,
		ekDecoder: ekDec,
		chunkSize: DefaultChunkSize,
	}

	malformed := []byte{0x00} // index=0, 0 data bytes instead of 32
	_, _, err = state.receiveHeaderReceived(&Message{
		Epoch: 2,
		Type:  MessageTypeEk,
		Data:  malformed,
	}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for malformed chunk in receiveHeaderReceived")
	}
}

// ================== receiveCt1SampledEk: AddChunk failure ==================

// TestReceiveCt1SampledEkAddChunkFail verifies that receiveCt1SampledEk returns
// an error when AddChunk fails due to malformed chunk data.
// This exercises state.go:852-854.
func TestReceiveCt1SampledEkAddChunkFail(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}

	ekDec, err := NewDecoder(MLKEM768EKSize, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:      StateCt1Sampled,
		epoch:     2,
		auth:      auth,
		ekDecoder: ekDec,
		chunkSize: DefaultChunkSize,
	}

	malformed := []byte{0x00}
	_, _, err = state.receiveCt1SampledEk(&Message{
		Epoch: 2,
		Type:  MessageTypeEk,
		Data:  malformed,
	}, DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for malformed chunk in receiveCt1SampledEk")
	}
}

// ================== receiveCt1SampledEkCt1Ack: AddChunk failure ==================

// TestReceiveCt1SampledEkCt1AckAddChunkFail verifies that receiveCt1SampledEkCt1Ack
// returns an error when AddChunk fails due to malformed chunk data.
// This exercises state.go:904-906.
func TestReceiveCt1SampledEkCt1AckAddChunkFail(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}

	ekDec, err := NewDecoder(MLKEM768EKSize, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:      StateCt1Sampled,
		epoch:     2,
		auth:      auth,
		ekDecoder: ekDec,
		chunkSize: DefaultChunkSize,
	}

	malformed := []byte{0x00}
	_, _, err = state.receiveCt1SampledEkCt1Ack(&Message{
		Epoch: 2,
		Type:  MessageTypeEkCt1Ack,
		Data:  malformed,
	}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for malformed chunk in receiveCt1SampledEkCt1Ack")
	}
}

// ================== receiveCt1Acknowledged: AddChunk failure ==================

// TestReceiveCt1AcknowledgedAddChunkFail verifies that receiveCt1Acknowledged
// returns an error when AddChunk fails due to malformed chunk data.
// This exercises state.go:992-994.
func TestReceiveCt1AcknowledgedAddChunkFail(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}

	ekDec, err := NewDecoder(MLKEM768EKSize, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:      StateCt1Acknowledged,
		epoch:     2,
		auth:      auth,
		ekDecoder: ekDec,
		chunkSize: DefaultChunkSize,
	}

	malformed := []byte{0x00}
	_, _, err = state.receiveCt1Acknowledged(&Message{
		Epoch: 2,
		Type:  MessageTypeEk,
		Data:  malformed,
	}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for malformed chunk in receiveCt1Acknowledged")
	}
}

// ================== receiveKeysSampled: AddChunk failure ==================

// TestReceiveKeysSampledAddChunkFail verifies that receiveKeysSampled returns an
// error when AddChunk fails due to a malformed chunk.
// This exercises state.go:380-382.
func TestReceiveKeysSampledAddChunkFail(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}

	ct1Dec, err := NewDecoder(MLKEM768CT1Size, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:       StateKeysSampled,
		epoch:      2,
		auth:       auth,
		ct1Decoder: ct1Dec,
		chunkSize:  DefaultChunkSize,
	}

	// A 1-byte chunk is malformed: after reading the varint index (1 byte),
	// 0 bytes remain instead of the required 32.
	malformed := []byte{0x00} // index=0, then 0 data bytes
	_, _, err = state.receiveKeysSampled(&Message{
		Epoch: 2,
		Type:  MessageTypeCt1,
		Data:  malformed,
	}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for malformed chunk in receiveKeysSampled")
	}
}

// ================== receiveHeaderSent: AddChunk failure ==================

// TestReceiveHeaderSentAddChunkFail verifies that receiveHeaderSent returns an
// error when AddChunk fails due to a malformed chunk.
// This exercises state.go:405-407.
func TestReceiveHeaderSentAddChunkFail(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}

	ct1Dec, err := NewDecoder(MLKEM768CT1Size, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:       StateHeaderSent,
		epoch:      2,
		auth:       auth,
		ct1Decoder: ct1Dec,
		chunkSize:  DefaultChunkSize,
	}

	malformed := []byte{0x00}
	_, _, err = state.receiveHeaderSent(&Message{
		Epoch: 2,
		Type:  MessageTypeCt1,
		Data:  malformed,
	}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for malformed chunk in receiveHeaderSent")
	}
}

// ================== receiveCt1Received: AddChunk failure ==================

// TestReceiveCt1ReceivedAddChunkFail verifies that receiveCt1Received returns an
// error when AddChunk fails due to a malformed chunk.
// This exercises state.go:448-450.
func TestReceiveCt1ReceivedAddChunkFail(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}

	ct2Dec, err := NewDecoder(MLKEM768CT2Size+MacSize, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:       StateCt1Received,
		epoch:      2,
		auth:       auth,
		ct2Decoder: ct2Dec,
		chunkSize:  DefaultChunkSize,
	}

	malformed := []byte{0x00}
	_, _, err = state.receiveCt1Received(&Message{
		Epoch: 2,
		Type:  MessageTypeCt2,
		Data:  malformed,
	}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for malformed chunk in receiveCt1Received")
	}
}
