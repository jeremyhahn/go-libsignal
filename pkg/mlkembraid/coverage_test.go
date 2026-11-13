package mlkembraid

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret/secrettest"
)

// mustSecret creates a *secret.Secret from raw bytes for testing.
func mustSecret(t *testing.T, data []byte) *secret.Secret {
	t.Helper()
	s, err := secret.New(data)
	if err != nil {
		t.Fatalf("secret.New failed: %v", err)
	}
	return s
}

// mustEmptySecret creates a zero-filled *secret.Secret for testing.
func mustEmptySecret(t *testing.T, size int) *secret.Secret {
	t.Helper()
	s, err := secret.NewEmpty(size)
	if err != nil {
		t.Fatalf("secret.NewEmpty failed: %v", err)
	}
	return s
}

// makeWireChunk builds a valid Rust-compatible wire chunk for testing:
// [varint(index)] [data(32 bytes, zero-filled by default)].
func makeWireChunk(index uint16) []byte {
	chunk := make([]byte, 1+ChunkDataSize) // small indices use 1-byte varint
	if index < 128 {
		chunk[0] = byte(index)
	} else {
		// Encode as 2-byte varint for indices 128-16383.
		chunk = make([]byte, 2+ChunkDataSize)
		chunk[0] = byte(index&0x7F) | 0x80
		chunk[1] = byte(index >> 7)
	}
	return chunk
}

// --- Decoder edge case tests ---

func TestDecoderAddChunkAfterCompleteCoverage(t *testing.T) {
	// 10 bytes -> ceil(10/32) = 1 chunk with 32-byte fixed payload
	dec, err := NewDecoder(10, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	enc, err := NewEncoder([]byte("0123456789"), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	for enc.HasMore() {
		chunk := enc.NextChunk()
		if err := dec.AddChunk(chunk); err != nil {
			t.Fatal(err)
		}
	}

	if !dec.HasMessage() {
		t.Fatal("decoder should be complete")
	}

	// With polynomial encoding, NextChunk() after HasMore()==false emits a
	// redundancy chunk with the next sequential index (not a duplicate of index 0).
	// Adding it increments ReceivedCount.
	redundancyChunk := enc.NextChunk()
	if err := dec.AddChunk(redundancyChunk); err != nil {
		t.Fatal(err)
	}
	if dec.ReceivedCount() != 2 {
		t.Errorf("received count should be 2 after adding redundancy chunk, got %d", dec.ReceivedCount())
	}
}

// --- Authenticator edge case tests ---

func TestAuthenticatorZeroize(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}
	auth.Zeroize() // Should not panic.
}

func TestAuthenticatorMacHdrNilMacKey(t *testing.T) {
	auth := &Authenticator{
		rootKey: mustEmptySecret(t, 32),
		macKey:  nil,
		epoch:   1,
	}

	_, err := auth.MacHdr(1, []byte("header"))
	if err == nil {
		t.Fatal("expected error for nil macKey")
	}
}

func TestAuthenticatorMacCtNilMacKey(t *testing.T) {
	auth := &Authenticator{
		rootKey: mustEmptySecret(t, 32),
		macKey:  nil,
		epoch:   1,
	}

	_, err := auth.MacCt(1, []byte("ct"))
	if err == nil {
		t.Fatal("expected error for nil macKey")
	}
}

func TestAuthenticatorVfyHdrFail(t *testing.T) {
	// Test VfyHdr returning false (not just error path).
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	valid, err := auth.VfyHdr(1, []byte("header"), make([]byte, MacSize))
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Error("expected VfyHdr to return false for wrong mac")
	}
}

func TestAuthenticatorVfyCtFail(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	valid, err := auth.VfyCt(1, []byte("ct"), make([]byte, MacSize))
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Error("expected VfyCt to return false for wrong mac")
	}
}

// --- KEM edge case tests ---

func TestMLKEM768IncrementalKEMKeyGenUniqueness(t *testing.T) {
	kemImpl := NewMLKEM768IncrementalKEM()

	_, ekSeed1, _, err := kemImpl.KeyGen()
	if err != nil {
		t.Fatal(err)
	}

	_, ekSeed2, _, err := kemImpl.KeyGen()
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(ekSeed1, ekSeed2) {
		t.Error("two key generations should produce different ek_seeds")
	}
}

// --- Protocol info and label tests ---

func TestProtocolInfoConstant(t *testing.T) {
	expected := "Signal_PQCKA_V1_MLKEM768"
	if ProtocolInfo != expected {
		t.Errorf("ProtocolInfo = %q, want %q", ProtocolInfo, expected)
	}
}

func TestBuildInfo(t *testing.T) {
	info := buildInfo("test", 1)
	if len(info) != 4+8 {
		t.Errorf("info length = %d, want 12", len(info))
	}
	if string(info[:4]) != "test" {
		t.Errorf("info prefix = %q, want %q", info[:4], "test")
	}
}

// --- OutputKey ---

func TestOutputKeyStruct(t *testing.T) {
	keyData := make([]byte, 32)
	keySecret, err := secret.New(keyData)
	if err != nil {
		t.Fatal(err)
	}
	key := &OutputKey{
		Epoch: 42,
		Key:   keySecret,
	}
	if key.Epoch != 42 {
		t.Error("Epoch mismatch")
	}
	if len(secrettest.Bytes(key.Key)) != 32 {
		t.Error("Key length mismatch")
	}
	key.Key.Destroy()
}

// --- Receive wrong message type tests ---

func TestReceiveNoHeaderReceivedWrongType(t *testing.T) {
	secret := randomSecret(t)
	bob, err := InitBob(secret, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = bob.Receive(&Message{Epoch: 1, Type: MessageTypeCt1})
	if err == nil {
		t.Fatal("expected error for wrong message type")
	}
	if _, ok := err.(*ErrInvalidMessageType); !ok {
		t.Errorf("expected ErrInvalidMessageType, got %T", err)
	}
}

func TestReceiveNoHeaderReceivedNone(t *testing.T) {
	secret := randomSecret(t)
	bob, err := InitBob(secret, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = bob.Receive(&Message{Epoch: 1, Type: MessageTypeNone})
	if err != nil {
		t.Fatalf("receiving None should not error: %v", err)
	}
}

// --- Large chunk size protocol exchange ---
// Tests with a very large chunk size so that all data fits in a single chunk,
// exercising different state transition paths.

func TestFullEpochExchangeLargeChunks(t *testing.T) {
	secret := randomSecret(t)
	kemImpl := NewMLKEM768IncrementalKEM()

	// Use a chunk size large enough to send everything in one chunk.
	chunkSize := 4096

	alice, err := InitAlice(secret, kemImpl, chunkSize)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := InitBob(secret, kemImpl, chunkSize)
	if err != nil {
		t.Fatal(err)
	}

	aliceKey, bobKey := runProtocol(t, alice, bob, 200)

	if aliceKey == nil || bobKey == nil {
		t.Fatal("both parties should produce output keys")
	}
	if !bytes.Equal(secrettest.Bytes(aliceKey.Key), secrettest.Bytes(bobKey.Key)) {
		t.Error("output keys should match with large chunks")
	}
	aliceKey.Key.Destroy()
	bobKey.Key.Destroy()
}

// --- State machine: sendCt1Received with remaining ek ---

func TestSendCt1ReceivedWithRemainingEk(t *testing.T) {
	// Create state that simulates Ct1Received with ekEncoder having more data.
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	ekEnc, err := NewEncoder(make([]byte, 64), 16)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:      StateCt1Received,
		epoch:     5,
		auth:      auth,
		ekEncoder: ekEnc,
	}

	msg, _, _, err := state.Send(NewMLKEM768IncrementalKEM())
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != MessageTypeEkCt1Ack {
		t.Errorf("expected EkCt1Ack, got %s", msg.Type)
	}
}

func TestSendCt1ReceivedAllEkSent(t *testing.T) {
	// Ct1Received with ekEncoder fully sent.
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	ekEnc, err := NewEncoder([]byte("data"), 32)
	if err != nil {
		t.Fatal(err)
	}
	// Drain encoder.
	for ekEnc.HasMore() {
		ekEnc.NextChunk()
	}

	state := &State{
		kind:      StateCt1Received,
		epoch:     5,
		auth:      auth,
		ekEncoder: ekEnc,
	}

	msg, _, _, err := state.Send(NewMLKEM768IncrementalKEM())
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != MessageTypeCt1Ack {
		t.Errorf("expected Ct1Ack, got %s", msg.Type)
	}
	if state.kind != StateEkSentCt1Received {
		t.Errorf("expected EkSentCt1Received, got %s", state.kind)
	}
}

// --- sendCt1Sampled with no encoder (shouldn't happen in practice) ---

func TestSendCt1SampledNoEncoder(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:  StateCt1Sampled,
		epoch: 5,
		auth:  auth,
	}

	msg, _, _, err := state.Send(NewMLKEM768IncrementalKEM())
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != MessageTypeNone {
		t.Errorf("expected None, got %s", msg.Type)
	}
}

// --- sendEkReceivedCt1Sampled ---

func TestSendEkReceivedCt1SampledWithEncoder(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	ct1Enc, err := NewEncoder(make([]byte, 64), 16)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:       StateEkReceivedCt1Sampled,
		epoch:      5,
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

func TestSendEkReceivedCt1SampledNoEncoder(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:  StateEkReceivedCt1Sampled,
		epoch: 5,
		auth:  auth,
	}

	msg, _, _, err := state.Send(NewMLKEM768IncrementalKEM())
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != MessageTypeNone {
		t.Errorf("expected None, got %s", msg.Type)
	}
}

// --- sendCt1Acknowledged ---

func TestSendCt1AcknowledgedNoEncoder(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:  StateCt1Acknowledged,
		epoch: 5,
		auth:  auth,
	}

	// Without ct1Encoder, sends None.
	msg, _, _, err := state.Send(NewMLKEM768IncrementalKEM())
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != MessageTypeNone {
		t.Errorf("expected None, got %s", msg.Type)
	}
}

func TestSendCt1AcknowledgedWithEncoder(t *testing.T) {
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
		epoch:      5,
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

// --- sendCt2Sampled ---

func TestSendCt2SampledWithEncoder(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	ct2Enc, err := NewEncoder(make([]byte, 64), 16)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:       StateCt2Sampled,
		epoch:      5,
		auth:       auth,
		ct2Encoder: ct2Enc,
	}

	msg, _, _, err := state.Send(NewMLKEM768IncrementalKEM())
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != MessageTypeCt2 {
		t.Errorf("expected Ct2, got %s", msg.Type)
	}
}

func TestSendCt2SampledNoEncoder(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:  StateCt2Sampled,
		epoch: 5,
		auth:  auth,
	}

	msg, _, _, err := state.Send(NewMLKEM768IncrementalKEM())
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != MessageTypeNone {
		t.Errorf("expected None, got %s", msg.Type)
	}
}

// --- receiveCt1Received ---

func TestReceiveCt1ReceivedNone(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:  StateCt1Received,
		epoch: 5,
		auth:  auth,
	}

	_, out, err := state.Receive(&Message{Epoch: 5, Type: MessageTypeNone}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Error("expected nil output for None message")
	}
}

func TestReceiveCt1ReceivedWrongType(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:  StateCt1Received,
		epoch: 5,
		auth:  auth,
	}

	_, _, err = state.Receive(&Message{Epoch: 5, Type: MessageTypeCt1}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for wrong message type")
	}
}

// --- receiveEkSentCt1Received ---

func TestReceiveEkSentCt1ReceivedNone(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:  StateEkSentCt1Received,
		epoch: 5,
		auth:  auth,
	}

	_, out, err := state.Receive(&Message{Epoch: 5, Type: MessageTypeNone}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Error("expected nil output")
	}
}

func TestReceiveEkSentCt1ReceivedWrongType(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:  StateEkSentCt1Received,
		epoch: 5,
		auth:  auth,
	}

	_, _, err = state.Receive(&Message{Epoch: 5, Type: MessageTypeCt1}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for wrong message type")
	}
}

// --- receiveCt1Sampled ---

func TestReceiveCt1SampledNone(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:  StateCt1Sampled,
		epoch: 5,
		auth:  auth,
	}

	_, out, err := state.Receive(&Message{Epoch: 5, Type: MessageTypeNone}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Error("expected nil output")
	}
}

func TestReceiveCt1SampledCt1AckAlreadyComplete(t *testing.T) {
	// When ct2Encoder is set (encapsulation already done), Ct1Ack transitions to Ct2Sampled.
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	ct2Enc, err := NewEncoder(make([]byte, 32), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:       StateCt1Sampled,
		epoch:      5,
		auth:       auth,
		ct2Encoder: ct2Enc,
	}

	_, _, err = state.Receive(&Message{Epoch: 5, Type: MessageTypeCt1Ack}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if state.kind != StateCt2Sampled {
		t.Errorf("expected Ct2Sampled, got %s", state.kind)
	}
}

func TestReceiveCt1SampledCt1AckNoEk(t *testing.T) {
	// When no ek_vector and no ct2Encoder, Ct1Ack transitions to Ct1Acknowledged.
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:  StateCt1Sampled,
		epoch: 5,
		auth:  auth,
	}

	_, _, err = state.Receive(&Message{Epoch: 5, Type: MessageTypeCt1Ack}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if state.kind != StateCt1Acknowledged {
		t.Errorf("expected Ct1Acknowledged, got %s", state.kind)
	}
	if !state.ct1Ack {
		t.Error("ct1Ack should be set")
	}
}

func TestReceiveCt1SampledEkCt1AckAlreadyComplete(t *testing.T) {
	// When ct2Encoder is set, EkCt1Ack transitions directly to Ct2Sampled.
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	ct2Enc, err := NewEncoder(make([]byte, 32), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:       StateCt1Sampled,
		epoch:      5,
		auth:       auth,
		ct2Encoder: ct2Enc,
	}

	_, _, err = state.Receive(&Message{Epoch: 5, Type: MessageTypeEkCt1Ack, Data: []byte("data")}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if state.kind != StateCt2Sampled {
		t.Errorf("expected Ct2Sampled, got %s", state.kind)
	}
}

func TestReceiveCt1SampledEkCt1AckPartialEk(t *testing.T) {
	// Transition 8: EkCt1Ack with incomplete ek -> Ct1Acknowledged.
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	// MLKEM768EKSize=1152, DefaultChunkSize=32, payloadSize=30,
	// totalChunks = ceil(1152/30) = 39.
	chunk := makeWireChunk(0)

	state := &State{
		kind:      StateCt1Sampled,
		epoch:     5,
		auth:      auth,
		chunkSize: DefaultChunkSize,
	}

	_, _, err = state.Receive(&Message{Epoch: 5, Type: MessageTypeEkCt1Ack, Data: chunk}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if state.kind != StateCt1Acknowledged {
		t.Errorf("expected Ct1Acknowledged, got %s", state.kind)
	}
	if !state.ct1Ack {
		t.Error("ct1Ack should be set")
	}
}

func TestReceiveCt1SampledEkAlreadyComplete(t *testing.T) {
	// When ct2Encoder is set, Ek chunks are accepted silently.
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	ct2Enc, err := NewEncoder(make([]byte, 32), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:       StateCt1Sampled,
		epoch:      5,
		auth:       auth,
		ct2Encoder: ct2Enc,
	}

	_, _, err = state.Receive(&Message{Epoch: 5, Type: MessageTypeEk, Data: []byte("data")}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if state.kind != StateCt1Sampled {
		t.Errorf("expected to stay in Ct1Sampled, got %s", state.kind)
	}
}

func TestReceiveCt1SampledEkPartial(t *testing.T) {
	// Ek chunk received but ek_decoder not complete: stay in Ct1Sampled.
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	// Create a properly formatted wire chunk: varint(0) + 32 bytes.
	chunk := makeWireChunk(0)

	state := &State{
		kind:      StateCt1Sampled,
		epoch:     5,
		auth:      auth,
		chunkSize: DefaultChunkSize,
	}

	_, _, err = state.Receive(&Message{Epoch: 5, Type: MessageTypeEk, Data: chunk}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if state.kind != StateCt1Sampled {
		t.Errorf("expected to stay in Ct1Sampled, got %s", state.kind)
	}
}

func TestReceiveCt1SampledWrongType(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:  StateCt1Sampled,
		epoch: 5,
		auth:  auth,
	}

	_, _, err = state.Receive(&Message{Epoch: 5, Type: MessageTypeHdr}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for wrong message type")
	}
}

// --- receiveEkReceivedCt1Sampled ---

func TestReceiveEkReceivedCt1SampledNone(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:  StateEkReceivedCt1Sampled,
		epoch: 5,
		auth:  auth,
	}

	_, out, err := state.Receive(&Message{Epoch: 5, Type: MessageTypeNone}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Error("expected nil output")
	}
}

func TestReceiveEkReceivedCt1SampledCt1AckAlreadyComplete(t *testing.T) {
	// When ct2Encoder is set, Ct1Ack transitions directly to Ct2Sampled.
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	ct2Enc, err := NewEncoder(make([]byte, 32), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:       StateEkReceivedCt1Sampled,
		epoch:      5,
		auth:       auth,
		ct2Encoder: ct2Enc,
	}

	_, _, err = state.Receive(&Message{Epoch: 5, Type: MessageTypeCt1Ack}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if state.kind != StateCt2Sampled {
		t.Errorf("expected Ct2Sampled, got %s", state.kind)
	}
}

func TestReceiveEkReceivedCt1SampledCt1AckWithEkVector(t *testing.T) {
	// EkReceivedCt1Sampled with bobEkVector: Ct1Ack triggers full encapsulation.
	sharedKey := randomSecret(t)
	kemImpl := NewMLKEM768IncrementalKEM()

	_, ekSeed, ekVector, err := kemImpl.KeyGen()
	if err != nil {
		t.Fatal(err)
	}

	hek := computeHEK(ekSeed, ekVector)
	auth, err := NewAuthenticator(1, sharedKey)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:        StateEkReceivedCt1Sampled,
		epoch:       5,
		auth:        auth,
		bobEkSeed:   mustSecret(t, ekSeed),
		bobHek:      mustSecret(t, hek),
		bobEkVector: mustSecret(t, ekVector),
		chunkSize:   DefaultChunkSize,
	}

	_, outKey, err := state.Receive(&Message{Epoch: 5, Type: MessageTypeCt1Ack}, kemImpl, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if state.kind != StateCt2Sampled {
		t.Errorf("expected Ct2Sampled, got %s", state.kind)
	}
	if outKey == nil {
		t.Error("expected output key from encapsulation")
	}
}

func TestReceiveEkReceivedCt1SampledWrongType(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:  StateEkReceivedCt1Sampled,
		epoch: 5,
		auth:  auth,
	}

	_, _, err = state.Receive(&Message{Epoch: 5, Type: MessageTypeHdr}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for wrong message type")
	}
}

// --- receiveCt1Acknowledged ---

func TestReceiveCt1AcknowledgedNone(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:  StateCt1Acknowledged,
		epoch: 5,
		auth:  auth,
	}

	_, out, err := state.Receive(&Message{Epoch: 5, Type: MessageTypeNone}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Error("expected nil output")
	}
}

func TestReceiveCt1AcknowledgedEkPartial(t *testing.T) {
	// Ek chunk received but ek_decoder not yet complete: stay in Ct1Acknowledged.
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	// Create a properly formatted wire chunk: varint(0) + 32 bytes.
	chunk := makeWireChunk(0)

	state := &State{
		kind:      StateCt1Acknowledged,
		epoch:     5,
		auth:      auth,
		chunkSize: DefaultChunkSize,
	}

	_, out, err := state.Receive(&Message{Epoch: 5, Type: MessageTypeEk, Data: chunk}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Error("expected nil output for partial ek")
	}
	if state.kind != StateCt1Acknowledged {
		t.Errorf("expected to stay in Ct1Acknowledged, got %s", state.kind)
	}
}

func TestReceiveCt1AcknowledgedWrongType(t *testing.T) {
	// Wrong message type should return error.
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:      StateCt1Acknowledged,
		epoch:     5,
		auth:      auth,
		chunkSize: DefaultChunkSize,
	}

	_, _, err = state.Receive(&Message{Epoch: 5, Type: MessageTypeHdr}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for wrong message type")
	}
	if _, ok := err.(*ErrInvalidMessageType); !ok {
		t.Errorf("expected ErrInvalidMessageType, got %T: %v", err, err)
	}
}

// --- receiveCt2Sampled ---

func TestReceiveCt2SampledNone(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:  StateCt2Sampled,
		epoch: 5,
		auth:  auth,
	}

	_, out, err := state.Receive(&Message{Epoch: 5, Type: MessageTypeNone}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Error("expected nil output")
	}
}

func TestReceiveCt2SampledCt1Ack(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:  StateCt2Sampled,
		epoch: 5,
		auth:  auth,
	}

	_, out, err := state.Receive(&Message{Epoch: 5, Type: MessageTypeCt1Ack}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Error("expected nil output")
	}
}

func TestReceiveCt2SampledOther(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:  StateCt2Sampled,
		epoch: 5,
		auth:  auth,
	}

	_, out, err := state.Receive(&Message{Epoch: 5, Type: MessageTypeHdr, Data: []byte("data")}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Error("expected nil output")
	}
}

// --- receiveHeaderReceived ---

func TestReceiveHeaderReceivedNone(t *testing.T) {
	sharedKey := randomSecret(t)
	auth, err := NewAuthenticator(1, sharedKey)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:      StateHeaderReceived,
		epoch:     5,
		auth:      auth,
		bobEkSeed: mustEmptySecret(t, 32),
		bobHek:    mustEmptySecret(t, 32),
	}

	_, out, err := state.Receive(&Message{Epoch: 5, Type: MessageTypeNone}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Error("expected nil output")
	}
}

func TestReceiveHeaderReceivedWrongType(t *testing.T) {
	sharedKey := randomSecret(t)
	auth, err := NewAuthenticator(1, sharedKey)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:      StateHeaderReceived,
		epoch:     5,
		auth:      auth,
		bobEkSeed: mustEmptySecret(t, 32),
		bobHek:    mustEmptySecret(t, 32),
	}

	_, _, err = state.Receive(&Message{Epoch: 5, Type: MessageTypeCt1}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for wrong type")
	}
}

// --- receiveKeysSampled ---

func TestReceiveKeysSampledNone(t *testing.T) {
	sharedKey := randomSecret(t)
	auth, err := NewAuthenticator(1, sharedKey)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:     StateKeysSampled,
		epoch:    5,
		auth:     auth,
		ekVector: mustEmptySecret(t, 64),
	}

	_, out, err := state.Receive(&Message{Epoch: 5, Type: MessageTypeNone}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Error("expected nil output")
	}
}

func TestReceiveKeysSampledWrongType(t *testing.T) {
	sharedKey := randomSecret(t)
	auth, err := NewAuthenticator(1, sharedKey)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:     StateKeysSampled,
		epoch:    5,
		auth:     auth,
		ekVector: mustEmptySecret(t, 64),
	}

	_, _, err = state.Receive(&Message{Epoch: 5, Type: MessageTypeHdr}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for wrong type")
	}
}

func TestReceiveKeysSampledCt1(t *testing.T) {
	sharedKey := randomSecret(t)
	auth, err := NewAuthenticator(1, sharedKey)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:     StateKeysSampled,
		epoch:    5,
		auth:     auth,
		ekVector: mustEmptySecret(t, 64),
	}

	// Build a valid ct1 wire chunk: varint(0) + 32 bytes.
	ct1Chunk := makeWireChunk(0)

	_, _, err = state.Receive(&Message{Epoch: 5, Type: MessageTypeCt1, Data: ct1Chunk}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if state.ct1Decoder == nil {
		t.Error("ct1Decoder should be initialized")
	}
}

// --- Send invalid state ---

func TestSendInvalidState(t *testing.T) {
	state := &State{
		kind:  StateKind(99),
		epoch: 1,
	}

	_, _, _, err := state.Send(NewMLKEM768IncrementalKEM())
	if err == nil {
		t.Fatal("expected error for invalid state")
	}
}

// --- Wrapping encoder tests ---

func TestSendCt1SampledWraparound(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	// Create encoder and drain it.
	ct1Enc, err := NewEncoder(make([]byte, 32), 16)
	if err != nil {
		t.Fatal(err)
	}
	for ct1Enc.HasMore() {
		ct1Enc.NextChunk()
	}

	state := &State{
		kind:       StateCt1Sampled,
		epoch:      5,
		auth:       auth,
		ct1Encoder: ct1Enc,
	}

	msg, _, _, err := state.Send(NewMLKEM768IncrementalKEM())
	if err != nil {
		t.Fatal(err)
	}
	// Should wrap around.
	if msg.Type != MessageTypeCt1 {
		t.Errorf("expected Ct1, got %s", msg.Type)
	}
}

func TestSendCt2SampledWraparound(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	ct2Enc, err := NewEncoder(make([]byte, 32), 16)
	if err != nil {
		t.Fatal(err)
	}
	for ct2Enc.HasMore() {
		ct2Enc.NextChunk()
	}

	state := &State{
		kind:       StateCt2Sampled,
		epoch:      5,
		auth:       auth,
		ct2Encoder: ct2Enc,
	}

	msg, _, _, err := state.Send(NewMLKEM768IncrementalKEM())
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != MessageTypeCt2 {
		t.Errorf("expected Ct2, got %s", msg.Type)
	}
}

// --- EkReceivedCt1Sampled encoder wraparound ---

func TestSendEkReceivedCt1SampledWraparound(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	ct1Enc, err := NewEncoder(make([]byte, 32), 16)
	if err != nil {
		t.Fatal(err)
	}
	for ct1Enc.HasMore() {
		ct1Enc.NextChunk()
	}

	state := &State{
		kind:       StateEkReceivedCt1Sampled,
		epoch:      5,
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

// --- receiveCt1Received with Ct2 data ---

func TestReceiveCt1ReceivedCt2Partial(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:      StateCt1Received,
		epoch:     5,
		auth:      auth,
		chunkSize: DefaultChunkSize,
	}

	// Build a partial ct2 wire chunk: varint(0) + 32 bytes.
	partialChunk := makeWireChunk(0)

	_, out, err := state.Receive(&Message{Epoch: 5, Type: MessageTypeCt2, Data: partialChunk}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Error("expected nil output for partial ct2")
	}
	if state.kind != StateEkSentCt1Received {
		t.Errorf("expected EkSentCt1Received, got %s", state.kind)
	}
}

// --- bobCompleteEncapsulation error paths ---

func TestBobCompleteEncapsulationHekMismatch(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	kemImpl := NewMLKEM768IncrementalKEM()
	_, ekSeed, ekVector, err := kemImpl.KeyGen()
	if err != nil {
		t.Fatal(err)
	}

	// Use a large enough chunkSize so ek_vector fits in manageable chunks.
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
		kind:      StateHeaderReceived,
		epoch:     5,
		auth:      auth,
		bobEkSeed: mustSecret(t, ekSeed),
		bobHek:    mustEmptySecret(t, 32), // Wrong hek - all zeros.
		ekDecoder: ekDec,
		chunkSize: testChunkSize,
	}

	_, err = state.bobCompleteEncapsulation(kemImpl, testChunkSize)
	if err == nil {
		t.Fatal("expected error for hek mismatch")
	}
	if _, ok := err.(*ErrHeaderFormat); !ok {
		t.Errorf("expected ErrHeaderFormat, got %T: %v", err, err)
	}
}

// --- aliceCompleteCt2 error path: MAC verification failure ---

func TestAliceCompleteCt2BadMAC(t *testing.T) {
	secret := randomSecret(t)
	kemImpl := NewMLKEM768IncrementalKEM()

	dk, ekSeed, ekVector, err := kemImpl.KeyGen()
	if err != nil {
		t.Fatal(err)
	}

	ct1, ct2, _, err := kemImpl.FullEncaps(ekSeed, ekVector)
	if err != nil {
		t.Fatal(err)
	}

	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	// Create a ct2 decoder with bad MAC.
	badMAC := make([]byte, MacSize)
	ct2WithBadMAC := make([]byte, 0, len(ct2)+MacSize)
	ct2WithBadMAC = append(ct2WithBadMAC, ct2...)
	ct2WithBadMAC = append(ct2WithBadMAC, badMAC...)

	testChunkSize := 256
	ct2Enc, err := NewEncoder(ct2WithBadMAC, testChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	ct2Dec, err := NewDecoder(len(ct2WithBadMAC), testChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	for ct2Enc.HasMore() {
		if err := ct2Dec.AddChunk(ct2Enc.NextChunk()); err != nil {
			t.Fatal(err)
		}
	}

	state := &State{
		kind:        StateEkSentCt1Received,
		epoch:       5,
		auth:        auth,
		dk:          mustSecret(t, dk),
		receivedCt1: mustSecret(t, ct1),
		ct2Decoder:  ct2Dec,
		chunkSize:   testChunkSize,
	}

	_, _, err = state.aliceCompleteCt2(&Message{}, NewMLKEM768IncrementalKEM())
	if err == nil {
		t.Fatal("expected error for bad MAC")
	}
	if _, ok := err.(*ErrMACVerification); !ok {
		t.Errorf("expected ErrMACVerification, got %T: %v", err, err)
	}
}

// --- receiveNoHeaderReceived without decoder ---

func TestReceiveNoHeaderReceivedNoDecoder(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:          StateNoHeaderReceived,
		epoch:         5,
		auth:          auth,
		headerDecoder: nil, // No decoder.
	}

	_, _, err = state.Receive(&Message{Epoch: 5, Type: MessageTypeHdr, Data: []byte("data")}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for no header decoder")
	}
}

// --- HeaderReceived with EkCt1Ack ---

func TestReceiveHeaderReceivedEkCt1Ack(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:      StateHeaderReceived,
		epoch:     5,
		auth:      auth,
		bobEkSeed: mustEmptySecret(t, 32),
		bobHek:    mustEmptySecret(t, 32),
	}

	// EkCt1Ack should also be accepted. Build chunk with proper header.
	ekChunk := makeWireChunk(0)
	_, _, err = state.Receive(&Message{Epoch: 5, Type: MessageTypeEkCt1Ack, Data: ekChunk}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if !state.ct1Ack {
		t.Error("ct1Ack should be set")
	}
}
