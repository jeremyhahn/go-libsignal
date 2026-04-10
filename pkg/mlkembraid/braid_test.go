package mlkembraid

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

func randomSecret(t *testing.T) []byte {
	t.Helper()
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("failed to generate random secret: %v", err)
	}
	return buf
}

// --- InitAlice / InitBob ---

func TestInitAlice(t *testing.T) {
	secret := randomSecret(t)
	kemImpl := NewMLKEM768IncrementalKEM()

	alice, err := InitAlice(secret, kemImpl, DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice failed: %v", err)
	}

	if alice.StateKind() != StateKeysUnsampled {
		t.Errorf("expected state KeysUnsampled, got %s", alice.StateKind())
	}
	// Per spec Section 2.6: epoch=1 at initialization.
	if alice.Epoch() != 1 {
		t.Errorf("expected epoch 1, got %d", alice.Epoch())
	}
}

func TestInitAliceEmptySecret(t *testing.T) {
	_, err := InitAlice(nil, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for empty secret")
	}
	if _, ok := err.(*ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T: %v", err, err)
	}
}

func TestInitAliceNilKEM(t *testing.T) {
	_, err := InitAlice(randomSecret(t), nil, DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for nil KEM")
	}
}

func TestInitAliceInvalidChunkSize(t *testing.T) {
	_, err := InitAlice(randomSecret(t), NewMLKEM768IncrementalKEM(), 0)
	if err == nil {
		t.Fatal("expected error for zero chunk size")
	}
	if _, ok := err.(*ErrChunkSize); !ok {
		t.Errorf("expected ErrChunkSize, got %T: %v", err, err)
	}
}

func TestInitBob(t *testing.T) {
	secret := randomSecret(t)
	kemImpl := NewMLKEM768IncrementalKEM()

	bob, err := InitBob(secret, kemImpl, DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitBob failed: %v", err)
	}

	if bob.StateKind() != StateNoHeaderReceived {
		t.Errorf("expected state NoHeaderReceived, got %s", bob.StateKind())
	}
}

func TestInitBobEmptySecret(t *testing.T) {
	_, err := InitBob(nil, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for empty secret")
	}
}

func TestInitBobNilKEM(t *testing.T) {
	_, err := InitBob(randomSecret(t), nil, DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for nil KEM")
	}
}

func TestInitBobInvalidChunkSize(t *testing.T) {
	_, err := InitBob(randomSecret(t), NewMLKEM768IncrementalKEM(), -1)
	if err == nil {
		t.Fatal("expected error for negative chunk size")
	}
}

// --- Authenticator ---

func TestAuthenticatorInit(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatalf("NewAuthenticator failed: %v", err)
	}
	if auth.Epoch() != 1 {
		t.Errorf("expected epoch 1, got %d", auth.Epoch())
	}
}

func TestAuthenticatorEmptySecret(t *testing.T) {
	_, err := NewAuthenticator(1, nil)
	if err == nil {
		t.Fatal("expected error for nil secret")
	}

	_, err = NewAuthenticator(1, []byte{})
	if err == nil {
		t.Fatal("expected error for empty secret")
	}
}

func TestAuthenticatorUpdate(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	updateKey := randomSecret(t)
	if err := auth.Update(2, updateKey); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if auth.Epoch() != 2 {
		t.Errorf("expected epoch 2, got %d", auth.Epoch())
	}
}

func TestAuthenticatorUpdateEmptyKey(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	if err := auth.Update(2, nil); err == nil {
		t.Fatal("expected error for nil update key")
	}
}

func TestAuthenticatorMacHdrVerify(t *testing.T) {
	secret := randomSecret(t)
	auth1, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}
	auth2, err := auth1.Clone()
	if err != nil {
		t.Fatal(err)
	}

	header := []byte("test-header-data-with-ek-seed")
	mac, err := auth1.MacHdr(1, header)
	if err != nil {
		t.Fatalf("MacHdr failed: %v", err)
	}
	if len(mac) != MacSize {
		t.Errorf("MAC length = %d, want %d", len(mac), MacSize)
	}

	valid, err := auth2.VfyHdr(1, header, mac)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Error("header MAC should be valid")
	}

	// Tampered data should fail.
	valid, err = auth2.VfyHdr(1, []byte("tampered"), mac)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Error("tampered header MAC should be invalid")
	}
}

func TestAuthenticatorMacCtVerify(t *testing.T) {
	secret := randomSecret(t)
	auth1, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}
	auth2, err := auth1.Clone()
	if err != nil {
		t.Fatal(err)
	}

	ct := []byte("test-ciphertext-data")
	mac, err := auth1.MacCt(1, ct)
	if err != nil {
		t.Fatal(err)
	}

	valid, err := auth2.VfyCt(1, ct, mac)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Error("ciphertext MAC should be valid")
	}
}

func TestAuthenticatorMacWrongEpoch(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	_, err = auth.MacHdr(2, []byte("header"))
	if err == nil {
		t.Fatal("expected error for wrong epoch")
	}
	if _, ok := err.(*ErrInvalidEpoch); !ok {
		t.Errorf("expected ErrInvalidEpoch, got %T", err)
	}

	_, err = auth.MacCt(0, []byte("ct"))
	if err == nil {
		t.Fatal("expected error for wrong epoch")
	}
}

func TestAuthenticatorCloneIndependence(t *testing.T) {
	secret := randomSecret(t)
	auth1, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	auth2, err := auth1.Clone()
	if err != nil {
		t.Fatal(err)
	}

	if err := auth1.Update(2, randomSecret(t)); err != nil {
		t.Fatal(err)
	}

	if auth1.Epoch() != 2 {
		t.Errorf("auth1 epoch = %d, want 2", auth1.Epoch())
	}
	if auth2.Epoch() != 1 {
		t.Errorf("auth2 epoch = %d, want 1", auth2.Epoch())
	}
}

func TestAuthenticatorRejectsWrongEpoch(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	_, err = auth.MacHdr(5, []byte("header"))
	if err == nil {
		t.Fatal("expected error for epoch mismatch")
	}
}

// --- KDFOK ---

func TestKDFOKDeterministic(t *testing.T) {
	ss := make([]byte, 32)
	for i := range ss {
		ss[i] = byte(i)
	}

	key1, err := KDFOK(ss, 1)
	if err != nil {
		t.Fatal(err)
	}

	key2, err := KDFOK(ss, 1)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(key1, key2) {
		t.Error("KDF_OK should be deterministic for same inputs")
	}
	if len(key1) != 32 {
		t.Errorf("output key length = %d, want 32", len(key1))
	}
}

func TestKDFOKDifferentEpochs(t *testing.T) {
	ss := randomSecret(t)

	key1, err := KDFOK(ss, 1)
	if err != nil {
		t.Fatal(err)
	}

	key2, err := KDFOK(ss, 2)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(key1, key2) {
		t.Error("different epochs should produce different keys")
	}
}

// --- KEM Interface ---

func TestMLKEM768IncrementalKEMKeyGen(t *testing.T) {
	kemImpl := NewMLKEM768IncrementalKEM()

	dk, ekSeed, ekVector, err := kemImpl.KeyGen()
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	if len(dk) == 0 {
		t.Error("dk should not be empty")
	}
	if len(ekSeed) != EKSeedSize {
		t.Errorf("ekSeed length = %d, want %d", len(ekSeed), EKSeedSize)
	}
	if len(ekVector) != MLKEM768EKSize {
		t.Errorf("ekVector length = %d, want %d", len(ekVector), MLKEM768EKSize)
	}
}

func TestMLKEM768IncrementalKEMFullEncapsDecaps(t *testing.T) {
	kemImpl := NewMLKEM768IncrementalKEM()

	dk, ekSeed, ekVector, err := kemImpl.KeyGen()
	if err != nil {
		t.Fatal(err)
	}

	ct1, ct2, ssEncaps, err := kemImpl.FullEncaps(ekSeed, ekVector)
	if err != nil {
		t.Fatalf("FullEncaps failed: %v", err)
	}

	if len(ct1) != MLKEM768CT1Size {
		t.Errorf("ct1 length = %d, want %d", len(ct1), MLKEM768CT1Size)
	}
	if len(ct2) != MLKEM768CT2Size {
		t.Errorf("ct2 length = %d, want %d", len(ct2), MLKEM768CT2Size)
	}
	if len(ssEncaps) != 32 {
		t.Errorf("shared secret length = %d, want 32", len(ssEncaps))
	}

	ssDecaps, err := kemImpl.Decaps(dk, ct1, ct2)
	if err != nil {
		t.Fatalf("Decaps failed: %v", err)
	}

	if !bytes.Equal(ssEncaps, ssDecaps) {
		t.Error("encaps and decaps shared secrets should match")
	}
}

func TestMLKEM768IncrementalKEMDecapsInvalidInput(t *testing.T) {
	kemImpl := NewMLKEM768IncrementalKEM()

	_, err := kemImpl.Decaps(nil, make([]byte, MLKEM768CT1Size), make([]byte, MLKEM768CT2Size))
	if err == nil {
		t.Fatal("expected error for nil dk")
	}

	_, err = kemImpl.Decaps([]byte("dk"), make([]byte, 10), make([]byte, MLKEM768CT2Size))
	if err == nil {
		t.Fatal("expected error for wrong ct1 size")
	}

	_, err = kemImpl.Decaps([]byte("dk"), make([]byte, MLKEM768CT1Size), make([]byte, 10))
	if err == nil {
		t.Fatal("expected error for wrong ct2 size")
	}
}

func TestMLKEM768IncrementalKEMFullEncapsInvalidInput(t *testing.T) {
	kemImpl := NewMLKEM768IncrementalKEM()

	_, _, _, err := kemImpl.FullEncaps(nil, []byte("vector"))
	if err == nil {
		t.Fatal("expected error for nil ekSeed")
	}

	_, _, _, err = kemImpl.FullEncaps(make([]byte, EKSeedSize), nil)
	if err == nil {
		t.Fatal("expected error for nil ekVector")
	}
}

func TestMLKEM768IncrementalKEMSizes(t *testing.T) {
	kemImpl := NewMLKEM768IncrementalKEM()

	if kemImpl.EKSize() != MLKEM768EKSize {
		t.Errorf("EKSize() = %d, want %d", kemImpl.EKSize(), MLKEM768EKSize)
	}
	if kemImpl.CT1Size() != MLKEM768CT1Size {
		t.Errorf("CT1Size() = %d, want %d", kemImpl.CT1Size(), MLKEM768CT1Size)
	}
	if kemImpl.CT2Size() != MLKEM768CT2Size {
		t.Errorf("CT2Size() = %d, want %d", kemImpl.CT2Size(), MLKEM768CT2Size)
	}
	if kemImpl.HeaderSize() != HeaderSize {
		t.Errorf("HeaderSize() = %d, want %d", kemImpl.HeaderSize(), HeaderSize)
	}
}

// --- Header ---

func TestHeaderFormat(t *testing.T) {
	kemImpl := NewMLKEM768IncrementalKEM()
	_, ekSeed, ekVector, err := kemImpl.KeyGen()
	if err != nil {
		t.Fatal(err)
	}

	header := Header(ekSeed, ekVector)
	if len(header) != HeaderSize {
		t.Fatalf("header length = %d, want %d", len(header), HeaderSize)
	}

	// First 32 bytes should be ek_seed.
	if !bytes.Equal(header[:EKSeedSize], ekSeed) {
		t.Error("header first 32 bytes should be ek_seed")
	}

	// Last 32 bytes should be SHA3-256(ek_seed || ek_vector).
	hek := computeHEK(ekSeed, ekVector)
	if !bytes.Equal(header[EKSeedSize:], hek) {
		t.Error("header last 32 bytes should be SHA3-256(ek_seed||ek_vector)")
	}
}

// --- Message Types ---

func TestMessageTypeStrings(t *testing.T) {
	tests := []struct {
		mt   MessageType
		want string
	}{
		{MessageTypeNone, "None"},
		{MessageTypeHdr, "Hdr"},
		{MessageTypeEk, "Ek"},
		{MessageTypeEkCt1Ack, "EkCt1Ack"},
		{MessageTypeCt1Ack, "Ct1Ack"},
		{MessageTypeCt1, "Ct1"},
		{MessageTypeCt2, "Ct2"},
		{MessageType(99), "Unknown(99)"},
	}

	for _, tt := range tests {
		if got := tt.mt.String(); got != tt.want {
			t.Errorf("%d.String() = %q, want %q", tt.mt, got, tt.want)
		}
	}
}

// --- State Kind ---

func TestStateKindStrings(t *testing.T) {
	tests := []struct {
		sk   StateKind
		want string
	}{
		{StateKeysUnsampled, "KeysUnsampled"},
		{StateKeysSampled, "KeysSampled"},
		{StateHeaderSent, "HeaderSent"},
		{StateCt1Received, "Ct1Received"},
		{StateEkSentCt1Received, "EkSentCt1Received"},
		{StateNoHeaderReceived, "NoHeaderReceived"},
		{StateHeaderReceived, "HeaderReceived"},
		{StateCt1Sampled, "Ct1Sampled"},
		{StateEkReceivedCt1Sampled, "EkReceivedCt1Sampled"},
		{StateCt1Acknowledged, "Ct1Acknowledged"},
		{StateCt2Sampled, "Ct2Sampled"},
		{StateKind(99), "Unknown(99)"},
	}

	for _, tt := range tests {
		if got := tt.sk.String(); got != tt.want {
			t.Errorf("%d.String() = %q, want %q", tt.sk, got, tt.want)
		}
	}
}

// --- Error Types ---

func TestErrorTypes(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"ErrInvalidState", &ErrInvalidState{Current: StateKeysUnsampled, Expected: StateHeaderSent, Op: "Send"}},
		{"ErrInvalidEpoch", &ErrInvalidEpoch{Expected: 5, Received: 3}},
		{"ErrInvalidMessageType", &ErrInvalidMessageType{Expected: MessageTypeCt1, Received: MessageTypeNone}},
		{"ErrMACVerification", &ErrMACVerification{Epoch: 10, Kind: "ct1"}},
		{"ErrDecoderIncomplete", &ErrDecoderIncomplete{Received: 1, Required: 3}},
		{"ErrKEMOperation", &ErrKEMOperation{Op: "Generate", Err: &ErrInvalidInput{Field: "x", Reason: "y"}}},
		{"ErrInvalidInput", &ErrInvalidInput{Field: "data", Reason: "empty"}},
		{"ErrChunkSize", &ErrChunkSize{Size: -1, Reason: "must be positive"}},
		{"ErrHeaderFormat", &ErrHeaderFormat{Reason: "bad hek"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.err.Error()
			if s == "" {
				t.Error("error string should not be empty")
			}
		})
	}

	// Test Unwrap on ErrKEMOperation.
	inner := &ErrInvalidInput{Field: "test", Reason: "inner"}
	kemErr := &ErrKEMOperation{Op: "test", Err: inner}
	if kemErr.Unwrap() != inner {
		t.Error("Unwrap should return inner error")
	}
}

// --- Receive edge cases ---

func TestBraidReceiveNilMessage(t *testing.T) {
	secret := randomSecret(t)
	bob, err := InitBob(secret, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = bob.Receive(nil)
	if err == nil {
		t.Fatal("expected error for nil message")
	}
	if _, ok := err.(*ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestBraidReceiveReplayedEpoch(t *testing.T) {
	secret := randomSecret(t)
	bob, err := InitBob(secret, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	// Send a message at epoch 2 (one ahead of Bob's epoch 1, valid).
	_, _, err = bob.Receive(&Message{Epoch: 2, Type: MessageTypeNone})
	if err != nil {
		t.Fatal(err)
	}

	// Replay at epoch 1 should fail (behind lastReceivedEpoch=2).
	_, _, err = bob.Receive(&Message{Epoch: 1, Type: MessageTypeNone})
	if err == nil {
		t.Fatal("expected error for replayed epoch")
	}
	if _, ok := err.(*ErrInvalidEpoch); !ok {
		t.Errorf("expected ErrInvalidEpoch, got %T", err)
	}
}

func TestBraidReceiveKeysUnsampledIgnoresMessages(t *testing.T) {
	secret := randomSecret(t)
	alice, err := InitAlice(secret, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	// Per spec: KeysUnsampled.Receive ignores all messages (no-op).
	_, outputKey, err := alice.Receive(&Message{Epoch: 1, Type: MessageTypeNone})
	if err != nil {
		t.Fatalf("expected no error for receive in KeysUnsampled state, got: %v", err)
	}
	if outputKey != nil {
		t.Error("expected nil output key for KeysUnsampled receive")
	}
}

// --- Zeroize ---

func TestBraidZeroize(t *testing.T) {
	secret := randomSecret(t)
	alice, err := InitAlice(secret, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	alice.Zeroize() // Should not panic.
}

// --- Protocol Exchange Helpers ---

func newAliceBob(t *testing.T) (*Braid, *Braid) {
	t.Helper()
	secret := randomSecret(t)
	kemImpl := NewMLKEM768IncrementalKEM()

	alice, err := InitAlice(secret, kemImpl, DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}

	bob, err := InitBob(secret, kemImpl, DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitBob: %v", err)
	}

	return alice, bob
}

// runProtocol drives Alice and Bob through message exchange until both
// produce an output key or maxRounds is exceeded.
func runProtocol(t *testing.T, alice, bob *Braid, maxRounds int) (aliceKey, bobKey *OutputKey) {
	t.Helper()

	for round := 0; round < maxRounds; round++ {
		// Alice sends.
		msgA, _, outA, err := alice.Send()
		if err != nil {
			t.Fatalf("round %d: Alice.Send: %v", round, err)
		}
		if outA != nil && aliceKey == nil {
			aliceKey = outA
		}

		// Bob receives Alice's message.
		_, outBRecv, err := bob.Receive(msgA)
		if err != nil {
			t.Fatalf("round %d: Bob.Receive(Alice): %v", round, err)
		}
		if outBRecv != nil && bobKey == nil {
			bobKey = outBRecv
		}

		// Bob sends.
		msgB, _, outB, err := bob.Send()
		if err != nil {
			t.Fatalf("round %d: Bob.Send: %v", round, err)
		}
		if outB != nil && bobKey == nil {
			bobKey = outB
		}

		// Alice receives Bob's message.
		_, outARecv, err := alice.Receive(msgB)
		if err != nil {
			t.Fatalf("round %d: Alice.Receive(Bob): %v", round, err)
		}
		if outARecv != nil && aliceKey == nil {
			aliceKey = outARecv
		}

		if aliceKey != nil && bobKey != nil {
			return aliceKey, bobKey
		}
	}

	return aliceKey, bobKey
}

// --- Full Protocol Tests ---

func TestFullEpochExchange(t *testing.T) {
	alice, bob := newAliceBob(t)

	aliceKey, bobKey := runProtocol(t, alice, bob, 200)

	if aliceKey == nil {
		t.Fatal("Alice did not produce an output key")
	}
	if bobKey == nil {
		t.Fatal("Bob did not produce an output key")
	}

	t.Logf("Alice key epoch=%d, Bob key epoch=%d", aliceKey.Epoch, bobKey.Epoch)
	t.Logf("Alice state=%s, Bob state=%s", alice.StateKind(), bob.StateKind())
}

func TestFullEpochExchangeKeysMatch(t *testing.T) {
	alice, bob := newAliceBob(t)

	aliceKey, bobKey := runProtocol(t, alice, bob, 200)

	if aliceKey == nil || bobKey == nil {
		t.Fatal("both parties should produce output keys")
	}

	if !bytes.Equal(aliceKey.Key.Bytes(), bobKey.Key.Bytes()) {
		t.Errorf("output keys do not match:\n  Alice: %x\n  Bob:   %x", aliceKey.Key.Bytes(), bobKey.Key.Bytes())
	}

	if aliceKey.Epoch != bobKey.Epoch {
		t.Errorf("output key epochs do not match: Alice=%d, Bob=%d", aliceKey.Epoch, bobKey.Epoch)
	}
}

func TestEpochStartsAtOne(t *testing.T) {
	alice, bob := newAliceBob(t)

	aliceKey, bobKey := runProtocol(t, alice, bob, 200)

	if aliceKey == nil || bobKey == nil {
		t.Fatal("both parties should produce output keys")
	}

	if aliceKey.Epoch != 1 {
		t.Errorf("first output key epoch should be 1, got %d", aliceKey.Epoch)
	}
}

// --- State transition verification ---

func TestAliceStateTransitions(t *testing.T) {
	alice, bob := newAliceBob(t)

	// Alice starts in KeysUnsampled.
	if alice.StateKind() != StateKeysUnsampled {
		t.Fatalf("expected KeysUnsampled, got %s", alice.StateKind())
	}

	// Alice sends first message -> KeysSampled.
	msg, _, _, err := alice.Send()
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != MessageTypeHdr {
		t.Errorf("expected Hdr message, got %s", msg.Type)
	}
	if alice.StateKind() != StateKeysSampled {
		t.Errorf("expected KeysSampled after first send, got %s", alice.StateKind())
	}

	// Deliver to Bob.
	_, _, err = bob.Receive(msg)
	if err != nil {
		t.Fatal(err)
	}
}

func TestBobStateTransitions(t *testing.T) {
	_, bob := newAliceBob(t)

	// Bob starts in NoHeaderReceived.
	if bob.StateKind() != StateNoHeaderReceived {
		t.Fatalf("expected NoHeaderReceived, got %s", bob.StateKind())
	}

	// Bob sends None initially.
	msg, _, _, err := bob.Send()
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != MessageTypeNone {
		t.Errorf("expected None message, got %s", msg.Type)
	}
}

// --- Decoder/Encoder ---

func TestDecoderAddChunkAfterComplete(t *testing.T) {
	// 10 bytes -> ceil(10/32) = 1 chunk
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

	// Adding another valid chunk (duplicate of index 0) should be silently ignored.
	dupChunk := enc.NextChunk() // wraps around to index 0
	if err := dec.AddChunk(dupChunk); err != nil {
		t.Fatal(err)
	}
	if dec.ReceivedCount() != 1 {
		t.Errorf("received count should still be 1, got %d", dec.ReceivedCount())
	}
}

func TestDecoderAddChunkTruncation(t *testing.T) {
	// 3 bytes data -> 1 chunk (32 bytes, zero-padded)
	dec, err := NewDecoder(3, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	// Build a valid wire chunk: varint(0) + 32 bytes with "123" + zero padding.
	chunk := make([]byte, 1+ChunkDataSize)
	chunk[0] = 0 // varint(0)
	chunk[1] = '1'
	chunk[2] = '2'
	chunk[3] = '3'
	if err := dec.AddChunk(chunk); err != nil {
		t.Fatal(err)
	}

	if !dec.HasMessage() {
		t.Fatal("decoder should be complete after single chunk")
	}

	msg, err := dec.Message()
	if err != nil {
		t.Fatal(err)
	}
	if string(msg) != "123" {
		t.Errorf("message = %q, want %q", msg, "123")
	}
}

func TestDecoderInvalidInputs(t *testing.T) {
	_, err := NewDecoder(0, 5)
	if err == nil {
		t.Fatal("expected error for zero expectedSize")
	}
	if _, ok := err.(*ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}

	_, err = NewDecoder(-1, 5)
	if err == nil {
		t.Fatal("expected error for negative expectedSize")
	}

	// chunkSize is now ignored (Rust uses fixed 32-byte chunks),
	// so any value is accepted. Test that zero chunkSize is fine.
	_, err = NewDecoder(10, 0)
	if err != nil {
		t.Fatalf("unexpected error for zero chunkSize (should be ignored): %v", err)
	}
}

func TestDecoderMessageBeforeComplete(t *testing.T) {
	// 64 bytes data -> 2 chunks
	dec, err := NewDecoder(64, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	// Add one valid wire chunk: varint(0) + 32 zero bytes.
	chunk := make([]byte, 1+ChunkDataSize)
	if err := dec.AddChunk(chunk); err != nil {
		t.Fatal(err)
	}

	_, err = dec.Message()
	if err == nil {
		t.Fatal("expected error for incomplete decoder")
	}
	if _, ok := err.(*ErrDecoderIncomplete); !ok {
		t.Errorf("expected ErrDecoderIncomplete, got %T", err)
	}
}

func TestEncoderInvalidInputs(t *testing.T) {
	_, err := NewEncoder(nil, 5)
	if err == nil {
		t.Fatal("expected error for nil data")
	}
	if _, ok := err.(*ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}

	// chunkSize is now ignored (Rust uses fixed 32-byte chunks),
	// so any value is accepted. Test that zero chunkSize is fine.
	_, err = NewEncoder([]byte("data"), 0)
	if err != nil {
		t.Fatalf("unexpected error for zero chunkSize (should be ignored): %v", err)
	}
}

func TestEncoderRoundTrip(t *testing.T) {
	data := []byte("hello world, this is test data!")
	enc, err := NewEncoder(data, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	dec, err := NewDecoder(len(data), DefaultChunkSize)
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

	result, err := dec.Message()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, data) {
		t.Errorf("round trip failed: got %q, want %q", result, data)
	}
}

func TestEncoderTotalChunks(t *testing.T) {
	// 64 bytes -> ceil(64/32) = 2 chunks
	enc, err := NewEncoder(make([]byte, 64), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if enc.TotalChunks() != 2 {
		t.Errorf("TotalChunks() = %d, want 2", enc.TotalChunks())
	}
}

func TestDecoderTotalChunksAndReset(t *testing.T) {
	// chunkSize=5, payload=3, 15 bytes -> ceil(15/3) = 5 chunks
	// 64 bytes -> 2 chunks of 32 bytes each
	dec, err := NewDecoder(64, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if dec.TotalChunks() != 2 {
		t.Errorf("TotalChunks() = %d, want 2", dec.TotalChunks())
	}

	// Add a properly formatted wire chunk: varint(0) + 32 zero bytes.
	chunk := make([]byte, 1+ChunkDataSize)
	if err := dec.AddChunk(chunk); err != nil {
		t.Fatal(err)
	}
	dec.Reset()
	if dec.ReceivedCount() != 0 {
		t.Errorf("after reset, ReceivedCount() = %d, want 0", dec.ReceivedCount())
	}
}

func TestEncoderReset(t *testing.T) {
	// 64 bytes -> 2 chunks
	enc, err := NewEncoder(make([]byte, 64), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	enc.NextChunk()
	enc.Reset()
	if !enc.HasMore() {
		t.Error("after reset, encoder should have more")
	}
}

// --- Encaps1/Encaps2 ---

func TestEncaps1Stores(t *testing.T) {
	kemImpl := NewMLKEM768IncrementalKEM()
	_, ekSeed, ekVector, err := kemImpl.KeyGen()
	if err != nil {
		t.Fatal(err)
	}

	hek := computeHEK(ekSeed, ekVector)
	encapsSecret, ct1, ss, err := kemImpl.Encaps1(ekSeed, hek)
	if err != nil {
		t.Fatal(err)
	}

	// Encaps1 returns placeholder values.
	if encapsSecret == nil {
		t.Fatal("encapsSecret should not be nil")
	}
	if ct1 != nil {
		t.Error("ct1 should be nil from Encaps1 (deferred)")
	}
	if ss != nil {
		t.Error("ss should be nil from Encaps1 (deferred)")
	}
}

func TestEncaps1InvalidInput(t *testing.T) {
	kemImpl := NewMLKEM768IncrementalKEM()

	_, _, _, err := kemImpl.Encaps1(nil, make([]byte, 32))
	if err == nil {
		t.Fatal("expected error for nil ekSeed")
	}

	_, _, _, err = kemImpl.Encaps1(make([]byte, EKSeedSize), nil)
	if err == nil {
		t.Fatal("expected error for nil hek")
	}
}

func TestEncaps2ReturnsError(t *testing.T) {
	kemImpl := NewMLKEM768IncrementalKEM()
	_, err := kemImpl.Encaps2(nil, nil, nil)
	if err == nil {
		t.Fatal("expected error from Encaps2")
	}
}

// --- State Zeroize ---

func TestStateZeroize(t *testing.T) {
	sharedKey := randomSecret(t)
	auth, _ := NewAuthenticator(1, sharedKey)
	dk, _ := secret.NewEmpty(32)
	ekSeedSec, _ := secret.NewEmpty(32)
	bobSSSec, _ := secret.NewEmpty(32)
	state := &State{
		kind:   StateKeysUnsampled,
		epoch:  1,
		auth:   auth,
		dk:     dk,
		ekSeed: ekSeedSec,
		bobSS:  bobSSSec,
	}
	state.Zeroize() // Should not panic.
}

func TestStateKindAndEpochAccessors(t *testing.T) {
	secret := randomSecret(t)
	auth, _ := NewAuthenticator(1, secret)
	state := &State{
		kind:  StateKeysSampled,
		epoch: 42,
		auth:  auth,
	}
	if state.Kind() != StateKeysSampled {
		t.Error("Kind() mismatch")
	}
	if state.Epoch() != 42 {
		t.Error("Epoch() mismatch")
	}
}

// --- MAC Tamper Test ---

func TestMACTamperRejection(t *testing.T) {
	secret := randomSecret(t)
	auth, err := NewAuthenticator(1, secret)
	if err != nil {
		t.Fatal(err)
	}

	header := []byte("valid-header-content-here")
	mac, err := auth.MacHdr(1, header)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with MAC.
	tamperedMAC := make([]byte, len(mac))
	copy(tamperedMAC, mac)
	tamperedMAC[0] ^= 0xFF

	auth2, err := auth.Clone()
	if err != nil {
		t.Fatal(err)
	}
	valid, err := auth2.VfyHdr(1, header, tamperedMAC)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Error("tampered MAC should not verify")
	}
}

// ============================================================================
// Two-phase incremental encapsulation (Encaps1/CompleteEncaps2) tests
// ============================================================================

func TestCompleteEncaps2RoundTrip(t *testing.T) {
	kemImpl := NewMLKEM768IncrementalKEM()

	dk, ekSeed, ekVector, err := kemImpl.KeyGen()
	if err != nil {
		t.Fatal(err)
	}

	hek := computeHEK(ekSeed, ekVector)

	// Phase 1: Encaps1 stores ek_seed and hek.
	encapsSecret, ct1, ss, err := kemImpl.Encaps1(ekSeed, hek)
	if err != nil {
		t.Fatalf("Encaps1 failed: %v", err)
	}
	if encapsSecret == nil {
		t.Fatal("encapsSecret must not be nil")
	}
	if ct1 != nil {
		t.Error("ct1 should be nil from Encaps1 (deferred)")
	}
	if ss != nil {
		t.Error("ss should be nil from Encaps1 (deferred)")
	}

	// Phase 2: CompleteEncaps2 performs the actual encapsulation.
	ct1, ct2, ssEncaps, err := kemImpl.CompleteEncaps2(encapsSecret, ekSeed, ekVector)
	if err != nil {
		t.Fatalf("CompleteEncaps2 failed: %v", err)
	}

	if len(ct1) != MLKEM768CT1Size {
		t.Errorf("ct1 length = %d, want %d", len(ct1), MLKEM768CT1Size)
	}
	if len(ct2) != MLKEM768CT2Size {
		t.Errorf("ct2 length = %d, want %d", len(ct2), MLKEM768CT2Size)
	}
	if len(ssEncaps) != 32 {
		t.Errorf("shared secret length = %d, want 32", len(ssEncaps))
	}

	// Decapsulate and verify shared secrets match.
	ssDecaps, err := kemImpl.Decaps(dk, ct1, ct2)
	if err != nil {
		t.Fatalf("Decaps failed: %v", err)
	}

	if !bytes.Equal(ssEncaps, ssDecaps) {
		t.Error("encaps and decaps shared secrets should match")
	}
}

func TestCompleteEncaps2HekMismatch(t *testing.T) {
	kemImpl := NewMLKEM768IncrementalKEM()

	_, ekSeed, ekVector, err := kemImpl.KeyGen()
	if err != nil {
		t.Fatal(err)
	}

	// Create encapsSecret with wrong hek (all zeros).
	badEncapsSecret := make([]byte, EKSeedSize+32)
	copy(badEncapsSecret[:EKSeedSize], ekSeed)
	// hek portion left as zeros.

	_, _, _, err = kemImpl.CompleteEncaps2(badEncapsSecret, ekSeed, ekVector)
	if err == nil {
		t.Fatal("expected error for hek mismatch")
	}
	if _, ok := err.(*ErrHeaderFormat); !ok {
		t.Errorf("expected ErrHeaderFormat, got %T: %v", err, err)
	}
}

func TestCompleteEncaps2InvalidEncapsSecret(t *testing.T) {
	kemImpl := NewMLKEM768IncrementalKEM()

	_, _, _, err := kemImpl.CompleteEncaps2(nil, make([]byte, EKSeedSize), []byte("vector"))
	if err == nil {
		t.Fatal("expected error for nil encapsSecret")
	}

	_, _, _, err = kemImpl.CompleteEncaps2(make([]byte, 10), make([]byte, EKSeedSize), []byte("vector"))
	if err == nil {
		t.Fatal("expected error for wrong encapsSecret size")
	}
}

func TestCompleteEncaps2InvalidEkSeed(t *testing.T) {
	kemImpl := NewMLKEM768IncrementalKEM()

	_, _, _, err := kemImpl.CompleteEncaps2(make([]byte, EKSeedSize+32), nil, []byte("vector"))
	if err == nil {
		t.Fatal("expected error for nil ekSeed")
	}
}

func TestCompleteEncaps2EmptyEkVector(t *testing.T) {
	kemImpl := NewMLKEM768IncrementalKEM()

	_, _, _, err := kemImpl.CompleteEncaps2(make([]byte, EKSeedSize+32), make([]byte, EKSeedSize), nil)
	if err == nil {
		t.Fatal("expected error for nil ekVector")
	}
}

func TestEncaps2ValidRoundTrip(t *testing.T) {
	kemImpl := NewMLKEM768IncrementalKEM()

	dk, ekSeed, ekVector, err := kemImpl.KeyGen()
	if err != nil {
		t.Fatal(err)
	}

	hek := computeHEK(ekSeed, ekVector)
	encapsSecret, _, _, err := kemImpl.Encaps1(ekSeed, hek)
	if err != nil {
		t.Fatal(err)
	}

	// Encaps2 (interface method) returns only ct2.
	ct2, err := kemImpl.Encaps2(encapsSecret, ekSeed, ekVector)
	if err != nil {
		t.Fatalf("Encaps2 failed: %v", err)
	}
	if len(ct2) != MLKEM768CT2Size {
		t.Errorf("ct2 length = %d, want %d", len(ct2), MLKEM768CT2Size)
	}

	// We cannot do a full decaps roundtrip with just ct2 since Encaps2
	// only returns ct2 per the interface. Use CompleteEncaps2 for full roundtrip.
	_ = dk
}

func TestEncaps2InvalidInputs(t *testing.T) {
	kemImpl := NewMLKEM768IncrementalKEM()

	// Wrong encapsSecret size.
	_, err := kemImpl.Encaps2(make([]byte, 10), make([]byte, EKSeedSize), []byte("vector"))
	if err == nil {
		t.Fatal("expected error for wrong encapsSecret size")
	}

	// Wrong ekSeed size.
	_, err = kemImpl.Encaps2(make([]byte, EKSeedSize+32), nil, []byte("vector"))
	if err == nil {
		t.Fatal("expected error for nil ekSeed")
	}

	// Empty ekVector.
	_, err = kemImpl.Encaps2(make([]byte, EKSeedSize+32), make([]byte, EKSeedSize), nil)
	if err == nil {
		t.Fatal("expected error for nil ekVector")
	}

	// hek mismatch.
	_, ekSeed, ekVector, err := kemImpl.KeyGen()
	if err != nil {
		t.Fatal(err)
	}
	badSecret := make([]byte, EKSeedSize+32)
	copy(badSecret[:EKSeedSize], ekSeed)
	_, err = kemImpl.Encaps2(badSecret, ekSeed, ekVector)
	if err == nil {
		t.Fatal("expected error for hek mismatch")
	}
}

func TestSendHeaderReceivedCallsEncaps1(t *testing.T) {
	kemImpl := NewMLKEM768IncrementalKEM()
	sharedKey := randomSecret(t)
	auth, err := NewAuthenticator(1, sharedKey)
	if err != nil {
		t.Fatal(err)
	}

	_, ekSeed, ekVector, err := kemImpl.KeyGen()
	if err != nil {
		t.Fatal(err)
	}
	hek := computeHEK(ekSeed, ekVector)

	bobEkSeedSec, err := secret.New(ekSeed)
	if err != nil {
		t.Fatal(err)
	}
	bobHekSec, err := secret.New(hek)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:      StateHeaderReceived,
		epoch:     1,
		auth:      auth,
		bobEkSeed: bobEkSeedSec,
		bobHek:    bobHekSec,
		chunkSize: DefaultChunkSize,
	}

	// First Send in HeaderReceived should call Encaps1.
	msg, _, _, err := state.Send(kemImpl)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != MessageTypeNone {
		t.Errorf("expected None, got %s", msg.Type)
	}
	if state.bobEncapSecret == nil {
		t.Fatal("bobEncapSecret should be set after first Send in HeaderReceived")
	}
	if state.bobEncapSecret.Size() != EKSeedSize+32 {
		t.Errorf("bobEncapSecret size = %d, want %d", state.bobEncapSecret.Size(), EKSeedSize+32)
	}

	// Second Send should be idempotent (encapsSecret already set).
	prevSecret := make([]byte, state.bobEncapSecret.Size())
	copy(prevSecret, state.bobEncapSecret.Bytes())

	_, _, _, err = state.Send(kemImpl)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(state.bobEncapSecret.Bytes(), prevSecret) {
		t.Error("bobEncapSecret should not change on subsequent Sends")
	}
}

func TestTwoPhaseEncapsViaProtocol(t *testing.T) {
	// Full protocol exchange verifies two-phase encapsulation works end-to-end.
	// After sendHeaderReceived calls Encaps1, and receiveHeaderReceived calls
	// CompleteEncaps2 via bobCompleteEncapsulation, the resulting keys must match.
	alice, bob := newAliceBob(t)

	aliceKey, bobKey := runProtocol(t, alice, bob, 200)

	if aliceKey == nil || bobKey == nil {
		t.Fatal("both parties should produce output keys")
	}
	if !bytes.Equal(aliceKey.Key.Bytes(), bobKey.Key.Bytes()) {
		t.Error("output keys should match with two-phase encapsulation")
	}
	if aliceKey.Epoch != bobKey.Epoch {
		t.Errorf("epochs should match: alice=%d, bob=%d", aliceKey.Epoch, bobKey.Epoch)
	}
}

func TestBobEncapSecretZeroizedAfterCompletion(t *testing.T) {
	// Verify that bobEncapSecret is properly zeroized after encapsulation completes.
	kemImpl := NewMLKEM768IncrementalKEM()
	secret := randomSecret(t)

	alice, err := InitAlice(secret, kemImpl, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := InitBob(secret, kemImpl, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	var bobHadEncapSecret bool

	for round := 0; round < 200; round++ {
		msgA, _, _, err := alice.Send()
		if err != nil {
			t.Fatalf("round %d: Alice.Send: %v", round, err)
		}
		_, _, err = bob.Receive(msgA)
		if err != nil {
			t.Fatalf("round %d: Bob.Receive: %v", round, err)
		}

		// Check if Bob has entered the Encaps1 phase.
		if bob.state.bobEncapSecret != nil {
			bobHadEncapSecret = true
		}

		msgB, _, _, err := bob.Send()
		if err != nil {
			t.Fatalf("round %d: Bob.Send: %v", round, err)
		}
		_, _, err = alice.Receive(msgB)
		if err != nil {
			t.Fatalf("round %d: Alice.Receive: %v", round, err)
		}

		// After Bob completes encapsulation, encapSecret should be zeroized.
		if bob.StateKind() == StateCt1Sampled || bob.StateKind() == StateCt2Sampled {
			if bob.state.bobEncapSecret != nil {
				t.Fatal("bobEncapSecret should be nil after encapsulation completes")
			}
			break
		}
	}

	if !bobHadEncapSecret {
		t.Error("Bob should have had a non-nil encapSecret at some point during the protocol")
	}
}
