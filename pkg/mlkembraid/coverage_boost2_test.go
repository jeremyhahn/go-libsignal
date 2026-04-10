package mlkembraid

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// ================== Error types not previously covered ==================

// TestErrChunkCountErrorMessage verifies ErrChunkCount.Error() returns a non-empty message.
func TestErrChunkCountErrorMessage(t *testing.T) {
	e := &ErrChunkCount{Count: 100, Max: 50}
	msg := e.Error()
	if msg == "" {
		t.Fatal("ErrChunkCount.Error() must return non-empty string")
	}
}

// TestErrEpochOutOfRangeError verifies ErrEpochOutOfRange.Error() returns a non-empty message.
func TestErrEpochOutOfRangeError(t *testing.T) {
	e := &ErrEpochOutOfRange{Expected: 5, Got: 10}
	msg := e.Error()
	if msg == "" {
		t.Fatal("ErrEpochOutOfRange.Error() must return non-empty string")
	}
	var target *ErrEpochOutOfRange
	if !errors.As(e, &target) {
		t.Fatal("errors.As should find *ErrEpochOutOfRange in itself")
	}
}

// TestErrSCKADecodeError verifies ErrSCKADecode.Error() returns a non-empty message.
func TestErrSCKADecodeError(t *testing.T) {
	e := &ErrSCKADecode{Reason: "bad input"}
	msg := e.Error()
	if msg == "" {
		t.Fatal("ErrSCKADecode.Error() must return non-empty string")
	}
}

// ================== DeserializeSCKA error paths ==================

// TestDeserializeSCKAEmptyInput verifies that empty input returns ErrSCKADecode.
func TestDeserializeSCKAEmptyInput(t *testing.T) {
	_, _, err := DeserializeSCKA(nil)
	if err == nil {
		t.Fatal("expected error for nil input")
	}
	if _, ok := err.(*ErrSCKADecode); !ok {
		t.Errorf("expected *ErrSCKADecode, got %T", err)
	}
}

// TestDeserializeSCKAWrongVersion verifies that a wrong version byte returns ErrSCKADecode.
func TestDeserializeSCKAWrongVersion(t *testing.T) {
	data := []byte{0xFF, 0x01, 0x00, 0x00, 0x00}
	_, _, err := DeserializeSCKA(data)
	if err == nil {
		t.Fatal("expected error for wrong version byte")
	}
	if _, ok := err.(*ErrSCKADecode); !ok {
		t.Errorf("expected *ErrSCKADecode, got %T: %v", err, err)
	}
}

// TestDeserializeSCKAMissingMessageType verifies that truncated data returns ErrSCKADecode.
func TestDeserializeSCKAMissingMessageType(t *testing.T) {
	// Version(1) + epoch varint(1) + chainIndex varint(1) = 3 bytes, no message type.
	data := []byte{SPQRVersion, 0x01, 0x00} // version + epoch=1 + chainIndex=0, no msg type byte
	_, _, err := DeserializeSCKA(data)
	if err == nil {
		t.Fatal("expected error for missing message type")
	}
}

// TestDeserializeSCKAEpochZero verifies that epoch=0 is rejected.
func TestDeserializeSCKAEpochZero(t *testing.T) {
	// Version(1) + epoch=0 varint(1) ...
	data := []byte{SPQRVersion, 0x00, 0x01, byte(MessageTypeNone)}
	_, _, err := DeserializeSCKA(data)
	if err == nil {
		t.Fatal("expected error for zero epoch")
	}
}

// TestDeserializeSCKAUnknownMessageType verifies that unknown message type returns ErrSCKADecode.
func TestDeserializeSCKAUnknownMessageType(t *testing.T) {
	// Version(1) + epoch=1 varint(1) + chainIndex=0 varint(1) + type=0xFF
	data := []byte{SPQRVersion, 0x01, 0x00, 0xFF}
	_, _, err := DeserializeSCKA(data)
	if err == nil {
		t.Fatal("expected error for unknown message type")
	}
}

// TestDeserializeSCKAValidNone verifies that a valid None message is parsed.
func TestDeserializeSCKAValidNone(t *testing.T) {
	data := []byte{SPQRVersion, 0x01, 0x00, byte(MessageTypeNone)}
	msg, chainIndex, err := DeserializeSCKA(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg == nil {
		t.Fatal("message should not be nil")
	}
	if msg.Epoch != 1 {
		t.Errorf("expected epoch 1, got %d", msg.Epoch)
	}
	if chainIndex != 0 {
		t.Errorf("expected chain index 0, got %d", chainIndex)
	}
	if msg.Type != MessageTypeNone {
		t.Errorf("expected None type, got %s", msg.Type)
	}
}

// ================== appendBool false path ==================

// TestAppendBoolFalse exercises the false branch of appendBool.
func TestAppendBoolFalse(t *testing.T) {
	buf := appendBool(nil, false)
	if len(buf) != 1 || buf[0] != 0x00 {
		t.Errorf("appendBool(false) = %v, want [0x00]", buf)
	}

	buf2 := appendBool(nil, true)
	if len(buf2) != 1 || buf2[0] != 0x01 {
		t.Errorf("appendBool(true) = %v, want [0x01]", buf2)
	}
}

// ================== readOptionalSecret error paths ==================

// TestReadOptionalSecretShortForLength exercises the branch where data has the
// present flag but is too short to contain the 4-byte length field.
func TestReadOptionalSecretShortForLength(t *testing.T) {
	// Flag=0x01, but no length bytes follow.
	data := []byte{0x01, 0x00} // only 2 bytes: flag + partial length
	_, _, err := readOptionalSecret(data)
	if err == nil {
		t.Fatal("expected error for data too short for length")
	}
	if _, ok := err.(*ErrDeserialize); !ok {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// TestReadOptionalSecretShortForData exercises the branch where the declared
// length is valid but there is not enough data remaining.
func TestReadOptionalSecretShortForData(t *testing.T) {
	// Flag=0x01, length=100, but only 2 bytes of data follow.
	buf := []byte{0x01, 0x00, 0x00, 0x00, 0x64, 0xAB, 0xCD} // length=100, only 2 data bytes
	_, _, err := readOptionalSecret(buf)
	if err == nil {
		t.Fatal("expected error for data too short for secret data")
	}
	if _, ok := err.(*ErrDeserialize); !ok {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// TestReadOptionalSecretTooLong exercises the branch where the declared length
// exceeds the maxSecretLength limit.
func TestReadOptionalSecretTooLong(t *testing.T) {
	// Flag=0x01, length=0x10000000 (268MB >> maxSecretLength).
	buf := []byte{0x01, 0x10, 0x00, 0x00, 0x00}
	_, _, err := readOptionalSecret(buf)
	if err == nil {
		t.Fatal("expected error for secret length exceeding maximum")
	}
	if _, ok := err.(*ErrDeserialize); !ok {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// ================== readOptionalEncoder error paths ==================

// TestReadOptionalEncoderShortForDataLen exercises the branch where data has
// the present flag but is too short for the data length field.
func TestReadOptionalEncoderShortForDataLen(t *testing.T) {
	// Flag=0x01, but not enough bytes for 4-byte dataLen.
	data := []byte{0x01, 0x00, 0x01} // flag + 2 bytes (need 4 more)
	_, _, err := readOptionalEncoder(data)
	if err == nil {
		t.Fatal("expected error for data too short for encoder data length")
	}
	if _, ok := err.(*ErrDeserialize); !ok {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// TestReadOptionalEncoderDataLenTooLarge exercises the branch where dataLen
// exceeds the maxSecretLength limit.
func TestReadOptionalEncoderDataLenTooLarge(t *testing.T) {
	// Flag=0x01, dataLen=0x10000000 >> maxSecretLength.
	buf := []byte{0x01, 0x10, 0x00, 0x00, 0x00}
	_, _, err := readOptionalEncoder(buf)
	if err == nil {
		t.Fatal("expected error for encoder data length exceeding maximum")
	}
	if _, ok := err.(*ErrDeserialize); !ok {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// TestReadOptionalEncoderShortForFields exercises the branch where data is too
// short for the encoder fields (data + offset(4) + total(4)).
func TestReadOptionalEncoderShortForFields(t *testing.T) {
	// Flag=0x01, dataLen=4, only 1 byte of data (need 4 + 8 = 12 more bytes).
	buf := []byte{0x01, 0x00, 0x00, 0x00, 0x04, 0xAA}
	_, _, err := readOptionalEncoder(buf)
	if err == nil {
		t.Fatal("expected error for encoder fields data too short")
	}
}

// ================== serializeAuthenticator error paths ==================

// TestSerializeAuthenticatorNil verifies that a nil authenticator returns ErrSerialize.
func TestSerializeAuthenticatorNil(t *testing.T) {
	_, err := serializeAuthenticator(nil)
	if err == nil {
		t.Fatal("expected error for nil authenticator")
	}
	if _, ok := err.(*ErrSerialize); !ok {
		t.Errorf("expected *ErrSerialize, got %T: %v", err, err)
	}
}

// TestSerializeAuthenticatorNilRootKey verifies that a nil/destroyed rootKey
// returns ErrSerialize.
func TestSerializeAuthenticatorNilRootKey(t *testing.T) {
	auth := &Authenticator{
		rootKey: nil,
		macKey:  nil,
		epoch:   1,
	}
	_, err := serializeAuthenticator(auth)
	if err == nil {
		t.Fatal("expected error for nil rootKey")
	}
}

// TestDeserializeAuthenticatorShortData verifies that insufficient data returns ErrDeserialize.
func TestDeserializeAuthenticatorShortData(t *testing.T) {
	data := make([]byte, 5) // too short (need 32+8+1=41 bytes minimum)
	_, _, err := deserializeAuthenticator(data)
	if err == nil {
		t.Fatal("expected error for short data")
	}
	if _, ok := err.(*ErrDeserialize); !ok {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// TestDeserializeAuthenticatorMACKeyTooShort verifies that declaring a MAC key
// present but having insufficient data returns ErrDeserialize.
func TestDeserializeAuthenticatorMACKeyTooShort(t *testing.T) {
	// rootKey(32) + epoch(8) + hasMac=0x01 + only 5 bytes of macKey (need 32).
	buf := make([]byte, 32+8+1+5)
	buf[32+8] = 0x01 // hasMAC = true
	_, _, err := deserializeAuthenticator(buf)
	if err == nil {
		t.Fatal("expected error for MAC key data too short")
	}
}

// ================== Authenticator Update error path ==================

// TestAuthenticatorUpdateNilKey verifies that Update with nil updateKey returns error.
func TestAuthenticatorUpdateNilKey(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}

	err = auth.Update(1, nil)
	if err == nil {
		t.Fatal("Update with empty updateKey should return error")
	}
	if _, ok := err.(*ErrInvalidInput); !ok {
		t.Errorf("expected *ErrInvalidInput, got %T: %v", err, err)
	}
}

// TestAuthenticatorNewEmptySharedSecret verifies NewAuthenticator with empty secret returns error.
func TestAuthenticatorNewEmptySharedSecret(t *testing.T) {
	_, err := NewAuthenticator(1, nil)
	if err == nil {
		t.Fatal("NewAuthenticator with empty sharedSecret should return error")
	}
	if _, ok := err.(*ErrInvalidInput); !ok {
		t.Errorf("expected *ErrInvalidInput, got %T: %v", err, err)
	}
}

// TestAuthenticatorVfyHdrWrongEpoch verifies that VfyHdr returns error on epoch mismatch.
func TestAuthenticatorVfyHdrWrongEpoch(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}

	_, err = auth.VfyHdr(99, []byte("header"), make([]byte, MacSize))
	if err == nil {
		t.Fatal("VfyHdr with wrong epoch should return error")
	}
	if _, ok := err.(*ErrInvalidEpoch); !ok {
		t.Errorf("expected *ErrInvalidEpoch, got %T: %v", err, err)
	}
}

// TestAuthenticatorVfyCtWrongEpoch verifies that VfyCt returns error on epoch mismatch.
func TestAuthenticatorVfyCtWrongEpoch(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}

	_, err = auth.VfyCt(99, []byte("ct"), make([]byte, MacSize))
	if err == nil {
		t.Fatal("VfyCt with wrong epoch should return error")
	}
	if _, ok := err.(*ErrInvalidEpoch); !ok {
		t.Errorf("expected *ErrInvalidEpoch, got %T: %v", err, err)
	}
}

// TestAuthenticatorCloneWithNilMacKey exercises the Clone() nil macKey branch.
func TestAuthenticatorCloneWithNilMacKey(t *testing.T) {
	// Create an authenticator with nil macKey (before any Update).
	rootData := make([]byte, 32)
	rootSecret, err := mustSecret2(t, rootData)
	if err != nil {
		t.Fatal(err)
	}
	auth := &Authenticator{
		rootKey: rootSecret,
		macKey:  nil,
		epoch:   1,
	}

	cloned, err := auth.Clone()
	if err != nil {
		t.Fatalf("Clone with nil macKey failed: %v", err)
	}
	if cloned == nil {
		t.Fatal("Clone returned nil")
	}
	if cloned.macKey != nil {
		t.Fatal("cloned authenticator should also have nil macKey")
	}
	if cloned.epoch != 1 {
		t.Fatal("epoch mismatch in clone")
	}
}

// mustSecret2 is a helper that does not call t.Fatal so it can be used
// in non-table-driven contexts where returning an error is acceptable.
func mustSecret2(t *testing.T, data []byte) (*secret.Secret, error) {
	t.Helper()
	cp := make([]byte, len(data))
	copy(cp, data)
	return secret.New(cp)
}

// ================== receiveCt2Sampled Transition 13 ==================

// TestReceiveCt2SampledTransition13 exercises Transition (13): receiving
// an Hdr message for epoch+1 while in Ct2Sampled, which advances Bob to
// KeysUnsampled for the new epoch.
func TestReceiveCt2SampledTransition13(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:  StateCt2Sampled,
		epoch: 5,
		auth:  auth,
	}

	// Transition 13: receive Hdr with epoch = state.epoch + 1.
	_, out, err := state.Receive(&Message{Epoch: 6, Type: MessageTypeHdr}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatalf("Receive Transition13 failed: %v", err)
	}
	if out != nil {
		t.Error("expected nil output for Transition 13")
	}
	if state.kind != StateKeysUnsampled {
		t.Errorf("expected StateKeysUnsampled after Transition 13, got %s", state.kind)
	}
	if state.epoch != 6 {
		t.Errorf("expected epoch 6 after Transition 13, got %d", state.epoch)
	}
}

// TestReceiveCt2SampledTransition13WithSecrets exercises Transition 13 when
// various bob secrets are set, verifying they are properly zeroized.
func TestReceiveCt2SampledTransition13WithSecrets(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}

	ct1Data := make([]byte, 32)
	ct1Secret, err := secret.New(ct1Data)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:   StateCt2Sampled,
		epoch:  5,
		auth:   auth,
		bobCt1: ct1Secret,
	}

	_, _, err = state.Receive(&Message{Epoch: 6, Type: MessageTypeHdr}, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatalf("Receive Transition13 with secrets failed: %v", err)
	}
	if state.kind != StateKeysUnsampled {
		t.Errorf("expected StateKeysUnsampled, got %s", state.kind)
	}
}

// ================== NewDecoder / NewEncoder error paths ==================

// TestNewDecoderZeroExpectedSize verifies that NewDecoder with expectedSize=0
// returns an error.
func TestNewDecoderZeroExpectedSize(t *testing.T) {
	_, err := NewDecoder(0, DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for expectedSize=0")
	}
}

// TestNewEncoderEmptyData verifies that NewEncoder with empty data returns an error.
func TestNewEncoderEmptyData(t *testing.T) {
	_, err := NewEncoder(nil, DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for nil data")
	}
}

// ================== sendHeaderReceived: Encaps1 path ==================

// TestSendHeaderReceivedWithEkSeed exercises sendHeaderReceived when bobEkSeed
// and bobHek are set, triggering the Encaps1 path.
func TestSendHeaderReceivedWithEkSeed(t *testing.T) {
	ss := randomSecret(t)
	kemImpl := NewMLKEM768IncrementalKEM()
	_, ekSeed, _, err := kemImpl.KeyGen()
	if err != nil {
		t.Fatal(err)
	}

	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}

	hek := make([]byte, 32) // zero hek - Encaps1 accepts any 32-byte value

	state := &State{
		kind:      StateHeaderReceived,
		epoch:     5,
		auth:      auth,
		bobEkSeed: mustSecret(t, ekSeed),
		bobHek:    mustSecret(t, hek),
		chunkSize: DefaultChunkSize,
	}

	msg, _, _, err := state.Send(kemImpl)
	if err != nil {
		t.Fatalf("sendHeaderReceived failed: %v", err)
	}
	if msg.Type != MessageTypeNone {
		t.Errorf("expected None while waiting for ek_vector, got %s", msg.Type)
	}
	// After first Send, bobEncapSecret should be populated.
	if state.bobEncapSecret == nil {
		t.Fatal("bobEncapSecret should be set after Encaps1")
	}
}

// TestSendHeaderReceivedIdempotent verifies that calling Send twice in
// HeaderReceived state does not re-run Encaps1 (idempotent guard).
func TestSendHeaderReceivedIdempotent(t *testing.T) {
	ss := randomSecret(t)
	kemImpl := NewMLKEM768IncrementalKEM()
	_, ekSeed, _, err := kemImpl.KeyGen()
	if err != nil {
		t.Fatal(err)
	}

	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:      StateHeaderReceived,
		epoch:     5,
		auth:      auth,
		bobEkSeed: mustSecret(t, ekSeed),
		bobHek:    mustSecret(t, make([]byte, 32)),
		chunkSize: DefaultChunkSize,
	}

	// First send - triggers Encaps1.
	if _, _, _, err := state.Send(kemImpl); err != nil {
		t.Fatal(err)
	}
	firstSecret := state.bobEncapSecret

	// Second send - should be idempotent (no re-encaps).
	if _, _, _, err := state.Send(kemImpl); err != nil {
		t.Fatal(err)
	}
	if state.bobEncapSecret != firstSecret {
		t.Fatal("bobEncapSecret should not change on second Send (idempotent)")
	}
}

// ================== deserializeState error paths ==================

// TestDeserializeStateTooShort verifies that short data returns ErrDeserialize.
func TestDeserializeStateTooShort(t *testing.T) {
	data := make([]byte, 5) // much less than stateFixedHeaderSize
	_, err := deserializeState(data)
	if err == nil {
		t.Fatal("expected error for data too short")
	}
	if _, ok := err.(*ErrDeserialize); !ok {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// TestDeserializeStateInvalidKind verifies that an invalid state kind returns ErrDeserialize.
func TestDeserializeStateInvalidKind(t *testing.T) {
	// Build a full-sized header with an invalid kind byte.
	data := make([]byte, stateFixedHeaderSize+100)
	data[0] = 0xFF // invalid kind
	_, err := deserializeState(data)
	if err == nil {
		t.Fatal("expected error for invalid state kind")
	}
	if _, ok := err.(*ErrDeserialize); !ok {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// ================== InitBob error paths ==================

// TestInitBobNilSharedSecret verifies that empty sharedSecret returns error.
func TestInitBobNilSharedSecret(t *testing.T) {
	_, err := InitBob(nil, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for empty secret")
	}
	if _, ok := err.(*ErrInvalidInput); !ok {
		t.Errorf("expected *ErrInvalidInput, got %T: %v", err, err)
	}
}

// TestInitBobWithNilKEM verifies that nil KEM returns error.
func TestInitBobWithNilKEM(t *testing.T) {
	_, err := InitBob(randomSecret(t), nil, DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for nil KEM")
	}
}

// TestInitBobZeroChunkSize verifies that zero chunk size returns ErrChunkSize.
func TestInitBobZeroChunkSize(t *testing.T) {
	_, err := InitBob(randomSecret(t), NewMLKEM768IncrementalKEM(), 0)
	if err == nil {
		t.Fatal("expected error for zero chunk size")
	}
	if _, ok := err.(*ErrChunkSize); !ok {
		t.Errorf("expected *ErrChunkSize, got %T: %v", err, err)
	}
}

// ================== receiveNoHeaderReceived: wrong epoch path ==================

// TestReceiveNoHeaderReceivedWrongEpoch verifies that a Hdr message with
// a different epoch (not current) is silently ignored.
func TestReceiveNoHeaderReceivedWrongEpoch(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatal(err)
	}

	headerDec, err := NewDecoder(HeaderSize+MacSize, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{
		kind:          StateNoHeaderReceived,
		epoch:         5,
		auth:          auth,
		headerDecoder: headerDec,
		chunkSize:     DefaultChunkSize,
	}

	// Send Hdr with epoch=3 (not current epoch=5), should be silently ignored.
	_, out, err := state.Receive(
		&Message{Epoch: 3, Type: MessageTypeHdr, Data: makeWireChunk(0)},
		NewMLKEM768IncrementalKEM(),
		DefaultChunkSize,
	)
	if err != nil {
		t.Fatalf("unexpected error for wrong-epoch Hdr: %v", err)
	}
	if out != nil {
		t.Error("expected nil output for wrong-epoch Hdr")
	}
	// State should remain unchanged.
	if state.kind != StateNoHeaderReceived {
		t.Errorf("expected to stay in NoHeaderReceived, got %s", state.kind)
	}
}

// ================== Receive on Braid: epoch boundary ==================

// TestBraidReceiveFutureEpochRejected verifies that a message with an epoch
// far in the future (epoch > current+1) is rejected with ErrEpochOutOfRange.
func TestBraidReceiveFutureEpochRejected(t *testing.T) {
	ss := randomSecret(t)
	bob, err := InitBob(ss, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	// Send a None message at epoch=99 (far ahead: bob is at epoch 1).
	_, _, err = bob.Receive(&Message{Epoch: 99, Type: MessageTypeNone})
	if err == nil {
		t.Fatal("expected error for epoch far in the future")
	}
	if _, ok := err.(*ErrEpochOutOfRange); !ok {
		t.Errorf("expected *ErrEpochOutOfRange, got %T: %v", err, err)
	}
}

// ================== SerializeBraid error path ==================

// TestSerializeBraidNilKEM verifies that Serialize handles state without auth
// (defensive nil check).
func TestSerializeBraidNilAuth(t *testing.T) {
	// Serialize a nil-auth Braid - should return ErrSerialize.
	b := &Braid{
		state: &State{
			kind:      StateKeysUnsampled,
			epoch:     1,
			auth:      nil, // nil auth
			chunkSize: DefaultChunkSize,
		},
		kem:       NewMLKEM768IncrementalKEM(),
		chunkSize: DefaultChunkSize,
	}

	_, err := b.Serialize()
	if err == nil {
		t.Fatal("expected error for nil authenticator in serialize")
	}
}
