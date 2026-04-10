package mlkembraid

import (
	"testing"
)

// ================== deserializeState: error during secret loop ==================

// TestDeserializeStateSecretLoopError exercises the s.Zeroize() path in
// deserializeState when readOptionalSecret returns an error partway through
// the secrets array (after the fixed header and authenticator are parsed
// successfully). This covers the "Secrets" error branch in deserializeState.
func TestDeserializeStateSecretLoopError(t *testing.T) {
	// Build a valid state binary up to the point where secrets start, then
	// append a malformed optional secret (flag=0x01 but no length/data).

	// Fixed header: kind(1) + epoch(8) + chunkSize(4) + ct1Ack(1) + headerMACEpoch(8) + lastReceivedEpoch(8) = 30 bytes
	// stateFixedHeaderSize = 30
	header := make([]byte, stateFixedHeaderSize)
	header[0] = byte(StateKeysUnsampled) // valid kind
	// epoch = 1, chunkSize = 32 (DefaultChunkSize), rest = 0

	putU64BE(header[1:], 1)                    // epoch
	putU32BE(header[9:], uint32(DefaultChunkSize)) // chunkSize
	// ct1Ack = 0x00 (false), headerMACEpoch = 0, lastReceivedEpoch = 0

	// Valid authenticator: rootKey(32) + epoch(8) + hasMac(0x00)
	auth := make([]byte, 32+8+1)
	// rootKey = all zeros, epoch = 0, hasMac = 0x00

	// Append a valid nil secret (0x00) then an invalid secret (0x01 with no data).
	secrets := []byte{
		0x00, // secret 0 (dk) = nil
		0x01, // secret 1 (ekSeed) = present, but no length follows → error
	}

	data := make([]byte, 0, len(header)+len(auth)+len(secrets))
	data = append(data, header...)
	data = append(data, auth...)
	data = append(data, secrets...)

	_, err := deserializeState(data)
	if err == nil {
		t.Fatal("expected error when secrets data is truncated mid-loop")
	}
	if _, ok := err.(*ErrDeserialize); !ok {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// TestDeserializeStateEncoderLoopError exercises the s.Zeroize() path in
// deserializeState when readOptionalEncoder returns an error after secrets
// are read successfully. This covers the "Encoders" error branch.
func TestDeserializeStateEncoderLoopError(t *testing.T) {
	// Fixed header
	header := make([]byte, stateFixedHeaderSize)
	header[0] = byte(StateKeysUnsampled)
	putU64BE(header[1:], 1)
	putU32BE(header[9:], uint32(DefaultChunkSize))

	// Valid authenticator: rootKey(32) + epoch(8) + hasMac(0x00)
	auth := make([]byte, 32+8+1)

	// All 11 nil secrets (one byte each = 0x00)
	secrets := make([]byte, 11)

	// Append a valid nil encoder (0x00) then an invalid encoder (0x01 with no data).
	encoders := []byte{
		0x00, // encoder 0 (headerEncoder) = nil
		0x01, // encoder 1 (ekEncoder) = present, but no data → error
	}

	data := make([]byte, 0, len(header)+len(auth)+len(secrets)+len(encoders))
	data = append(data, header...)
	data = append(data, auth...)
	data = append(data, secrets...)
	data = append(data, encoders...)

	_, err := deserializeState(data)
	if err == nil {
		t.Fatal("expected error when encoders data is truncated mid-loop")
	}
	if _, ok := err.(*ErrDeserialize); !ok {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// TestDeserializeStateDecoderLoopError exercises the s.Zeroize() path in
// deserializeState when readOptionalDecoder returns an error after encoders
// are read successfully. This covers the "Decoders" error branch.
func TestDeserializeStateDecoderLoopError(t *testing.T) {
	// Fixed header
	header := make([]byte, stateFixedHeaderSize)
	header[0] = byte(StateKeysUnsampled)
	putU64BE(header[1:], 1)
	putU32BE(header[9:], uint32(DefaultChunkSize))

	// Valid authenticator: rootKey(32) + epoch(8) + hasMac(0x00)
	auth := make([]byte, 32+8+1)

	// All 11 nil secrets
	secrets := make([]byte, 11)

	// All 4 nil encoders
	encoders := make([]byte, 4)

	// Append a valid nil decoder (0x00) then an invalid decoder (0x01 with incomplete header).
	decoders := []byte{
		0x00, // decoder 0 (headerDecoder) = nil
		0x01, // decoder 1 (ekDecoder) = present, but only flag byte → too short
	}

	data := make([]byte, 0, len(header)+len(auth)+len(secrets)+len(encoders)+len(decoders))
	data = append(data, header...)
	data = append(data, auth...)
	data = append(data, secrets...)
	data = append(data, encoders...)
	data = append(data, decoders...)

	_, err := deserializeState(data)
	if err == nil {
		t.Fatal("expected error when decoders data is truncated mid-loop")
	}
	if _, ok := err.(*ErrDeserialize); !ok {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

// ================== bobCompleteEncapsulation: two-phase CompleteEncaps2 path ==================

// TestBobCompleteEncapsulationTwoPhase exercises the CompleteEncaps2 branch in
// bobCompleteEncapsulation when bobEncapSecret is non-nil. This covers the
// if s.bobEncapSecret != nil path in receiveHeaderReceived → bobCompleteEncapsulation.
func TestBobCompleteEncapsulationTwoPhase(t *testing.T) {
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

	// Simulate what sendHeaderReceived does: call Encaps1 to produce bobEncapSecret.
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
		kind:           StateHeaderReceived,
		epoch:          5,
		auth:           auth,
		bobEkSeed:      mustSecret(t, ekSeed),
		bobHek:         mustSecret(t, hek),
		bobEncapSecret: encapsSecret,
		ekDecoder:      ekDec,
		chunkSize:      testChunkSize,
	}

	outputKey, err := state.bobCompleteEncapsulation(kemImpl, testChunkSize)
	if err != nil {
		t.Fatalf("bobCompleteEncapsulation two-phase failed: %v", err)
	}
	if outputKey == nil {
		t.Fatal("expected non-nil output key")
	}
	if state.kind != StateCt1Sampled {
		t.Errorf("expected StateCt1Sampled, got %s", state.kind)
	}
	outputKey.Key.Destroy()
}

// ================== helpers ==================

// putU64BE writes a uint64 in big-endian order into dst.
func putU64BE(dst []byte, v uint64) {
	dst[0] = byte(v >> 56)
	dst[1] = byte(v >> 48)
	dst[2] = byte(v >> 40)
	dst[3] = byte(v >> 32)
	dst[4] = byte(v >> 24)
	dst[5] = byte(v >> 16)
	dst[6] = byte(v >> 8)
	dst[7] = byte(v)
}

// putU32BE writes a uint32 in big-endian order into dst.
func putU32BE(dst []byte, v uint32) {
	dst[0] = byte(v >> 24)
	dst[1] = byte(v >> 16)
	dst[2] = byte(v >> 8)
	dst[3] = byte(v)
}
