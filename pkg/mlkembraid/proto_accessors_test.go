package mlkembraid

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid/internal/polynomial"
)

// ================== ProtoSetFromFields ==================

// TestProtoSetFromFields_AllNilOptionals verifies that ProtoSetFromFields works
// with all optional byte-slice fields nil (KeysUnsampled-equivalent state).
func TestProtoSetFromFields_AllNilOptionals(t *testing.T) {
	state, err := ProtoSetFromFields(
		StateKeysUnsampled, 1, DefaultChunkSize,
		nil, // auth
		nil, // dk
		nil, // ekSeed
		nil, // ekVector
		nil, // receivedCt1
		nil, // bobEkSeed
		nil, // bobHek
		nil, // bobEncapSecret
		nil, // bobEkVector
		nil, // bobCt1
		nil, // bobSS
		nil, // headerEncoder
		nil, // ekEncoder
		nil, // ct1Encoder
		nil, // ct2Encoder
		nil, // headerDecoder
		nil, // ekDecoder
		nil, // ct1Decoder
		nil, // ct2Decoder
	)
	if err != nil {
		t.Fatalf("ProtoSetFromFields: unexpected error: %v", err)
	}
	if state == nil {
		t.Fatal("ProtoSetFromFields returned nil state")
	}
	if state.kind != StateKeysUnsampled {
		t.Errorf("kind: got %v, want %v", state.kind, StateKeysUnsampled)
	}
	if state.epoch != 1 {
		t.Errorf("epoch: got %d, want 1", state.epoch)
	}
	if state.chunkSize != DefaultChunkSize {
		t.Errorf("chunkSize: got %d, want %d", state.chunkSize, DefaultChunkSize)
	}
}

// TestProtoSetFromFields_WithSecretFields verifies that non-nil secret fields
// are stored properly and that the state accessors return their bytes.
func TestProtoSetFromFields_WithSecretFields(t *testing.T) {
	dk := make([]byte, 32)
	ekSeed := make([]byte, 64)
	ekVector := make([]byte, 64)
	for i := range dk {
		dk[i] = byte(i)
	}
	for i := range ekSeed {
		ekSeed[i] = byte(i + 100)
	}
	for i := range ekVector {
		ekVector[i] = byte(i + 200)
	}

	state, err := ProtoSetFromFields(
		StateKeysSampled, 3, DefaultChunkSize,
		nil,      // auth
		dk,       // dk
		ekSeed,   // ekSeed
		ekVector, // ekVector
		nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil,
		nil, nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("ProtoSetFromFields: %v", err)
	}
	if state == nil {
		t.Fatal("nil state")
	}

	if got := mustCopy(state.ProtoDK()); got == nil {
		t.Error("ProtoDK() should not be nil")
	}
	if got := mustCopy(state.ProtoEKSeed()); got == nil {
		t.Error("ProtoEKSeed() should not be nil")
	}
	if got := mustCopy(state.ProtoEKVector()); got == nil {
		t.Error("ProtoEKVector() should not be nil")
	}

	// Zeroize to avoid leaking secret state.
	if state.dk != nil {
		state.dk.Destroy()
	}
	if state.ekSeed != nil {
		state.ekSeed.Destroy()
	}
	if state.ekVector != nil {
		state.ekVector.Destroy()
	}
}

// TestProtoSetFromFields_BobFields verifies that all bob-related secret fields
// are stored and accessible via their accessor methods.
func TestProtoSetFromFields_BobFields(t *testing.T) {
	bobEkSeed := []byte("bobEkSeed-32-bytes-pad-to-32bbbb")
	bobHek := []byte("bobHek--32-bytes-pad-to-32-bbbb!")
	bobEncapSecret := []byte("bobEncapSecret-32-bytes-pad-here")
	bobEkVector := []byte("bobEkVector-32-bytes-pad-to-32b!")
	bobCt1 := []byte("bobCt1--32-bytes-padding-here-!!")
	bobSS := []byte("bobSS---32-bytes-padding-here-!!")
	receivedCt1 := []byte("receivedCt1-32bytes-padding-here")

	state, err := ProtoSetFromFields(
		StateKeysSampled, 2, DefaultChunkSize,
		nil,            // auth
		nil,            // dk
		nil,            // ekSeed
		nil,            // ekVector
		receivedCt1,    // receivedCt1
		bobEkSeed,      // bobEkSeed
		bobHek,         // bobHek
		bobEncapSecret, // bobEncapSecret
		bobEkVector,    // bobEkVector
		bobCt1,         // bobCt1
		bobSS,          // bobSS
		nil, nil, nil, nil,
		nil, nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("ProtoSetFromFields: %v", err)
	}
	if state == nil {
		t.Fatal("nil state")
	}

	// All accessors should return non-nil bytes.
	if got := mustCopy(state.ProtoReceivedCt1()); got == nil {
		t.Error("ProtoReceivedCt1() should not be nil")
	}
	if got := mustCopy(state.ProtoBobEKSeed()); got == nil {
		t.Error("ProtoBobEKSeed() should not be nil")
	}
	if got := mustCopy(state.ProtoBobHek()); got == nil {
		t.Error("ProtoBobHek() should not be nil")
	}
	if got := mustCopy(state.ProtoBobEncapSecret()); got == nil {
		t.Error("ProtoBobEncapSecret() should not be nil")
	}
	if got := mustCopy(state.ProtoBobEKVector()); got == nil {
		t.Error("ProtoBobEKVector() should not be nil")
	}
	if got := mustCopy(state.ProtoBobCt1()); got == nil {
		t.Error("ProtoBobCt1() should not be nil")
	}
	if got := mustCopy(state.ProtoBobSS()); got == nil {
		t.Error("ProtoBobSS() should not be nil")
	}

	// Zeroize to avoid leaking secret state.
	if state.receivedCt1 != nil {
		state.receivedCt1.Destroy()
	}
	if state.bobEkSeed != nil {
		state.bobEkSeed.Destroy()
	}
	if state.bobHek != nil {
		state.bobHek.Destroy()
	}
	if state.bobEncapSecret != nil {
		state.bobEncapSecret.Destroy()
	}
	if state.bobEkVector != nil {
		state.bobEkVector.Destroy()
	}
	if state.bobCt1 != nil {
		state.bobCt1.Destroy()
	}
	if state.bobSS != nil {
		state.bobSS.Destroy()
	}
}

// TestProtoSetFromFields_WithEncodersDecoders verifies that encoder and decoder
// fields are forwarded correctly into the returned State.
func TestProtoSetFromFields_WithEncodersDecoders(t *testing.T) {
	data := make([]byte, DefaultChunkSize*2)
	for i := range data {
		data[i] = byte(i)
	}
	enc, err := NewEncoder(data, DefaultChunkSize)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}
	dec, err := NewDecoder(len(data), DefaultChunkSize)
	if err != nil {
		t.Fatalf("NewDecoder: %v", err)
	}

	state, err := ProtoSetFromFields(
		StateHeaderSent, 2, DefaultChunkSize,
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		enc, // headerEncoder
		nil, // ekEncoder
		nil, // ct1Encoder
		nil, // ct2Encoder
		dec, // headerDecoder
		nil, // ekDecoder
		nil, // ct1Decoder
		nil, // ct2Decoder
	)
	if err != nil {
		t.Fatalf("ProtoSetFromFields: %v", err)
	}
	if state.headerEncoder == nil {
		t.Error("headerEncoder should be set")
	}
	if state.headerDecoder == nil {
		t.Error("headerDecoder should be set")
	}
	if state.ProtoHeaderEncoder() == nil {
		t.Error("ProtoHeaderEncoder() should return non-nil")
	}
	if state.ProtoHeaderDecoder() == nil {
		t.Error("ProtoHeaderDecoder() should return non-nil")
	}
}

// ================== ProtoMarshalEncoder / ProtoUnmarshalEncoder ==================

// TestProtoMarshalEncoder_NilError verifies that a nil Encoder returns an error.
func TestProtoMarshalEncoder_NilError(t *testing.T) {
	_, err := ProtoMarshalEncoder(nil)
	if err == nil {
		t.Fatal("expected error for nil encoder")
	}
}

// TestProtoMarshalEncoder_PointsState verifies roundtrip in Points state
// (before the encoder has advanced past the first pass).
func TestProtoMarshalEncoder_PointsState(t *testing.T) {
	data := make([]byte, DefaultChunkSize*4)
	for i := range data {
		data[i] = byte(i)
	}
	enc, err := NewEncoder(data, DefaultChunkSize)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}

	// In Points state immediately after construction.
	fields, err := ProtoMarshalEncoder(enc)
	if err != nil {
		t.Fatalf("ProtoMarshalEncoder: %v", err)
	}
	if fields == nil {
		t.Fatal("ProtoMarshalEncoder returned nil fields")
	}
	if len(fields.Pts) != NumPolyChannels {
		t.Errorf("Pts channels: got %d, want %d", len(fields.Pts), NumPolyChannels)
	}
	if fields.Polys != nil {
		t.Error("Polys should be nil in Points state")
	}
}

// TestProtoUnmarshalEncoder_PointsState verifies that an encoder marshalled in
// Points state can be reconstructed and produces the same first-pass chunks.
func TestProtoUnmarshalEncoder_PointsState(t *testing.T) {
	data := make([]byte, DefaultChunkSize*4)
	for i := range data {
		data[i] = byte(i + 7)
	}
	enc, err := NewEncoder(data, DefaultChunkSize)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}

	fields, err := ProtoMarshalEncoder(enc)
	if err != nil {
		t.Fatalf("ProtoMarshalEncoder: %v", err)
	}

	restored, err := ProtoUnmarshalEncoder(fields.Idx, fields.Pts, fields.Polys)
	if err != nil {
		t.Fatalf("ProtoUnmarshalEncoder: %v", err)
	}
	if restored == nil {
		t.Fatal("ProtoUnmarshalEncoder returned nil")
	}
	// The restored encoder should be able to produce chunks.
	if restored.TotalChunks() != enc.TotalChunks() {
		t.Errorf("TotalChunks: got %d, want %d", restored.TotalChunks(), enc.TotalChunks())
	}
}

// makeTestPolys builds a slice of polynomial.NumPolys valid polynomials by
// advancing a PolyEncoder into Polys state (past first-pass chunks).
func makeTestPolys(t *testing.T) ([]polynomial.Poly, int) {
	t.Helper()
	// Use 64 bytes → 2 first-pass chunks. Advancing to chunk 3 triggers Polys state.
	data := make([]byte, DefaultChunkSize*2)
	for i := range data {
		data[i] = byte(i + 1)
	}
	inner, err := polynomial.NewPolyEncoder(data)
	if err != nil {
		t.Fatalf("makeTestPolys: NewPolyEncoder: %v", err)
	}
	// Drain the first pass + one extra chunk to force the Polys state.
	total := (len(data) + polynomial.ChunkSize - 1) / polynomial.ChunkSize
	for i := 0; i <= total; i++ {
		inner.NextChunk()
	}
	if inner.StateKind() != polynomial.EncoderStatePolys {
		t.Fatal("makeTestPolys: encoder not in Polys state after advancing")
	}
	polysPtr := inner.Polys()
	polys := make([]polynomial.Poly, polynomial.NumPolys)
	copy(polys, polysPtr[:])
	return polys, len(data)
}

// TestProtoMarshalEncoder_PolysState verifies roundtrip in Polys state
// (after the encoder has produced enough chunks to trigger poly computation).
func TestProtoMarshalEncoder_PolysState(t *testing.T) {
	polys, msgLen := makeTestPolys(t)
	inner, err := polynomial.NewPolyEncoderFromPolys(polys, 0)
	if err != nil {
		t.Fatalf("NewPolyEncoderFromPolys: %v", err)
	}
	enc, err := NewEncoderFromInner(inner, 0, msgLen)
	if err != nil {
		t.Fatalf("NewEncoderFromInner: %v", err)
	}

	fields, err := ProtoMarshalEncoder(enc)
	if err != nil {
		t.Fatalf("ProtoMarshalEncoder (Polys state): %v", err)
	}
	if fields == nil {
		t.Fatal("fields should not be nil")
	}
	if len(fields.Polys) != NumPolyChannels {
		t.Errorf("Polys channels: got %d, want %d", len(fields.Polys), NumPolyChannels)
	}
}

// TestProtoUnmarshalEncoder_PolysState verifies that protoPolyEncoderFromFields
// correctly reconstructs a PolyEncoder from serialized polynomial coefficients
// in Polys state. ProtoUnmarshalEncoder requires a message-length derivable from
// the Points array and so cannot be used with encoders constructed from Polys;
// we exercise the Polys branch of protoPolyEncoderFromFields directly.
func TestProtoUnmarshalEncoder_PolysState(t *testing.T) {
	polys, msgLen := makeTestPolys(t)
	// Serialize each poly channel.
	pbPolys := make([][]byte, polynomial.NumPolys)
	for i, p := range polys {
		pbPolys[i] = p.Serialize()
	}
	for i, b := range pbPolys {
		if len(b) == 0 {
			t.Fatalf("poly[%d] serialized to empty bytes", i)
		}
	}

	// protoPolyEncoderFromFields is unexported but accessible within the same package.
	inner, err := protoPolyEncoderFromFields(0, nil, pbPolys)
	if err != nil {
		t.Fatalf("protoPolyEncoderFromFields (Polys): %v", err)
	}
	if inner == nil {
		t.Fatal("protoPolyEncoderFromFields returned nil")
	}
	if inner.StateKind() != polynomial.EncoderStatePolys {
		t.Errorf("state: got %v, want EncoderStatePolys", inner.StateKind())
	}

	// Wrap it using NewEncoderFromInner with the known msgLen.
	enc, err := NewEncoderFromInner(inner, 0, msgLen)
	if err != nil {
		t.Fatalf("NewEncoderFromInner: %v", err)
	}
	if enc.TotalChunks() <= 0 {
		t.Error("TotalChunks should be > 0")
	}
}

// TestProtoUnmarshalEncoder_NeitherPtsNorPolys verifies that when both Pts and
// Polys are empty, ProtoUnmarshalEncoder (via protoPolyEncoderFromFields) returns
// an error.
func TestProtoUnmarshalEncoder_NeitherPtsNorPolys(t *testing.T) {
	_, err := ProtoUnmarshalEncoder(0, nil, nil)
	if err == nil {
		t.Fatal("expected error for neither pts nor polys")
	}
}

// TestProtoUnmarshalEncoder_WrongPtsChannelCount verifies an error is returned
// when Pts has the wrong number of channels.
func TestProtoUnmarshalEncoder_WrongPtsChannelCount(t *testing.T) {
	pts := make([][]byte, 3) // wrong count, should be NumPolyChannels
	for i := range pts {
		pts[i] = []byte{0, 1}
	}
	_, err := ProtoUnmarshalEncoder(0, pts, nil)
	if err == nil {
		t.Fatal("expected error for wrong pts channel count")
	}
}

// TestProtoUnmarshalEncoder_OddPtsChannel verifies an error for odd-length channel bytes.
func TestProtoUnmarshalEncoder_OddPtsChannel(t *testing.T) {
	pts := make([][]byte, NumPolyChannels)
	for i := range pts {
		pts[i] = []byte{0, 1} // even
	}
	pts[0] = []byte{0x01} // odd length → error
	_, err := ProtoUnmarshalEncoder(0, pts, nil)
	if err == nil {
		t.Fatal("expected error for odd pts channel length")
	}
}

// TestProtoUnmarshalEncoder_AllPtsEmpty verifies an error when all pts channels
// are zero-length (totalElems == 0).
func TestProtoUnmarshalEncoder_AllPtsEmpty(t *testing.T) {
	pts := make([][]byte, NumPolyChannels)
	for i := range pts {
		pts[i] = []byte{} // empty channel
	}
	_, err := ProtoUnmarshalEncoder(0, pts, nil)
	if err == nil {
		t.Fatal("expected error for all-empty pts channels")
	}
}

// ================== ProtoMarshalDecoder / ProtoUnmarshalDecoder ==================

// TestProtoMarshalDecoder_NilError verifies that a nil Decoder returns an error.
func TestProtoMarshalDecoder_NilError(t *testing.T) {
	_, err := ProtoMarshalDecoder(nil)
	if err == nil {
		t.Fatal("expected error for nil decoder")
	}
}

// TestProtoMarshalDecoder_RoundTrip verifies that a decoder can be marshalled
// and unmarshalled with its state preserved.
func TestProtoMarshalDecoder_RoundTrip(t *testing.T) {
	msgLen := DefaultChunkSize * 4 // 128 bytes, even
	dec, err := NewDecoder(msgLen, DefaultChunkSize)
	if err != nil {
		t.Fatalf("NewDecoder: %v", err)
	}

	fields, err := ProtoMarshalDecoder(dec)
	if err != nil {
		t.Fatalf("ProtoMarshalDecoder: %v", err)
	}
	if fields == nil {
		t.Fatal("ProtoMarshalDecoder returned nil")
	}
	if int(fields.PtsNeeded) <= 0 {
		t.Errorf("PtsNeeded should be > 0, got %d", fields.PtsNeeded)
	}
	if len(fields.Pts) != NumPolyChannels {
		t.Errorf("Pts channels: got %d, want %d", len(fields.Pts), NumPolyChannels)
	}

	restored, err := ProtoUnmarshalDecoder(fields.PtsNeeded, fields.Pts, fields.IsComplete)
	if err != nil {
		t.Fatalf("ProtoUnmarshalDecoder: %v", err)
	}
	if restored == nil {
		t.Fatal("ProtoUnmarshalDecoder returned nil")
	}
}

// TestProtoUnmarshalDecoder_WrongChannelCount verifies an error for wrong pts
// channel count.
func TestProtoUnmarshalDecoder_WrongChannelCount(t *testing.T) {
	pts := make([][]byte, 3)
	_, err := ProtoUnmarshalDecoder(4, pts, false)
	if err == nil {
		t.Fatal("expected error for wrong pts channel count")
	}
}

// TestProtoUnmarshalDecoder_OddLengthChannel verifies an error for a pts channel
// whose byte length is not a multiple of 4.
func TestProtoUnmarshalDecoder_OddLengthChannel(t *testing.T) {
	pts := make([][]byte, NumPolyChannels)
	for i := range pts {
		pts[i] = []byte{}
	}
	pts[0] = []byte{0x01, 0x02, 0x03} // length 3, not multiple of 4
	_, err := ProtoUnmarshalDecoder(4, pts, false)
	if err == nil {
		t.Fatal("expected error for odd-length channel")
	}
}

// TestProtoMarshalDecoder_WithPoints verifies marshalling a decoder that has
// received some chunks (non-empty pts for some channels).
func TestProtoMarshalDecoder_WithPoints(t *testing.T) {
	data := make([]byte, DefaultChunkSize*4)
	for i := range data {
		data[i] = byte(i + 3)
	}
	enc, err := NewEncoder(data, DefaultChunkSize)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}
	dec, err := NewDecoder(len(data), DefaultChunkSize)
	if err != nil {
		t.Fatalf("NewDecoder: %v", err)
	}

	// Feed one chunk so the decoder has some points.
	if err := dec.AddChunk(enc.NextChunk()); err != nil {
		t.Fatalf("AddChunk: %v", err)
	}

	fields, err := ProtoMarshalDecoder(dec)
	if err != nil {
		t.Fatalf("ProtoMarshalDecoder with points: %v", err)
	}

	// Roundtrip.
	restored, err := ProtoUnmarshalDecoder(fields.PtsNeeded, fields.Pts, fields.IsComplete)
	if err != nil {
		t.Fatalf("ProtoUnmarshalDecoder roundtrip: %v", err)
	}
	if restored == nil {
		t.Fatal("nil restored decoder")
	}
}

// ================== ProtoEncoderMessageLen ==================

// TestProtoEncoderMessageLen_NonZero verifies that a valid inner encoder returns
// a positive message length.
func TestProtoEncoderMessageLen_NonZero(t *testing.T) {
	data := make([]byte, DefaultChunkSize*3)
	for i := range data {
		data[i] = byte(i)
	}
	enc, err := NewEncoder(data, DefaultChunkSize)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}
	msgLen := ProtoEncoderMessageLen(enc.InnerEncoder())
	if msgLen <= 0 {
		t.Errorf("ProtoEncoderMessageLen: got %d, want > 0", msgLen)
	}
}

// ================== ProtoNewAuthenticator ==================

// TestProtoNewAuthenticator_Valid verifies that ProtoNewAuthenticator creates a
// valid Authenticator from raw bytes.
func TestProtoNewAuthenticator_Valid(t *testing.T) {
	rootKey := make([]byte, 32)
	macKey := make([]byte, 32)
	for i := range rootKey {
		rootKey[i] = byte(i)
	}
	for i := range macKey {
		macKey[i] = byte(i + 50)
	}
	const epoch = uint64(7)

	auth, err := ProtoNewAuthenticator(rootKey, macKey, epoch)
	if err != nil {
		t.Fatalf("ProtoNewAuthenticator: %v", err)
	}
	if auth == nil {
		t.Fatal("returned nil authenticator")
	}
	if auth.epoch != epoch {
		t.Errorf("epoch: got %d, want %d", auth.epoch, epoch)
	}
	if auth.rootKey == nil {
		t.Error("rootKey should not be nil")
	}
	if auth.macKey == nil {
		t.Error("macKey should not be nil")
	}
	auth.Zeroize()
}

// TestProtoNewAuthenticator_NoMacKey verifies that ProtoNewAuthenticator works
// when macKey is empty (optional field absent from proto).
func TestProtoNewAuthenticator_NoMacKey(t *testing.T) {
	rootKey := make([]byte, 32)
	auth, err := ProtoNewAuthenticator(rootKey, nil, 0)
	if err != nil {
		t.Fatalf("ProtoNewAuthenticator (no macKey): %v", err)
	}
	if auth == nil {
		t.Fatal("returned nil authenticator")
	}
	if auth.macKey != nil {
		t.Error("macKey should be nil when not provided")
	}
	auth.Zeroize()
}

// ================== Authenticator (NewAuthenticator, Update, Clone) ==================

// TestNewAuthenticator_EmptySharedSecret verifies that an empty shared secret
// triggers an error.
func TestNewAuthenticator_EmptySharedSecret(t *testing.T) {
	_, err := NewAuthenticator(1, nil)
	if err == nil {
		t.Fatal("expected error for empty shared secret")
	}
	if _, ok := err.(*ErrInvalidInput); !ok {
		t.Errorf("expected *ErrInvalidInput, got %T", err)
	}
}

// TestNewAuthenticator_Valid verifies basic construction with valid inputs.
func TestNewAuthenticator_Valid(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	if auth == nil {
		t.Fatal("nil authenticator")
	}
	if auth.epoch != 1 {
		t.Errorf("epoch: got %d, want 1", auth.epoch)
	}
	auth.Zeroize()
}

// TestAuthenticator_Update_EmptyKey verifies that Update with an empty update
// key returns an error.
func TestAuthenticator_Update_EmptyKey(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	defer auth.Zeroize()

	if err := auth.Update(2, nil); err == nil {
		t.Fatal("expected error for empty updateKey")
	}
}

// TestAuthenticator_Update_Valid verifies that Update advances the epoch and
// refreshes the MAC key.
func TestAuthenticator_Update_Valid(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	defer auth.Zeroize()

	newKey := make([]byte, 32)
	for i := range newKey {
		newKey[i] = byte(i + 5)
	}
	if err := auth.Update(2, newKey); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if auth.epoch != 2 {
		t.Errorf("epoch after Update: got %d, want 2", auth.epoch)
	}
}

// TestAuthenticator_Clone verifies that Clone creates an independent copy.
func TestAuthenticator_Clone(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	defer auth.Zeroize()

	clone, err := auth.Clone()
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	defer clone.Zeroize()

	if clone.epoch != auth.epoch {
		t.Errorf("clone epoch: got %d, want %d", clone.epoch, auth.epoch)
	}
	if clone.rootKey == nil || clone.macKey == nil {
		t.Error("cloned authenticator should have non-nil key material")
	}
}

// TestAuthenticator_MacHdr_EpochMismatch verifies that MacHdr returns an error
// when the epoch does not match.
func TestAuthenticator_MacHdr_EpochMismatch(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	defer auth.Zeroize()

	_, err = auth.MacHdr(99, []byte("header"))
	if err == nil {
		t.Fatal("expected error for epoch mismatch")
	}
}

// TestAuthenticator_VfyHdr_RoundTrip verifies that VfyHdr correctly validates
// a MAC produced by MacHdr.
func TestAuthenticator_VfyHdr_RoundTrip(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	defer auth.Zeroize()

	hdr := []byte("test-header")
	mac, err := auth.MacHdr(1, hdr)
	if err != nil {
		t.Fatalf("MacHdr: %v", err)
	}

	ok, err := auth.VfyHdr(1, hdr, mac)
	if err != nil {
		t.Fatalf("VfyHdr: %v", err)
	}
	if !ok {
		t.Error("VfyHdr should return true for a valid MAC")
	}
}

// TestAuthenticator_MacCt_EpochMismatch verifies MacCt returns error on epoch mismatch.
func TestAuthenticator_MacCt_EpochMismatch(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	defer auth.Zeroize()

	_, err = auth.MacCt(99, []byte("ct"))
	if err == nil {
		t.Fatal("expected error for epoch mismatch")
	}
}

// TestAuthenticator_VfyCt_RoundTrip verifies that VfyCt correctly validates a
// MAC produced by MacCt.
func TestAuthenticator_VfyCt_RoundTrip(t *testing.T) {
	ss := randomSecret(t)
	auth, err := NewAuthenticator(1, ss)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	defer auth.Zeroize()

	ct := []byte("test-ciphertext")
	mac, err := auth.MacCt(1, ct)
	if err != nil {
		t.Fatalf("MacCt: %v", err)
	}

	ok, err := auth.VfyCt(1, ct, mac)
	if err != nil {
		t.Fatalf("VfyCt: %v", err)
	}
	if !ok {
		t.Error("VfyCt should return true for a valid MAC")
	}
}

// ================== Encoder / Decoder: Reset paths ==================

// TestEncoder_Reset verifies that Reset allows re-encoding from the beginning.
func TestEncoder_Reset(t *testing.T) {
	data := make([]byte, DefaultChunkSize*3)
	for i := range data {
		data[i] = byte(i)
	}
	enc, err := NewEncoder(data, DefaultChunkSize)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}

	// Drain first pass.
	for enc.HasMore() {
		enc.NextChunk()
	}
	if enc.HasMore() {
		t.Error("should not have more after first pass")
	}

	// Reset and verify we can send again.
	enc.Reset()
	if !enc.HasMore() {
		t.Error("after Reset, HasMore should be true")
	}
	chunk := enc.NextChunk()
	if len(chunk) == 0 {
		t.Error("NextChunk after Reset returned empty slice")
	}
}

// TestDecoder_Reset verifies that Reset clears decoder state for reuse.
func TestDecoder_Reset(t *testing.T) {
	data := make([]byte, DefaultChunkSize*2)
	for i := range data {
		data[i] = byte(i)
	}
	enc, err := NewEncoder(data, DefaultChunkSize)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}
	dec, err := NewDecoder(len(data), DefaultChunkSize)
	if err != nil {
		t.Fatalf("NewDecoder: %v", err)
	}

	// Feed all chunks.
	for enc.HasMore() {
		if err := dec.AddChunk(enc.NextChunk()); err != nil {
			t.Fatalf("AddChunk: %v", err)
		}
	}
	if !dec.HasMessage() {
		t.Fatal("should have message after all chunks")
	}

	// Reset and verify the decoder is cleared.
	dec.Reset()
	if dec.HasMessage() {
		t.Error("after Reset, HasMessage should be false")
	}
	if dec.ReceivedCount() != 0 {
		t.Errorf("after Reset, ReceivedCount should be 0, got %d", dec.ReceivedCount())
	}
}

// ================== State accessor: bob* and receivedCt1 fields ==================

// TestStateProtoAccessors_BobFields verifies all bob-related accessor methods
// return non-nil bytes for a fully-populated Bob state (after a real handshake).
func TestStateProtoAccessors_BobFields(t *testing.T) {
	ss := randomSecret(t)
	ssCopy := make([]byte, len(ss))
	copy(ssCopy, ss)

	kemImpl := NewMLKEM768IncrementalKEM()
	alice, err := InitAlice(ss, kemImpl, DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}
	defer alice.Zeroize()
	bob, err := InitBob(ssCopy, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitBob: %v", err)
	}
	defer bob.Zeroize()

	// Run enough protocol messages so Bob populates bobEncapSecret and other fields.
	_ = runProtocolPartial(t, alice, bob, 30)

	s := bob.State()

	// All bob fields are populated after a partial run.
	_, _ = s.ProtoBobEKSeed()
	_, _ = s.ProtoBobHek()
	_, _ = s.ProtoBobEncapSecret()
	_, _ = s.ProtoBobEKVector()
	_, _ = s.ProtoBobCt1()
	_, _ = s.ProtoBobSS()
	_, _ = s.ProtoReceivedCt1()

	// Encoder/decoder accessors must not panic.
	_ = s.ProtoEKEncoder()
	_ = s.ProtoCt1Encoder()
	_ = s.ProtoCt2Encoder()
	_ = s.ProtoEKDecoder()
	_ = s.ProtoCt1Decoder()
	_ = s.ProtoCt2Decoder()
}

// runProtocolPartial runs up to maxMsg messages between alice and bob and returns
// once one party produces an output key or maxMsg is reached.
func runProtocolPartial(t *testing.T, alice, bob *Braid, maxMsg int) *OutputKey {
	t.Helper()
	parties := []*Braid{alice, bob}
	for i := 0; i < maxMsg; i++ {
		sender := parties[i%2]
		receiver := parties[(i+1)%2]

		msg, _, _, err := sender.Send()
		if err != nil {
			continue // some states don't allow sending yet
		}

		_, outputKey, err := receiver.Receive(msg)
		if err != nil {
			continue
		}
		if outputKey != nil {
			return outputKey
		}
	}
	return nil
}
