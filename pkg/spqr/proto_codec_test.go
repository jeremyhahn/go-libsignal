package spqr

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
	pqratchetpb "github.com/jeremyhahn/go-libsignal/pkg/proto/pqratchetpb"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret/secrettest"
)

// sharedSecretForTest returns a deterministic 32-byte shared secret for a
// given seed index. Seed values match those used in the Rust interop harness.
func sharedSecretForTest(seed int) []byte {
	ss := make([]byte, 32)
	for i := range ss {
		ss[i] = byte((seed*7 + i*3 + 11) % 251)
	}
	return ss
}

// braidAliceForTest creates an Alice-side Braid from a deterministic seed.
func braidAliceForTest(t *testing.T, seed int) *mlkembraid.Braid {
	t.Helper()
	kem := mlkembraid.NewMLKEM768IncrementalKEM()
	b, err := mlkembraid.InitAlice(sharedSecretForTest(seed), kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice seed=%d: %v", seed, err)
	}
	return b
}

// braidBobForTest creates a Bob-side Braid from a deterministic seed.
func braidBobForTest(t *testing.T, seed int) *mlkembraid.Braid {
	t.Helper()
	kem := mlkembraid.NewMLKEM768IncrementalKEM()
	b, err := mlkembraid.InitBob(sharedSecretForTest(seed), kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitBob seed=%d: %v", seed, err)
	}
	return b
}

// roundTripSPQR marshals s to proto bytes, unmarshals back, and marshals again.
// It verifies that the two serialized byte slices are identical (structural
// round-trip). It does NOT require byte parity with Rust — that is tested
// separately by the interop tests.
func roundTripSPQR(t *testing.T, s *SPQR, label string) {
	t.Helper()

	first, err := MarshalStateProto(s)
	if err != nil {
		t.Fatalf("%s: MarshalStateProto: %v", label, err)
	}

	s2, err := UnmarshalStateProto(first)
	if err != nil {
		t.Fatalf("%s: UnmarshalStateProto: %v", label, err)
	}
	defer s2.Zeroize()

	second, err := MarshalStateProto(s2)
	if err != nil {
		t.Fatalf("%s: MarshalStateProto (second): %v", label, err)
	}

	if !bytes.Equal(first, second) {
		t.Errorf("%s: round-trip mismatch:\nfirst:  %s\nsecond: %s",
			label, hex.EncodeToString(first), hex.EncodeToString(second))
	}
}

// ─────────────────────── StateKeysUnsampled ──────────────────────────────────

func TestProtoCodec_KeysUnsampled_Alice(t *testing.T) {
	ss := sharedSecretForTest(1)
	braid := braidAliceForTest(t, 1)
	defer braid.Zeroize()

	s, err := InitWithBraid(ss, DirectionA2B, maxJump, braid)
	if err != nil {
		t.Fatalf("InitWithBraid: %v", err)
	}
	defer s.Zeroize()

	if s.braid.StateKind() != mlkembraid.StateKeysUnsampled {
		t.Fatalf("InitAlice must produce StateKeysUnsampled, got %v", s.braid.StateKind())
	}

	roundTripSPQR(t, s, "KeysUnsampled/Alice")
}

func TestProtoCodec_KeysUnsampled_MarshalError_NilAuth(t *testing.T) {
	// Build a state with a nil authenticator to trigger ErrProtoMissingField.
	state, err := mlkembraid.ProtoSetFromFields(
		mlkembraid.StateKeysUnsampled, 0, mlkembraid.DefaultChunkSize,
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, nil, nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("ProtoSetFromFields: %v", err)
	}
	braid := mlkembraid.BraidFromState(state, mlkembraid.NewMLKEM768IncrementalKEM(), mlkembraid.DefaultChunkSize)

	ss := sharedSecretForTest(1)
	s, err := Init(ss, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()
	s.braid = braid

	_, err = MarshalStateProto(s)
	if err == nil {
		t.Fatal("expected error marshaling state with nil auth")
	}
}

// ─────────────────────── StateNoHeaderReceived ───────────────────────────────

func TestProtoCodec_NoHeaderReceived_Bob(t *testing.T) {
	ss := sharedSecretForTest(2)
	braid := braidBobForTest(t, 2)
	defer braid.Zeroize()

	s, err := InitWithBraid(ss, DirectionB2A, maxJump, braid)
	if err != nil {
		t.Fatalf("InitWithBraid: %v", err)
	}
	defer s.Zeroize()

	if s.braid.StateKind() != mlkembraid.StateNoHeaderReceived {
		t.Fatalf("InitBob must produce StateNoHeaderReceived, got %v", s.braid.StateKind())
	}

	roundTripSPQR(t, s, "NoHeaderReceived/Bob")
}

func TestProtoCodec_NoHeaderReceived_InvalidUnmarshal(t *testing.T) {
	_, err := UnmarshalStateProto([]byte{0xFF, 0xFE, 0xFD})
	if err == nil {
		t.Fatal("expected error unmarshaling garbage bytes")
	}
	if _, ok := err.(*ErrProtoInvalidState); !ok {
		t.Errorf("expected *ErrProtoInvalidState, got %T: %v", err, err)
	}
}

// ─────────────────────── Chain-only (no braid) ───────────────────────────────

func TestProtoCodec_ChainOnly_A2B(t *testing.T) {
	ss := sharedSecretForTest(3)
	s, err := Init(ss, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	roundTripSPQR(t, s, "ChainOnly/A2B")
}

func TestProtoCodec_ChainOnly_B2A(t *testing.T) {
	ss := sharedSecretForTest(4)
	s, err := Init(ss, DirectionB2A, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	roundTripSPQR(t, s, "ChainOnly/B2A")
}

// ─────────────────────── Version negotiation ─────────────────────────────────

func TestProtoCodec_VersionNegotiationPending(t *testing.T) {
	// InitialStateWithParams creates a pending negotiation state.
	serialized, err := InitialStateWithParams(Params{
		AuthKey:    sharedSecretForTest(5),
		Version:    VersionV1,
		Direction:  DirectionA2B,
		MinVersion: VersionV0,
		MaxJump:    maxJump,
		MaxOOOKeys: maxSkippedKeys,
	})
	if err != nil {
		t.Fatalf("InitialStateWithParams: %v", err)
	}

	// Deserialize using the legacy serializer, then re-marshal with proto codec.
	s, err := Deserialize(serialized)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	defer s.Zeroize()

	roundTripSPQR(t, s, "VersionNegotiationPending")
}

// ─────────────────────── Typed error validation ───────────────────────────────

func TestProtoCodec_ErrProtoMarshalUnknownState(t *testing.T) {
	e := &ErrProtoMarshalUnknownState{Kind: mlkembraid.StateKind(99)}
	if e.Error() == "" {
		t.Fatal("ErrProtoMarshalUnknownState.Error() must not be empty")
	}
}

func TestProtoCodec_ErrProtoMissingField(t *testing.T) {
	e := &ErrProtoMissingField{Name: "test_field"}
	if e.Error() == "" {
		t.Fatal("ErrProtoMissingField.Error() must not be empty")
	}
	want := `"test_field"`
	if !containsSubstring(e.Error(), want) {
		t.Errorf("ErrProtoMissingField.Error() = %q, want substring %q", e.Error(), want)
	}
}

func TestProtoCodec_ErrProtoEpochOutOfRange(t *testing.T) {
	e := &ErrProtoEpochOutOfRange{ProtoEpoch: 0}
	if e.Error() == "" {
		t.Fatal("ErrProtoEpochOutOfRange.Error() must not be empty")
	}
}

func TestProtoCodec_ErrProtoInvalidState(t *testing.T) {
	e := &ErrProtoInvalidState{Reason: "some reason"}
	if e.Error() == "" {
		t.Fatal("ErrProtoInvalidState.Error() must not be empty")
	}
}

// ─────────────────────── Braid-attached round trips ─────────────────────────

func TestProtoCodec_AliceBraid_MultipleSeeds(t *testing.T) {
	seeds := []int{1, 2, 3, 5, 7}
	for _, seed := range seeds {
		seed := seed // capture
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			ss := sharedSecretForTest(seed)
			braid := braidAliceForTest(t, seed)
			defer braid.Zeroize()

			s, err := InitWithBraid(ss, DirectionA2B, maxJump, braid)
			if err != nil {
				t.Fatalf("InitWithBraid: %v", err)
			}
			defer s.Zeroize()

			roundTripSPQR(t, s, fmt.Sprintf("Alice/seed=%d/state=%v", seed, s.braid.StateKind()))
		})
	}
}

func TestProtoCodec_BobBraid_MultipleSeeds(t *testing.T) {
	seeds := []int{1, 2, 3, 5, 7}
	for _, seed := range seeds {
		seed := seed // capture
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			ss := sharedSecretForTest(seed)
			braid := braidBobForTest(t, seed)
			defer braid.Zeroize()

			s, err := InitWithBraid(ss, DirectionB2A, maxJump, braid)
			if err != nil {
				t.Fatalf("InitWithBraid: %v", err)
			}
			defer s.Zeroize()

			roundTripSPQR(t, s, fmt.Sprintf("Bob/seed=%d/state=%v", seed, s.braid.StateKind()))
		})
	}
}

// ─────────────────────── Unmarshal empty / nil input ─────────────────────────

func TestProtoCodec_UnmarshalEmpty(t *testing.T) {
	// An empty protobuf message is valid — it decodes to a zero-value
	// PqRatchetState with no fields set.
	s, err := UnmarshalStateProto([]byte{})
	if err != nil {
		t.Fatalf("UnmarshalStateProto(empty): %v", err)
	}
	defer s.Zeroize()
}

func TestProtoCodec_MarshalNilBraid(t *testing.T) {
	ss := sharedSecretForTest(9)
	s, err := Init(ss, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()
	// s.braid is nil — marshal should succeed.
	out, err := MarshalStateProto(s)
	if err != nil {
		t.Fatalf("MarshalStateProto with nil braid: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("expected non-empty proto bytes")
	}
}

// ─────────────── All 11 state kinds via ProtoSetFromFields ──────────────────

// makeTestEncoder builds a minimal Encoder suitable for testing proto round-trips.
// The encoder is seeded with msgLen bytes, which must be > 0 and even.
func makeTestEncoder(t *testing.T, msgLen int) *mlkembraid.Encoder {
	t.Helper()
	msg := make([]byte, msgLen)
	for i := range msg {
		msg[i] = byte(i % 251)
	}
	enc, err := mlkembraid.NewEncoder(msg, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("NewEncoder(msgLen=%d): %v", msgLen, err)
	}
	return enc
}

// makeTestDecoder builds a minimal Decoder suitable for testing proto round-trips.
func makeTestDecoder(t *testing.T, msgLen int) *mlkembraid.Decoder {
	t.Helper()
	dec, err := mlkembraid.NewDecoder(msgLen, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("NewDecoder(msgLen=%d): %v", msgLen, err)
	}
	return dec
}

// makeTestAuth builds an Authenticator from deterministic key material.
func makeTestAuth(t *testing.T, seed int) *mlkembraid.Authenticator {
	t.Helper()
	rk := make([]byte, 32)
	mk := make([]byte, 32)
	for i := range rk {
		rk[i] = byte((seed*13 + i) % 251)
		mk[i] = byte((seed*17 + i + 1) % 251)
	}
	auth, err := mlkembraid.ProtoNewAuthenticator(rk, mk, uint64(seed))
	if err != nil {
		t.Fatalf("ProtoNewAuthenticator: %v", err)
	}
	return auth
}

// buildAndRoundTrip creates a SPQR with the given braid state, marshals/unmarshals,
// and asserts byte-level round-trip equality.
func buildAndRoundTrip(t *testing.T, state *mlkembraid.State, label string) {
	t.Helper()
	braid := mlkembraid.BraidFromState(state, mlkembraid.NewMLKEM768IncrementalKEM(), mlkembraid.DefaultChunkSize)
	ss := sharedSecretForTest(42)
	s, err := Init(ss, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("%s Init: %v", label, err)
	}
	defer s.Zeroize()
	s.braid = braid
	roundTripSPQR(t, s, label)
}

func TestProtoCodec_AllStates_KeysSampled(t *testing.T) {
	auth := makeTestAuth(t, 1)
	dk := make([]byte, mlkembraid.MLKEM768FullEKSize) // reuse size for dk
	ekSeed := make([]byte, mlkembraid.EKSeedSize)
	ekVec := make([]byte, mlkembraid.MLKEM768EKSize)
	for i := range dk {
		dk[i] = byte(i % 251)
	}
	for i := range ekSeed {
		ekSeed[i] = byte((i + 7) % 251)
	}
	for i := range ekVec {
		ekVec[i] = byte((i + 13) % 251)
	}
	enc := makeTestEncoder(t, mlkembraid.HeaderSize+mlkembraid.MacSize)
	state, err := mlkembraid.ProtoSetFromFields(
		mlkembraid.StateKeysSampled, 0, mlkembraid.DefaultChunkSize,
		auth, dk, ekSeed, ekVec, nil, nil, nil, nil, nil, nil, nil,
		enc, nil, nil, nil, nil, nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("ProtoSetFromFields: %v", err)
	}
	buildAndRoundTrip(t, state, "KeysSampled")
}

func TestProtoCodec_AllStates_HeaderSent(t *testing.T) {
	auth := makeTestAuth(t, 2)
	dk := make([]byte, 2400)
	for i := range dk {
		dk[i] = byte(i % 251)
	}
	ekEnc := makeTestEncoder(t, mlkembraid.MLKEM768EKSize)
	ct1Dec := makeTestDecoder(t, mlkembraid.MLKEM768CT1Size)
	state, err := mlkembraid.ProtoSetFromFields(
		mlkembraid.StateHeaderSent, 0, mlkembraid.DefaultChunkSize,
		auth, dk, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, ekEnc, nil, nil, nil, nil, ct1Dec, nil,
	)
	if err != nil {
		t.Fatalf("ProtoSetFromFields: %v", err)
	}
	buildAndRoundTrip(t, state, "HeaderSent")
}

func TestProtoCodec_AllStates_Ct1Received(t *testing.T) {
	auth := makeTestAuth(t, 3)
	dk := make([]byte, 2400)
	ct1 := make([]byte, mlkembraid.MLKEM768CT1Size)
	for i := range ct1 {
		ct1[i] = byte(i % 251)
	}
	ekEnc := makeTestEncoder(t, mlkembraid.MLKEM768EKSize)
	state, err := mlkembraid.ProtoSetFromFields(
		mlkembraid.StateCt1Received, 0, mlkembraid.DefaultChunkSize,
		auth, dk, nil, nil, ct1, nil, nil, nil, nil, nil, nil,
		nil, ekEnc, nil, nil, nil, nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("ProtoSetFromFields: %v", err)
	}
	buildAndRoundTrip(t, state, "Ct1Received")
}

func TestProtoCodec_AllStates_EkSentCt1Received(t *testing.T) {
	auth := makeTestAuth(t, 4)
	dk := make([]byte, 2400)
	ct1 := make([]byte, mlkembraid.MLKEM768CT1Size)
	ct2Dec := makeTestDecoder(t, mlkembraid.MLKEM768CT2Size)
	state, err := mlkembraid.ProtoSetFromFields(
		mlkembraid.StateEkSentCt1Received, 0, mlkembraid.DefaultChunkSize,
		auth, dk, nil, nil, ct1, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, nil, nil, nil, ct2Dec,
	)
	if err != nil {
		t.Fatalf("ProtoSetFromFields: %v", err)
	}
	buildAndRoundTrip(t, state, "EkSentCt1Received")
}

func TestProtoCodec_AllStates_HeaderReceived(t *testing.T) {
	auth := makeTestAuth(t, 5)
	bobEkSeed := make([]byte, mlkembraid.EKSeedSize)
	bobHek := make([]byte, 32)
	for i := range bobEkSeed {
		bobEkSeed[i] = byte((i + 3) % 251)
	}
	for i := range bobHek {
		bobHek[i] = byte((i + 5) % 251)
	}
	ekDec := makeTestDecoder(t, mlkembraid.MLKEM768EKSize)
	state, err := mlkembraid.ProtoSetFromFields(
		mlkembraid.StateHeaderReceived, 0, mlkembraid.DefaultChunkSize,
		auth, nil, nil, nil, nil, bobEkSeed, bobHek, nil, nil, nil, nil,
		nil, nil, nil, nil, nil, ekDec, nil, nil,
	)
	if err != nil {
		t.Fatalf("ProtoSetFromFields: %v", err)
	}
	buildAndRoundTrip(t, state, "HeaderReceived")
}

func TestProtoCodec_AllStates_Ct1Sampled(t *testing.T) {
	auth := makeTestAuth(t, 6)
	bobEkSeed := make([]byte, mlkembraid.EKSeedSize)
	bobHek := make([]byte, 32)
	es := make([]byte, mlkembraid.MLKEM768EncapStateSize)
	ct1 := make([]byte, mlkembraid.MLKEM768CT1Size)
	for i := range ct1 {
		ct1[i] = byte(i % 251)
	}
	ct1Enc := makeTestEncoder(t, mlkembraid.MLKEM768CT1Size)
	ekDec := makeTestDecoder(t, mlkembraid.MLKEM768EKSize)
	state, err := mlkembraid.ProtoSetFromFields(
		mlkembraid.StateCt1Sampled, 0, mlkembraid.DefaultChunkSize,
		auth, nil, nil, nil, nil, bobEkSeed, bobHek, es, nil, ct1, nil,
		nil, nil, ct1Enc, nil, nil, ekDec, nil, nil,
	)
	if err != nil {
		t.Fatalf("ProtoSetFromFields: %v", err)
	}
	buildAndRoundTrip(t, state, "Ct1Sampled")
}

func TestProtoCodec_AllStates_EkReceivedCt1Sampled(t *testing.T) {
	auth := makeTestAuth(t, 7)
	es := make([]byte, mlkembraid.MLKEM768EncapStateSize)
	ek := make([]byte, mlkembraid.MLKEM768EKSize)
	ct1 := make([]byte, mlkembraid.MLKEM768CT1Size)
	for i := range ct1 {
		ct1[i] = byte(i % 251)
	}
	ct1Enc := makeTestEncoder(t, mlkembraid.MLKEM768CT1Size)
	state, err := mlkembraid.ProtoSetFromFields(
		mlkembraid.StateEkReceivedCt1Sampled, 0, mlkembraid.DefaultChunkSize,
		auth, nil, nil, nil, nil, nil, nil, es, ek, ct1, nil,
		nil, nil, ct1Enc, nil, nil, nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("ProtoSetFromFields: %v", err)
	}
	buildAndRoundTrip(t, state, "EkReceivedCt1Sampled")
}

func TestProtoCodec_AllStates_Ct1Acknowledged(t *testing.T) {
	auth := makeTestAuth(t, 8)
	bobEkSeed := make([]byte, mlkembraid.EKSeedSize)
	bobHek := make([]byte, 32)
	es := make([]byte, mlkembraid.MLKEM768EncapStateSize)
	ct1 := make([]byte, mlkembraid.MLKEM768CT1Size)
	for i := range ct1 {
		ct1[i] = byte(i % 251)
	}
	ekDec := makeTestDecoder(t, mlkembraid.MLKEM768EKSize)
	state, err := mlkembraid.ProtoSetFromFields(
		mlkembraid.StateCt1Acknowledged, 0, mlkembraid.DefaultChunkSize,
		auth, nil, nil, nil, nil, bobEkSeed, bobHek, es, nil, ct1, nil,
		nil, nil, nil, nil, nil, ekDec, nil, nil,
	)
	if err != nil {
		t.Fatalf("ProtoSetFromFields: %v", err)
	}
	buildAndRoundTrip(t, state, "Ct1Acknowledged")
}

func TestProtoCodec_AllStates_Ct2Sampled(t *testing.T) {
	auth := makeTestAuth(t, 9)
	ct2Enc := makeTestEncoder(t, mlkembraid.MLKEM768CT2Size)
	state, err := mlkembraid.ProtoSetFromFields(
		mlkembraid.StateCt2Sampled, 0, mlkembraid.DefaultChunkSize,
		auth, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, ct2Enc, nil, nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("ProtoSetFromFields: %v", err)
	}
	buildAndRoundTrip(t, state, "Ct2Sampled")
}

// TestProtoCodec_UnknownState ensures an unknown StateKind returns ErrProtoMarshalUnknownState.
func TestProtoCodec_UnknownState(t *testing.T) {
	auth := makeTestAuth(t, 99)
	state, err := mlkembraid.ProtoSetFromFields(
		mlkembraid.StateKind(99), 0, mlkembraid.DefaultChunkSize,
		auth, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, nil, nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("ProtoSetFromFields: %v", err)
	}
	braid := mlkembraid.BraidFromState(state, mlkembraid.NewMLKEM768IncrementalKEM(), mlkembraid.DefaultChunkSize)
	ss := sharedSecretForTest(99)
	s, err := Init(ss, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()
	s.braid = braid

	_, err = MarshalStateProto(s)
	if err == nil {
		t.Fatal("expected ErrProtoMarshalUnknownState")
	}
	if _, ok := err.(*ErrProtoMarshalUnknownState); !ok {
		t.Errorf("expected *ErrProtoMarshalUnknownState, got %T: %v", err, err)
	}
}

// TestProtoCodec_InvalidInput_KeysUnsampledNilUc verifies nil uc handling.
func TestProtoCodec_InvalidInput_NilInnerState(t *testing.T) {
	// Marshal a valid state, then break the inner field and unmarshal.
	// Simplest: marshal an empty V1State with nil InnerState via direct proto.
	// We instead unmarshal a zero-value proto where inner is nil.
	s, err := UnmarshalStateProto([]byte{})
	if err != nil {
		t.Fatalf("UnmarshalStateProto(empty) should succeed: %v", err)
	}
	defer s.Zeroize()
	// Empty proto has no inner — this is valid (no braid).
	if s.braid != nil {
		t.Error("expected nil braid for empty proto")
	}
}

// TestProtoCodec_ChainOnly_MultipleEpochs tests chain serialization with
// multiple epochs to exercise the sortedEpochs path.
func TestProtoCodec_ChainOnly_MultipleEpochs(t *testing.T) {
	ss := sharedSecretForTest(11)
	s, err := Init(ss, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	// Add a second epoch via ReceiveKey to exercise sortedEpochs with 2 entries.
	sckaOutput := make([]byte, 32)
	for i := range sckaOutput {
		sckaOutput[i] = byte(i + 1)
	}
	if err := s.ReceiveKey(sckaOutput, 1); err != nil {
		t.Fatalf("ReceiveKey: %v", err)
	}

	roundTripSPQR(t, s, "ChainOnly/MultipleEpochs")
}

// TestProtoCodec_DirectionB2A_RoundTrip tests the B2A direction code path
// for directionToProto and protoDirectionToGo.
func TestProtoCodec_DirectionB2A_RoundTrip(t *testing.T) {
	auth := makeTestAuth(t, 10)
	state, err := mlkembraid.ProtoSetFromFields(
		mlkembraid.StateKeysUnsampled, 0, mlkembraid.DefaultChunkSize,
		auth, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, nil, nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("ProtoSetFromFields: %v", err)
	}
	braid := mlkembraid.BraidFromState(state, mlkembraid.NewMLKEM768IncrementalKEM(), mlkembraid.DefaultChunkSize)
	ss := sharedSecretForTest(10)
	s, err := Init(ss, DirectionB2A, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()
	s.braid = braid
	roundTripSPQR(t, s, "DirectionB2A")
}

// TestProtoCodec_GoEpoch_ZeroProtoEpoch ensures goEpoch(0) returns ErrProtoEpochOutOfRange.
func TestProtoCodec_GoEpoch_ZeroProtoEpoch(t *testing.T) {
	_, err := goEpoch(0)
	if err == nil {
		t.Fatal("expected ErrProtoEpochOutOfRange for proto epoch 0")
	}
	if _, ok := err.(*ErrProtoEpochOutOfRange); !ok {
		t.Errorf("expected *ErrProtoEpochOutOfRange, got %T: %v", err, err)
	}
}

// TestProtoCodec_ProtoEpochRoundTrip verifies epoch offset arithmetic.
func TestProtoCodec_ProtoEpochRoundTrip(t *testing.T) {
	for _, goEp := range []uint64{0, 1, 5, 1000} {
		proto := protoEpoch(goEp)
		back, err := goEpoch(proto)
		if err != nil {
			t.Fatalf("goEpoch(protoEpoch(%d)): %v", goEp, err)
		}
		if back != goEp {
			t.Errorf("epoch round-trip: in=%d proto=%d back=%d", goEp, proto, back)
		}
	}
}

// TestProtoV1StateToBraidState_NilKeysUnsampled verifies that a nil KeysUnsampled
// inner state produces ErrProtoMissingField.
func TestProtoV1StateToBraidState_NilKeysUnsampled(t *testing.T) {
	pb := &pqratchetpb.V1State{
		InnerState: &pqratchetpb.V1State_KeysUnsampled{
			KeysUnsampled: nil,
		},
	}
	_, err := protoV1StateToBraidState(pb)
	if err == nil {
		t.Fatal("expected error for nil KeysUnsampled")
	}
}

// TestProtoV1StateToBraidState_NilKeysSampled verifies that a nil KeysSampled
// inner state produces ErrProtoMissingField.
func TestProtoV1StateToBraidState_NilKeysSampled(t *testing.T) {
	pb := &pqratchetpb.V1State{
		InnerState: &pqratchetpb.V1State_KeysSampled{
			KeysSampled: nil,
		},
	}
	_, err := protoV1StateToBraidState(pb)
	if err == nil {
		t.Fatal("expected error for nil KeysSampled")
	}
}

// TestProtoV1StateToBraidState_NilHeaderSent verifies that a nil HeaderSent
// inner state produces ErrProtoMissingField.
func TestProtoV1StateToBraidState_NilHeaderSent(t *testing.T) {
	pb := &pqratchetpb.V1State{
		InnerState: &pqratchetpb.V1State_HeaderSent{
			HeaderSent: nil,
		},
	}
	_, err := protoV1StateToBraidState(pb)
	if err == nil {
		t.Fatal("expected error for nil HeaderSent")
	}
}

// TestProtoV1StateToBraidState_NilCt1Received verifies that a nil Ct1Received
// inner state produces ErrProtoMissingField.
func TestProtoV1StateToBraidState_NilCt1Received(t *testing.T) {
	pb := &pqratchetpb.V1State{
		InnerState: &pqratchetpb.V1State_Ct1Received{
			Ct1Received: nil,
		},
	}
	_, err := protoV1StateToBraidState(pb)
	if err == nil {
		t.Fatal("expected error for nil Ct1Received")
	}
}

// TestProtoV1StateToBraidState_NilNoHeaderReceived verifies that a nil
// NoHeaderReceived inner state produces ErrProtoMissingField.
func TestProtoV1StateToBraidState_NilNoHeaderReceived(t *testing.T) {
	pb := &pqratchetpb.V1State{
		InnerState: &pqratchetpb.V1State_NoHeaderReceived{
			NoHeaderReceived: nil,
		},
	}
	_, err := protoV1StateToBraidState(pb)
	if err == nil {
		t.Fatal("expected error for nil NoHeaderReceived")
	}
}

// TestProtoV1StateToBraidState_NilCt1Sampled verifies that a nil Ct1Sampled
// inner state produces ErrProtoMissingField.
func TestProtoV1StateToBraidState_NilCt1Sampled(t *testing.T) {
	pb := &pqratchetpb.V1State{
		InnerState: &pqratchetpb.V1State_Ct1Sampled{
			Ct1Sampled: nil,
		},
	}
	_, err := protoV1StateToBraidState(pb)
	if err == nil {
		t.Fatal("expected error for nil Ct1Sampled")
	}
}

// TestProtoV1StateToBraidState_NilCt2Sampled verifies that a nil Ct2Sampled
// inner state produces ErrProtoMissingField.
func TestProtoV1StateToBraidState_NilCt2Sampled(t *testing.T) {
	pb := &pqratchetpb.V1State{
		InnerState: &pqratchetpb.V1State_Ct2Sampled{
			Ct2Sampled: nil,
		},
	}
	_, err := protoV1StateToBraidState(pb)
	if err == nil {
		t.Fatal("expected error for nil Ct2Sampled")
	}
}

// TestProtoV1StateToBraidState_NilEkSentCt1Received verifies that a nil
// EkSentCt1Received inner state produces ErrProtoMissingField.
func TestProtoV1StateToBraidState_NilEkSentCt1Received(t *testing.T) {
	pb := &pqratchetpb.V1State{
		InnerState: &pqratchetpb.V1State_EkSentCt1Received{
			EkSentCt1Received: nil,
		},
	}
	_, err := protoV1StateToBraidState(pb)
	if err == nil {
		t.Fatal("expected error for nil EkSentCt1Received")
	}
}

// TestProtoV1StateToBraidState_NilCt1Acknowledged verifies that a nil
// Ct1Acknowledged inner state produces ErrProtoMissingField.
func TestProtoV1StateToBraidState_NilCt1Acknowledged(t *testing.T) {
	pb := &pqratchetpb.V1State{
		InnerState: &pqratchetpb.V1State_Ct1Acknowledged{
			Ct1Acknowledged: nil,
		},
	}
	_, err := protoV1StateToBraidState(pb)
	if err == nil {
		t.Fatal("expected error for nil Ct1Acknowledged")
	}
}

// TestProtoV1StateToBraidState_NilEkReceivedCt1Sampled verifies that a nil
// EkReceivedCt1Sampled inner state produces ErrProtoMissingField.
func TestProtoV1StateToBraidState_NilEkReceivedCt1Sampled(t *testing.T) {
	pb := &pqratchetpb.V1State{
		InnerState: &pqratchetpb.V1State_EkReceivedCt1Sampled{
			EkReceivedCt1Sampled: nil,
		},
	}
	_, err := protoV1StateToBraidState(pb)
	if err == nil {
		t.Fatal("expected error for nil EkReceivedCt1Sampled")
	}
}

// TestProtoV1StateToBraidState_NilHeaderReceived verifies that a nil HeaderReceived
// inner state produces ErrProtoMissingField.
func TestProtoV1StateToBraidState_NilHeaderReceived(t *testing.T) {
	pb := &pqratchetpb.V1State{
		InnerState: &pqratchetpb.V1State_HeaderReceived{
			HeaderReceived: nil,
		},
	}
	_, err := protoV1StateToBraidState(pb)
	if err == nil {
		t.Fatal("expected error for nil HeaderReceived")
	}
}

// TestProtoToSPQR_V1InnerWithNilV1State verifies that protoToSPQR returns an
// error when the Inner field wraps a V1 type with a nil V1State value.
func TestProtoToSPQR_V1InnerWithNilV1State(t *testing.T) {
	pb := &pqratchetpb.PqRatchetState{
		// Set Inner to a V1 wrapper with nil V1State.
		Inner: &pqratchetpb.PqRatchetState_V1{V1: nil},
	}
	_, err := protoToSPQR(pb)
	if err == nil {
		t.Fatal("expected error for nil V1 inner state")
	}
	var e *ErrProtoInvalidState
	if _, ok := err.(*ErrProtoInvalidState); !ok {
		t.Errorf("expected *ErrProtoInvalidState, got %T: %v", err, err)
	}
	_ = e
}

// TestProtoChainToSPQR_NilLinkInLinksSlice verifies that protoChainToSPQR
// propagates the error from protoEpochLinkToChain when a nil link is in the
// Links slice. This covers the error path at protoChainToSPQR line 947-949.
func TestProtoChainToSPQR_NilLinkInLinksSlice(t *testing.T) {
	pb := &pqratchetpb.PqRatchetState{
		Chain: &pqratchetpb.Chain{
			CurrentEpoch: 1,
			Links: []*pqratchetpb.Chain_Epoch{
				nil, // nil link triggers protoEpochLinkToChain error
			},
		},
	}
	_, err := protoToSPQR(pb)
	if err == nil {
		t.Fatal("expected error for nil link in chain.Links")
	}
}

// TestProtoEpochLinkToChain_ValidRecords verifies that protoEpochLinkToChain
// correctly deserializes a Rust-format prev field containing one valid
// (be32 idx | 32 B key) record and populates the skippedKeys map.
func TestProtoEpochLinkToChain_ValidRecords(t *testing.T) {
	const recSize = 4 + keyLen // 36 bytes
	prev := make([]byte, recSize)
	// counter = 7 in big-endian.
	prev[0], prev[1], prev[2], prev[3] = 0, 0, 0, 7
	for i := 4; i < recSize; i++ {
		prev[i] = byte(i + 0x42)
	}
	link := &pqratchetpb.Chain_Epoch{
		Recv: &pqratchetpb.Chain_Epoch_EpochDirection{
			Ctr:  10,
			Prev: prev,
		},
	}
	const testEpoch uint64 = 3
	skipped := make(map[SkippedKeyID]*secret.Secret)
	chain, err := protoEpochLinkToChain(link, testEpoch, skipped)
	if err != nil {
		t.Fatalf("protoEpochLinkToChain: %v", err)
	}
	defer chain.Zeroize()

	if chain.recvCounter != 10 {
		t.Errorf("recvCounter: got %d, want 10", chain.recvCounter)
	}
	id := SkippedKeyID{Epoch: testEpoch, Counter: 7}
	sk, ok := skipped[id]
	if !ok {
		t.Fatal("skippedKeys should contain counter 7 for epoch 3")
	}
	if !bytes.Equal(secrettest.Bytes(sk), prev[4:recSize]) {
		t.Error("skipped key bytes mismatch")
	}
	sk.Destroy()
}

// TestProtoEpochLinkToChain_InvalidPrevLength verifies that protoEpochLinkToChain
// returns ErrInvalidPrevEncoding when the prev field length is not a multiple of 36.
// A 32-byte prev is not a valid Rust KeyHistory (KEY_SIZE=36); it is rejected.
func TestProtoEpochLinkToChain_InvalidPrevLength(t *testing.T) {
	link := &pqratchetpb.Chain_Epoch{
		Recv: &pqratchetpb.Chain_Epoch_EpochDirection{
			Ctr:  5,
			Prev: make([]byte, keyLen), // 32 bytes: not a multiple of 36
		},
	}
	skipped := make(map[SkippedKeyID]*secret.Secret)
	_, err := protoEpochLinkToChain(link, 0, skipped)
	if err == nil {
		t.Fatal("expected ErrInvalidPrevEncoding for 32-byte prev")
	}
	if _, ok := err.(*ErrInvalidPrevEncoding); !ok {
		t.Errorf("expected *ErrInvalidPrevEncoding, got %T: %v", err, err)
	}
}

// TestProtoEpochLinkToChain_NilLinkReturnsError verifies that a nil link
// causes protoEpochLinkToChain to return ErrProtoMissingField.
func TestProtoEpochLinkToChain_NilLinkReturnsError(t *testing.T) {
	skipped := make(map[SkippedKeyID]*secret.Secret)
	_, err := protoEpochLinkToChain(nil, 0, skipped)
	if err == nil {
		t.Fatal("expected error for nil link")
	}
	if _, ok := err.(*ErrProtoMissingField); !ok {
		t.Errorf("expected *ErrProtoMissingField, got %T: %v", err, err)
	}
}

// TestInsertionSortEpochs is what actually pins the shift loop. Driving the
// sort through a map cannot: Go randomises iteration order, so a map-based test
// exercises the shift only on the runs where the shuffle happens to come out
// unsorted — which is why the function's measured coverage moved between
// otherwise identical runs. Feeding the slice directly makes every case
// deterministic.
func TestInsertionSortEpochs(t *testing.T) {
	for name, tc := range map[string]struct {
		in   []uint64
		want []uint64
	}{
		"reverse order":      {[]uint64{2, 1, 0}, []uint64{0, 1, 2}},
		"already sorted":     {[]uint64{0, 1, 2}, []uint64{0, 1, 2}},
		"last element first": {[]uint64{2, 0, 1}, []uint64{0, 1, 2}},
		"duplicates":         {[]uint64{1, 0, 1}, []uint64{0, 1, 1}},
		"single":             {[]uint64{7}, []uint64{7}},
		"empty":              {[]uint64{}, []uint64{}},
	} {
		t.Run(name, func(t *testing.T) {
			got := append([]uint64(nil), tc.in...)
			insertionSortEpochs(got)
			if len(got) != len(tc.want) {
				t.Fatalf("length changed: got %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// TestSortedEpochs_MultiEpoch verifies that sortedEpochs returns epochs in
// ascending order regardless of map iteration order. It cannot control that
// order, so it pins the collection-and-sort contract rather than the shift
// loop; TestInsertionSortEpochs above covers the loop deterministically.
func TestSortedEpochs_MultiEpoch(t *testing.T) {
	chains := map[uint64]*EpochChain{
		2: {},
		0: {},
		1: {},
	}
	got := sortedEpochs(chains)
	if len(got) != 3 {
		t.Fatalf("expected 3 epochs, got %d", len(got))
	}
	for i := 0; i+1 < len(got); i++ {
		if got[i] >= got[i+1] {
			t.Errorf("epochs not sorted at [%d]: %d >= %d", i, got[i], got[i+1])
		}
	}
	if got[0] != 0 || got[1] != 1 || got[2] != 2 {
		t.Errorf("expected [0, 1, 2], got %v", got)
	}
}

// TestSortedEpochs_SingleEpoch verifies sortedEpochs with a single entry.
func TestSortedEpochs_SingleEpoch(t *testing.T) {
	chains := map[uint64]*EpochChain{5: {}}
	got := sortedEpochs(chains)
	if len(got) != 1 || got[0] != 5 {
		t.Errorf("expected [5], got %v", got)
	}
}

// TestProtoCodec_ChainParamDefaults ensures default values encode as 0.
func TestProtoCodec_ChainParamDefaults(t *testing.T) {
	if chainParamMaxJump(maxJump) != 0 {
		t.Errorf("chainParamMaxJump(default) should be 0, got %d", chainParamMaxJump(maxJump))
	}
	if chainParamMaxOOO(maxSkippedKeys) != 0 {
		t.Errorf("chainParamMaxOOO(default) should be 0, got %d", chainParamMaxOOO(maxSkippedKeys))
	}
	if chainParamMaxJump(100) != 100 {
		t.Errorf("chainParamMaxJump(100) should be 100, got %d", chainParamMaxJump(100))
	}
	if chainParamMaxOOO(100) != 100 {
		t.Errorf("chainParamMaxOOO(100) should be 100, got %d", chainParamMaxOOO(100))
	}
}

// ─────────────── skipped-key round-trip tests (Finding #25) ──────────────────

// TestSkippedKeysPrevRoundTrip verifies that a Chain.Epoch with 3 skipped recv
// keys survives a full marshal → proto bytes → unmarshal cycle byte-for-byte.
// The skipped keys must be present in the deserialized SPQR.skippedKeys map
// with the correct epoch and counter indices (Rust format: KEY_SIZE=36,
// be32 idx | 32 B key per record).
func TestSkippedKeysPrevRoundTrip(t *testing.T) {
	sharedSecret := randomBytes(t, 32)

	// Build an SPQR with epoch 0 and inject 3 skipped recv keys at counters
	// 2, 4, 6 to simulate out-of-order messages arriving before counter 7.
	s, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	// Inject synthetic skipped keys for epoch 0 at counters 2, 4, 6.
	for _, ctr := range []uint32{2, 4, 6} {
		keyBytes := randomBytes(t, keyLen)
		sk, newErr := secret.New(keyBytes)
		if newErr != nil {
			t.Fatalf("secret.New counter=%d: %v", ctr, newErr)
		}
		s.skippedKeys[SkippedKeyID{Epoch: 0, Counter: ctr}] = sk
	}
	// Advance the recv counter to 7 so the skipped counters are behind it.
	s.chains[0].recvCounter = 7

	// Marshal to proto bytes.
	first, err := MarshalStateProto(s)
	if err != nil {
		t.Fatalf("MarshalStateProto: %v", err)
	}

	// Unmarshal back and verify skipped keys are restored.
	s2, err := UnmarshalStateProto(first)
	if err != nil {
		t.Fatalf("UnmarshalStateProto: %v", err)
	}
	defer s2.Zeroize()

	for _, ctr := range []uint32{2, 4, 6} {
		id := SkippedKeyID{Epoch: 0, Counter: ctr}
		sk, ok := s2.skippedKeys[id]
		if !ok {
			t.Errorf("skippedKeys missing counter %d after unmarshal", ctr)
			continue
		}
		// Verify the key from original matches the key from deserialized.
		origSk := s.skippedKeys[id]
		if !bytes.Equal(secrettest.Bytes(sk), secrettest.Bytes(origSk)) {
			t.Errorf("counter %d: key mismatch after round-trip", ctr)
		}
	}

	// Marshal again and verify proto bytes are identical (structural round-trip).
	second, err := MarshalStateProto(s2)
	if err != nil {
		t.Fatalf("MarshalStateProto (second): %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Errorf("proto bytes differ across round-trip:\nfirst:  %s\nsecond: %s",
			hex.EncodeToString(first), hex.EncodeToString(second))
	}
}

// TestSkippedKeysPrevRustFormat verifies that Go correctly parses a hand-typed
// Rust-format prev buffer (concatenation of (be32 idx | 32 B key) records).
// The test constant is derived from Rust's KeyHistory wire format as described
// in chain.rs: KEY_SIZE=36, add() appends k.0.to_be_bytes() ++ k.1 (32 bytes).
//
// Rust source: spqr/src/chain.rs KeyHistory::add (line 140-142):
//
//	self.data.extend_from_slice(&k.0.to_be_bytes()[..]);
//	self.data.extend_from_slice(&k.1[..]);
func TestSkippedKeysPrevRustFormat(t *testing.T) {
	// Construct a synthetic Rust-emitted prev buffer with 2 records:
	//   record 0: idx=0x00000001, key=0x01 02 ... 20 (1..=32)
	//   record 1: idx=0x00000064, key=0x64 65 ... 83 (100..=131)
	const recSize = 4 + keyLen
	prev := make([]byte, 2*recSize)

	// Record 0: idx=1.
	prev[0], prev[1], prev[2], prev[3] = 0, 0, 0, 1
	for i := 0; i < keyLen; i++ {
		prev[4+i] = byte(i + 1)
	}
	// Record 1: idx=100.
	off := recSize
	prev[off], prev[off+1], prev[off+2], prev[off+3] = 0, 0, 0, 100
	for i := 0; i < keyLen; i++ {
		prev[off+4+i] = byte(100 + i)
	}

	link := &pqratchetpb.Chain_Epoch{
		Recv: &pqratchetpb.Chain_Epoch_EpochDirection{
			Ctr:  200,
			Prev: prev,
		},
	}
	const testEpoch uint64 = 5
	skipped := make(map[SkippedKeyID]*secret.Secret)
	chain, err := protoEpochLinkToChain(link, testEpoch, skipped)
	if err != nil {
		t.Fatalf("protoEpochLinkToChain: %v", err)
	}
	defer chain.Zeroize()

	if chain.recvCounter != 200 {
		t.Errorf("recvCounter: got %d, want 200", chain.recvCounter)
	}
	if len(skipped) != 2 {
		t.Fatalf("skipped map: got %d entries, want 2", len(skipped))
	}

	// Verify record 0.
	id1 := SkippedKeyID{Epoch: testEpoch, Counter: 1}
	sk1, ok := skipped[id1]
	if !ok {
		t.Fatal("missing skipped key for counter=1")
	}
	wantKey1 := prev[4 : 4+keyLen]
	if !bytes.Equal(secrettest.Bytes(sk1), wantKey1) {
		t.Errorf("counter=1 key mismatch: got %x, want %x", secrettest.Bytes(sk1), wantKey1)
	}
	sk1.Destroy()

	// Verify record 1.
	id2 := SkippedKeyID{Epoch: testEpoch, Counter: 100}
	sk2, ok := skipped[id2]
	if !ok {
		t.Fatal("missing skipped key for counter=100")
	}
	wantKey2 := prev[recSize+4 : recSize+4+keyLen]
	if !bytes.Equal(secrettest.Bytes(sk2), wantKey2) {
		t.Errorf("counter=100 key mismatch: got %x, want %x", secrettest.Bytes(sk2), wantKey2)
	}
	sk2.Destroy()
}

// TestSkippedKeysPrevEmptyIsOK verifies that an empty prev field causes no
// error and leaves the skippedKeys map untouched.
func TestSkippedKeysPrevEmptyIsOK(t *testing.T) {
	link := &pqratchetpb.Chain_Epoch{
		Recv: &pqratchetpb.Chain_Epoch_EpochDirection{
			Ctr:  3,
			Prev: nil,
		},
	}
	skipped := make(map[SkippedKeyID]*secret.Secret)
	chain, err := protoEpochLinkToChain(link, 0, skipped)
	if err != nil {
		t.Fatalf("protoEpochLinkToChain: %v", err)
	}
	defer chain.Zeroize()
	if len(skipped) != 0 {
		t.Errorf("expected empty skipped map, got %d entries", len(skipped))
	}
}

// ─────────────────────────── helpers ─────────────────────────────────────────

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsSubstringHelper(s, sub))
}

func containsSubstringHelper(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
