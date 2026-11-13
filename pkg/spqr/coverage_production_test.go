package spqr

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
	pqratchetpb "github.com/jeremyhahn/go-libsignal/pkg/proto/pqratchetpb"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// ─────────────────────────────────────────────────────────────────────────────
// kdf.go — ErrInvalidInput early-return branches
// ─────────────────────────────────────────────────────────────────────────────

// TestKdfSckaInit_EmptySharedSecret covers the ErrInvalidInput guard at the
// top of KdfSckaInit.
func TestKdfSckaInit_EmptySharedSecret(t *testing.T) {
	_, _, _, err := KdfSckaInit(nil)
	if err == nil {
		t.Fatal("expected error for nil sharedSecret")
	}
	var want *ErrInvalidInput
	if !errors.As(err, &want) {
		t.Fatalf("want *ErrInvalidInput, got %T: %v", err, err)
	}
	if want.Field != "sharedSecret" {
		t.Errorf("ErrInvalidInput.Field = %q, want %q", want.Field, "sharedSecret")
	}

	// Zero-length (non-nil) slice also triggers the guard.
	_, _, _, err2 := KdfSckaInit([]byte{})
	if err2 == nil {
		t.Fatal("expected error for empty sharedSecret")
	}
	var want2 *ErrInvalidInput
	if !errors.As(err2, &want2) {
		t.Fatalf("want *ErrInvalidInput, got %T: %v", err2, err2)
	}
}

// TestKdfSckaRK_NilRK covers the nil rk guard in KdfSckaRK.
func TestKdfSckaRK_NilRK(t *testing.T) {
	_, _, _, err := KdfSckaRK(nil, []byte{0x01})
	if err == nil {
		t.Fatal("expected error for nil rk")
	}
	var want *ErrInvalidInput
	if !errors.As(err, &want) {
		t.Fatalf("want *ErrInvalidInput, got %T: %v", err, err)
	}
	if want.Field != "rk" {
		t.Errorf("ErrInvalidInput.Field = %q, want %q", want.Field, "rk")
	}
}

// TestKdfSckaRK_DestroyedRK covers the destroyed-secret guard in KdfSckaRK.
func TestKdfSckaRK_DestroyedRK(t *testing.T) {
	rkBytes := make([]byte, 32)
	rk, err := secret.New(rkBytes)
	if err != nil {
		t.Fatalf("secret.New: %v", err)
	}
	rk.Destroy()

	_, _, _, err = KdfSckaRK(rk, []byte{0x01})
	if err == nil {
		t.Fatal("expected error for destroyed rk")
	}
	var want *ErrInvalidInput
	if !errors.As(err, &want) {
		t.Fatalf("want *ErrInvalidInput, got %T: %v", err, err)
	}
	if want.Field != "rk" {
		t.Errorf("ErrInvalidInput.Field = %q, want %q", want.Field, "rk")
	}
}

// TestKdfSckaRK_EmptySckaOutput covers the empty sckaOutput guard in KdfSckaRK.
func TestKdfSckaRK_EmptySckaOutput(t *testing.T) {
	rkBytes := make([]byte, 32)
	for i := range rkBytes {
		rkBytes[i] = byte(i + 1)
	}
	rk, err := secret.New(rkBytes)
	if err != nil {
		t.Fatalf("secret.New: %v", err)
	}
	defer rk.Destroy()

	_, _, _, err = KdfSckaRK(rk, nil)
	if err == nil {
		t.Fatal("expected error for nil sckaOutput")
	}
	var want *ErrInvalidInput
	if !errors.As(err, &want) {
		t.Fatalf("want *ErrInvalidInput, got %T: %v", err, err)
	}
	if want.Field != "sckaOutput" {
		t.Errorf("ErrInvalidInput.Field = %q, want %q", want.Field, "sckaOutput")
	}

	_, _, _, err2 := KdfSckaRK(rk, []byte{})
	if err2 == nil {
		t.Fatal("expected error for empty sckaOutput")
	}
}

// TestKdfSckaCK_NilCK covers the nil ck guard in KdfSckaCK.
func TestKdfSckaCK_NilCK(t *testing.T) {
	_, _, err := KdfSckaCK(nil, 1)
	if err == nil {
		t.Fatal("expected error for nil ck")
	}
	var want *ErrInvalidInput
	if !errors.As(err, &want) {
		t.Fatalf("want *ErrInvalidInput, got %T: %v", err, err)
	}
	if want.Field != "ck" {
		t.Errorf("ErrInvalidInput.Field = %q, want %q", want.Field, "ck")
	}
}

// TestKdfSckaCK_DestroyedCK covers the destroyed-secret guard in KdfSckaCK.
func TestKdfSckaCK_DestroyedCK(t *testing.T) {
	ckBytes := make([]byte, 32)
	ck, err := secret.New(ckBytes)
	if err != nil {
		t.Fatalf("secret.New: %v", err)
	}
	ck.Destroy()

	_, _, err = KdfSckaCK(ck, 0)
	if err == nil {
		t.Fatal("expected error for destroyed ck")
	}
	var want *ErrInvalidInput
	if !errors.As(err, &want) {
		t.Fatalf("want *ErrInvalidInput, got %T: %v", err, err)
	}
	if want.Field != "ck" {
		t.Errorf("ErrInvalidInput.Field = %q, want %q", want.Field, "ck")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// proto_codec.go — encoderToProto / decoderToProto nil-arg branches
// ─────────────────────────────────────────────────────────────────────────────

// TestEncoderToProto_Nil covers the nil encoder guard in encoderToProto. The
// function is package-private so we reach it by marshaling a state whose
// ProtoHeaderEncoder() returns nil (KeysSampled state without a header encoder).
func TestEncoderToProto_Nil(t *testing.T) {
	// Build a KeysSampled state with a nil headerEncoder.
	auth := makeTestAuth(t, 50)
	dk := make([]byte, mlkembraid.MLKEM768FullEKSize)
	ekSeed := make([]byte, mlkembraid.EKSeedSize)
	ekVec := make([]byte, mlkembraid.MLKEM768EKSize)
	state, err := mlkembraid.ProtoSetFromFields(
		mlkembraid.StateKeysSampled, 0, mlkembraid.DefaultChunkSize,
		auth, dk, ekSeed, ekVec, nil, nil, nil, nil, nil, nil, nil,
		nil, // headerEncoder = nil → triggers encoderToProto(nil)
		nil, nil, nil, nil, nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("ProtoSetFromFields: %v", err)
	}
	braid := mlkembraid.BraidFromState(state, mlkembraid.NewMLKEM768IncrementalKEM(), mlkembraid.DefaultChunkSize)
	ss := sharedSecretForTest(50)
	s, err := Init(ss, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()
	s.braid = braid

	_, err = MarshalStateProto(s)
	if err == nil {
		t.Fatal("expected error marshaling KeysSampled with nil headerEncoder")
	}
	var want *ErrProtoMissingField
	if !errors.As(err, &want) {
		t.Fatalf("want *ErrProtoMissingField, got %T: %v", err, err)
	}
}

// TestDecoderToProto_Nil covers the nil decoder guard in decoderToProto. We
// reach it via marshalNoHeaderReceived which requires a headerDecoder.
func TestDecoderToProto_Nil(t *testing.T) {
	// Build a NoHeaderReceived state with nil headerDecoder.
	auth := makeTestAuth(t, 51)
	state, err := mlkembraid.ProtoSetFromFields(
		mlkembraid.StateNoHeaderReceived, 0, mlkembraid.DefaultChunkSize,
		auth, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil,
		nil, // headerDecoder = nil → triggers decoderToProto(nil)
		nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("ProtoSetFromFields: %v", err)
	}
	braid := mlkembraid.BraidFromState(state, mlkembraid.NewMLKEM768IncrementalKEM(), mlkembraid.DefaultChunkSize)
	ss := sharedSecretForTest(51)
	s, err := Init(ss, DirectionB2A, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()
	s.braid = braid

	_, err = MarshalStateProto(s)
	if err == nil {
		t.Fatal("expected error marshaling NoHeaderReceived with nil headerDecoder")
	}
	var want *ErrProtoMissingField
	if !errors.As(err, &want) {
		t.Fatalf("want *ErrProtoMissingField, got %T: %v", err, err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// proto_codec.go — authToProto: destroyed root_key path
// ─────────────────────────────────────────────────────────────────────────────

// TestAuthToProto_DestroyedRootKey covers the auth.root_key nil branch in
// authToProto. We build a state whose ProtoAuth().ProtoAuthRootKey() returns
// nil because the authenticator's root key has been destroyed.
func TestAuthToProto_DestroyedRootKey(t *testing.T) {
	auth := makeTestAuth(t, 52)
	// Destroy the authenticator so ProtoAuthRootKey() fails its borrow.
	auth.Zeroize()

	state, err := mlkembraid.ProtoSetFromFields(
		mlkembraid.StateKeysUnsampled, 0, mlkembraid.DefaultChunkSize,
		auth, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, nil, nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("ProtoSetFromFields: %v", err)
	}
	braid := mlkembraid.BraidFromState(state, mlkembraid.NewMLKEM768IncrementalKEM(), mlkembraid.DefaultChunkSize)
	ss := sharedSecretForTest(52)
	s, err := Init(ss, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()
	s.braid = braid

	_, err = MarshalStateProto(s)
	if err == nil {
		t.Fatal("expected error marshaling with destroyed authenticator root key")
	}
	// A destroyed key is reported as destroyed, not hidden as a missing field.
	if !errors.Is(err, secret.ErrSecretDestroyed) {
		t.Fatalf("want ErrSecretDestroyed, got %T: %v", err, err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// proto_codec.go — protoAuthToGo: nil proto arg
// ─────────────────────────────────────────────────────────────────────────────

// TestProtoAuthToGo_Nil covers the nil check in protoAuthToGo.
func TestProtoAuthToGo_Nil(t *testing.T) {
	_, err := protoAuthToGo(nil, 0)
	if err == nil {
		t.Fatal("expected error for nil proto auth")
	}
	var want *ErrProtoMissingField
	if !errors.As(err, &want) {
		t.Fatalf("want *ErrProtoMissingField, got %T: %v", err, err)
	}
	if want.Name != "auth" {
		t.Errorf("ErrProtoMissingField.Name = %q, want %q", want.Name, "auth")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// proto_codec.go — protoEncoderToGo: nil proto arg and unmarshal error
// ─────────────────────────────────────────────────────────────────────────────

// TestProtoEncoderToGo_Nil covers the nil check in protoEncoderToGo.
func TestProtoEncoderToGo_Nil(t *testing.T) {
	_, err := protoEncoderToGo(nil)
	if err == nil {
		t.Fatal("expected error for nil proto encoder")
	}
	var want *ErrProtoMissingField
	if !errors.As(err, &want) {
		t.Fatalf("want *ErrProtoMissingField, got %T: %v", err, err)
	}
	if want.Name != "encoder" {
		t.Errorf("ErrProtoMissingField.Name = %q, want %q", want.Name, "encoder")
	}
}

// TestProtoEncoderToGo_InvalidData covers the ProtoUnmarshalEncoder error path
// in protoEncoderToGo. Passing wrong pts channel count triggers the error.
func TestProtoEncoderToGo_InvalidData(t *testing.T) {
	// ProtoUnmarshalEncoder requires pts to have exactly NumPolys=16 channels
	// (when pts is non-empty). Providing an incorrect channel count triggers the
	// "want 16 channels" error.
	pb := &pqratchetpb.PolynomialEncoder{
		Idx: 0,
		Pts: [][]byte{
			{0x00, 0x01}, // only 1 channel instead of 16
		},
		Polys: nil,
	}
	_, err := protoEncoderToGo(pb)
	if err == nil {
		t.Fatal("expected error for malformed encoder proto")
	}
	var want *ErrProtoInvalidState
	if !errors.As(err, &want) {
		t.Fatalf("want *ErrProtoInvalidState, got %T: %v", err, err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// proto_codec.go — protoDecoderToGo: nil proto arg and unmarshal error
// ─────────────────────────────────────────────────────────────────────────────

// TestProtoDecoderToGo_Nil covers the nil check in protoDecoderToGo.
func TestProtoDecoderToGo_Nil(t *testing.T) {
	_, err := protoDecoderToGo(nil)
	if err == nil {
		t.Fatal("expected error for nil proto decoder")
	}
	var want *ErrProtoMissingField
	if !errors.As(err, &want) {
		t.Fatalf("want *ErrProtoMissingField, got %T: %v", err, err)
	}
	if want.Name != "decoder" {
		t.Errorf("ErrProtoMissingField.Name = %q, want %q", want.Name, "decoder")
	}
}

// TestProtoDecoderToGo_InvalidData covers the ProtoUnmarshalDecoder error path
// in protoDecoderToGo. ProtoUnmarshalDecoder requires pts to have exactly
// NumPolys=16 channels; fewer channels triggers the error.
func TestProtoDecoderToGo_InvalidData(t *testing.T) {
	pb := &pqratchetpb.PolynomialDecoder{
		PtsNeeded:  4,
		IsComplete: false,
		Pts: [][]byte{
			{0x00, 0x00, 0x00, 0x01}, // only 1 channel instead of 16
		},
	}
	_, err := protoDecoderToGo(pb)
	if err == nil {
		t.Fatal("expected error for malformed decoder proto")
	}
	var want *ErrProtoInvalidState
	if !errors.As(err, &want) {
		t.Fatalf("want *ErrProtoInvalidState, got %T: %v", err, err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// unmarshal* helpers — epoch=0 error (ErrProtoEpochOutOfRange) for each state
// ─────────────────────────────────────────────────────────────────────────────

// makeValidAuth returns a non-nil Authenticator proto for use in unmarshal tests.
func makeValidAuthProto(t *testing.T) *pqratchetpb.Authenticator {
	t.Helper()
	rk := make([]byte, 32)
	mk := make([]byte, 32)
	for i := range rk {
		rk[i] = byte(i + 1)
		mk[i] = byte(i + 2)
	}
	return &pqratchetpb.Authenticator{RootKey: rk, MacKey: mk}
}

// makeValidEncoder returns a minimal valid PolynomialEncoder proto for use in
// unmarshal tests. It uses empty pts and polys (zero-state encoder).
func makeValidEncoderProto(t *testing.T, msgLen int) *pqratchetpb.PolynomialEncoder {
	t.Helper()
	enc := makeTestEncoder(t, msgLen)
	fields, err := mlkembraid.ProtoMarshalEncoder(enc)
	if err != nil {
		t.Fatalf("ProtoMarshalEncoder: %v", err)
	}
	return &pqratchetpb.PolynomialEncoder{
		Idx:   fields.Idx,
		Pts:   fields.Pts,
		Polys: fields.Polys,
	}
}

// makeValidDecoderProto returns a minimal valid PolynomialDecoder proto.
func makeValidDecoderProto(t *testing.T, msgLen int) *pqratchetpb.PolynomialDecoder {
	t.Helper()
	dec := makeTestDecoder(t, msgLen)
	fields, err := mlkembraid.ProtoMarshalDecoder(dec)
	if err != nil {
		t.Fatalf("ProtoMarshalDecoder: %v", err)
	}
	return &pqratchetpb.PolynomialDecoder{
		PtsNeeded:  fields.PtsNeeded,
		IsComplete: fields.IsComplete,
		Pts:        fields.Pts,
	}
}

// assertEpochOutOfRange asserts that err is *ErrProtoEpochOutOfRange.
func assertEpochOutOfRange(t *testing.T, err error, context string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected error for epoch=0", context)
	}
	var want *ErrProtoEpochOutOfRange
	if !errors.As(err, &want) {
		t.Fatalf("%s: want *ErrProtoEpochOutOfRange, got %T: %v", context, err, err)
	}
}

// assertMissingField asserts that err is *ErrProtoMissingField with the given name.
func assertMissingField(t *testing.T, err error, name, context string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected ErrProtoMissingField(%q)", context, name)
	}
	var want *ErrProtoMissingField
	if !errors.As(err, &want) {
		t.Fatalf("%s: want *ErrProtoMissingField, got %T: %v", context, err, err)
	}
	if want.Name != name {
		t.Errorf("%s: ErrProtoMissingField.Name = %q, want %q", context, want.Name, name)
	}
}

// TestUnmarshalKeysUnsampled_EpochZero covers goEpoch(0) in unmarshalKeysUnsampled.
func TestUnmarshalKeysUnsampled_EpochZero(t *testing.T) {
	pb := &pqratchetpb.V1State_Chunked_KeysUnsampled{
		Uc: &pqratchetpb.V1State_Unchunked_KeysUnsampled{
			Epoch: 0, // proto epoch 0 is invalid → ErrProtoEpochOutOfRange
			Auth:  makeValidAuthProto(t),
		},
	}
	_, err := unmarshalKeysUnsampled(pb)
	assertEpochOutOfRange(t, err, "unmarshalKeysUnsampled/epoch=0")
}

// TestUnmarshalKeysUnsampled_NilAuth covers the nil auth path in unmarshalKeysUnsampled.
func TestUnmarshalKeysUnsampled_NilAuth(t *testing.T) {
	pb := &pqratchetpb.V1State_Chunked_KeysUnsampled{
		Uc: &pqratchetpb.V1State_Unchunked_KeysUnsampled{
			Epoch: 1, // valid proto epoch
			Auth:  nil,
		},
	}
	_, err := unmarshalKeysUnsampled(pb)
	assertMissingField(t, err, "auth", "unmarshalKeysUnsampled/nil-auth")
}

// TestUnmarshalKeysSampled_EpochZero covers goEpoch(0) in unmarshalKeysSampled.
func TestUnmarshalKeysSampled_EpochZero(t *testing.T) {
	enc := makeValidEncoderProto(t, mlkembraid.HeaderSize+mlkembraid.MacSize)
	ek := make([]byte, mlkembraid.EKSeedSize+mlkembraid.MLKEM768EKSize)
	pb := &pqratchetpb.V1State_Chunked_KeysSampled{
		Uc: &pqratchetpb.V1State_Unchunked_HeaderSent{
			Epoch: 0,
			Auth:  makeValidAuthProto(t),
			Ek:    ek,
			Dk:    make([]byte, 32),
		},
		SendingHdr: enc,
	}
	_, err := unmarshalKeysSampled(pb)
	assertEpochOutOfRange(t, err, "unmarshalKeysSampled/epoch=0")
}

// TestUnmarshalKeysSampled_NilAuth covers the nil auth path in unmarshalKeysSampled.
func TestUnmarshalKeysSampled_NilAuth(t *testing.T) {
	enc := makeValidEncoderProto(t, mlkembraid.HeaderSize+mlkembraid.MacSize)
	ek := make([]byte, mlkembraid.EKSeedSize+mlkembraid.MLKEM768EKSize)
	pb := &pqratchetpb.V1State_Chunked_KeysSampled{
		Uc: &pqratchetpb.V1State_Unchunked_HeaderSent{
			Epoch: 1,
			Auth:  nil,
			Ek:    ek,
			Dk:    make([]byte, 32),
		},
		SendingHdr: enc,
	}
	_, err := unmarshalKeysSampled(pb)
	assertMissingField(t, err, "auth", "unmarshalKeysSampled/nil-auth")
}

// TestUnmarshalKeysSampled_BadEkLength covers the wrong ek-length error.
func TestUnmarshalKeysSampled_BadEkLength(t *testing.T) {
	enc := makeValidEncoderProto(t, mlkembraid.HeaderSize+mlkembraid.MacSize)
	pb := &pqratchetpb.V1State_Chunked_KeysSampled{
		Uc: &pqratchetpb.V1State_Unchunked_HeaderSent{
			Epoch: 1,
			Auth:  makeValidAuthProto(t),
			Ek:    []byte{0x01, 0x02}, // wrong length
			Dk:    make([]byte, 32),
		},
		SendingHdr: enc,
	}
	_, err := unmarshalKeysSampled(pb)
	if err == nil {
		t.Fatal("expected error for bad ek length in unmarshalKeysSampled")
	}
	var want *ErrProtoInvalidState
	if !errors.As(err, &want) {
		t.Fatalf("want *ErrProtoInvalidState, got %T: %v", err, err)
	}
}

// TestUnmarshalKeysSampled_NilSendingHdr covers the nil SendingHdr encoder path.
func TestUnmarshalKeysSampled_NilSendingHdr(t *testing.T) {
	ek := make([]byte, mlkembraid.EKSeedSize+mlkembraid.MLKEM768EKSize)
	pb := &pqratchetpb.V1State_Chunked_KeysSampled{
		Uc: &pqratchetpb.V1State_Unchunked_HeaderSent{
			Epoch: 1,
			Auth:  makeValidAuthProto(t),
			Ek:    ek,
			Dk:    make([]byte, 32),
		},
		SendingHdr: nil, // nil encoder → protoEncoderToGo(nil) → ErrProtoMissingField
	}
	_, err := unmarshalKeysSampled(pb)
	assertMissingField(t, err, "encoder", "unmarshalKeysSampled/nil-sending-hdr")
}

// TestUnmarshalHeaderSent_EpochZero covers goEpoch(0) in unmarshalHeaderSent.
func TestUnmarshalHeaderSent_EpochZero(t *testing.T) {
	enc := makeValidEncoderProto(t, mlkembraid.MLKEM768EKSize)
	pb := &pqratchetpb.V1State_Chunked_HeaderSent{
		Uc: &pqratchetpb.V1State_Unchunked_EkSent{
			Epoch: 0,
			Auth:  makeValidAuthProto(t),
			Dk:    make([]byte, 32),
		},
		SendingEk: enc,
	}
	_, err := unmarshalHeaderSent(pb)
	assertEpochOutOfRange(t, err, "unmarshalHeaderSent/epoch=0")
}

// TestUnmarshalHeaderSent_NilAuth covers the nil auth path in unmarshalHeaderSent.
func TestUnmarshalHeaderSent_NilAuth(t *testing.T) {
	enc := makeValidEncoderProto(t, mlkembraid.MLKEM768EKSize)
	pb := &pqratchetpb.V1State_Chunked_HeaderSent{
		Uc: &pqratchetpb.V1State_Unchunked_EkSent{
			Epoch: 1,
			Auth:  nil,
			Dk:    make([]byte, 32),
		},
		SendingEk: enc,
	}
	_, err := unmarshalHeaderSent(pb)
	assertMissingField(t, err, "auth", "unmarshalHeaderSent/nil-auth")
}

// TestUnmarshalHeaderSent_NilSendingEk covers the nil SendingEk encoder path.
func TestUnmarshalHeaderSent_NilSendingEk(t *testing.T) {
	pb := &pqratchetpb.V1State_Chunked_HeaderSent{
		Uc: &pqratchetpb.V1State_Unchunked_EkSent{
			Epoch: 1,
			Auth:  makeValidAuthProto(t),
			Dk:    make([]byte, 32),
		},
		SendingEk: nil, // nil encoder → ErrProtoMissingField
	}
	_, err := unmarshalHeaderSent(pb)
	assertMissingField(t, err, "encoder", "unmarshalHeaderSent/nil-sending-ek")
}

// TestUnmarshalCt1Received_EpochZero covers goEpoch(0) in unmarshalCt1Received.
func TestUnmarshalCt1Received_EpochZero(t *testing.T) {
	enc := makeValidEncoderProto(t, mlkembraid.MLKEM768EKSize)
	pb := &pqratchetpb.V1State_Chunked_Ct1Received{
		Uc: &pqratchetpb.V1State_Unchunked_EkSentCt1Received{
			Epoch: 0,
			Auth:  makeValidAuthProto(t),
			Dk:    make([]byte, 32),
			Ct1:   make([]byte, mlkembraid.MLKEM768CT1Size),
		},
		SendingEk: enc,
	}
	_, err := unmarshalCt1Received(pb)
	assertEpochOutOfRange(t, err, "unmarshalCt1Received/epoch=0")
}

// TestUnmarshalCt1Received_NilAuth covers the nil auth path.
func TestUnmarshalCt1Received_NilAuth(t *testing.T) {
	enc := makeValidEncoderProto(t, mlkembraid.MLKEM768EKSize)
	pb := &pqratchetpb.V1State_Chunked_Ct1Received{
		Uc: &pqratchetpb.V1State_Unchunked_EkSentCt1Received{
			Epoch: 1,
			Auth:  nil,
			Dk:    make([]byte, 32),
			Ct1:   make([]byte, mlkembraid.MLKEM768CT1Size),
		},
		SendingEk: enc,
	}
	_, err := unmarshalCt1Received(pb)
	assertMissingField(t, err, "auth", "unmarshalCt1Received/nil-auth")
}

// TestUnmarshalCt1Received_NilSendingEk covers the nil ekEncoder path.
func TestUnmarshalCt1Received_NilSendingEk(t *testing.T) {
	pb := &pqratchetpb.V1State_Chunked_Ct1Received{
		Uc: &pqratchetpb.V1State_Unchunked_EkSentCt1Received{
			Epoch: 1,
			Auth:  makeValidAuthProto(t),
			Dk:    make([]byte, 32),
			Ct1:   make([]byte, mlkembraid.MLKEM768CT1Size),
		},
		SendingEk: nil,
	}
	_, err := unmarshalCt1Received(pb)
	assertMissingField(t, err, "encoder", "unmarshalCt1Received/nil-sending-ek")
}

// TestUnmarshalEkSentCt1Received_EpochZero covers goEpoch(0).
func TestUnmarshalEkSentCt1Received_EpochZero(t *testing.T) {
	dec := makeValidDecoderProto(t, mlkembraid.MLKEM768CT2Size)
	pb := &pqratchetpb.V1State_Chunked_EkSentCt1Received{
		Uc: &pqratchetpb.V1State_Unchunked_EkSentCt1Received{
			Epoch: 0,
			Auth:  makeValidAuthProto(t),
			Dk:    make([]byte, 32),
			Ct1:   make([]byte, mlkembraid.MLKEM768CT1Size),
		},
		ReceivingCt2: dec,
	}
	_, err := unmarshalEkSentCt1Received(pb)
	assertEpochOutOfRange(t, err, "unmarshalEkSentCt1Received/epoch=0")
}

// TestUnmarshalEkSentCt1Received_NilAuth covers the nil auth path.
func TestUnmarshalEkSentCt1Received_NilAuth(t *testing.T) {
	dec := makeValidDecoderProto(t, mlkembraid.MLKEM768CT2Size)
	pb := &pqratchetpb.V1State_Chunked_EkSentCt1Received{
		Uc: &pqratchetpb.V1State_Unchunked_EkSentCt1Received{
			Epoch: 1,
			Auth:  nil,
			Dk:    make([]byte, 32),
			Ct1:   make([]byte, mlkembraid.MLKEM768CT1Size),
		},
		ReceivingCt2: dec,
	}
	_, err := unmarshalEkSentCt1Received(pb)
	assertMissingField(t, err, "auth", "unmarshalEkSentCt1Received/nil-auth")
}

// TestUnmarshalEkSentCt1Received_NilReceivingCt2 covers the nil ct2 decoder path.
func TestUnmarshalEkSentCt1Received_NilReceivingCt2(t *testing.T) {
	pb := &pqratchetpb.V1State_Chunked_EkSentCt1Received{
		Uc: &pqratchetpb.V1State_Unchunked_EkSentCt1Received{
			Epoch: 1,
			Auth:  makeValidAuthProto(t),
			Dk:    make([]byte, 32),
			Ct1:   make([]byte, mlkembraid.MLKEM768CT1Size),
		},
		ReceivingCt2: nil,
	}
	_, err := unmarshalEkSentCt1Received(pb)
	assertMissingField(t, err, "decoder", "unmarshalEkSentCt1Received/nil-receiving-ct2")
}

// TestUnmarshalNoHeaderReceived_EpochZero covers goEpoch(0) in unmarshalNoHeaderReceived.
func TestUnmarshalNoHeaderReceived_EpochZero(t *testing.T) {
	dec := makeValidDecoderProto(t, mlkembraid.HeaderSize+mlkembraid.MacSize)
	pb := &pqratchetpb.V1State_Chunked_NoHeaderReceived{
		Uc: &pqratchetpb.V1State_Unchunked_NoHeaderReceived{
			Epoch: 0,
			Auth:  makeValidAuthProto(t),
		},
		ReceivingHdr: dec,
	}
	_, err := unmarshalNoHeaderReceived(pb)
	assertEpochOutOfRange(t, err, "unmarshalNoHeaderReceived/epoch=0")
}

// TestUnmarshalNoHeaderReceived_NilAuth covers the nil auth path.
func TestUnmarshalNoHeaderReceived_NilAuth(t *testing.T) {
	dec := makeValidDecoderProto(t, mlkembraid.HeaderSize+mlkembraid.MacSize)
	pb := &pqratchetpb.V1State_Chunked_NoHeaderReceived{
		Uc: &pqratchetpb.V1State_Unchunked_NoHeaderReceived{
			Epoch: 1,
			Auth:  nil,
		},
		ReceivingHdr: dec,
	}
	_, err := unmarshalNoHeaderReceived(pb)
	assertMissingField(t, err, "auth", "unmarshalNoHeaderReceived/nil-auth")
}

// TestUnmarshalNoHeaderReceived_NilReceivingHdr covers the nil hdr decoder path.
func TestUnmarshalNoHeaderReceived_NilReceivingHdr(t *testing.T) {
	pb := &pqratchetpb.V1State_Chunked_NoHeaderReceived{
		Uc: &pqratchetpb.V1State_Unchunked_NoHeaderReceived{
			Epoch: 1,
			Auth:  makeValidAuthProto(t),
		},
		ReceivingHdr: nil,
	}
	_, err := unmarshalNoHeaderReceived(pb)
	assertMissingField(t, err, "decoder", "unmarshalNoHeaderReceived/nil-receiving-hdr")
}

// TestUnmarshalHeaderReceived_EpochZero covers goEpoch(0) in unmarshalHeaderReceived.
func TestUnmarshalHeaderReceived_EpochZero(t *testing.T) {
	hdr := make([]byte, mlkembraid.HeaderSize)
	pb := &pqratchetpb.V1State_Chunked_HeaderReceived{
		Uc: &pqratchetpb.V1State_Unchunked_HeaderReceived{
			Epoch: 0,
			Auth:  makeValidAuthProto(t),
			Hdr:   hdr,
		},
	}
	_, err := unmarshalHeaderReceived(pb)
	assertEpochOutOfRange(t, err, "unmarshalHeaderReceived/epoch=0")
}

// TestUnmarshalHeaderReceived_NilAuth covers the nil auth path.
func TestUnmarshalHeaderReceived_NilAuth(t *testing.T) {
	hdr := make([]byte, mlkembraid.HeaderSize)
	pb := &pqratchetpb.V1State_Chunked_HeaderReceived{
		Uc: &pqratchetpb.V1State_Unchunked_HeaderReceived{
			Epoch: 1,
			Auth:  nil,
			Hdr:   hdr,
		},
	}
	_, err := unmarshalHeaderReceived(pb)
	assertMissingField(t, err, "auth", "unmarshalHeaderReceived/nil-auth")
}

// TestUnmarshalHeaderReceived_BadHdrLength covers the wrong hdr-length error.
func TestUnmarshalHeaderReceived_BadHdrLength(t *testing.T) {
	pb := &pqratchetpb.V1State_Chunked_HeaderReceived{
		Uc: &pqratchetpb.V1State_Unchunked_HeaderReceived{
			Epoch: 1,
			Auth:  makeValidAuthProto(t),
			Hdr:   []byte{0x01, 0x02}, // wrong length
		},
	}
	_, err := unmarshalHeaderReceived(pb)
	if err == nil {
		t.Fatal("expected error for wrong hdr length in unmarshalHeaderReceived")
	}
	var want *ErrProtoInvalidState
	if !errors.As(err, &want) {
		t.Fatalf("want *ErrProtoInvalidState, got %T: %v", err, err)
	}
}

// TestUnmarshalCt1Sampled_EpochZero covers goEpoch(0) in unmarshalCt1Sampled.
func TestUnmarshalCt1Sampled_EpochZero(t *testing.T) {
	hdr := make([]byte, mlkembraid.HeaderSize)
	ct1Enc := makeValidEncoderProto(t, mlkembraid.MLKEM768CT1Size)
	ekDec := makeValidDecoderProto(t, mlkembraid.MLKEM768EKSize)
	pb := &pqratchetpb.V1State_Chunked_Ct1Sampled{
		Uc: &pqratchetpb.V1State_Unchunked_Ct1Sent{
			Epoch: 0,
			Auth:  makeValidAuthProto(t),
			Hdr:   hdr,
			Es:    make([]byte, mlkembraid.MLKEM768EncapStateSize),
			Ct1:   make([]byte, mlkembraid.MLKEM768CT1Size),
		},
		SendingCt1:  ct1Enc,
		ReceivingEk: ekDec,
	}
	_, err := unmarshalCt1Sampled(pb)
	assertEpochOutOfRange(t, err, "unmarshalCt1Sampled/epoch=0")
}

// TestUnmarshalCt1Sampled_NilAuth covers the nil auth path.
func TestUnmarshalCt1Sampled_NilAuth(t *testing.T) {
	hdr := make([]byte, mlkembraid.HeaderSize)
	ct1Enc := makeValidEncoderProto(t, mlkembraid.MLKEM768CT1Size)
	ekDec := makeValidDecoderProto(t, mlkembraid.MLKEM768EKSize)
	pb := &pqratchetpb.V1State_Chunked_Ct1Sampled{
		Uc: &pqratchetpb.V1State_Unchunked_Ct1Sent{
			Epoch: 1,
			Auth:  nil,
			Hdr:   hdr,
			Es:    make([]byte, mlkembraid.MLKEM768EncapStateSize),
			Ct1:   make([]byte, mlkembraid.MLKEM768CT1Size),
		},
		SendingCt1:  ct1Enc,
		ReceivingEk: ekDec,
	}
	_, err := unmarshalCt1Sampled(pb)
	assertMissingField(t, err, "auth", "unmarshalCt1Sampled/nil-auth")
}

// TestUnmarshalCt1Sampled_BadHdrLength covers the wrong hdr-length error.
func TestUnmarshalCt1Sampled_BadHdrLength(t *testing.T) {
	ct1Enc := makeValidEncoderProto(t, mlkembraid.MLKEM768CT1Size)
	ekDec := makeValidDecoderProto(t, mlkembraid.MLKEM768EKSize)
	pb := &pqratchetpb.V1State_Chunked_Ct1Sampled{
		Uc: &pqratchetpb.V1State_Unchunked_Ct1Sent{
			Epoch: 1,
			Auth:  makeValidAuthProto(t),
			Hdr:   []byte{0x01}, // wrong length
			Es:    make([]byte, mlkembraid.MLKEM768EncapStateSize),
			Ct1:   make([]byte, mlkembraid.MLKEM768CT1Size),
		},
		SendingCt1:  ct1Enc,
		ReceivingEk: ekDec,
	}
	_, err := unmarshalCt1Sampled(pb)
	if err == nil {
		t.Fatal("expected error for wrong hdr length in unmarshalCt1Sampled")
	}
	var want *ErrProtoInvalidState
	if !errors.As(err, &want) {
		t.Fatalf("want *ErrProtoInvalidState, got %T: %v", err, err)
	}
}

// TestUnmarshalCt1Sampled_NilSendingCt1 covers the nil ct1Encoder path.
func TestUnmarshalCt1Sampled_NilSendingCt1(t *testing.T) {
	hdr := make([]byte, mlkembraid.HeaderSize)
	ekDec := makeValidDecoderProto(t, mlkembraid.MLKEM768EKSize)
	pb := &pqratchetpb.V1State_Chunked_Ct1Sampled{
		Uc: &pqratchetpb.V1State_Unchunked_Ct1Sent{
			Epoch: 1,
			Auth:  makeValidAuthProto(t),
			Hdr:   hdr,
			Es:    make([]byte, mlkembraid.MLKEM768EncapStateSize),
			Ct1:   make([]byte, mlkembraid.MLKEM768CT1Size),
		},
		SendingCt1:  nil, // nil encoder
		ReceivingEk: ekDec,
	}
	_, err := unmarshalCt1Sampled(pb)
	assertMissingField(t, err, "encoder", "unmarshalCt1Sampled/nil-sending-ct1")
}

// TestUnmarshalCt1Sampled_NilReceivingEk covers the nil ekDecoder path.
func TestUnmarshalCt1Sampled_NilReceivingEk(t *testing.T) {
	hdr := make([]byte, mlkembraid.HeaderSize)
	ct1Enc := makeValidEncoderProto(t, mlkembraid.MLKEM768CT1Size)
	pb := &pqratchetpb.V1State_Chunked_Ct1Sampled{
		Uc: &pqratchetpb.V1State_Unchunked_Ct1Sent{
			Epoch: 1,
			Auth:  makeValidAuthProto(t),
			Hdr:   hdr,
			Es:    make([]byte, mlkembraid.MLKEM768EncapStateSize),
			Ct1:   make([]byte, mlkembraid.MLKEM768CT1Size),
		},
		SendingCt1:  ct1Enc,
		ReceivingEk: nil, // nil decoder
	}
	_, err := unmarshalCt1Sampled(pb)
	assertMissingField(t, err, "decoder", "unmarshalCt1Sampled/nil-receiving-ek")
}

// TestUnmarshalEkReceivedCt1Sampled_EpochZero covers goEpoch(0).
func TestUnmarshalEkReceivedCt1Sampled_EpochZero(t *testing.T) {
	ct1Enc := makeValidEncoderProto(t, mlkembraid.MLKEM768CT1Size)
	pb := &pqratchetpb.V1State_Chunked_EkReceivedCt1Sampled{
		Uc: &pqratchetpb.V1State_Unchunked_Ct1SentEkReceived{
			Epoch: 0,
			Auth:  makeValidAuthProto(t),
			Es:    make([]byte, mlkembraid.MLKEM768EncapStateSize),
			Ek:    make([]byte, mlkembraid.MLKEM768EKSize),
			Ct1:   make([]byte, mlkembraid.MLKEM768CT1Size),
		},
		SendingCt1: ct1Enc,
	}
	_, err := unmarshalEkReceivedCt1Sampled(pb)
	assertEpochOutOfRange(t, err, "unmarshalEkReceivedCt1Sampled/epoch=0")
}

// TestUnmarshalEkReceivedCt1Sampled_NilAuth covers the nil auth path.
func TestUnmarshalEkReceivedCt1Sampled_NilAuth(t *testing.T) {
	ct1Enc := makeValidEncoderProto(t, mlkembraid.MLKEM768CT1Size)
	pb := &pqratchetpb.V1State_Chunked_EkReceivedCt1Sampled{
		Uc: &pqratchetpb.V1State_Unchunked_Ct1SentEkReceived{
			Epoch: 1,
			Auth:  nil,
			Es:    make([]byte, mlkembraid.MLKEM768EncapStateSize),
			Ek:    make([]byte, mlkembraid.MLKEM768EKSize),
			Ct1:   make([]byte, mlkembraid.MLKEM768CT1Size),
		},
		SendingCt1: ct1Enc,
	}
	_, err := unmarshalEkReceivedCt1Sampled(pb)
	assertMissingField(t, err, "auth", "unmarshalEkReceivedCt1Sampled/nil-auth")
}

// TestUnmarshalEkReceivedCt1Sampled_NilSendingCt1 covers the nil ct1Encoder path.
func TestUnmarshalEkReceivedCt1Sampled_NilSendingCt1(t *testing.T) {
	pb := &pqratchetpb.V1State_Chunked_EkReceivedCt1Sampled{
		Uc: &pqratchetpb.V1State_Unchunked_Ct1SentEkReceived{
			Epoch: 1,
			Auth:  makeValidAuthProto(t),
			Es:    make([]byte, mlkembraid.MLKEM768EncapStateSize),
			Ek:    make([]byte, mlkembraid.MLKEM768EKSize),
			Ct1:   make([]byte, mlkembraid.MLKEM768CT1Size),
		},
		SendingCt1: nil, // nil encoder
	}
	_, err := unmarshalEkReceivedCt1Sampled(pb)
	assertMissingField(t, err, "encoder", "unmarshalEkReceivedCt1Sampled/nil-sending-ct1")
}

// TestUnmarshalCt1Acknowledged_EpochZero covers goEpoch(0).
func TestUnmarshalCt1Acknowledged_EpochZero(t *testing.T) {
	hdr := make([]byte, mlkembraid.HeaderSize)
	ekDec := makeValidDecoderProto(t, mlkembraid.MLKEM768EKSize)
	pb := &pqratchetpb.V1State_Chunked_Ct1Acknowledged{
		Uc: &pqratchetpb.V1State_Unchunked_Ct1Sent{
			Epoch: 0,
			Auth:  makeValidAuthProto(t),
			Hdr:   hdr,
			Es:    make([]byte, mlkembraid.MLKEM768EncapStateSize),
			Ct1:   make([]byte, mlkembraid.MLKEM768CT1Size),
		},
		ReceivingEk: ekDec,
	}
	_, err := unmarshalCt1Acknowledged(pb)
	assertEpochOutOfRange(t, err, "unmarshalCt1Acknowledged/epoch=0")
}

// TestUnmarshalCt1Acknowledged_NilAuth covers the nil auth path.
func TestUnmarshalCt1Acknowledged_NilAuth(t *testing.T) {
	hdr := make([]byte, mlkembraid.HeaderSize)
	ekDec := makeValidDecoderProto(t, mlkembraid.MLKEM768EKSize)
	pb := &pqratchetpb.V1State_Chunked_Ct1Acknowledged{
		Uc: &pqratchetpb.V1State_Unchunked_Ct1Sent{
			Epoch: 1,
			Auth:  nil,
			Hdr:   hdr,
			Es:    make([]byte, mlkembraid.MLKEM768EncapStateSize),
			Ct1:   make([]byte, mlkembraid.MLKEM768CT1Size),
		},
		ReceivingEk: ekDec,
	}
	_, err := unmarshalCt1Acknowledged(pb)
	assertMissingField(t, err, "auth", "unmarshalCt1Acknowledged/nil-auth")
}

// TestUnmarshalCt1Acknowledged_BadHdrLength covers the wrong hdr-length error.
func TestUnmarshalCt1Acknowledged_BadHdrLength(t *testing.T) {
	ekDec := makeValidDecoderProto(t, mlkembraid.MLKEM768EKSize)
	pb := &pqratchetpb.V1State_Chunked_Ct1Acknowledged{
		Uc: &pqratchetpb.V1State_Unchunked_Ct1Sent{
			Epoch: 1,
			Auth:  makeValidAuthProto(t),
			Hdr:   []byte{0x01}, // wrong length
			Es:    make([]byte, mlkembraid.MLKEM768EncapStateSize),
			Ct1:   make([]byte, mlkembraid.MLKEM768CT1Size),
		},
		ReceivingEk: ekDec,
	}
	_, err := unmarshalCt1Acknowledged(pb)
	if err == nil {
		t.Fatal("expected error for wrong hdr length in unmarshalCt1Acknowledged")
	}
	var want *ErrProtoInvalidState
	if !errors.As(err, &want) {
		t.Fatalf("want *ErrProtoInvalidState, got %T: %v", err, err)
	}
}

// TestUnmarshalCt1Acknowledged_NilReceivingEk covers the nil ekDecoder path.
func TestUnmarshalCt1Acknowledged_NilReceivingEk(t *testing.T) {
	hdr := make([]byte, mlkembraid.HeaderSize)
	pb := &pqratchetpb.V1State_Chunked_Ct1Acknowledged{
		Uc: &pqratchetpb.V1State_Unchunked_Ct1Sent{
			Epoch: 1,
			Auth:  makeValidAuthProto(t),
			Hdr:   hdr,
			Es:    make([]byte, mlkembraid.MLKEM768EncapStateSize),
			Ct1:   make([]byte, mlkembraid.MLKEM768CT1Size),
		},
		ReceivingEk: nil, // nil decoder
	}
	_, err := unmarshalCt1Acknowledged(pb)
	assertMissingField(t, err, "decoder", "unmarshalCt1Acknowledged/nil-receiving-ek")
}

// TestUnmarshalCt2Sampled_EpochZero covers goEpoch(0) in unmarshalCt2Sampled.
func TestUnmarshalCt2Sampled_EpochZero(t *testing.T) {
	ct2Enc := makeValidEncoderProto(t, mlkembraid.MLKEM768CT2Size)
	pb := &pqratchetpb.V1State_Chunked_Ct2Sampled{
		Uc: &pqratchetpb.V1State_Unchunked_Ct2Sent{
			Epoch: 0,
			Auth:  makeValidAuthProto(t),
		},
		SendingCt2: ct2Enc,
	}
	_, err := unmarshalCt2Sampled(pb)
	assertEpochOutOfRange(t, err, "unmarshalCt2Sampled/epoch=0")
}

// TestUnmarshalCt2Sampled_NilAuth covers the nil auth path.
func TestUnmarshalCt2Sampled_NilAuth(t *testing.T) {
	ct2Enc := makeValidEncoderProto(t, mlkembraid.MLKEM768CT2Size)
	pb := &pqratchetpb.V1State_Chunked_Ct2Sampled{
		Uc: &pqratchetpb.V1State_Unchunked_Ct2Sent{
			Epoch: 1,
			Auth:  nil,
		},
		SendingCt2: ct2Enc,
	}
	_, err := unmarshalCt2Sampled(pb)
	assertMissingField(t, err, "auth", "unmarshalCt2Sampled/nil-auth")
}

// TestUnmarshalCt2Sampled_NilSendingCt2 covers the nil ct2Encoder path.
func TestUnmarshalCt2Sampled_NilSendingCt2(t *testing.T) {
	pb := &pqratchetpb.V1State_Chunked_Ct2Sampled{
		Uc: &pqratchetpb.V1State_Unchunked_Ct2Sent{
			Epoch: 1,
			Auth:  makeValidAuthProto(t),
		},
		SendingCt2: nil, // nil encoder
	}
	_, err := unmarshalCt2Sampled(pb)
	assertMissingField(t, err, "encoder", "unmarshalCt2Sampled/nil-sending-ct2")
}

// ─────────────────────────────────────────────────────────────────────────────
// stateKindToInnerState — error propagation for each state variant
// ─────────────────────────────────────────────────────────────────────────────

// TestStateKindToInnerState_KeysSampled_ErrorPropagation verifies that an error
// from marshalKeysSampled (missing ekSeed) propagates through stateKindToInnerState.
func TestStateKindToInnerState_KeysSampled_MissingEkSeed(t *testing.T) {
	auth := makeTestAuth(t, 60)
	// No ekSeed → marshalKeysSampled returns ErrProtoMissingField.
	state, err := mlkembraid.ProtoSetFromFields(
		mlkembraid.StateKeysSampled, 0, mlkembraid.DefaultChunkSize,
		auth, make([]byte, 32), nil, nil, nil, nil, nil, nil, nil, nil, nil,
		makeTestEncoder(t, mlkembraid.HeaderSize+mlkembraid.MacSize),
		nil, nil, nil, nil, nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("ProtoSetFromFields: %v", err)
	}
	pb := &pqratchetpb.V1State{}
	err = stateKindToInnerState(state, pb, &braidCopies{})
	if err == nil {
		t.Fatal("expected error from stateKindToInnerState with missing ekSeed")
	}
	var want *ErrProtoMissingField
	if !errors.As(err, &want) {
		t.Fatalf("want *ErrProtoMissingField, got %T: %v", err, err)
	}
}

// TestStateKindToInnerState_HeaderSent_MissingDK verifies error propagation for
// HeaderSent state missing the dk field.
func TestStateKindToInnerState_HeaderSent_MissingDK(t *testing.T) {
	auth := makeTestAuth(t, 61)
	// No dk → marshalHeaderSent returns ErrProtoMissingField for "HeaderSent.dk".
	state, err := mlkembraid.ProtoSetFromFields(
		mlkembraid.StateHeaderSent, 0, mlkembraid.DefaultChunkSize,
		auth, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil,
		makeTestEncoder(t, mlkembraid.MLKEM768EKSize),
		nil, nil, nil, nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("ProtoSetFromFields: %v", err)
	}
	pb := &pqratchetpb.V1State{}
	err = stateKindToInnerState(state, pb, &braidCopies{})
	if err == nil {
		t.Fatal("expected error from stateKindToInnerState with missing dk (HeaderSent)")
	}
	var want *ErrProtoMissingField
	if !errors.As(err, &want) {
		t.Fatalf("want *ErrProtoMissingField, got %T: %v", err, err)
	}
}

// TestStateKindToInnerState_Ct1Received_MissingDK verifies error propagation for
// Ct1Received state missing dk.
func TestStateKindToInnerState_Ct1Received_MissingDK(t *testing.T) {
	auth := makeTestAuth(t, 62)
	state, err := mlkembraid.ProtoSetFromFields(
		mlkembraid.StateCt1Received, 0, mlkembraid.DefaultChunkSize,
		auth, nil, nil, nil,
		make([]byte, mlkembraid.MLKEM768CT1Size), // ct1
		nil, nil, nil, nil, nil, nil,
		nil,
		makeTestEncoder(t, mlkembraid.MLKEM768EKSize),
		nil, nil, nil, nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("ProtoSetFromFields: %v", err)
	}
	pb := &pqratchetpb.V1State{}
	err = stateKindToInnerState(state, pb, &braidCopies{})
	if err == nil {
		t.Fatal("expected error from stateKindToInnerState with missing dk (Ct1Received)")
	}
	var want *ErrProtoMissingField
	if !errors.As(err, &want) {
		t.Fatalf("want *ErrProtoMissingField, got %T: %v", err, err)
	}
}

// TestStateKindToInnerState_EkSentCt1Received_MissingDK verifies error propagation
// for EkSentCt1Received state missing dk.
func TestStateKindToInnerState_EkSentCt1Received_MissingDK(t *testing.T) {
	auth := makeTestAuth(t, 63)
	state, err := mlkembraid.ProtoSetFromFields(
		mlkembraid.StateEkSentCt1Received, 0, mlkembraid.DefaultChunkSize,
		auth, nil, nil, nil,
		make([]byte, mlkembraid.MLKEM768CT1Size),
		nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, nil, nil, nil,
		makeTestDecoder(t, mlkembraid.MLKEM768CT2Size),
	)
	if err != nil {
		t.Fatalf("ProtoSetFromFields: %v", err)
	}
	pb := &pqratchetpb.V1State{}
	err = stateKindToInnerState(state, pb, &braidCopies{})
	if err == nil {
		t.Fatal("expected error from stateKindToInnerState with missing dk (EkSentCt1Received)")
	}
	var want *ErrProtoMissingField
	if !errors.As(err, &want) {
		t.Fatalf("want *ErrProtoMissingField, got %T: %v", err, err)
	}
}

// TestStateKindToInnerState_NoHeaderReceived_MissingDecoder verifies error
// propagation for NoHeaderReceived state missing headerDecoder.
func TestStateKindToInnerState_NoHeaderReceived_MissingDecoder(t *testing.T) {
	auth := makeTestAuth(t, 64)
	state, err := mlkembraid.ProtoSetFromFields(
		mlkembraid.StateNoHeaderReceived, 0, mlkembraid.DefaultChunkSize,
		auth, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil,
		nil, // headerDecoder nil → ErrProtoMissingField
		nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("ProtoSetFromFields: %v", err)
	}
	pb := &pqratchetpb.V1State{}
	err = stateKindToInnerState(state, pb, &braidCopies{})
	if err == nil {
		t.Fatal("expected error from stateKindToInnerState with missing headerDecoder (NoHeaderReceived)")
	}
	var want *ErrProtoMissingField
	if !errors.As(err, &want) {
		t.Fatalf("want *ErrProtoMissingField, got %T: %v", err, err)
	}
}

// TestStateKindToInnerState_Ct2Sampled_MissingEncoder verifies error propagation
// for Ct2Sampled state missing ct2Encoder.
func TestStateKindToInnerState_Ct2Sampled_MissingEncoder(t *testing.T) {
	auth := makeTestAuth(t, 65)
	state, err := mlkembraid.ProtoSetFromFields(
		mlkembraid.StateCt2Sampled, 0, mlkembraid.DefaultChunkSize,
		auth, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil,
		nil, // ct2Encoder nil → ErrProtoMissingField
		nil, nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("ProtoSetFromFields: %v", err)
	}
	pb := &pqratchetpb.V1State{}
	err = stateKindToInnerState(state, pb, &braidCopies{})
	if err == nil {
		t.Fatal("expected error from stateKindToInnerState with missing ct2Encoder (Ct2Sampled)")
	}
	var want *ErrProtoMissingField
	if !errors.As(err, &want) {
		t.Fatalf("want *ErrProtoMissingField, got %T: %v", err, err)
	}
}

// TestStateKindToInnerState_Ct1Sampled_MissingCt1 verifies error propagation for
// Ct1Sampled state where bobCt1 is nil.
func TestStateKindToInnerState_Ct1Sampled_MissingCt1(t *testing.T) {
	auth := makeTestAuth(t, 66)
	// ProtoSetFromFields param order (positions 4-22):
	//   auth, dk, ekSeed, ekVector, receivedCt1,
	//   bobEkSeed, bobHek, bobEncapSecret, bobEkVector, bobCt1, bobSS,
	//   headerEncoder, ekEncoder, ct1Encoder, ct2Encoder,
	//   headerDecoder, ekDecoder, ct1Decoder, ct2Decoder
	// bobCt1 = nil → marshalCt1Sampled returns ErrProtoMissingField for "Ct1Sampled.bobCt1".
	state, err := mlkembraid.ProtoSetFromFields(
		mlkembraid.StateCt1Sampled, 0, mlkembraid.DefaultChunkSize,
		auth,
		nil,                                 // dk
		nil,                                 // ekSeed
		nil,                                 // ekVector
		nil,                                 // receivedCt1
		make([]byte, mlkembraid.EKSeedSize), // bobEkSeed
		make([]byte, 32),                    // bobHek
		make([]byte, mlkembraid.MLKEM768EncapStateSize), // bobEncapSecret
		nil, // bobEkVector
		nil, // bobCt1 = nil → triggers error
		nil, // bobSS
		nil, // headerEncoder
		nil, // ekEncoder
		makeTestEncoder(t, mlkembraid.MLKEM768CT1Size), // ct1Encoder
		nil, // ct2Encoder
		nil, // headerDecoder
		makeTestDecoder(t, mlkembraid.MLKEM768EKSize), // ekDecoder
		nil, // ct1Decoder
		nil, // ct2Decoder
	)
	if err != nil {
		t.Fatalf("ProtoSetFromFields: %v", err)
	}
	pb := &pqratchetpb.V1State{}
	err = stateKindToInnerState(state, pb, &braidCopies{})
	if err == nil {
		t.Fatal("expected error from stateKindToInnerState with nil bobCt1 (Ct1Sampled)")
	}
	var want *ErrProtoMissingField
	if !errors.As(err, &want) {
		t.Fatalf("want *ErrProtoMissingField, got %T: %v", err, err)
	}
}

// TestStateKindToInnerState_EkReceivedCt1Sampled_MissingCt1 verifies error
// propagation for EkReceivedCt1Sampled state where bobCt1 is nil.
func TestStateKindToInnerState_EkReceivedCt1Sampled_MissingCt1(t *testing.T) {
	auth := makeTestAuth(t, 67)
	state, err := mlkembraid.ProtoSetFromFields(
		mlkembraid.StateEkReceivedCt1Sampled, 0, mlkembraid.DefaultChunkSize,
		auth,
		nil, // dk
		nil, // ekSeed
		nil, // ekVector
		nil, // receivedCt1
		nil, // bobEkSeed
		nil, // bobHek
		make([]byte, mlkembraid.MLKEM768EncapStateSize), // bobEncapSecret
		make([]byte, mlkembraid.MLKEM768EKSize),         // bobEkVector
		nil,                                             // bobCt1 = nil → triggers error
		nil,                                             // bobSS
		nil,                                             // headerEncoder
		nil,                                             // ekEncoder
		makeTestEncoder(t, mlkembraid.MLKEM768CT1Size), // ct1Encoder
		nil, // ct2Encoder
		nil, // headerDecoder
		nil, // ekDecoder
		nil, // ct1Decoder
		nil, // ct2Decoder
	)
	if err != nil {
		t.Fatalf("ProtoSetFromFields: %v", err)
	}
	pb := &pqratchetpb.V1State{}
	err = stateKindToInnerState(state, pb, &braidCopies{})
	if err == nil {
		t.Fatal("expected error from stateKindToInnerState with nil bobCt1 (EkReceivedCt1Sampled)")
	}
	var want *ErrProtoMissingField
	if !errors.As(err, &want) {
		t.Fatalf("want *ErrProtoMissingField, got %T: %v", err, err)
	}
}

// TestStateKindToInnerState_Ct1Acknowledged_MissingCt1 verifies error propagation
// for Ct1Acknowledged state where bobCt1 is nil.
func TestStateKindToInnerState_Ct1Acknowledged_MissingCt1(t *testing.T) {
	auth := makeTestAuth(t, 68)
	state, err := mlkembraid.ProtoSetFromFields(
		mlkembraid.StateCt1Acknowledged, 0, mlkembraid.DefaultChunkSize,
		auth,
		nil,                                 // dk
		nil,                                 // ekSeed
		nil,                                 // ekVector
		nil,                                 // receivedCt1
		make([]byte, mlkembraid.EKSeedSize), // bobEkSeed
		make([]byte, 32),                    // bobHek
		make([]byte, mlkembraid.MLKEM768EncapStateSize), // bobEncapSecret
		nil, // bobEkVector
		nil, // bobCt1 = nil → triggers error
		nil, // bobSS
		nil, // headerEncoder
		nil, // ekEncoder
		nil, // ct1Encoder
		nil, // ct2Encoder
		nil, // headerDecoder
		makeTestDecoder(t, mlkembraid.MLKEM768EKSize), // ekDecoder
		nil, // ct1Decoder
		nil, // ct2Decoder
	)
	if err != nil {
		t.Fatalf("ProtoSetFromFields: %v", err)
	}
	pb := &pqratchetpb.V1State{}
	err = stateKindToInnerState(state, pb, &braidCopies{})
	if err == nil {
		t.Fatal("expected error from stateKindToInnerState with nil bobCt1 (Ct1Acknowledged)")
	}
	var want *ErrProtoMissingField
	if !errors.As(err, &want) {
		t.Fatalf("want *ErrProtoMissingField, got %T: %v", err, err)
	}
}

// TestStateKindToInnerState_HeaderReceived_MissingBobEkSeed verifies error
// propagation for HeaderReceived state where bobEkSeed is nil.
func TestStateKindToInnerState_HeaderReceived_MissingBobEkSeed(t *testing.T) {
	auth := makeTestAuth(t, 69)
	state, err := mlkembraid.ProtoSetFromFields(
		mlkembraid.StateHeaderReceived, 0, mlkembraid.DefaultChunkSize,
		auth, nil, nil, nil, nil,
		nil,              // bobEkSeed = nil → triggers the error
		make([]byte, 32), // bobHek
		nil, nil, nil, nil,
		nil, nil, nil, nil, nil,
		makeTestDecoder(t, mlkembraid.MLKEM768EKSize),
		nil, nil,
	)
	if err != nil {
		t.Fatalf("ProtoSetFromFields: %v", err)
	}
	pb := &pqratchetpb.V1State{}
	err = stateKindToInnerState(state, pb, &braidCopies{})
	if err == nil {
		t.Fatal("expected error from stateKindToInnerState with nil bobEkSeed (HeaderReceived)")
	}
	var want *ErrProtoMissingField
	if !errors.As(err, &want) {
		t.Fatalf("want *ErrProtoMissingField, got %T: %v", err, err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// protoV1StateToBraidState — nil inner_state path
// ─────────────────────────────────────────────────────────────────────────────

// TestProtoV1StateToBraidState_NilInnerState covers the nil InnerState branch.
func TestProtoV1StateToBraidState_NilInnerState(t *testing.T) {
	pb := &pqratchetpb.V1State{InnerState: nil}
	_, err := protoV1StateToBraidState(pb)
	if err == nil {
		t.Fatal("expected error for nil inner_state")
	}
	var want *ErrProtoInvalidState
	if !errors.As(err, &want) {
		t.Fatalf("want *ErrProtoInvalidState, got %T: %v", err, err)
	}
}
