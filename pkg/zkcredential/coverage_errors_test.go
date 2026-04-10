package zkcredential

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/gtank/ristretto255"
)

// --- Error type coverage: all Error() and Unwrap() methods ---

func TestErrDerivingScalar_Methods(t *testing.T) {
	inner := errors.New("inner error")
	e := &ErrDerivingScalar{Label: "scalar_t", Err: inner}
	msg := e.Error()
	if !strings.Contains(msg, "scalar_t") {
		t.Errorf("Error() = %q, want 'scalar_t'", msg)
	}
	if !errors.Is(e, inner) {
		t.Error("Unwrap() should return inner error")
	}
}

func TestErrDerivingPoint_Methods(t *testing.T) {
	inner := errors.New("point fail")
	e := &ErrDerivingPoint{Label: "point_U", Err: inner}
	msg := e.Error()
	if !strings.Contains(msg, "point_U") {
		t.Errorf("Error() = %q, want 'point_U'", msg)
	}
	if !errors.Is(e, inner) {
		t.Error("Unwrap() should return inner error")
	}
}

func TestErrTooManyAttributes_Error(t *testing.T) {
	e := &ErrTooManyAttributes{Max: 7}
	msg := e.Error()
	if !strings.Contains(msg, "7") {
		t.Errorf("Error() = %q, want '7'", msg)
	}
}

func TestErrMissingInverseDomain_Error(t *testing.T) {
	e := &ErrMissingInverseDomain{}
	msg := e.Error()
	if msg == "" {
		t.Error("Error() returned empty string")
	}
	if !strings.Contains(msg, "inverse") {
		t.Errorf("Error() = %q, want 'inverse'", msg)
	}
}

func TestErrCiphertextSize_Error(t *testing.T) {
	e := &ErrCiphertextSize{Got: 32}
	msg := e.Error()
	if !strings.Contains(msg, "32") {
		t.Errorf("Error() = %q, want '32'", msg)
	}
}

func TestErrInvalidEncoding_Methods(t *testing.T) {
	inner := errors.New("bad bytes")
	e := &ErrInvalidEncoding{Field: "point", Err: inner}
	msg := e.Error()
	if !strings.Contains(msg, "point") {
		t.Errorf("Error() = %q, want 'point'", msg)
	}
	if !errors.Is(e, inner) {
		t.Error("Unwrap() should return inner error")
	}
}

func TestErrCredentialSize_Error(t *testing.T) {
	e := &ErrCredentialSize{Got: 48}
	msg := e.Error()
	if !strings.Contains(msg, "48") {
		t.Errorf("Error() = %q, want '48'", msg)
	}
}

func TestErrProofCreation_Methods(t *testing.T) {
	inner := errors.New("proof fail")
	e := &ErrProofCreation{ProofType: "issuance", Err: inner}
	msg := e.Error()
	if !strings.Contains(msg, "issuance") {
		t.Errorf("Error() = %q, want 'issuance'", msg)
	}
	if !errors.Is(e, inner) {
		t.Error("Unwrap() should return inner error")
	}
}

func TestErrComputingCredential_Methods(t *testing.T) {
	inner := errors.New("compute fail")
	e := &ErrComputingCredential{Err: inner}
	msg := e.Error()
	if msg == "" {
		t.Error("Error() returned empty string")
	}
	if !errors.Is(e, inner) {
		t.Error("Unwrap() should return inner error")
	}
}

func TestErrMissingHiddenAttributes_Error(t *testing.T) {
	e := &ErrMissingHiddenAttributes{}
	msg := e.Error()
	if msg == "" {
		t.Error("Error() returned empty string")
	}
}

func TestErrTooManyHiddenAttributes_Error(t *testing.T) {
	e := &ErrTooManyHiddenAttributes{Max: 3}
	msg := e.Error()
	if !strings.Contains(msg, "3") {
		t.Errorf("Error() = %q, want '3'", msg)
	}
}

func TestErrGeneratingBlindingKey_Methods(t *testing.T) {
	inner := errors.New("keygen fail")
	e := &ErrGeneratingBlindingKey{Err: inner}
	msg := e.Error()
	if msg == "" {
		t.Error("Error() returned empty string")
	}
	if !errors.Is(e, inner) {
		t.Error("Unwrap() should return inner error")
	}
}

func TestErrGeneratingBlindingNonce_Methods(t *testing.T) {
	inner := errors.New("nonce fail")
	e := &ErrGeneratingBlindingNonce{Err: inner}
	msg := e.Error()
	if msg == "" {
		t.Error("Error() returned empty string")
	}
	if !errors.Is(e, inner) {
		t.Error("Unwrap() should return inner error")
	}
}

func TestErrComputingBaseCredential_Methods(t *testing.T) {
	inner := errors.New("base cred fail")
	e := &ErrComputingBaseCredential{Err: inner}
	msg := e.Error()
	if msg == "" {
		t.Error("Error() returned empty string")
	}
	if !errors.Is(e, inner) {
		t.Error("Unwrap() should return inner error")
	}
}

func TestErrGeneratingRootKey_Methods(t *testing.T) {
	inner := errors.New("root key fail")
	e := &ErrGeneratingRootKey{Err: inner}
	msg := e.Error()
	if msg == "" {
		t.Error("Error() returned empty string")
	}
	if !errors.Is(e, inner) {
		t.Error("Unwrap() should return inner error")
	}
}

func TestErrDerivingTagScalar_Methods(t *testing.T) {
	inner := errors.New("tag fail")
	e := &ErrDerivingTagScalar{Err: inner}
	msg := e.Error()
	if msg == "" {
		t.Error("Error() returned empty string")
	}
	if !errors.Is(e, inner) {
		t.Error("Unwrap() should return inner error")
	}
}

func TestErrMissingHiddenPoints_Error(t *testing.T) {
	e := &ErrMissingHiddenPoints{}
	msg := e.Error()
	if msg == "" {
		t.Error("Error() returned empty string")
	}
}

func TestErrSHODerivePoint_Methods(t *testing.T) {
	inner := errors.New("sho point fail")
	e := &ErrSHODerivePoint{Err: inner}
	msg := e.Error()
	if msg == "" {
		t.Error("Error() returned empty string")
	}
	if !errors.Is(e, inner) {
		t.Error("Unwrap() should return inner error")
	}
}

func TestErrSingleElligatorInputSize_Error(t *testing.T) {
	e := &ErrSingleElligatorInputSize{Got: 16}
	msg := e.Error()
	if !strings.Contains(msg, "16") {
		t.Errorf("Error() = %q, want '16'", msg)
	}
}

func TestErrSingleElligatorMap_Methods(t *testing.T) {
	inner := errors.New("map fail")
	e := &ErrSingleElligatorMap{Err: inner}
	msg := e.Error()
	if msg == "" {
		t.Error("Error() returned empty string")
	}
	if !errors.Is(e, inner) {
		t.Error("Unwrap() should return inner error")
	}
}

func TestErrSHODeriveScalar_Methods(t *testing.T) {
	inner := errors.New("scalar fail")
	e := &ErrSHODeriveScalar{Err: inner}
	msg := e.Error()
	if msg == "" {
		t.Error("Error() returned empty string")
	}
	if !errors.Is(e, inner) {
		t.Error("Unwrap() should return inner error")
	}
}

// --- zeroScalar coverage ---

func TestZeroScalar_NonNil(t *testing.T) {
	// Set non-zero value
	sho := NewShoHmacSha256Ext("test_zero_scalar")
	sho.AbsorbAndRatchet([]byte("data"))
	s := sho.MustGetScalar()

	// Verify non-zero before
	zero := ristretto255.NewScalar()
	if s.Equal(zero) == 1 {
		t.Skip("scalar is zero, skipping zeroize test")
	}

	zeroScalar(s)
	// After zeroing, should be zero
	if s.Equal(zero) != 1 {
		t.Error("zeroScalar should set scalar to zero")
	}
}

func TestZeroScalar_Nil(t *testing.T) {
	// Should not panic on nil
	zeroScalar(nil)
}

// --- CredentialPrivateKey.Zeroize ---

func TestCredentialPrivateKey_Zeroize(t *testing.T) {
	var randomness [RandomnessLen]byte
	for i := range randomness {
		randomness[i] = byte(i + 1)
	}
	kp := GenerateCredentialKeyPair(randomness)
	if kp == nil {
		t.Fatal("expected non-nil key pair")
	}

	// Verify key is populated
	if kp.privateKey == nil {
		t.Fatal("expected non-nil private key before zeroize")
	}

	// Call Zeroize on the credential key pair (which calls private key Zeroize)
	kp.Zeroize()

	if kp.privateKey != nil {
		t.Error("privateKey should be nil after Zeroize")
	}
	if kp.publicKey != nil {
		t.Error("publicKey should be nil after Zeroize")
	}
}

// --- BlindingPrivateKey.Zeroize and BlindingKeyPair.Zeroize ---

func TestBlindingPrivateKey_Zeroize(t *testing.T) {
	sho := NewShoHmacSha256Ext("test_blinding_priv")
	sho.AbsorbAndRatchet([]byte("data"))
	bkp, err := GenerateBlindingKeyPair(sho)
	if err != nil {
		t.Fatalf("GenerateBlindingKeyPair failed: %v", err)
	}

	bkp.PrivKey.Zeroize()

	if bkp.PrivKey.Y != nil {
		t.Error("Y should be nil after Zeroize")
	}
}

func TestBlindingKeyPair_Zeroize(t *testing.T) {
	sho := NewShoHmacSha256Ext("test_blinding_kp")
	sho.AbsorbAndRatchet([]byte("data"))
	bkp, err := GenerateBlindingKeyPair(sho)
	if err != nil {
		t.Fatalf("GenerateBlindingKeyPair failed: %v", err)
	}

	bkp.Zeroize()

	if bkp.PrivKey != nil {
		t.Error("PrivKey should be nil after Zeroize")
	}
	if bkp.PubKey != nil {
		t.Error("PubKey should be nil after Zeroize")
	}
}

func TestBlindingKeyPair_Zeroize_NilPrivKey(t *testing.T) {
	bkp := &BlindingKeyPair{PrivKey: nil, PubKey: nil}
	bkp.Zeroize() // must not panic
}

// --- ShoExt.PointFromSingleElligator ---

func TestPointFromSingleElligator_Valid(t *testing.T) {
	input := make([]byte, 32)
	for i := range input {
		input[i] = byte(i + 1)
	}

	p, err := PointFromSingleElligator(input)
	if err != nil {
		t.Fatalf("PointFromSingleElligator failed: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil point")
	}
}

func TestPointFromSingleElligator_WrongSize(t *testing.T) {
	_, err := PointFromSingleElligator(make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for wrong input size")
	}
	var sizeErr *ErrSingleElligatorInputSize
	if !errors.As(err, &sizeErr) {
		t.Errorf("expected ErrSingleElligatorInputSize, got: %T", err)
	}
	if sizeErr.Got != 16 {
		t.Errorf("Got = %d, want 16", sizeErr.Got)
	}
}

func TestPointFromSingleElligator_Deterministic(t *testing.T) {
	input := make([]byte, 32)
	for i := range input {
		input[i] = byte(i + 5)
	}

	p1, err := PointFromSingleElligator(input)
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	p2, err := PointFromSingleElligator(input)
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}

	if p1.Equal(p2) != 1 {
		t.Fatal("PointFromSingleElligator should be deterministic")
	}
}

func TestPointFromSingleElligator_DifferentInputs(t *testing.T) {
	input1 := make([]byte, 32)
	input2 := make([]byte, 32)
	input2[0] = 1

	p1, _ := PointFromSingleElligator(input1)
	p2, _ := PointFromSingleElligator(input2)

	if p1.Equal(p2) == 1 {
		t.Fatal("different inputs should produce different points")
	}
}

// --- ShoExt.GetPointSingleElligator and MustGetPointSingleElligator ---

func TestGetPointSingleElligator_Valid(t *testing.T) {
	sho := NewShoHmacSha256Ext("test_single_elligator")
	sho.AbsorbAndRatchet([]byte("test"))

	p, err := sho.GetPointSingleElligator()
	if err != nil {
		t.Fatalf("GetPointSingleElligator failed: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil point")
	}
}

func TestMustGetPointSingleElligator_NoPanic(t *testing.T) {
	sho := NewShoHmacSha256Ext("test_must_single_elligator")
	sho.AbsorbAndRatchet([]byte("data"))

	p := sho.MustGetPointSingleElligator()
	if p == nil {
		t.Fatal("expected non-nil point")
	}
}

func TestGetPointSingleElligator_Deterministic(t *testing.T) {
	sho1 := NewShoHmacSha256Ext("test_single_elligator_det")
	sho1.AbsorbAndRatchet([]byte("seed"))
	p1, err := sho1.GetPointSingleElligator()
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}

	sho2 := NewShoHmacSha256Ext("test_single_elligator_det")
	sho2.AbsorbAndRatchet([]byte("seed"))
	p2, err := sho2.GetPointSingleElligator()
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}

	if p1.Equal(p2) != 1 {
		t.Fatal("GetPointSingleElligator should be deterministic")
	}
}

// --- issuance_blind.go: encoding/decoding functions ---

func TestEncodeDecodeBlindedCredential_RoundTrip(t *testing.T) {
	sho := NewShoHmacSha256Ext("test_blinded_cred_roundtrip")
	sho.AbsorbAndRatchet([]byte("data"))

	// Build a BlindedCredential from random scalars/points.
	T := sho.MustGetScalar()
	U := sho.MustGetPoint()
	S1 := sho.MustGetPoint()
	S2 := sho.MustGetPoint()

	cred := &BlindedCredential{T: T, U: U, S1: S1, S2: S2}
	encoded := EncodeBlindedCredential(cred)

	if len(encoded) != 128 {
		t.Fatalf("expected 128 bytes, got %d", len(encoded))
	}

	decoded, err := DecodeBlindedCredential(encoded)
	if err != nil {
		t.Fatalf("DecodeBlindedCredential failed: %v", err)
	}

	if decoded.T.Equal(T) != 1 {
		t.Error("T mismatch")
	}
	if decoded.U.Equal(U) != 1 {
		t.Error("U mismatch")
	}
	if decoded.S1.Equal(S1) != 1 {
		t.Error("S1 mismatch")
	}
	if decoded.S2.Equal(S2) != 1 {
		t.Error("S2 mismatch")
	}
}

func TestDecodeBlindedCredential_TooShort(t *testing.T) {
	_, err := DecodeBlindedCredential(make([]byte, 64))
	if err == nil {
		t.Fatal("expected error for too-short input")
	}
}

func TestEncodeBlindedIssuanceProof_Valid(t *testing.T) {
	sho := NewShoHmacSha256Ext("test_blinded_proof")
	sho.AbsorbAndRatchet([]byte("data"))

	cred := &BlindedCredential{
		T:  sho.MustGetScalar(),
		U:  sho.MustGetPoint(),
		S1: sho.MustGetPoint(),
		S2: sho.MustGetPoint(),
	}
	proof := &BlindedIssuanceProof{
		Credential:  cred,
		PokshoProof: []byte{0x01, 0x02, 0x03},
	}

	encoded := EncodeBlindedIssuanceProof(proof)
	if len(encoded) != 128+3 {
		t.Errorf("encoded length = %d, want 131", len(encoded))
	}
}

func TestEncodeDecodeBlindedPoint_RoundTrip(t *testing.T) {
	sho := NewShoHmacSha256Ext("test_blinded_point")
	sho.AbsorbAndRatchet([]byte("data"))

	d1 := sho.MustGetPoint()
	d2 := sho.MustGetPoint()
	bp := &BlindedPoint{D1: d1, D2: d2}

	encoded := EncodeBlindedPoint(bp)
	if len(encoded) != 64 {
		t.Fatalf("expected 64 bytes, got %d", len(encoded))
	}

	decoded, err := DecodeBlindedPoint(encoded)
	if err != nil {
		t.Fatalf("DecodeBlindedPoint failed: %v", err)
	}
	if decoded.D1.Equal(d1) != 1 {
		t.Error("D1 mismatch")
	}
	if decoded.D2.Equal(d2) != 1 {
		t.Error("D2 mismatch")
	}
}

func TestDecodeBlindedPoint_TooShort(t *testing.T) {
	_, err := DecodeBlindedPoint(make([]byte, 32))
	if err == nil {
		t.Fatal("expected error for too-short input")
	}
}

func TestEncodeDecodeBlindingPublicKey_RoundTrip(t *testing.T) {
	sho := NewShoHmacSha256Ext("test_blinding_pubkey")
	sho.AbsorbAndRatchet([]byte("data"))

	pk := sho.MustGetPoint()
	bpk := &BlindingPublicKey{Ypoint: pk}

	encoded := EncodeBlindingPublicKey(bpk)
	if len(encoded) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(encoded))
	}

	decoded, err := DecodeBlindingPublicKey(encoded)
	if err != nil {
		t.Fatalf("DecodeBlindingPublicKey failed: %v", err)
	}
	if decoded.Ypoint.Equal(pk) != 1 {
		t.Error("Ypoint mismatch")
	}
}

func TestDecodeBlindingPublicKey_TooShort(t *testing.T) {
	_, err := DecodeBlindingPublicKey(make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for too-short input")
	}
}

// --- EncodeBlindedPoint content verification ---

func TestEncodeBlindedPoint_Content(t *testing.T) {
	sho := NewShoHmacSha256Ext("test_encode_blinded_pt")
	sho.AbsorbAndRatchet([]byte("seed"))

	d1 := sho.MustGetPoint()
	d2 := sho.MustGetPoint()
	bp := &BlindedPoint{D1: d1, D2: d2}

	encoded := EncodeBlindedPoint(bp)

	d1Bytes := d1.Bytes()
	d2Bytes := d2.Bytes()
	expected := append(d1Bytes, d2Bytes...)

	if !bytes.Equal(encoded, expected) {
		t.Error("EncodeBlindedPoint produced unexpected bytes")
	}
}

// --- generateCredentialPrivateKeyFromSHO ---

func TestGenerateCredentialPrivateKeyFromSHO(t *testing.T) {
	sho := NewShoHmacSha256Ext("test_gen_cred_from_sho")
	sho.AbsorbAndRatchet([]byte("randomness"))

	pk := generateCredentialPrivateKeyFromSHO(sho)
	if pk == nil {
		t.Fatal("expected non-nil credential private key")
	}
	if pk.W == nil {
		t.Error("expected non-nil W scalar")
	}
	if pk.Wprime == nil {
		t.Error("expected non-nil Wprime scalar")
	}
	for i, y := range pk.Y {
		if y == nil {
			t.Errorf("Y[%d] is nil", i)
		}
	}
}
