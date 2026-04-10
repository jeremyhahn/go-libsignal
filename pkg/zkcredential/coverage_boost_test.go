package zkcredential

import (
	"testing"

	"github.com/gtank/ristretto255"
)

// --- ShoExt GetPoint / GetScalar error paths ---
// In practice, SetUniformBytes on 64-byte input from SHO never fails
// because the ristretto255 library accepts any 64-byte input.
// These tests verify the happy paths and that MustGetPoint/MustGetScalar
// do not panic with valid SHO state.

func TestShoExt_GetPoint_Valid(t *testing.T) {
	sho := NewShoHmacSha256Ext("test_get_point")
	sho.AbsorbAndRatchet([]byte("test data"))

	p, err := sho.GetPoint()
	if err != nil {
		t.Fatalf("GetPoint failed: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil point")
	}

	// Verify it's a valid ristretto point by encoding and re-decoding.
	encoded := p.Bytes()
	check := ristretto255.NewIdentityElement()
	if _, err := check.SetCanonicalBytes(encoded); err != nil {
		t.Fatalf("point is not valid ristretto: %v", err)
	}
}

func TestShoExt_GetScalar_Valid(t *testing.T) {
	sho := NewShoHmacSha256Ext("test_get_scalar")
	sho.AbsorbAndRatchet([]byte("test data"))

	sc, err := sho.GetScalar()
	if err != nil {
		t.Fatalf("GetScalar failed: %v", err)
	}
	if sc == nil {
		t.Fatal("expected non-nil scalar")
	}

	// Verify it's a valid scalar by encoding.
	encoded := sc.Bytes()
	if len(encoded) != 32 {
		t.Fatalf("expected 32-byte scalar encoding, got %d", len(encoded))
	}
}

func TestShoExt_MustGetPoint_NoPanic(t *testing.T) {
	sho := NewShoHmacSha256Ext("test_must_get_point")
	sho.AbsorbAndRatchet([]byte("data"))
	// Should not panic.
	p := sho.MustGetPoint()
	if p == nil {
		t.Fatal("expected non-nil point")
	}
}

func TestShoExt_MustGetScalar_NoPanic(t *testing.T) {
	sho := NewShoHmacSha256Ext("test_must_get_scalar")
	sho.AbsorbAndRatchet([]byte("data"))
	// Should not panic.
	sc := sho.MustGetScalar()
	if sc == nil {
		t.Fatal("expected non-nil scalar")
	}
}

func TestShoExt_MultiplePointsAreDistinct(t *testing.T) {
	sho := NewShoHmacSha256Ext("test_distinct_points")
	sho.AbsorbAndRatchet([]byte("seed"))

	p1 := sho.MustGetPoint()
	p2 := sho.MustGetPoint()

	if p1.Equal(p2) == 1 {
		t.Fatal("successive GetPoint calls should produce different points")
	}
}

func TestShoExt_MultipleScalarsAreDistinct(t *testing.T) {
	sho := NewShoHmacSha256Ext("test_distinct_scalars")
	sho.AbsorbAndRatchet([]byte("seed"))

	s1 := sho.MustGetScalar()
	s2 := sho.MustGetScalar()

	if s1.Equal(s2) == 1 {
		t.Fatal("successive GetScalar calls should produce different scalars")
	}
}

// --- DecodeCredential error paths ---

func TestDecodeCredential_WrongLength(t *testing.T) {
	_, err := DecodeCredential(make([]byte, 50))
	if err == nil {
		t.Fatal("expected error for wrong length")
	}
}

func TestDecodeCredential_InvalidScalarT(t *testing.T) {
	data := make([]byte, 96)
	// Set first 32 bytes (t scalar) to non-canonical value.
	for i := 0; i < 32; i++ {
		data[i] = 0xFF
	}
	_, err := DecodeCredential(data)
	if err == nil {
		t.Fatal("expected error for invalid scalar t")
	}
}

func TestDecodeCredential_InvalidPointU(t *testing.T) {
	data := make([]byte, 96)
	// Valid scalar t (all zeros is the zero scalar, which is canonical).
	// Invalid point U (bytes 32-63).
	for i := 32; i < 64; i++ {
		data[i] = 0xFF
	}
	_, err := DecodeCredential(data)
	if err == nil {
		t.Fatal("expected error for invalid point U")
	}
}

func TestDecodeCredential_InvalidPointV(t *testing.T) {
	data := make([]byte, 96)
	// Valid t (zeros) and U (zeros = identity), invalid V.
	for i := 64; i < 96; i++ {
		data[i] = 0xFF
	}
	_, err := DecodeCredential(data)
	if err == nil {
		t.Fatal("expected error for invalid point V")
	}
}

func TestEncodeDecodeCredential_RoundTrip(t *testing.T) {
	sho := NewShoHmacSha256Ext("test_credential_roundtrip")
	sho.AbsorbAndRatchet([]byte("randomness"))

	t1 := sho.MustGetScalar()
	U := sho.MustGetPoint()
	V := sho.MustGetPoint()

	cred := &Credential{T: t1, U: U, V: V}
	encoded := EncodeCredential(cred)
	decoded, err := DecodeCredential(encoded)
	if err != nil {
		t.Fatalf("DecodeCredential failed: %v", err)
	}

	if decoded.T.Equal(cred.T) != 1 {
		t.Error("T scalar mismatch")
	}
	if decoded.U.Equal(cred.U) != 1 {
		t.Error("U point mismatch")
	}
	if decoded.V.Equal(cred.V) != 1 {
		t.Error("V point mismatch")
	}
}

// --- GenerateServerRootKeyPair ---

func TestGenerateServerRootKeyPair_Valid(t *testing.T) {
	var randomness [RandomnessLen]byte
	for i := range randomness {
		randomness[i] = byte(i + 1)
	}
	kp, err := GenerateServerRootKeyPair(randomness)
	if err != nil {
		t.Fatalf("GenerateServerRootKeyPair failed: %v", err)
	}
	if kp == nil {
		t.Fatal("expected non-nil key pair")
	}
	if kp.PublicKey() == nil {
		t.Fatal("expected non-nil public key")
	}
}

func TestGenerateServerRootKeyPair_Deterministic(t *testing.T) {
	var randomness [RandomnessLen]byte
	for i := range randomness {
		randomness[i] = byte(i)
	}
	kp1, err := GenerateServerRootKeyPair(randomness)
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	kp2, err := GenerateServerRootKeyPair(randomness)
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}

	// Same randomness should produce same public key.
	if kp1.Public.PK.Equal(kp2.Public.PK) != 1 {
		t.Fatal("expected same key pair from same randomness")
	}
}

// --- DeriveKey (ServerRootKeyPair and ServerRootPublicKey) ---

func TestServerRootKeyPair_DeriveKey(t *testing.T) {
	var randomness [RandomnessLen]byte
	for i := range randomness {
		randomness[i] = byte(i + 1)
	}
	rkp, err := GenerateServerRootKeyPair(randomness)
	if err != nil {
		t.Fatalf("GenerateServerRootKeyPair failed: %v", err)
	}

	tagInfo := NewShoHmacSha256Ext("test_tag_info")
	tagInfo.AbsorbAndRatchet([]byte("some public attributes"))

	dkp, err := rkp.DeriveKey(tagInfo)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}
	if dkp == nil {
		t.Fatal("expected non-nil derived key pair")
	}
	if dkp.Public == nil {
		t.Fatal("expected non-nil derived public key")
	}
}

func TestServerRootPublicKey_DeriveKey(t *testing.T) {
	var randomness [RandomnessLen]byte
	for i := range randomness {
		randomness[i] = byte(i + 2)
	}
	rkp, err := GenerateServerRootKeyPair(randomness)
	if err != nil {
		t.Fatalf("GenerateServerRootKeyPair failed: %v", err)
	}

	tagInfo := NewShoHmacSha256Ext("test_tag_info")
	tagInfo.AbsorbAndRatchet([]byte("some attributes"))

	dpk, err := rkp.PublicKey().DeriveKey(tagInfo)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}
	if dpk == nil {
		t.Fatal("expected non-nil derived public key")
	}
}

// --- GenerateBlindingKeyPair ---

func TestGenerateBlindingKeyPair_Valid(t *testing.T) {
	sho := NewShoHmacSha256Ext("test_blinding_keypair")
	sho.AbsorbAndRatchet([]byte("randomness"))

	bkp, err := GenerateBlindingKeyPair(sho)
	if err != nil {
		t.Fatalf("GenerateBlindingKeyPair failed: %v", err)
	}
	if bkp == nil || bkp.PrivKey == nil || bkp.PubKey == nil {
		t.Fatal("expected non-nil key pair components")
	}
}

// --- DeriveKeyPair ---

func TestDeriveKeyPair_Valid(t *testing.T) {
	sho := NewShoHmacSha256Ext("test_derive_keypair")
	sho.AbsorbAndRatchet([]byte("randomness"))

	domain := newTestDomain("DeriveKeyPairTest")
	kp, err := DeriveKeyPair(sho, domain)
	if err != nil {
		t.Fatalf("DeriveKeyPair failed: %v", err)
	}
	if kp == nil {
		t.Fatal("expected non-nil key pair")
	}
	if kp.PublicKey == nil {
		t.Fatal("expected non-nil public key")
	}
}

// --- ClientDecryptionKey ---

func TestNewClientDecryptionKeyFromBlinding_Valid(t *testing.T) {
	sho := NewShoHmacSha256Ext("test_decrypt_key")
	sho.AbsorbAndRatchet([]byte("randomness"))
	scalar := sho.MustGetScalar()

	key := NewClientDecryptionKeyFromBlinding(scalar)
	if key == nil {
		t.Fatal("expected non-nil decryption key")
	}
	if key.aInv == nil {
		t.Fatal("expected non-nil inverse scalar")
	}
}

func TestNewClientDecryptionKeyForFirstPoint_CoverageBoost(t *testing.T) {
	domain := newTestDomain("DecKeyBoostTest")
	sho := NewShoHmacSha256Ext("dec_key_boost_test")
	kp, err := DeriveKeyPair(sho, domain)
	if err != nil {
		t.Fatalf("DeriveKeyPair failed: %v", err)
	}

	key := NewClientDecryptionKeyForFirstPoint(kp)
	if key == nil {
		t.Fatal("expected non-nil decryption key")
	}
	// Verify that aInv * A1 = 1 (scalar identity).
	product := ristretto255.NewScalar().Multiply(key.aInv, kp.A1)
	var scalarOne [32]byte
	scalarOne[0] = 1
	one, err := new(ristretto255.Scalar).SetCanonicalBytes(scalarOne[:])
	if err != nil {
		t.Fatal(err)
	}
	if product.Equal(one) != 1 {
		t.Fatal("expected aInv * A1 = 1")
	}
}

// --- ShoExt Clone ---

func TestShoExt_Clone(t *testing.T) {
	sho := NewShoHmacSha256Ext("test_clone")
	sho.AbsorbAndRatchet([]byte("data"))

	cloned := sho.Clone()
	// Both should produce the same point.
	p1 := sho.MustGetPoint()
	p2 := cloned.MustGetPoint()

	if p1.Equal(p2) != 1 {
		t.Fatal("cloned SHO should produce the same output")
	}
}

// --- BlindedPoint.StripNonce ---

func TestBlindedPoint_StripNonce(t *testing.T) {
	sho := NewShoHmacSha256Ext("test_strip_nonce")
	sho.AbsorbAndRatchet([]byte("randomness"))

	r := sho.MustGetScalar()
	d1 := sho.MustGetPoint()
	d2 := sho.MustGetPoint()

	bp := &BlindedPoint{R: r, D1: d1, D2: d2}
	stripped := bp.StripNonce()

	if stripped.D1.Equal(d1) != 1 {
		t.Error("D1 mismatch after StripNonce")
	}
	if stripped.D2.Equal(d2) != 1 {
		t.Error("D2 mismatch after StripNonce")
	}
}

// --- BlindedAttribute.StripNonce ---

func TestBlindedAttribute_StripNonce(t *testing.T) {
	sho := NewShoHmacSha256Ext("test_strip_nonce_attr")
	sho.AbsorbAndRatchet([]byte("randomness"))

	bp0 := &BlindedPoint{
		R:  sho.MustGetScalar(),
		D1: sho.MustGetPoint(),
		D2: sho.MustGetPoint(),
	}
	bp1 := &BlindedPoint{
		R:  sho.MustGetScalar(),
		D1: sho.MustGetPoint(),
		D2: sho.MustGetPoint(),
	}

	ba := &BlindedAttribute{BlindedPoints: [2]*BlindedPoint{bp0, bp1}}
	stripped := ba.StripNonce()

	if stripped.BlindedPoints[0].D1.Equal(bp0.D1) != 1 {
		t.Error("D1[0] mismatch after StripNonce")
	}
	if stripped.BlindedPoints[1].D2.Equal(bp1.D2) != 1 {
		t.Error("D2[1] mismatch after StripNonce")
	}
}

// --- SqueezeAndRatchet ---

func TestShoExt_SqueezeAndRatchet(t *testing.T) {
	sho1 := NewShoHmacSha256Ext("test_squeeze_ratchet")
	sho1.AbsorbAndRatchet([]byte("seed"))
	out1 := sho1.SqueezeAndRatchet(32)

	sho2 := NewShoHmacSha256Ext("test_squeeze_ratchet")
	sho2.AbsorbAndRatchet([]byte("seed"))
	out2 := sho2.SqueezeAndRatchet(32)

	if len(out1) != 32 || len(out2) != 32 {
		t.Fatal("expected 32-byte output")
	}
	for i := range out1 {
		if out1[i] != out2[i] {
			t.Fatal("SqueezeAndRatchet should be deterministic")
		}
	}
}

// --- AbsorbAndRatchet ---

func TestShoExt_AbsorbAndRatchet(t *testing.T) {
	sho1 := NewShoHmacSha256Ext("test_absorb_ratchet")
	sho1.AbsorbAndRatchet([]byte("data1"))
	p1 := sho1.MustGetPoint()

	sho2 := NewShoHmacSha256Ext("test_absorb_ratchet")
	sho2.AbsorbAndRatchet([]byte("data2"))
	p2 := sho2.MustGetPoint()

	if p1.Equal(p2) == 1 {
		t.Fatal("different absorbed data should produce different points")
	}
}

// --- KeyPair.Equal ---

func TestKeyPairEqual_Same(t *testing.T) {
	sho := NewShoHmacSha256Ext("test_kp_equal")
	sho.AbsorbAndRatchet([]byte("seed"))

	domain := newTestDomain("KeyPairEqualTest")
	kp1, _ := DeriveKeyPair(sho.Clone(), domain)

	sho2 := NewShoHmacSha256Ext("test_kp_equal")
	sho2.AbsorbAndRatchet([]byte("seed"))
	kp2, _ := DeriveKeyPair(sho2, domain)

	if !kp1.Equal(kp2) {
		t.Fatal("expected key pairs from same seed to be equal")
	}
}

func TestKeyPairEqual_Different(t *testing.T) {
	sho1 := NewShoHmacSha256Ext("test_kp_diff_1")
	sho1.AbsorbAndRatchet([]byte("seed1"))
	domain := newTestDomain("KeyPairDiffTest")
	kp1, _ := DeriveKeyPair(sho1, domain)

	sho2 := NewShoHmacSha256Ext("test_kp_diff_2")
	sho2.AbsorbAndRatchet([]byte("seed2"))
	kp2, _ := DeriveKeyPair(sho2, domain)

	if kp1.Equal(kp2) {
		t.Fatal("expected key pairs from different seeds to not be equal")
	}
}

// --- PublicKey.Equal ---

func TestPublicKeyEqual_Same(t *testing.T) {
	sho := NewShoHmacSha256Ext("test_pk_equal")
	sho.AbsorbAndRatchet([]byte("seed"))

	domain := newTestDomain("PubKeyEqualTest")
	kp1, _ := DeriveKeyPair(sho.Clone(), domain)

	sho2 := NewShoHmacSha256Ext("test_pk_equal")
	sho2.AbsorbAndRatchet([]byte("seed"))
	kp2, _ := DeriveKeyPair(sho2, domain)

	if !kp1.PublicKey.Equal(kp2.PublicKey) {
		t.Fatal("expected public keys from same seed to be equal")
	}
}

func TestPublicKeyEqual_Different(t *testing.T) {
	sho1 := NewShoHmacSha256Ext("test_pk_diff_1")
	sho1.AbsorbAndRatchet([]byte("seed1"))
	domain := newTestDomain("PubKeyDiffTest")
	kp1, _ := DeriveKeyPair(sho1, domain)

	sho2 := NewShoHmacSha256Ext("test_pk_diff_2")
	sho2.AbsorbAndRatchet([]byte("seed2"))
	kp2, _ := DeriveKeyPair(sho2, domain)

	if kp1.PublicKey.Equal(kp2.PublicKey) {
		t.Fatal("expected public keys from different seeds to not be equal")
	}
}

// --- DecodeCiphertext error paths ---

func TestDecodeCiphertext_WrongLength(t *testing.T) {
	_, err := DecodeCiphertext(make([]byte, 50))
	if err == nil {
		t.Fatal("expected error for wrong length")
	}
}

func TestDecodeCiphertext_InvalidEA1(t *testing.T) {
	data := make([]byte, 64)
	for i := 0; i < 32; i++ {
		data[i] = 0xFF
	}
	_, err := DecodeCiphertext(data)
	if err == nil {
		t.Fatal("expected error for invalid EA1")
	}
}

func TestDecodeCiphertext_InvalidEA2(t *testing.T) {
	data := make([]byte, 64)
	// EA1 is valid (zeros = identity).
	// EA2 is invalid.
	for i := 32; i < 64; i++ {
		data[i] = 0xFF
	}
	_, err := DecodeCiphertext(data)
	if err == nil {
		t.Fatal("expected error for invalid EA2")
	}
}

func TestEncodeDecode_Ciphertext_RoundTrip(t *testing.T) {
	sho := NewShoHmacSha256Ext("test_ciphertext_roundtrip")
	sho.AbsorbAndRatchet([]byte("data"))

	ea1 := sho.MustGetPoint()
	ea2 := sho.MustGetPoint()

	ct := &Ciphertext{EA1: ea1, EA2: ea2}
	encoded := EncodeCiphertext(ct)
	decoded, err := DecodeCiphertext(encoded)
	if err != nil {
		t.Fatalf("DecodeCiphertext failed: %v", err)
	}
	if decoded.EA1.Equal(ct.EA1) != 1 {
		t.Error("EA1 mismatch")
	}
	if decoded.EA2.Equal(ct.EA2) != 1 {
		t.Error("EA2 mismatch")
	}
}

// --- CredentialCore ---

func TestCredentialCore_TooManyAttributes(t *testing.T) {
	// Create a credential private key.
	sho := NewShoHmacSha256Ext("test_credential_core")
	sho.AbsorbAndRatchet([]byte("key material"))

	system := GetSystemParams()
	_ = system

	// Create more than NumSupportedAttrs points.
	M := make([]*ristretto255.Element, NumSupportedAttrs+1)
	for i := range M {
		M[i] = sho.MustGetPoint()
	}

	// Build a minimal CredentialPrivateKey.
	w := sho.MustGetScalar()
	wprime := sho.MustGetScalar()
	x0 := sho.MustGetScalar()
	x1 := sho.MustGetScalar()
	var y [NumSupportedAttrs]*ristretto255.Scalar
	for i := range y {
		y[i] = sho.MustGetScalar()
	}
	G := ristretto255.NewGeneratorElement()
	Wpoint := new(ristretto255.Element).ScalarMult(w, G)

	pk := &CredentialPrivateKey{
		W:      w,
		Wprime: wprime,
		X0:     x0,
		X1:     x1,
		Y:      y,
		Wpoint: Wpoint,
	}

	coreSho := NewShoHmacSha256Ext("core_sho")
	coreSho.AbsorbAndRatchet([]byte("randomness"))

	_, err := pk.CredentialCore(M, coreSho)
	if err == nil {
		t.Fatal("expected error for too many attributes")
	}
}

// --- DeriveDefaultGeneratorPoints ---

func TestDeriveDefaultGeneratorPoints_Deterministic(t *testing.T) {
	ga1 := DeriveDefaultGeneratorPoints("test_domain_1")
	ga2 := DeriveDefaultGeneratorPoints("test_domain_1")

	if ga1[0].Equal(ga2[0]) != 1 || ga1[1].Equal(ga2[1]) != 1 {
		t.Fatal("DeriveDefaultGeneratorPoints should be deterministic")
	}
}

func TestDeriveDefaultGeneratorPoints_DifferentDomains(t *testing.T) {
	ga1 := DeriveDefaultGeneratorPoints("domain_a")
	ga2 := DeriveDefaultGeneratorPoints("domain_b")

	if ga1[0].Equal(ga2[0]) == 1 {
		t.Fatal("different domains should produce different generator points")
	}
}

// --- NewShoSha256Ext ---

func TestNewShoSha256Ext(t *testing.T) {
	sho := NewShoSha256Ext("test_sha256_ext")
	if sho == nil {
		t.Fatal("expected non-nil ShoExt")
	}
	sho.AbsorbAndRatchet([]byte("data"))
	p := sho.MustGetPoint()
	if p == nil {
		t.Fatal("expected non-nil point from SHA-256 ShoExt")
	}
}

// --- NewShoExt wrapping ---

func TestNewShoExt_Wrapping(t *testing.T) {
	inner := NewShoHmacSha256Ext("inner")
	wrapped := NewShoExt(inner.SHO)
	if wrapped == nil {
		t.Fatal("expected non-nil wrapped ShoExt")
	}
	wrapped.AbsorbAndRatchet([]byte("data"))
	p := wrapped.MustGetPoint()
	if p == nil {
		t.Fatal("expected non-nil point from wrapped ShoExt")
	}
}

// --- ServerRootKeyPairFromRaw ---

func TestServerRootKeyPairFromRaw(t *testing.T) {
	sho := NewShoHmacSha256Ext("test_raw_keypair")
	sho.AbsorbAndRatchet([]byte("randomness"))
	sk := sho.MustGetScalar()

	kp := ServerRootKeyPairFromRaw(sk)
	if kp == nil {
		t.Fatal("expected non-nil key pair")
	}
	if kp.Public == nil || kp.Public.PK == nil {
		t.Fatal("expected non-nil public key")
	}
}

// --- ServerRootPublicKeyFromRaw ---

func TestServerRootPublicKeyFromRaw_RoundTrip(t *testing.T) {
	sho := NewShoHmacSha256Ext("test_raw_pubkey")
	sho.AbsorbAndRatchet([]byte("randomness"))
	pk := sho.MustGetPoint()

	rpk := ServerRootPublicKeyFromRaw(pk)
	if rpk == nil {
		t.Fatal("expected non-nil root public key")
	}
	if rpk.PK.Equal(pk) != 1 {
		t.Fatal("public key mismatch")
	}
}
