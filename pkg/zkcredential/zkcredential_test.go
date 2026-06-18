package zkcredential

import (
	"testing"

	"github.com/gtank/ristretto255"
)

func TestShoExtGetPoint(t *testing.T) {
	sho := NewShoSha256Ext("test_label")
	p, err := sho.GetPoint()
	if err != nil {
		t.Fatalf("GetPoint failed: %v", err)
	}
	if p == nil {
		t.Fatal("GetPoint returned nil")
	}
	// Verify it's not the identity
	identity := ristretto255.NewIdentityElement()
	if p.Equal(identity) == 1 {
		t.Fatal("GetPoint returned identity")
	}
}

func TestShoExtGetScalar(t *testing.T) {
	sho := NewShoSha256Ext("test_label")
	s, err := sho.GetScalar()
	if err != nil {
		t.Fatalf("GetScalar failed: %v", err)
	}
	if s == nil {
		t.Fatal("GetScalar returned nil")
	}
	// Verify it's not zero
	zero := ristretto255.NewScalar()
	if s.Equal(zero) == 1 {
		t.Fatal("GetScalar returned zero")
	}
}

func TestShoExtDeterministic(t *testing.T) {
	sho1 := NewShoSha256Ext("deterministic_test")
	sho2 := NewShoSha256Ext("deterministic_test")

	p1 := sho1.MustGetPoint()
	p2 := sho2.MustGetPoint()

	if p1.Equal(p2) != 1 {
		t.Fatal("same SHO label should produce same point")
	}

	s1 := sho1.MustGetScalar()
	s2 := sho2.MustGetScalar()

	if s1.Equal(s2) != 1 {
		t.Fatal("same SHO state should produce same scalar")
	}
}

func TestSystemParamsGenerate(t *testing.T) {
	params := GetSystemParams()
	if params == nil {
		t.Fatal("GetSystemParams returned nil")
	}
	if params.Gw == nil {
		t.Fatal("Gw is nil")
	}
	if params.Gwprime == nil {
		t.Fatal("Gwprime is nil")
	}
	if params.Gx0 == nil {
		t.Fatal("Gx0 is nil")
	}
	if params.Gx1 == nil {
		t.Fatal("Gx1 is nil")
	}
	if params.GV == nil {
		t.Fatal("GV is nil")
	}
	if params.Gz == nil {
		t.Fatal("Gz is nil")
	}
	for i, gy := range params.Gy {
		if gy == nil {
			t.Fatalf("Gy[%d] is nil", i)
		}
	}

	// Verify determinism
	params2 := generateSystemParams()
	if params.Gw.Equal(params2.Gw) != 1 {
		t.Fatal("system params are not deterministic")
	}
}

func TestDeriveDefaultGeneratorPoints(t *testing.T) {
	ga1 := DeriveDefaultGeneratorPoints("TestDomain")
	ga2 := DeriveDefaultGeneratorPoints("TestDomain")

	if ga1[0].Equal(ga2[0]) != 1 || ga1[1].Equal(ga2[1]) != 1 {
		t.Fatal("DeriveDefaultGeneratorPoints is not deterministic")
	}

	ga3 := DeriveDefaultGeneratorPoints("OtherDomain")
	if ga1[0].Equal(ga3[0]) == 1 {
		t.Fatal("different domains should produce different points")
	}
}

type testDomain struct {
	id string
	ga [2]*ristretto255.Element
}

func (d *testDomain) ID() string                   { return d.id }
func (d *testDomain) Ga() [2]*ristretto255.Element { return d.ga }

func newTestDomain(id string) *testDomain {
	ga := DeriveDefaultGeneratorPoints(id)
	return &testDomain{id: id, ga: ga}
}

func TestKeyPairEncryptDecrypt(t *testing.T) {
	domain := newTestDomain("TestEncryption")
	sho := NewShoHmacSha256Ext("key_derivation")
	kp, err := DeriveKeyPair(sho, domain)
	if err != nil {
		t.Fatalf("DeriveKeyPair failed: %v", err)
	}

	// Create a test attribute (two random points)
	attrSho := NewShoSha256Ext("test_attribute")
	m1 := attrSho.MustGetPoint()
	m2 := attrSho.MustGetPoint()
	attr := PointPairAttribute{m1, m2}

	// Encrypt
	ct := kp.Encrypt(attr)
	if ct == nil {
		t.Fatal("Encrypt returned nil")
	}

	// Decrypt second point
	decM2, err := kp.DecryptToSecondPoint(ct)
	if err != nil {
		t.Fatalf("DecryptToSecondPoint failed: %v", err)
	}

	if decM2.Equal(m2) != 1 {
		t.Fatal("decrypted M2 does not match original")
	}
}

func TestCiphertextEncodeDecode(t *testing.T) {
	domain := newTestDomain("TestCiphertextRoundTrip")
	sho := NewShoHmacSha256Ext("key_derivation")
	kp, err := DeriveKeyPair(sho, domain)
	if err != nil {
		t.Fatalf("DeriveKeyPair failed: %v", err)
	}

	attrSho := NewShoSha256Ext("test_attr")
	attr := PointPairAttribute{attrSho.MustGetPoint(), attrSho.MustGetPoint()}
	ct := kp.Encrypt(attr)

	encoded := EncodeCiphertext(ct)
	if len(encoded) != 64 {
		t.Fatalf("encoded ciphertext is %d bytes, want 64", len(encoded))
	}

	decoded, err := DecodeCiphertext(encoded)
	if err != nil {
		t.Fatalf("DecodeCiphertext failed: %v", err)
	}

	if !ct.Equal(decoded) {
		t.Fatal("round-trip ciphertext mismatch")
	}
}

func TestCredentialKeyPairGenerate(t *testing.T) {
	var randomness [RandomnessLen]byte
	for i := range randomness {
		randomness[i] = 0x42
	}
	kp := GenerateCredentialKeyPair(randomness)
	if kp == nil {
		t.Fatal("GenerateCredentialKeyPair returned nil")
	}
	if kp.PublicKey() == nil {
		t.Fatal("PublicKey is nil")
	}
	if kp.PrivateKey() == nil {
		t.Fatal("PrivateKey is nil")
	}
}

func TestGenerateCredentialKeyPairFromSHO(t *testing.T) {
	t.Run("produces valid key pair", func(t *testing.T) {
		sho := NewShoHmacSha256Ext("test_from_sho")
		sho.AbsorbAndRatchet([]byte("test_randomness"))
		kp := GenerateCredentialKeyPairFromSHO(sho)
		if kp == nil {
			t.Fatal("returned nil")
		}
		if kp.PublicKey() == nil {
			t.Fatal("PublicKey is nil")
		}
		if kp.PrivateKey() == nil {
			t.Fatal("PrivateKey is nil")
		}
	})

	t.Run("deterministic from same SHO state", func(t *testing.T) {
		sho1 := NewShoHmacSha256Ext("deterministic_test")
		sho1.AbsorbAndRatchet([]byte("seed"))
		kp1 := GenerateCredentialKeyPairFromSHO(sho1)

		sho2 := NewShoHmacSha256Ext("deterministic_test")
		sho2.AbsorbAndRatchet([]byte("seed"))
		kp2 := GenerateCredentialKeyPairFromSHO(sho2)

		if kp1.PublicKey().CW.Equal(kp2.PublicKey().CW) != 1 {
			t.Error("same SHO state produced different public keys")
		}
	})

	t.Run("sequential draws produce different keys", func(t *testing.T) {
		sho := NewShoHmacSha256Ext("chain_test")
		sho.AbsorbAndRatchet([]byte("seed"))
		kp1 := GenerateCredentialKeyPairFromSHO(sho)
		kp2 := GenerateCredentialKeyPairFromSHO(sho)

		if kp1.PublicKey().CW.Equal(kp2.PublicKey().CW) == 1 {
			t.Error("sequential SHO draws produced identical public keys")
		}
	})

	t.Run("differs from independent SHO generation", func(t *testing.T) {
		// GenerateCredentialKeyPair creates its own SHO internally, so the
		// chained version must produce different output even with same seed bytes.
		var randomness [RandomnessLen]byte
		copy(randomness[:], []byte("Signal_ZKCredential_CredentialPrivateKey_generate_20230410"))

		independentKP := GenerateCredentialKeyPair(randomness)

		sho := NewShoHmacSha256Ext("Signal_ZKGroup_20200424_Random_ServerSecretParams_Generate")
		sho.AbsorbAndRatchet(randomness[:])
		chainedKP := GenerateCredentialKeyPairFromSHO(sho)

		// These use different SHO labels/construction, so they must differ.
		if independentKP.PublicKey().CW.Equal(chainedKP.PublicKey().CW) == 1 {
			t.Error("chained and independent generation produced identical keys unexpectedly")
		}
	})
}

func TestCredentialIssuanceAndVerification(t *testing.T) {
	var keyRandomness [RandomnessLen]byte
	for i := range keyRandomness {
		keyRandomness[i] = 0x42
	}
	credKeyPair := GenerateCredentialKeyPair(keyRandomness)

	// Create a test attribute (two points)
	attrSho := NewShoSha256Ext("test_attribute_for_issuance")
	m1 := attrSho.MustGetPoint()
	m2 := attrSho.MustGetPoint()
	attr := PointPairAttribute{m1, m2}

	// Create a public attribute
	label := []byte("Signal_TestCredential_20230410")

	// Issue
	builder := NewIssuanceProofBuilder(label)
	builder.AddPublicAttribute(PublicAttributeBytes([]byte("public_attr_1")))
	if err := builder.AddAttribute(attr); err != nil {
		t.Fatalf("AddAttribute failed: %v", err)
	}

	var issueRandomness [RandomnessLen]byte
	for i := range issueRandomness {
		issueRandomness[i] = 0x43
	}
	proof, err := builder.Issue(credKeyPair, issueRandomness)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}
	if proof.Credential == nil {
		t.Fatal("credential is nil")
	}

	// Verify
	verifier := NewIssuanceProofBuilder(label)
	verifier.AddPublicAttribute(PublicAttributeBytes([]byte("public_attr_1")))
	if err := verifier.AddAttribute(attr); err != nil {
		t.Fatalf("AddAttribute failed: %v", err)
	}

	cred, err := verifier.Verify(credKeyPair.PublicKey(), proof)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if cred == nil {
		t.Fatal("verified credential is nil")
	}
}

func TestEndorsementDefaultFlow(t *testing.T) {
	inputSho := NewShoSha256Ext("test")

	var rootRandomness [RandomnessLen]byte
	for i := range rootRandomness {
		rootRandomness[i] = 42
	}
	rootKey, err := GenerateServerRootKeyPair(rootRandomness)
	if err != nil {
		t.Fatalf("GenerateServerRootKeyPair failed: %v", err)
	}

	// Client: create hidden attribute points
	clientPoints := make([]*ristretto255.Element, 3)
	for i := range clientPoints {
		clientPoints[i] = inputSho.MustGetPoint()
	}
	clientRawKey := inputSho.MustGetScalar()
	encryptedPoints := make([]*ristretto255.Element, 3)
	for i, p := range clientPoints {
		encryptedPoints[i] = new(ristretto255.Element).ScalarMult(clientRawKey, p)
	}

	infoSho := NewShoHmacSha256Ext("ExamplePass")
	infoSho.AbsorbAndRatchet([]byte("today's date"))

	// Server: derive key and issue endorsements
	todaysKey, err := rootKey.DeriveKey(infoSho.Clone())
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	var issueRandomness [RandomnessLen]byte
	for i := range issueRandomness {
		issueRandomness[i] = 43
	}
	response, err := IssueEndorsements(encryptedPoints, todaysKey, issueRandomness)
	if err != nil {
		t.Fatalf("IssueEndorsements failed: %v", err)
	}

	// Client: receive and validate endorsements
	decryptKey := NewClientDecryptionKeyFromBlinding(clientRawKey)
	todaysPublicKey, err := rootKey.PublicKey().DeriveKey(infoSho.Clone())
	if err != nil {
		t.Fatalf("DeriveKey (public) failed: %v", err)
	}

	endorsements, err := response.Receive(encryptedPoints, todaysPublicKey)
	if err != nil {
		t.Fatalf("Receive failed: %v", err)
	}

	if len(endorsements.Decompressed) != len(clientPoints) {
		t.Fatalf("wrong number of endorsements: got %d, want %d",
			len(endorsements.Decompressed), len(clientPoints))
	}
	if len(endorsements.Compressed) != len(clientPoints) {
		t.Fatalf("wrong number of compressed endorsements")
	}

	// Verify tokens
	for i, endorsement := range endorsements.Decompressed {
		token := endorsement.ToToken(decryptKey)
		if err := todaysKey.Verify(clientPoints[i], token); err != nil {
			t.Fatalf("token verification failed for point %d: %v", i, err)
		}
	}

	// Verify wrong point fails
	wrongPoint := ristretto255.NewGeneratorElement()
	token := endorsements.Decompressed[0].ToToken(decryptKey)
	if err := todaysKey.Verify(wrongPoint, token); err == nil {
		t.Fatal("expected verification failure for wrong point")
	}
}

func TestEndorsementCombine(t *testing.T) {
	inputSho := NewShoSha256Ext("test_combine")

	var rootRandomness [RandomnessLen]byte
	for i := range rootRandomness {
		rootRandomness[i] = 42
	}
	rootKey, err := GenerateServerRootKeyPair(rootRandomness)
	if err != nil {
		t.Fatalf("GenerateServerRootKeyPair failed: %v", err)
	}

	clientPoints := make([]*ristretto255.Element, 3)
	for i := range clientPoints {
		clientPoints[i] = inputSho.MustGetPoint()
	}
	clientRawKey := inputSho.MustGetScalar()
	encryptedPoints := make([]*ristretto255.Element, 3)
	for i, p := range clientPoints {
		encryptedPoints[i] = new(ristretto255.Element).ScalarMult(clientRawKey, p)
	}

	infoSho := NewShoHmacSha256Ext("ExampleEndorsements")
	infoSho.AbsorbAndRatchet([]byte("today's date"))

	todaysKey, err := rootKey.DeriveKey(infoSho.Clone())
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	var issueRandomness [RandomnessLen]byte
	for i := range issueRandomness {
		issueRandomness[i] = 43
	}
	response, err := IssueEndorsements(encryptedPoints, todaysKey, issueRandomness)
	if err != nil {
		t.Fatalf("IssueEndorsements failed: %v", err)
	}

	todaysPublicKey, err := rootKey.PublicKey().DeriveKey(infoSho.Clone())
	if err != nil {
		t.Fatalf("DeriveKey (public) failed: %v", err)
	}

	endorsements, err := response.Receive(encryptedPoints, todaysPublicKey)
	if err != nil {
		t.Fatalf("Receive failed: %v", err)
	}

	// Combine all three and remove the second
	combined := CombineEndorsements(endorsements.Decompressed)
	result := combined.Remove(endorsements.Decompressed[1])

	decryptKey := NewClientDecryptionKeyFromBlinding(clientRawKey)
	token := result.ToToken(decryptKey)

	// Should verify against sum of points 0 and 2
	combinedPoint := new(ristretto255.Element).Add(clientPoints[0], clientPoints[2])
	if err := todaysKey.Verify(combinedPoint, token); err != nil {
		t.Fatalf("combined token verification failed: %v", err)
	}

	// Manual combine should produce same token
	manual := endorsements.Decompressed[0].CombineWith(endorsements.Decompressed[2])
	manualToken := manual.ToToken(decryptKey)

	if len(token) != len(manualToken) {
		t.Fatal("token lengths differ")
	}
	for i := range token {
		if token[i] != manualToken[i] {
			t.Fatal("tokens differ")
		}
	}
}

func TestDefaultEndorsementIsIdentity(t *testing.T) {
	combined := CombineEndorsements(nil)
	def := DefaultEndorsement()
	if combined.R.Equal(def.R) != 1 {
		t.Fatal("combining zero endorsements should produce identity")
	}
}

func TestCredentialEncodeDecode(t *testing.T) {
	var randomness [RandomnessLen]byte
	for i := range randomness {
		randomness[i] = 0x42
	}
	kp := GenerateCredentialKeyPair(randomness)

	sho := NewShoHmacSha256Ext("test_credential")
	sho.AbsorbAndRatchet(randomness[:])

	attrPoints := []*ristretto255.Element{sho.MustGetPoint()}
	cred, err := kp.PrivateKey().CredentialCore(attrPoints, sho)
	if err != nil {
		t.Fatalf("CredentialCore failed: %v", err)
	}

	encoded := EncodeCredential(cred)
	if len(encoded) != 96 {
		t.Fatalf("encoded credential is %d bytes, want 96", len(encoded))
	}

	decoded, err := DecodeCredential(encoded)
	if err != nil {
		t.Fatalf("DecodeCredential failed: %v", err)
	}

	if cred.T.Equal(decoded.T) != 1 {
		t.Fatal("T mismatch")
	}
	if cred.U.Equal(decoded.U) != 1 {
		t.Fatal("U mismatch")
	}
	if cred.V.Equal(decoded.V) != 1 {
		t.Fatal("V mismatch")
	}
}
