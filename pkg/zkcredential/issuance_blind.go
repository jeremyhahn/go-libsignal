package zkcredential

import (
	"github.com/gtank/ristretto255"
	"github.com/jeremyhahn/go-libsignal/pkg/poksho"
)

// BlindedPoint is a representation of a single blinded point.
type BlindedPoint struct {
	// R is the nonce scalar (only present on client side).
	R  *ristretto255.Scalar
	D1 *ristretto255.Element
	D2 *ristretto255.Element
}

// BlindedPointWithoutNonce is a BlindedPoint without the nonce,
// suitable for serialization and sending to the server.
type BlindedPointWithoutNonce struct {
	D1 *ristretto255.Element
	D2 *ristretto255.Element
}

// StripNonce removes the nonce from a BlindedPoint.
func (bp *BlindedPoint) StripNonce() *BlindedPointWithoutNonce {
	return &BlindedPointWithoutNonce{
		D1: bp.D1,
		D2: bp.D2,
	}
}

// BlindedAttribute is an attribute blinded for issuance.
type BlindedAttribute struct {
	BlindedPoints [2]*BlindedPoint
}

// BlindedAttributeWithoutNonce is a BlindedAttribute without nonces.
type BlindedAttributeWithoutNonce struct {
	BlindedPoints [2]*BlindedPointWithoutNonce
}

// StripNonce removes nonces from a BlindedAttribute.
func (ba *BlindedAttribute) StripNonce() *BlindedAttributeWithoutNonce {
	return &BlindedAttributeWithoutNonce{
		BlindedPoints: [2]*BlindedPointWithoutNonce{
			ba.BlindedPoints[0].StripNonce(),
			ba.BlindedPoints[1].StripNonce(),
		},
	}
}

// BlindingPrivateKey is used by the client to blind attributes.
type BlindingPrivateKey struct {
	Y *ristretto255.Scalar
}

// Zeroize overwrites the private scalar with zero.
// This should be called when the key is no longer needed.
func (bpk *BlindingPrivateKey) Zeroize() {
	zeroScalar(bpk.Y)
	bpk.Y = nil
}

// BlindingPublicKey is used by the issuing server to work with blinded attributes.
type BlindingPublicKey struct {
	Ypoint *ristretto255.Element
}

// BlindingKeyPair is used by the client to blind attributes for issuance.
type BlindingKeyPair struct {
	PrivKey *BlindingPrivateKey
	PubKey  *BlindingPublicKey
}

// Zeroize overwrites the private key material and nils all references.
// This should be called when the key pair is no longer needed.
func (bkp *BlindingKeyPair) Zeroize() {
	if bkp.PrivKey != nil {
		bkp.PrivKey.Zeroize()
		bkp.PrivKey = nil
	}
	bkp.PubKey = nil
}

// GenerateBlindingKeyPair generates a new blinding key pair from the SHO state.
func GenerateBlindingKeyPair(sho *ShoExt) (*BlindingKeyPair, error) {
	y, err := sho.GetScalar()
	if err != nil {
		return nil, &ErrGeneratingBlindingKey{Err: err}
	}
	priv := &BlindingPrivateKey{Y: y}
	G := ristretto255.NewGeneratorElement()
	pub := &BlindingPublicKey{
		Ypoint: new(ristretto255.Element).ScalarMult(y, G),
	}
	return &BlindingKeyPair{PrivKey: priv, PubKey: pub}, nil
}

// Blind blinds a revealed attribute for credential issuance.
func (bkp *BlindingKeyPair) Blind(attr RevealedAttribute, sho *ShoExt) (*BlindedPoint, error) {
	r, err := sho.GetScalar()
	if err != nil {
		return nil, &ErrGeneratingBlindingNonce{Err: err}
	}
	G := ristretto255.NewGeneratorElement()
	D1 := new(ristretto255.Element).ScalarMult(r, G)
	rY := new(ristretto255.Element).ScalarMult(r, bkp.PubKey.Ypoint)
	D2 := new(ristretto255.Element).Add(rY, attr.AsPoint())
	return &BlindedPoint{R: r, D1: D1, D2: D2}, nil
}

// Encrypt blinds a regular attribute for credential issuance.
func (bkp *BlindingKeyPair) Encrypt(attr Attribute, sho *ShoExt) (*BlindedAttribute, error) {
	points := attr.AsPoints()
	bp0, err := bkp.Blind(&PointAttribute{Point: points[0]}, sho)
	if err != nil {
		return nil, err
	}
	bp1, err := bkp.Blind(&PointAttribute{Point: points[1]}, sho)
	if err != nil {
		return nil, err
	}
	return &BlindedAttribute{BlindedPoints: [2]*BlindedPoint{bp0, bp1}}, nil
}

// BlindedCredential is a credential encrypted with a blinding key.
type BlindedCredential struct {
	T  *ristretto255.Scalar
	U  *ristretto255.Element
	S1 *ristretto255.Element
	S2 *ristretto255.Element
}

// BlindedIssuanceProof contains a BlindedCredential along with a proof.
type BlindedIssuanceProof struct {
	Credential  *BlindedCredential
	PokshoProof []byte
}

// BlindedIssuanceProofBuilder handles blinded attribute issuance.
type BlindedIssuanceProofBuilder struct {
	inner             *IssuanceProofBuilder
	blindedAttrPoints []*BlindedPointWithoutNonce
}

// NewBlindedIssuanceProofBuilder creates a BlindedIssuanceProofBuilder from
// an IssuanceProofBuilder.
func NewBlindedIssuanceProofBuilder(inner *IssuanceProofBuilder) *BlindedIssuanceProofBuilder {
	return &BlindedIssuanceProofBuilder{
		inner:             inner,
		blindedAttrPoints: nil,
	}
}

// AddBlindedAttribute adds a blinded attribute (two blinded points).
func (b *BlindedIssuanceProofBuilder) AddBlindedAttribute(
	attr *BlindedAttributeWithoutNonce,
) error {
	if err := b.AddBlindedRevealedAttribute(attr.BlindedPoints[0]); err != nil {
		return err
	}
	return b.AddBlindedRevealedAttribute(attr.BlindedPoints[1])
}

// AddBlindedRevealedAttribute adds a single blinded point attribute.
func (b *BlindedIssuanceProofBuilder) AddBlindedRevealedAttribute(
	attr *BlindedPointWithoutNonce,
) error {
	b.blindedAttrPoints = append(b.blindedAttrPoints, attr)
	totalAttrs := len(b.inner.attrPoints) + len(b.blindedAttrPoints)
	if totalAttrs > NumSupportedAttrs {
		return &ErrTooManyHiddenAttributes{Max: NumSupportedAttrs - 1}
	}
	return nil
}

// getPokshoStatement builds the poksho Statement for blinded issuance proofs.
// Generalized from Chase-Perrin-Zaverucha section 5.9.
func (b *BlindedIssuanceProofBuilder) getPokshoStatement() *poksho.Statement {
	numUnblinded := len(b.inner.attrPoints)
	numBlinded := len(b.blindedAttrPoints)
	totalAttrs := numUnblinded + numBlinded

	st := poksho.NewStatement()
	st.Add("C_W", [][2]string{{"w", "G_w"}, {"wprime", "G_wprime"}})

	// G_V - I = x0 * G_x0 + x1 * G_x1 + sum(yi * G_yi, i = 0..n)
	allTerms := [][2]string{
		{"x0", "G_x0"},
		{"x1", "G_x1"},
		{"y0", "G_y0"},
		{"y1", "G_y1"},
		{"y2", "G_y2"},
		{"y3", "G_y3"},
		{"y4", "G_y4"},
		{"y5", "G_y5"},
		{"y6", "G_y6"},
	}
	st.Add("G_V-I", allTerms[:2+totalAttrs])

	// S1 = rprime * G + sum(yi * D1_i, i = numUnblinded..total)
	s1Terms := [][2]string{
		{"y0", "D1_0"},
		{"y1", "D1_1"},
		{"y2", "D1_2"},
		{"y3", "D1_3"},
		{"y4", "D1_4"},
		{"y5", "D1_5"},
		{"y6", "D1_6"},
	}
	s1 := make([][2]string, 0, numBlinded+1)
	s1 = append(s1, s1Terms[numUnblinded:numUnblinded+numBlinded]...)
	s1 = append(s1, [2]string{"rprime", "G"})
	st.Add("S1", s1)

	// S2 = rprime * Y + w * G_w + x0 * U + x1 * tU + sum(yi * Mi, i = 0..numUnblinded)
	//    + sum(yi * D2_i, i = numUnblinded..total)
	vTermsWithRprime := [][2]string{
		{"rprime", "Y"},
		{"w", "G_w"},
		{"x0", "U"},
		{"x1", "tU"},
		{"y0", "M0"},
		{"y1", "M1"},
		{"y2", "M2"},
		{"y3", "M3"},
		{"y4", "M4"},
		{"y5", "M5"},
		{"y6", "M6"},
	}
	s2Terms := [][2]string{
		{"y0", "D2_0"},
		{"y1", "D2_1"},
		{"y2", "D2_2"},
		{"y3", "D2_3"},
		{"y4", "D2_4"},
		{"y5", "D2_5"},
		{"y6", "D2_6"},
	}
	s2 := make([][2]string, 0, 4+numUnblinded+numBlinded)
	s2 = append(s2, vTermsWithRprime[:4+numUnblinded]...)
	s2 = append(s2, s2Terms[numUnblinded:numUnblinded+numBlinded]...)
	st.Add("S2", s2)

	return st
}

func (b *BlindedIssuanceProofBuilder) prepareScalarArgs(
	keyPair *CredentialKeyPair,
	rprime *ristretto255.Scalar,
) *poksho.ScalarArgs {
	totalAttrs := len(b.inner.attrPoints) + len(b.blindedAttrPoints)
	args := b.inner.prepareScalarArgs(keyPair, totalAttrs)
	args.Add("rprime", rprime)
	return args
}

func (b *BlindedIssuanceProofBuilder) preparePointArgs(
	key *CredentialPublicKey,
	blindingKey *BlindingPublicKey,
	credential *BlindedCredential,
) *poksho.PointArgs {
	totalAttrs := len(b.inner.attrPoints) + len(b.blindedAttrPoints)
	args := b.inner.preparePointArgs(key, totalAttrs, nil)

	d1Names := [NumSupportedAttrs]string{"D1_0", "D1_1", "D1_2", "D1_3", "D1_4", "D1_5", "D1_6"}
	d2Names := [NumSupportedAttrs]string{"D2_0", "D2_1", "D2_2", "D2_3", "D2_4", "D2_5", "D2_6"}
	numUnblinded := len(b.inner.attrPoints)
	for i, bp := range b.blindedAttrPoints {
		args.Add(d1Names[numUnblinded+i], bp.D1)
		args.Add(d2Names[numUnblinded+i], bp.D2)
	}

	args.Add("S1", credential.S1)
	args.Add("S2", credential.S2)
	args.Add("U", credential.U)
	tU := new(ristretto255.Element).ScalarMult(credential.T, credential.U)
	args.Add("tU", tU)
	args.Add("Y", blindingKey.Ypoint)

	return args
}

// Issue generates a blinded credential and proof.
func (b *BlindedIssuanceProofBuilder) Issue(
	keyPair *CredentialKeyPair,
	blindingKey *BlindingPublicKey,
	randomness [RandomnessLen]byte,
) (*BlindedIssuanceProof, error) {
	b.inner.finalizePublicAttrs()

	totalAttrs := len(b.inner.attrPoints) + len(b.blindedAttrPoints)
	if totalAttrs < 2 {
		return nil, &ErrMissingHiddenAttributes{}
	}

	sho := NewShoHmacSha256Ext("Signal_ZKCredential_BlindIssuance_20230410")
	sho.AbsorbAndRatchet(randomness[:])

	rprime := sho.MustGetScalar()

	// S1 = rprime * G + sum(yi * D1_i)
	G := ristretto255.NewGeneratorElement()
	S1 := new(ristretto255.Element).ScalarMult(rprime, G)
	priv := keyPair.PrivateKey()
	numUnblinded := len(b.inner.attrPoints)
	for i, bp := range b.blindedAttrPoints {
		yD1 := new(ristretto255.Element).ScalarMult(priv.Y[numUnblinded+i], bp.D1)
		S1 = S1.Add(S1, yD1)
	}

	// Compute base credential over unblinded attributes
	baseCred, err := priv.CredentialCore(b.inner.attrPoints, sho)
	if err != nil {
		return nil, &ErrComputingBaseCredential{Err: err}
	}

	// S2 = rprime * Y + V + sum(yi * D2_i)
	S2 := new(ristretto255.Element).ScalarMult(rprime, blindingKey.Ypoint)
	S2 = S2.Add(S2, baseCred.V)
	for i, bp := range b.blindedAttrPoints {
		yD2 := new(ristretto255.Element).ScalarMult(priv.Y[numUnblinded+i], bp.D2)
		S2 = S2.Add(S2, yD2)
	}

	credential := &BlindedCredential{
		T:  baseCred.T,
		U:  baseCred.U,
		S1: S1,
		S2: S2,
	}

	scalarArgs := b.prepareScalarArgs(keyPair, rprime)
	pointArgs := b.preparePointArgs(keyPair.PublicKey(), blindingKey, credential)

	proofRandomness := sho.SqueezeAndRatchet(RandomnessLen)
	pokshoProof, err := b.getPokshoStatement().Prove(
		scalarArgs,
		pointArgs,
		b.inner.authenticatedMessage,
		proofRandomness,
	)
	if err != nil {
		return nil, &ErrProofCreation{ProofType: "blinded issuance", Err: err}
	}

	return &BlindedIssuanceProof{
		Credential:  credential,
		PokshoProof: pokshoProof,
	}, nil
}

// Verify verifies a blinded issuance proof and decrypts the credential.
// This is a complete implementation that recomputes the transcript and
// verifies the proof using the poksho Statement system.
func (b *BlindedIssuanceProofBuilder) Verify(
	publicKey *CredentialPublicKey,
	blindingKeyPair *BlindingKeyPair,
	proof *BlindedIssuanceProof,
) (*Credential, error) {
	b.inner.finalizePublicAttrs()

	totalAttrs := len(b.inner.attrPoints) + len(b.blindedAttrPoints)
	if totalAttrs < 2 {
		return nil, ErrVerification
	}

	pointArgs := b.preparePointArgs(publicKey, blindingKeyPair.PubKey, proof.Credential)
	if err := b.getPokshoStatement().VerifyProof(
		proof.PokshoProof,
		pointArgs,
		b.inner.authenticatedMessage,
	); err != nil {
		return nil, ErrVerification
	}

	// Decrypt: V = S2 - y * S1
	yS1 := new(ristretto255.Element).ScalarMult(blindingKeyPair.PrivKey.Y, proof.Credential.S1)
	V := new(ristretto255.Element).Subtract(proof.Credential.S2, yS1)

	return &Credential{
		T: proof.Credential.T,
		U: proof.Credential.U,
		V: V,
	}, nil
}

// EncodeBlindedCredential encodes a BlindedCredential to bytes.
func EncodeBlindedCredential(c *BlindedCredential) []byte {
	out := make([]byte, 0, 32+32+32+32)
	out = append(out, c.T.Bytes()...)
	out = append(out, c.U.Bytes()...)
	out = append(out, c.S1.Bytes()...)
	out = append(out, c.S2.Bytes()...)
	return out
}

// DecodeBlindedCredential decodes a BlindedCredential from bytes.
func DecodeBlindedCredential(data []byte) (*BlindedCredential, error) {
	if len(data) < 128 {
		return nil, ErrVerification
	}
	t := ristretto255.NewScalar()
	if _, err := t.SetCanonicalBytes(data[0:32]); err != nil {
		return nil, ErrVerification
	}
	u := ristretto255.NewIdentityElement()
	if _, err := u.SetCanonicalBytes(data[32:64]); err != nil {
		return nil, ErrVerification
	}
	s1 := ristretto255.NewIdentityElement()
	if _, err := s1.SetCanonicalBytes(data[64:96]); err != nil {
		return nil, ErrVerification
	}
	s2 := ristretto255.NewIdentityElement()
	if _, err := s2.SetCanonicalBytes(data[96:128]); err != nil {
		return nil, ErrVerification
	}
	return &BlindedCredential{T: t, U: u, S1: s1, S2: s2}, nil
}

// EncodeBlindedIssuanceProof serializes a BlindedIssuanceProof.
func EncodeBlindedIssuanceProof(p *BlindedIssuanceProof) []byte {
	cred := EncodeBlindedCredential(p.Credential)
	out := make([]byte, 0, len(cred)+len(p.PokshoProof))
	out = append(out, cred...)
	out = append(out, p.PokshoProof...)
	return out
}

// DecodeBlindedPoint decodes a BlindedPoint (without nonce) from bytes.
// The serialized form is D1 (32 bytes) + D2 (32 bytes).
func DecodeBlindedPoint(data []byte) (*BlindedPoint, error) {
	if len(data) < 64 {
		return nil, ErrVerification
	}
	d1 := ristretto255.NewIdentityElement()
	if _, err := d1.SetCanonicalBytes(data[0:32]); err != nil {
		return nil, ErrVerification
	}
	d2 := ristretto255.NewIdentityElement()
	if _, err := d2.SetCanonicalBytes(data[32:64]); err != nil {
		return nil, ErrVerification
	}
	return &BlindedPoint{D1: d1, D2: d2}, nil
}

// DecodeBlindingPublicKey decodes a BlindingPublicKey from bytes.
func DecodeBlindingPublicKey(data []byte) (*BlindingPublicKey, error) {
	if len(data) < 32 {
		return nil, ErrVerification
	}
	ypoint := ristretto255.NewIdentityElement()
	if _, err := ypoint.SetCanonicalBytes(data[0:32]); err != nil {
		return nil, ErrVerification
	}
	return &BlindingPublicKey{Ypoint: ypoint}, nil
}

// EncodeBlindedPoint encodes a BlindedPoint (D1+D2 only, without nonce) to bytes.
func EncodeBlindedPoint(bp *BlindedPoint) []byte {
	out := make([]byte, 0, 64)
	out = append(out, bp.D1.Bytes()...)
	out = append(out, bp.D2.Bytes()...)
	return out
}

// EncodeBlindingPublicKey encodes a BlindingPublicKey to bytes.
func EncodeBlindingPublicKey(pk *BlindingPublicKey) []byte {
	return pk.Ypoint.Bytes()
}
