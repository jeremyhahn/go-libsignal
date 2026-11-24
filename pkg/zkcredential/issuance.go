package zkcredential

import (
	"github.com/gtank/ristretto255"
	"github.com/jeremyhahn/go-libsignal/pkg/poksho"
)

// IssuanceProof contains a Credential along with a proof of its validity.
type IssuanceProof struct {
	Credential  *Credential
	PokshoProof []byte
}

// IssuanceProofBuilder is used to generate and verify issuance proofs.
//
// The same type is used for both generation (issue) and verification (verify).
type IssuanceProofBuilder struct {
	publicAttrs          *ShoExt
	attrPoints           []*ristretto255.Element
	authenticatedMessage []byte
}

// NewIssuanceProofBuilder creates a new builder with the given credential label.
// label is a mandatory public attribute that should uniquely identify the credential.
func NewIssuanceProofBuilder(label []byte) *IssuanceProofBuilder {
	return NewIssuanceProofBuilderWithMessage(label, nil)
}

// NewIssuanceProofBuilderWithMessage creates a new builder with a label and
// an authenticated message that must match between issuing server and client.
func NewIssuanceProofBuilderWithMessage(label []byte, message []byte) *IssuanceProofBuilder {
	return &IssuanceProofBuilder{
		publicAttrs:          NewShoHmacSha256Ext(string(label)),
		attrPoints:           []*ristretto255.Element{ristretto255.NewIdentityElement()},
		authenticatedMessage: message,
	}
}

// AddPublicAttribute adds a public attribute to the credential.
// This is order-sensitive.
func (b *IssuanceProofBuilder) AddPublicAttribute(attr PublicAttribute) *IssuanceProofBuilder {
	attr.HashInto(b.publicAttrs)
	b.publicAttrs.Ratchet()
	return b
}

// AddAttribute adds an attribute to the credential.
// This is order-sensitive.
func (b *IssuanceProofBuilder) AddAttribute(attr Attribute) error {
	points := attr.AsPoints()
	b.attrPoints = append(b.attrPoints, points[0], points[1])
	if len(b.attrPoints) > NumSupportedAttrs {
		return &ErrTooManyHiddenAttributes{Max: NumSupportedAttrs - 1}
	}
	return nil
}

func (b *IssuanceProofBuilder) finalizePublicAttrs() {
	b.attrPoints[0] = b.publicAttrs.MustGetPoint()
}

// getPokshoStatement builds the poksho Statement for issuance proofs.
// See Chase-Perrin-Zaverucha section 3.2.
func (b *IssuanceProofBuilder) getPokshoStatement() *poksho.Statement {
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
	st.Add("G_V-I", allTerms[:2+len(b.attrPoints)])

	// V = w * G_w + x0 * U + x1 * tU + sum(yi * Mi, i = 0..n)
	vTerms := [][2]string{
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
	st.Add("V", vTerms[:3+len(b.attrPoints)])

	return st
}

// prepareScalarArgs builds the scalar arguments for the proof.
func (b *IssuanceProofBuilder) prepareScalarArgs(
	keyPair *CredentialKeyPair,
	totalAttrCount int,
) *poksho.ScalarArgs {
	priv := keyPair.PrivateKey()
	args := poksho.NewScalarArgs()
	args.Add("w", priv.W)
	args.Add("wprime", priv.Wprime)
	args.Add("x0", priv.X0)
	args.Add("x1", priv.X1)

	yNames := [NumSupportedAttrs]string{"y0", "y1", "y2", "y3", "y4", "y5", "y6"}
	for i := 0; i < totalAttrCount; i++ {
		args.Add(yNames[i], priv.Y[i])
	}
	return args
}

// preparePointArgs builds the point arguments for the proof.
// If credential is nil, the caller is responsible for adding V, U, tU, and M points.
func (b *IssuanceProofBuilder) preparePointArgs(
	key *CredentialPublicKey,
	totalAttrCount int,
	credential *Credential,
) *poksho.PointArgs {
	system := GetSystemParams()
	args := poksho.NewPointArgs()

	args.Add("C_W", key.CW)
	args.Add("G_w", system.Gw)
	args.Add("G_wprime", system.Gwprime)
	args.Add("G_V-I", new(ristretto255.Element).Subtract(system.GV, key.GetI(totalAttrCount)))
	args.Add("G_x0", system.Gx0)
	args.Add("G_x1", system.Gx1)

	gyNames := [NumSupportedAttrs]string{"G_y0", "G_y1", "G_y2", "G_y3", "G_y4", "G_y5", "G_y6"}
	for i := 0; i < totalAttrCount; i++ {
		args.Add(gyNames[i], system.Gy[i])
	}

	if credential != nil {
		args.Add("V", credential.V)
		args.Add("U", credential.U)
		tU := new(ristretto255.Element).ScalarMult(credential.T, credential.U)
		args.Add("tU", tU)
	}

	mNames := [NumSupportedAttrs]string{"M0", "M1", "M2", "M3", "M4", "M5", "M6"}
	for i, pt := range b.attrPoints {
		args.Add(mNames[i], pt)
	}

	return args
}

// Issue generates a new credential and proof over the accumulated attributes.
//
// It is critical that different randomness is used each time a credential
// is issued. Failing to do so effectively reveals the server's private key.
func (b *IssuanceProofBuilder) Issue(
	keyPair *CredentialKeyPair,
	randomness [RandomnessLen]byte,
) (*IssuanceProof, error) {
	b.finalizePublicAttrs()

	if len(b.attrPoints) < 2 {
		return nil, &ErrMissingHiddenAttributes{}
	}

	sho := NewShoHmacSha256Ext("Signal_ZKCredential_Issuance_20230410")
	sho.AbsorbAndRatchet(randomness[:])

	credential, err := keyPair.PrivateKey().CredentialCore(b.attrPoints, sho)
	if err != nil {
		return nil, &ErrComputingCredential{Err: err}
	}

	scalarArgs := b.prepareScalarArgs(keyPair, len(b.attrPoints))
	pointArgs := b.preparePointArgs(keyPair.PublicKey(), len(b.attrPoints), credential)

	proofRandomness := sho.SqueezeAndRatchet(RandomnessLen)
	pokshoProof, err := b.getPokshoStatement().Prove(
		scalarArgs,
		pointArgs,
		b.authenticatedMessage,
		proofRandomness,
	)
	if err != nil {
		return nil, &ErrProofCreation{ProofType: "issuance", Err: err}
	}

	return &IssuanceProof{
		Credential:  credential,
		PokshoProof: pokshoProof,
	}, nil
}

// Verify verifies the given proof over the accrued attributes using the
// given public key. On success, returns the Credential.
func (b *IssuanceProofBuilder) Verify(
	publicKey *CredentialPublicKey,
	proof *IssuanceProof,
) (*Credential, error) {
	b.finalizePublicAttrs()

	if len(b.attrPoints) < 2 {
		return nil, ErrVerification
	}

	pointArgs := b.preparePointArgs(publicKey, len(b.attrPoints), proof.Credential)
	if err := b.getPokshoStatement().VerifyProof(
		proof.PokshoProof,
		pointArgs,
		b.authenticatedMessage,
	); err != nil {
		return nil, ErrVerification
	}
	return proof.Credential, nil
}

// EncodeIssuanceProof serializes an IssuanceProof.
func EncodeIssuanceProof(p *IssuanceProof) []byte {
	cred := EncodeCredential(p.Credential)
	out := make([]byte, 0, len(cred)+len(p.PokshoProof))
	out = append(out, cred...)
	out = append(out, p.PokshoProof...)
	return out
}
