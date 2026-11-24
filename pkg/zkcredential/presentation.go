package zkcredential

import (
	"encoding/binary"
	"fmt"

	"github.com/gtank/ristretto255"
	"github.com/jeremyhahn/go-libsignal/pkg/poksho"
)

// PresentationProofCommitments holds the commitment points for a presentation proof.
type PresentationProofCommitments struct {
	Cx0 *ristretto255.Element
	Cx1 *ristretto255.Element
	CV  *ristretto255.Element
	Cy  []*ristretto255.Element
}

// PresentationProof demonstrates to the verifying server that the client holds
// a particular credential.
type PresentationProof struct {
	Commitments PresentationProofCommitments
	PokshoProof []byte
}

// attributeRef tracks an attribute's position and encryption key.
type attributeRef struct {
	keyIndex         int // -1 if no key (revealed attribute)
	firstPointIndex  int
	secondPointIndex int
}

// anyPublicKey is a type-erased public key for heterogeneous storage.
type anyPublicKey struct {
	id string
	ga func() [2]*ristretto255.Element
	A  *ristretto255.Element
}

// anyKeyPair is a type-erased key pair for heterogeneous storage.
type anyKeyPair struct {
	a1        *ristretto255.Scalar
	a2        *ristretto255.Scalar
	publicKey *anyPublicKey // nil if key is not verified
	domainID  string
}

// mayHavePublicKey is a trait-like interface for types that may have a public key.
type mayHavePublicKey interface {
	id() string
	pubKey() *anyPublicKey
}

func (k *anyKeyPair) id() string            { return k.domainID }
func (k *anyKeyPair) pubKey() *anyPublicKey { return k.publicKey }

type presentationVerifierKey struct {
	domainID  string
	publicKey *anyPublicKey // nil if key is not verified
}

func (k *presentationVerifierKey) id() string            { return k.domainID }
func (k *presentationVerifierKey) pubKey() *anyPublicKey { return k.publicKey }

// presentationCore contains the common logic for building presentation statements.
type presentationCore struct {
	encryptionKeys       []mayHavePublicKey
	attributes           []attributeRef
	attrPoints           []*ristretto255.Element
	authenticatedMessage []byte
}

func newPresentationCore(message []byte) *presentationCore {
	return &presentationCore{
		attrPoints:           []*ristretto255.Element{ristretto255.NewIdentityElement()},
		authenticatedMessage: message,
	}
}

func (c *presentationCore) addAttribute(attrPoints []*ristretto255.Element, key mayHavePublicKey) {
	firstIndex := len(c.attrPoints)
	c.attrPoints = append(c.attrPoints, attrPoints...)
	if len(c.attrPoints) > NumSupportedAttrs {
		panic(fmt.Sprintf("zkcredential: more than %d hidden attribute points not supported", NumSupportedAttrs-1))
	}

	keyIndex := -1
	if key != nil {
		keyID := key.id()
		for i, existing := range c.encryptionKeys {
			if existing.id() == keyID {
				keyIndex = i
				break
			}
		}
		if keyIndex < 0 {
			keyIndex = len(c.encryptionKeys)
			c.encryptionKeys = append(c.encryptionKeys, key)
		}
	}

	c.attributes = append(c.attributes, attributeRef{
		keyIndex:         keyIndex,
		firstPointIndex:  firstIndex,
		secondPointIndex: firstIndex + len(attrPoints) - 1,
	})
}

// getPokshoStatement builds the poksho Statement for presentation proofs.
// Matches Rust's PresentationProofBuilderCore::get_poksho_statement.
func (c *presentationCore) getPokshoStatement() *poksho.Statement {
	st := poksho.NewStatement()
	// Chase-Perrin-Zaverucha section 3.2
	st.Add("Z", [][2]string{{"z", "I"}})
	st.Add("C_x1", [][2]string{{"t", "C_x0"}, {"z0", "G_x0"}, {"z", "G_x1"}})

	// Chase-Perrin-Zaverucha section 4.1 — encryption key validity
	var encryptionSumTerms [][2]string
	for _, key := range c.encryptionKeys {
		keyID := key.id()
		a1Name := fmt.Sprintf("a1_%s", keyID)

		// 0 = z1_uid * I + a1_uid * Z
		st.Add("0", [][2]string{
			{fmt.Sprintf("z1_%s", keyID), "I"},
			{a1Name, "Z"},
		})

		if key.pubKey() != nil {
			encryptionSumTerms = append(encryptionSumTerms,
				[2]string{a1Name, fmt.Sprintf("G_a1_%s", keyID)},
				[2]string{fmt.Sprintf("a2_%s", keyID), fmt.Sprintf("G_a2_%s", keyID)},
			)
		}
	}
	if len(encryptionSumTerms) > 0 {
		st.Add("sum(A)", encryptionSumTerms)
	}

	for _, attr := range c.attributes {
		if attr.keyIndex >= 0 {
			keyID := c.encryptionKeys[attr.keyIndex].id()
			// E_A1 = a1_uid * C_y1 + z1_uid * G_y1
			st.Add(
				fmt.Sprintf("E_A%d", attr.firstPointIndex),
				[][2]string{
					{fmt.Sprintf("a1_%s", keyID), fmt.Sprintf("C_y%d", attr.firstPointIndex)},
					{fmt.Sprintf("z1_%s", keyID), fmt.Sprintf("G_y%d", attr.firstPointIndex)},
				},
			)
			// C_y2 - E_A2 = z * G_y2 + a2_uid * -E_A1
			st.Add(
				fmt.Sprintf("C_y%d-E_A%d", attr.secondPointIndex, attr.secondPointIndex),
				[][2]string{
					{"z", fmt.Sprintf("G_y%d", attr.secondPointIndex)},
					{fmt.Sprintf("a2_%s", keyID), fmt.Sprintf("-E_A%d", attr.firstPointIndex)},
				},
			)
		} else {
			// Revealed attribute: C_y1 = z * G_y1
			st.Add(
				fmt.Sprintf("C_y%d", attr.firstPointIndex),
				[][2]string{{"z", fmt.Sprintf("G_y%d", attr.firstPointIndex)}},
			)
		}
	}

	// Point 0 is a hardcoded public attribute
	st.Add("C_y0", [][2]string{{"z", "G_y0"}})

	return st
}

// prepareNonAttributePointArgs builds the point args not derived from attributes.
func (c *presentationCore) prepareNonAttributePointArgs(
	I *ristretto255.Element,
	commitments *PresentationProofCommitments,
) *poksho.PointArgs {
	system := GetSystemParams()
	args := poksho.NewPointArgs()
	args.Add("I", I)
	args.Add("C_x0", commitments.Cx0)
	args.Add("C_x1", commitments.Cx1)
	args.Add("G_x0", system.Gx0)
	args.Add("G_x1", system.Gx1)

	if len(c.encryptionKeys) > 0 {
		args.Add("0", ristretto255.NewIdentityElement())
		sumA := ristretto255.NewIdentityElement()
		for _, key := range c.encryptionKeys {
			if pk := key.pubKey(); pk != nil {
				ga := pk.ga()
				args.Add(fmt.Sprintf("G_a1_%s", pk.id), ga[0])
				args.Add(fmt.Sprintf("G_a2_%s", pk.id), ga[1])
				sumA = sumA.Add(sumA, pk.A)
			}
		}
		// Only add sum(A) if we had at least one public key
		if sumA.Equal(ristretto255.NewIdentityElement()) != 1 {
			args.Add("sum(A)", sumA)
		}
	}

	gyNames := [NumSupportedAttrs]string{"G_y0", "G_y1", "G_y2", "G_y3", "G_y4", "G_y5", "G_y6"}
	for i := 0; i < len(c.attrPoints); i++ {
		args.Add(gyNames[i], system.Gy[i])
	}

	args.Add("C_y0", commitments.Cy[0])

	return args
}

// PresentationProofBuilder is used to generate presentation proofs.
type PresentationProofBuilder struct {
	core *presentationCore
}

// NewPresentationProofBuilder creates a new builder for generating a presentation.
func NewPresentationProofBuilder(label []byte) *PresentationProofBuilder {
	return NewPresentationProofBuilderWithMessage(label, nil)
}

// NewPresentationProofBuilderWithMessage creates a builder with an authenticated message.
func NewPresentationProofBuilderWithMessage(label []byte, message []byte) *PresentationProofBuilder {
	_ = label
	return &PresentationProofBuilder{
		core: newPresentationCore(message),
	}
}

// AddAttribute adds an encrypted attribute to the proof.
func (b *PresentationProofBuilder) AddAttribute(attr Attribute, key *KeyPair) {
	points := attr.AsPoints()
	b.core.addAttribute([]*ristretto255.Element{points[0], points[1]}, &anyKeyPair{
		a1:       key.A1,
		a2:       key.A2,
		domainID: key.domain.ID(),
		publicKey: &anyPublicKey{
			id: key.domain.ID(),
			ga: key.domain.Ga,
			A:  key.PublicKey.A,
		},
	})
}

// AddAttributeWithoutVerifiedKey adds an encrypted attribute without proving
// which key was used.
func (b *PresentationProofBuilder) AddAttributeWithoutVerifiedKey(attr Attribute, key *KeyPair) {
	points := attr.AsPoints()
	b.core.addAttribute([]*ristretto255.Element{points[0], points[1]}, &anyKeyPair{
		a1:       key.A1,
		a2:       key.A2,
		domainID: key.domain.ID(),
	})
}

// AddRevealedAttribute adds a revealed attribute to the proof.
func (b *PresentationProofBuilder) AddRevealedAttribute(attr RevealedAttribute) {
	_ = attr
	b.core.addAttribute([]*ristretto255.Element{ristretto255.NewIdentityElement()}, nil)
}

// Present generates the presentation proof for the given credential.
func (b *PresentationProofBuilder) Present(
	publicKey *CredentialPublicKey,
	credential *Credential,
	randomness [RandomnessLen]byte,
) (*PresentationProof, error) {
	system := GetSystemParams()

	sho := NewShoHmacSha256Ext("Signal_ZKCredential_Presentation_20230410")
	sho.AbsorbAndRatchet(randomness[:])
	z := sho.MustGetScalar()

	// Compute C_y = z * G_y + M for each attribute point
	Cy := make([]*ristretto255.Element, len(b.core.attrPoints))
	for i := 0; i < len(b.core.attrPoints); i++ {
		zGy := new(ristretto255.Element).ScalarMult(z, system.Gy[i])
		Cy[i] = new(ristretto255.Element).Add(zGy, b.core.attrPoints[i])
	}

	Cx0 := new(ristretto255.Element).ScalarMult(z, system.Gx0)
	Cx0 = Cx0.Add(Cx0, credential.U)

	CV := new(ristretto255.Element).ScalarMult(z, system.GV)
	CV = CV.Add(CV, credential.V)

	tU := new(ristretto255.Element).ScalarMult(credential.T, credential.U)
	Cx1 := new(ristretto255.Element).ScalarMult(z, system.Gx1)
	Cx1 = Cx1.Add(Cx1, tU)

	commitments := PresentationProofCommitments{
		Cx0: Cx0,
		Cx1: Cx1,
		CV:  CV,
		Cy:  Cy,
	}

	z0 := new(ristretto255.Scalar).Multiply(z, credential.T)
	z0 = z0.Negate(z0)

	I := publicKey.GetI(len(b.core.attrPoints))
	Z := new(ristretto255.Element).ScalarMult(z, I)

	// Build scalar and point args
	scalarArgs := poksho.NewScalarArgs()
	scalarArgs.Add("z", z)
	scalarArgs.Add("t", credential.T)
	scalarArgs.Add("z0", z0)
	for _, key := range b.core.encryptionKeys {
		kp, ok := key.(*anyKeyPair)
		if !ok {
			return nil, &ErrKeyPairTypeAssertion{Got: key}
		}
		keyID := kp.domainID
		scalarArgs.Add(fmt.Sprintf("a1_%s", keyID), kp.a1)
		scalarArgs.Add(fmt.Sprintf("a2_%s", keyID), kp.a2)
		z1 := new(ristretto255.Scalar).Multiply(z, kp.a1)
		z1 = z1.Negate(z1)
		scalarArgs.Add(fmt.Sprintf("z1_%s", keyID), z1)
	}

	pointArgs := b.core.prepareNonAttributePointArgs(I, &commitments)
	pointArgs.Add("Z", Z)

	for _, attr := range b.core.attributes {
		pointArgs.Add(fmt.Sprintf("C_y%d", attr.firstPointIndex), commitments.Cy[attr.firstPointIndex])

		if attr.keyIndex >= 0 {
			kp, ok := b.core.encryptionKeys[attr.keyIndex].(*anyKeyPair)
			if !ok {
				return nil, &ErrKeyPairTypeAssertion{Got: b.core.encryptionKeys[attr.keyIndex]}
			}
			EA1 := new(ristretto255.Element).ScalarMult(kp.a1, b.core.attrPoints[attr.firstPointIndex])
			EA2 := new(ristretto255.Element).ScalarMult(kp.a2, EA1)
			EA2 = EA2.Add(EA2, b.core.attrPoints[attr.secondPointIndex])
			pointArgs.Add(fmt.Sprintf("E_A%d", attr.firstPointIndex), EA1)
			pointArgs.Add(fmt.Sprintf("-E_A%d", attr.firstPointIndex), new(ristretto255.Element).Negate(EA1))
			pointArgs.Add(
				fmt.Sprintf("C_y%d-E_A%d", attr.secondPointIndex, attr.secondPointIndex),
				new(ristretto255.Element).Subtract(commitments.Cy[attr.secondPointIndex], EA2),
			)
		}
	}

	proofRandomness := sho.SqueezeAndRatchet(RandomnessLen)
	pokshoProof, err := b.core.getPokshoStatement().Prove(
		scalarArgs,
		pointArgs,
		b.core.authenticatedMessage,
		proofRandomness,
	)
	if err != nil {
		return nil, &ErrProofCreation{ProofType: "presentation", Err: err}
	}

	return &PresentationProof{
		Commitments: commitments,
		PokshoProof: pokshoProof,
	}, nil
}

// PresentationProofVerifier is used to verify presentation proofs.
type PresentationProofVerifier struct {
	core        *presentationCore
	publicAttrs *ShoExt
}

// NewPresentationProofVerifier creates a new verifier.
func NewPresentationProofVerifier(label []byte) *PresentationProofVerifier {
	return NewPresentationProofVerifierWithMessage(label, nil)
}

// NewPresentationProofVerifierWithMessage creates a verifier with an authenticated message.
func NewPresentationProofVerifierWithMessage(label []byte, message []byte) *PresentationProofVerifier {
	return &PresentationProofVerifier{
		core:        newPresentationCore(message),
		publicAttrs: NewShoHmacSha256Ext(string(label)),
	}
}

// AddPublicAttribute adds a public attribute to check against the credential.
func (v *PresentationProofVerifier) AddPublicAttribute(attr PublicAttribute) {
	attr.HashInto(v.publicAttrs)
	v.publicAttrs.Ratchet()
}

// AddAttribute adds an encrypted attribute with its public key.
func (v *PresentationProofVerifier) AddAttribute(attr Attribute, key *PublicKey) {
	points := attr.AsPoints()
	v.core.addAttribute([]*ristretto255.Element{points[0], points[1]}, &presentationVerifierKey{
		domainID: key.DomainID(),
		publicKey: &anyPublicKey{
			id: key.DomainID(),
			ga: key.Ga,
			A:  key.A,
		},
	})
}

// AddAttributeWithoutVerifiedKey adds an encrypted attribute without verifying
// which key encrypted it.
func (v *PresentationProofVerifier) AddAttributeWithoutVerifiedKey(attr Attribute, keyID string) {
	points := attr.AsPoints()
	v.core.addAttribute([]*ristretto255.Element{points[0], points[1]}, &presentationVerifierKey{
		domainID: keyID,
	})
}

// AddRevealedAttribute adds an unencrypted attribute to verify.
func (v *PresentationProofVerifier) AddRevealedAttribute(attr RevealedAttribute) {
	v.core.addAttribute([]*ristretto255.Element{attr.AsPoint()}, nil)
}

func (v *PresentationProofVerifier) finalizePublicAttrs() {
	v.core.attrPoints[0] = v.publicAttrs.MustGetPoint()
}

// Verify verifies the presentation proof against the given key pair.
func (v *PresentationProofVerifier) Verify(
	keyPair *CredentialKeyPair,
	proof *PresentationProof,
) error {
	v.finalizePublicAttrs()

	if len(proof.Commitments.Cy) != len(v.core.attrPoints) {
		return ErrVerification
	}

	priv := keyPair.PrivateKey()

	// Compute Z = C_V - W - x0*C_x0 - x1*C_x1 - sum(yn*C_yn) - y0*M0
	Z := new(ristretto255.Element).Set(proof.Commitments.CV)
	Z = Z.Subtract(Z, priv.Wpoint)

	x0Cx0 := new(ristretto255.Element).ScalarMult(priv.X0, proof.Commitments.Cx0)
	Z = Z.Subtract(Z, x0Cx0)

	x1Cx1 := new(ristretto255.Element).ScalarMult(priv.X1, proof.Commitments.Cx1)
	Z = Z.Subtract(Z, x1Cx1)

	for i, Cyi := range proof.Commitments.Cy {
		ynCyn := new(ristretto255.Element).ScalarMult(priv.Y[i], Cyi)
		Z = Z.Subtract(Z, ynCyn)
	}

	// Incorporate public attributes
	y0M0 := new(ristretto255.Element).ScalarMult(priv.Y[0], v.core.attrPoints[0])
	Z = Z.Subtract(Z, y0M0)

	// Incorporate revealed attributes
	for _, attr := range v.core.attributes {
		if attr.keyIndex < 0 {
			ynMn := new(ristretto255.Element).ScalarMult(
				priv.Y[attr.firstPointIndex],
				v.core.attrPoints[attr.firstPointIndex],
			)
			Z = Z.Subtract(Z, ynMn)
		}
	}

	pub := keyPair.PublicKey()
	I := pub.GetI(len(v.core.attrPoints))

	pointArgs := v.core.prepareNonAttributePointArgs(I, &proof.Commitments)

	for _, attr := range v.core.attributes {
		pointArgs.Add(fmt.Sprintf("C_y%d", attr.firstPointIndex), proof.Commitments.Cy[attr.firstPointIndex])

		if attr.keyIndex >= 0 {
			pointArgs.Add(
				fmt.Sprintf("E_A%d", attr.firstPointIndex),
				v.core.attrPoints[attr.firstPointIndex],
			)
			pointArgs.Add(
				fmt.Sprintf("-E_A%d", attr.firstPointIndex),
				new(ristretto255.Element).Negate(v.core.attrPoints[attr.firstPointIndex]),
			)
			pointArgs.Add(
				fmt.Sprintf("C_y%d-E_A%d", attr.secondPointIndex, attr.secondPointIndex),
				new(ristretto255.Element).Subtract(
					proof.Commitments.Cy[attr.secondPointIndex],
					v.core.attrPoints[attr.secondPointIndex],
				),
			)
		}
	}

	pointArgs.Add("Z", Z)

	if err := v.core.getPokshoStatement().VerifyProof(
		proof.PokshoProof,
		pointArgs,
		v.core.authenticatedMessage,
	); err != nil {
		return ErrVerification
	}

	return nil
}

// EncodePresentationProof encodes a PresentationProof to bytes.
func EncodePresentationProof(p *PresentationProof) []byte {
	numCy := len(p.Commitments.Cy)
	size := 32*3 + 4 + 32*numCy + len(p.PokshoProof)
	out := make([]byte, 0, size)
	out = append(out, p.Commitments.Cx0.Bytes()...)
	out = append(out, p.Commitments.Cx1.Bytes()...)
	out = append(out, p.Commitments.CV.Bytes()...)
	out = append(out, byte(numCy>>24), byte(numCy>>16), byte(numCy>>8), byte(numCy))
	for _, cy := range p.Commitments.Cy {
		out = append(out, cy.Bytes()...)
	}
	out = append(out, p.PokshoProof...)
	return out
}

// EncodePresentationProofBincode encodes a PresentationProof to Rust bincode
// wire format. This is the inverse of DecodePresentationProofBincode and produces
// byte-identical output to Rust's bincode::serialize on a PresentationProof.
//
// Layout (matches Rust zkcredential PresentationProof serde/bincode):
//
//	[0..32]     Cx0 (compressed Ristretto255 point)
//	[32..64]    Cx1
//	[64..96]    CV
//	[96..104]   Cy vec length (8-byte LE u64)
//	[104..104+32*n] Cy[0..n] (n compressed Ristretto255 points)
//	[104+32*n..112+32*n] poksho_proof vec length (8-byte LE u64)
//	[112+32*n..]  poksho_proof bytes
func EncodePresentationProofBincode(p *PresentationProof) []byte {
	cyLen := len(p.Commitments.Cy)
	proofLen := len(p.PokshoProof)
	out := make([]byte, 0, 32*3+8+32*cyLen+8+proofLen)

	out = append(out, p.Commitments.Cx0.Bytes()...)
	out = append(out, p.Commitments.Cx1.Bytes()...)
	out = append(out, p.Commitments.CV.Bytes()...)

	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], uint64(cyLen))
	out = append(out, lenBuf[:]...)
	for _, cy := range p.Commitments.Cy {
		out = append(out, cy.Bytes()...)
	}

	binary.LittleEndian.PutUint64(lenBuf[:], uint64(proofLen))
	out = append(out, lenBuf[:]...)
	out = append(out, p.PokshoProof...)

	return out
}

// DecodePresentationProofBincode decodes a PresentationProof from Rust bincode
// wire format. This differs from the Go-native encoding (EncodePresentationProof)
// in that vec lengths are 8-byte little-endian u64 values rather than 4-byte
// big-endian values.
//
// Layout (matches Rust zkcredential PresentationProof serde/bincode):
//
//	[0..32]     Cx0 (compressed Ristretto255 point)
//	[32..64]    Cx1
//	[64..96]    CV
//	[96..104]   Cy vec length (8-byte LE u64)
//	[104..104+32*n] Cy[0..n] (n compressed Ristretto255 points)
//	[104+32*n..112+32*n] poksho_proof vec length (8-byte LE u64)
//	[112+32*n..]  poksho_proof bytes
//
// Returns the decoded proof and the number of bytes consumed from data.
func DecodePresentationProofBincode(data []byte) (*PresentationProof, int, error) {
	const minLen = 32 + 32 + 32 + 8 // Cx0 + Cx1 + CV + Cy vec len
	if len(data) < minLen {
		return nil, 0, &ErrInvalidEncoding{Field: "PresentationProof", Err: &ErrSizeConstraint{Min: minLen, Got: len(data)}}
	}

	off := 0
	decodePoint := func(name string) (*ristretto255.Element, error) {
		el := ristretto255.NewIdentityElement()
		if _, err := el.SetCanonicalBytes(data[off : off+32]); err != nil {
			return nil, &ErrInvalidEncoding{Field: name, Err: err}
		}
		return el, nil
	}

	cx0, err := decodePoint("Cx0")
	if err != nil {
		return nil, 0, err
	}
	off += 32

	cx1, err := decodePoint("Cx1")
	if err != nil {
		return nil, 0, err
	}
	off += 32

	cv, err := decodePoint("CV")
	if err != nil {
		return nil, 0, err
	}
	off += 32

	if len(data) < off+8 {
		return nil, 0, &ErrInvalidEncoding{Field: "Cy vec length", Err: &ErrTruncated{}}
	}
	// readBincodeU64Len guards against u64 values >= 2^63 (negative after int cast)
	// and against lengths that claim more data than the input contains, matching
	// Rust's reject_trailing_bytes + bounded-alloc behavior.
	cyLen, err := readBincodeU64Len(data, off, 32, "Cy")
	if err != nil {
		return nil, 0, err
	}
	off += 8

	if len(data) < off+cyLen*32+8 {
		return nil, 0, &ErrInvalidEncoding{Field: "Cy points", Err: &ErrTruncatedNeed{Need: cyLen*32 + 8}}
	}
	cy := make([]*ristretto255.Element, cyLen)
	for i := range cy {
		cy[i], err = decodePoint(fmt.Sprintf("Cy[%d]", i))
		if err != nil {
			return nil, 0, err
		}
		off += 32
	}

	if len(data) < off+8 {
		return nil, 0, &ErrInvalidEncoding{Field: "poksho_proof vec length", Err: &ErrTruncated{}}
	}
	proofLen, err := readBincodeU64Len(data, off, 1, "poksho_proof")
	if err != nil {
		return nil, 0, err
	}
	off += 8

	if len(data) < off+proofLen {
		return nil, 0, &ErrInvalidEncoding{Field: "poksho_proof", Err: &ErrTruncatedNeed{Need: proofLen}}
	}
	pokshoProof := make([]byte, proofLen)
	copy(pokshoProof, data[off:off+proofLen])
	off += proofLen

	proof := &PresentationProof{
		Commitments: PresentationProofCommitments{
			Cx0: cx0,
			Cx1: cx1,
			CV:  cv,
			Cy:  cy,
		},
		PokshoProof: pokshoProof,
	}
	return proof, off, nil
}
