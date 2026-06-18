package zkgroup

import (
	"github.com/gtank/ristretto255"
	"github.com/jeremyhahn/go-libsignal/pkg/poksho"
	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
)

// ReceiptCredential is a credential proving that a user has a valid receipt.
type ReceiptCredential struct {
	Credential            *zkcredential.Credential
	ReceiptExpirationTime Timestamp
	ReceiptLvl            ReceiptLevel
	ReceiptSerialBuf      ReceiptSerialBytes
}

// GetReceiptExpirationTime returns the receipt's expiration time.
func (rc *ReceiptCredential) GetReceiptExpirationTime() Timestamp {
	return rc.ReceiptExpirationTime
}

// GetReceiptLevel returns the receipt level.
func (rc *ReceiptCredential) GetReceiptLevel() ReceiptLevel {
	return rc.ReceiptLvl
}

// receiptCredentialRequestKeyPair is a key pair for blinding receipt serial
// bytes in a credential request. Matches Rust
// crypto::receipt_credential_request::KeyPair.
type receiptCredentialRequestKeyPair struct {
	y *ristretto255.Scalar
	Y *ristretto255.Element // Y = y * G
}

// receiptCredentialRequestCiphertextWithSecretNonce is the blinded receipt
// serial bytes with the secret nonce retained. Matches Rust
// crypto::receipt_credential_request::CiphertextWithSecretNonce.
type receiptCredentialRequestCiphertextWithSecretNonce struct {
	r1 *ristretto255.Scalar
	D1 *ristretto255.Element // D1 = r1 * G
	D2 *ristretto255.Element // D2 = r1 * Y + M2
}

// receiptCredentialRequestCiphertext is the public portion of the blinded
// receipt serial bytes. Matches Rust
// crypto::receipt_credential_request::Ciphertext.
type receiptCredentialRequestCiphertext struct {
	D1 *ristretto255.Element
	D2 *ristretto255.Element
}

// blindedReceiptCredential is a receipt credential blinded by the server.
// Matches Rust crypto::credentials::BlindedReceiptCredential.
type blindedReceiptCredential struct {
	t  *ristretto255.Scalar
	U  *ristretto255.Element
	S1 *ristretto255.Element
	S2 *ristretto255.Element
}

// blindedReceiptCredentialWithSecretNonce includes the secret nonce.
// Matches Rust crypto::credentials::BlindedReceiptCredentialWithSecretNonce.
type blindedReceiptCredentialWithSecretNonce struct {
	rprime *ristretto255.Scalar
	t      *ristretto255.Scalar
	U      *ristretto255.Element
	S1     *ristretto255.Element
	S2     *ristretto255.Element
}

// ReceiptCredentialRequest is the client's request for a receipt credential.
type ReceiptCredentialRequest struct {
	PublicKey  *ristretto255.Element
	Ciphertext *receiptCredentialRequestCiphertext
}

// ReceiptCredentialRequestContext holds the state needed to process a receipt
// credential response.
type ReceiptCredentialRequestContext struct {
	ReceiptSerialBuf          ReceiptSerialBytes
	KeyPair                   *receiptCredentialRequestKeyPair
	CiphertextWithSecretNonce *receiptCredentialRequestCiphertextWithSecretNonce
}

// GetRequest returns the receipt credential request to send to the server.
func (ctx *ReceiptCredentialRequestContext) GetRequest() *ReceiptCredentialRequest {
	return &ReceiptCredentialRequest{
		PublicKey: ctx.KeyPair.Y,
		Ciphertext: &receiptCredentialRequestCiphertext{
			D1: ctx.CiphertextWithSecretNonce.D1,
			D2: ctx.CiphertextWithSecretNonce.D2,
		},
	}
}

// ReceiptCredentialResponse is the server's response containing a blinded
// receipt credential.
type ReceiptCredentialResponse struct {
	ReceiptExpirationTime Timestamp
	ReceiptLvl            ReceiptLevel
	BlindedCredential     *blindedReceiptCredential
	Proof                 []byte // poksho proof bytes
}

// ReceiptCredentialPresentation is a presentation of a receipt credential for
// verification.
type ReceiptCredentialPresentation struct {
	Cx0                   *ristretto255.Element
	Cx1                   *ristretto255.Element
	Cy1                   *ristretto255.Element
	Cy2                   *ristretto255.Element
	CV                    *ristretto255.Element
	PokshoProof           []byte
	ReceiptExpirationTime Timestamp
	ReceiptLvl            ReceiptLevel
	ReceiptSerialBuf      ReceiptSerialBytes
}

// GetReceiptExpirationTime returns the receipt's expiration time.
func (p *ReceiptCredentialPresentation) GetReceiptExpirationTime() Timestamp {
	return p.ReceiptExpirationTime
}

// GetReceiptLevel returns the receipt level.
func (p *ReceiptCredentialPresentation) GetReceiptLevel() ReceiptLevel {
	return p.ReceiptLvl
}

// GetReceiptSerialBytes returns the receipt serial bytes.
func (p *ReceiptCredentialPresentation) GetReceiptSerialBytes() ReceiptSerialBytes {
	return p.ReceiptSerialBuf
}

// GetReceiptStruct returns the ReceiptStruct for this presentation.
func (p *ReceiptCredentialPresentation) GetReceiptStruct() *ReceiptStruct {
	return NewReceiptStruct(
		p.ReceiptSerialBuf,
		p.ReceiptExpirationTime,
		p.ReceiptLvl,
	)
}

// CreateReceiptCredentialRequestContext creates a receipt credential request
// context from randomness and a receipt serial number. This is a client-side
// operation.
//
// Matches Rust ServerPublicParams::create_receipt_credential_request_context.
func (pub *ServerPublicParams) CreateReceiptCredentialRequestContext(
	randomness RandomnessBytes,
	receiptSerialBytes ReceiptSerialBytes,
) *ReceiptCredentialRequestContext {
	sho := zkcredential.NewShoHmacSha256Ext(
		"Signal_ZKGroup_20210919_Random_ServerPublicParams_CreateReceiptCredentialRequestContext",
	)
	sho.AbsorbAndRatchet(randomness[:])

	// Generate blinding key pair: y, Y = y*G
	y := sho.MustGetScalar()
	Y := new(ristretto255.Element).ScalarBaseMult(y)

	// Encrypt the receipt serial bytes: D1 = r1*G, D2 = r1*Y + M2
	M2 := ConvertToPointM2ReceiptSerialBytes(receiptSerialBytes)
	r1 := sho.MustGetScalar()
	D1 := new(ristretto255.Element).ScalarBaseMult(r1)
	D2 := new(ristretto255.Element).ScalarMult(r1, Y)
	D2 = D2.Add(D2, M2)

	return &ReceiptCredentialRequestContext{
		ReceiptSerialBuf: receiptSerialBytes,
		KeyPair: &receiptCredentialRequestKeyPair{
			y: y,
			Y: Y,
		},
		CiphertextWithSecretNonce: &receiptCredentialRequestCiphertextWithSecretNonce{
			r1: r1,
			D1: D1,
			D2: D2,
		},
	}
}

// IssueReceiptCredential creates a blinded receipt credential response.
// This is a server-side operation.
//
// Matches Rust ServerSecretParams::issue_receipt_credential.
func (s *ServerSecretParams) IssueReceiptCredential(
	randomness RandomnessBytes,
	request *ReceiptCredentialRequest,
	receiptExpirationTime Timestamp,
	receiptLevel ReceiptLevel,
) (*ReceiptCredentialResponse, error) {
	sho := zkcredential.NewShoHmacSha256Ext(
		"Signal_ZKGroup_20210919_Random_ServerSecretParams_IssueReceiptCredential",
	)
	sho.AbsorbAndRatchet(randomness[:])

	// Compute M1 point for receipt attributes.
	m1Scalar := CalcReceiptM1(receiptExpirationTime, receiptLevel)
	legacySys := zkcredential.GetLegacySystemParams()
	M1Point := new(ristretto255.Element).ScalarMult(m1Scalar, legacySys.Gm[0])
	M := []*ristretto255.Element{M1Point}

	// Create blinded credential using the receipt credentials key pair.
	priv := s.ReceiptCredentialsKeyPair.PrivateKey()
	cred, err := priv.CredentialCore(M, sho)
	if err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "receipt credential core: " + err.Error()}
	}

	// Blind the credential: S1 = y2*D1 + rprime*G, S2 = y2*D2 + rprime*Y + V
	rprime := sho.MustGetScalar()
	y2 := priv.Y[1] // y[1] is the second y-scalar (0-indexed) = receipt serial blinding key

	R1 := new(ristretto255.Element).ScalarBaseMult(rprime)
	R2 := new(ristretto255.Element).ScalarMult(rprime, request.PublicKey)
	R2 = R2.Add(R2, cred.V)

	S1 := new(ristretto255.Element).ScalarMult(y2, request.Ciphertext.D1)
	S1 = S1.Add(S1, R1)

	S2 := new(ristretto255.Element).ScalarMult(y2, request.Ciphertext.D2)
	S2 = S2.Add(S2, R2)

	blindedCred := &blindedReceiptCredentialWithSecretNonce{
		rprime: rprime,
		t:      cred.T,
		U:      cred.U,
		S1:     S1,
		S2:     S2,
	}

	// Generate issuance proof.
	proof, err := receiptCredentialIssuanceProofNew(
		s.ReceiptCredentialsKeyPair,
		request.PublicKey,
		request.Ciphertext,
		blindedCred,
		receiptExpirationTime,
		receiptLevel,
		sho,
	)
	if err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "receipt issuance proof: " + err.Error()}
	}

	return &ReceiptCredentialResponse{
		ReceiptExpirationTime: receiptExpirationTime,
		ReceiptLvl:            receiptLevel,
		BlindedCredential: &blindedReceiptCredential{
			t:  blindedCred.t,
			U:  blindedCred.U,
			S1: blindedCred.S1,
			S2: blindedCred.S2,
		},
		Proof: proof,
	}, nil
}

// ReceiveReceiptCredential verifies the server's response and unblinds the
// credential. This is a client-side operation.
//
// Returns ErrVerificationFailure if the receipt expiration time is not
// day-aligned, matching Rust's is_day_aligned() guard in
// rust/zkgroup/src/api/server_params.rs.
//
// Matches Rust ServerPublicParams::receive_receipt_credential.
func (pub *ServerPublicParams) ReceiveReceiptCredential(
	ctx *ReceiptCredentialRequestContext,
	response *ReceiptCredentialResponse,
) (*ReceiptCredential, error) {
	if !response.ReceiptExpirationTime.IsDayAligned() {
		return nil, ErrVerificationFailure
	}

	receiptStruct := NewReceiptStruct(
		ctx.ReceiptSerialBuf,
		response.ReceiptExpirationTime,
		response.ReceiptLvl,
	)

	// Verify the issuance proof.
	err := receiptCredentialIssuanceProofVerify(
		response.Proof,
		pub.ReceiptCredentialsPublicKey,
		ctx.KeyPair.Y,
		&receiptCredentialRequestCiphertext{
			D1: ctx.CiphertextWithSecretNonce.D1,
			D2: ctx.CiphertextWithSecretNonce.D2,
		},
		response.BlindedCredential,
		receiptStruct,
	)
	if err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "receipt credential verification: " + err.Error()}
	}

	// Unblind: V = S2 - y * S1
	yS1 := new(ristretto255.Element).ScalarMult(ctx.KeyPair.y, response.BlindedCredential.S1)
	V := new(ristretto255.Element).Subtract(response.BlindedCredential.S2, yS1)

	return &ReceiptCredential{
		Credential: &zkcredential.Credential{
			T: response.BlindedCredential.t,
			U: response.BlindedCredential.U,
			V: V,
		},
		ReceiptExpirationTime: response.ReceiptExpirationTime,
		ReceiptLvl:            response.ReceiptLvl,
		ReceiptSerialBuf:      ctx.ReceiptSerialBuf,
	}, nil
}

// CreateReceiptCredentialPresentation creates a zero-knowledge presentation
// of a receipt credential. This is a client-side operation.
//
// Matches Rust ServerPublicParams::create_receipt_credential_presentation.
func (pub *ServerPublicParams) CreateReceiptCredentialPresentation(
	randomness RandomnessBytes,
	receiptCredential *ReceiptCredential,
) (*ReceiptCredentialPresentation, error) {
	sho := zkcredential.NewShoHmacSha256Ext(
		"Signal_ZKGroup_20210919_Random_ServerPublicParams_CreateReceiptCredentialPresentation",
	)
	sho.AbsorbAndRatchet(randomness[:])

	legacySys := zkcredential.GetLegacySystemParams()
	credPubKey := pub.ReceiptCredentialsPublicKey

	z := sho.MustGetScalar()
	cred := receiptCredential.Credential

	Cy1 := new(ristretto255.Element).ScalarMult(z, legacySys.Gy[0])
	Cy2 := new(ristretto255.Element).ScalarMult(z, legacySys.Gy[1])

	I := credPubKey.GetI(LegacyReceiptCredentialConfig.NumAttrs)

	Cx0 := new(ristretto255.Element).ScalarMult(z, legacySys.Gx0)
	Cx0 = Cx0.Add(Cx0, cred.U)

	tU := new(ristretto255.Element).ScalarMult(cred.T, cred.U)
	Cx1 := new(ristretto255.Element).ScalarMult(z, legacySys.Gx1)
	Cx1 = Cx1.Add(Cx1, tU)

	CV := new(ristretto255.Element).ScalarMult(z, legacySys.GV)
	CV = CV.Add(CV, cred.V)

	// Scalar arguments
	scalarArgs := poksho.NewScalarArgs()
	scalarArgs.Add("z", z)
	scalarArgs.Add("t", cred.T)
	zt := new(ristretto255.Scalar).Multiply(z, cred.T)
	negZt := new(ristretto255.Scalar).Negate(zt)
	scalarArgs.Add("-zt", negZt)

	// Point arguments
	Z := new(ristretto255.Element).ScalarMult(z, I)

	pointArgs := poksho.NewPointArgs()
	pointArgs.Add("Z", Z)
	pointArgs.Add("I", I)
	pointArgs.Add("C_x0", Cx0)
	pointArgs.Add("C_x1", Cx1)
	pointArgs.Add("C_y1", Cy1)
	pointArgs.Add("C_y2", Cy2)
	pointArgs.Add("G_x0", legacySys.Gx0)
	pointArgs.Add("G_x1", legacySys.Gx1)
	pointArgs.Add("G_y1", legacySys.Gy[0])
	pointArgs.Add("G_y2", legacySys.Gy[1])

	proofRandomness := sho.SqueezeAndRatchet(RandomnessLen)
	st := receiptCredentialPresentationStatement()
	proofBytes, err := st.Prove(scalarArgs, pointArgs, nil, proofRandomness)
	if err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "receipt presentation proof: " + err.Error()}
	}

	return &ReceiptCredentialPresentation{
		Cx0:                   Cx0,
		Cx1:                   Cx1,
		Cy1:                   Cy1,
		Cy2:                   Cy2,
		CV:                    CV,
		PokshoProof:           proofBytes,
		ReceiptExpirationTime: receiptCredential.ReceiptExpirationTime,
		ReceiptLvl:            receiptCredential.ReceiptLvl,
		ReceiptSerialBuf:      receiptCredential.ReceiptSerialBuf,
	}, nil
}

// VerifyReceiptCredentialPresentation verifies a receipt credential
// presentation. This is a server-side operation.
//
// Matches Rust ServerSecretParams::verify_receipt_credential_presentation.
func (s *ServerSecretParams) VerifyReceiptCredentialPresentation(
	presentation *ReceiptCredentialPresentation,
) error {
	legacySys := zkcredential.GetLegacySystemParams()
	priv := s.ReceiptCredentialsKeyPair.PrivateKey()
	credPubKey := s.ReceiptCredentialsKeyPair.PublicKey()

	receiptStruct := presentation.GetReceiptStruct()
	M := ConvertToPointsReceiptStruct(receiptStruct)

	// Reconstruct Z = C_V - W - x0*C_x0 - x1*C_x1 - y1*(C_y1 + M[0]) - y2*(C_y2 + M[1])
	Z := new(ristretto255.Element).Set(presentation.CV)
	Z = Z.Subtract(Z, priv.Wpoint)

	x0Cx0 := new(ristretto255.Element).ScalarMult(priv.X0, presentation.Cx0)
	Z = Z.Subtract(Z, x0Cx0)

	x1Cx1 := new(ristretto255.Element).ScalarMult(priv.X1, presentation.Cx1)
	Z = Z.Subtract(Z, x1Cx1)

	Cy1PlusM0 := new(ristretto255.Element).Add(presentation.Cy1, M[0])
	y1Term := new(ristretto255.Element).ScalarMult(priv.Y[0], Cy1PlusM0)
	Z = Z.Subtract(Z, y1Term)

	Cy2PlusM1 := new(ristretto255.Element).Add(presentation.Cy2, M[1])
	y2Term := new(ristretto255.Element).ScalarMult(priv.Y[1], Cy2PlusM1)
	Z = Z.Subtract(Z, y2Term)

	I := credPubKey.GetI(LegacyReceiptCredentialConfig.NumAttrs)

	pointArgs := poksho.NewPointArgs()
	pointArgs.Add("Z", Z)
	pointArgs.Add("I", I)
	pointArgs.Add("C_x0", presentation.Cx0)
	pointArgs.Add("C_x1", presentation.Cx1)
	pointArgs.Add("C_y1", presentation.Cy1)
	pointArgs.Add("C_y2", presentation.Cy2)
	pointArgs.Add("G_x0", legacySys.Gx0)
	pointArgs.Add("G_x1", legacySys.Gx1)
	pointArgs.Add("G_y1", legacySys.Gy[0])
	pointArgs.Add("G_y2", legacySys.Gy[1])

	st := receiptCredentialPresentationStatement()
	err := st.VerifyProof(presentation.PokshoProof, pointArgs, nil)
	if err != nil {
		return &ZkGroupVerificationFailure{Context: "receipt presentation verification failed"}
	}
	return nil
}

// receiptCredentialPresentationStatement returns the poksho statement for
// receipt credential presentations. Matches Rust
// ReceiptCredentialPresentationProof::get_poksho_statement.
func receiptCredentialPresentationStatement() *poksho.Statement {
	st := poksho.NewStatement()
	st.Add("Z", [][2]string{{"z", "I"}})
	st.Add("C_x1", [][2]string{{"t", "C_x0"}, {"-zt", "G_x0"}, {"z", "G_x1"}})
	st.Add("C_y1", [][2]string{{"z", "G_y1"}})
	st.Add("C_y2", [][2]string{{"z", "G_y2"}})
	return st
}

// receiptCredentialIssuanceStatement returns the poksho statement for receipt
// credential issuance. Matches Rust
// ReceiptCredentialIssuanceProof::get_poksho_statement.
func receiptCredentialIssuanceStatement() *poksho.Statement {
	st := poksho.NewStatement()
	st.Add("C_W", [][2]string{{"w", "G_w"}, {"wprime", "G_wprime"}})
	st.Add("G_V-I", [][2]string{{"x0", "G_x0"}, {"x1", "G_x1"}, {"y1", "G_y1"}, {"y2", "G_y2"}})
	st.Add("S1", [][2]string{{"y2", "D1"}, {"rprime", "G"}})
	st.Add("S2", [][2]string{{"y2", "D2"}, {"rprime", "Y"}, {"w", "G_w"}, {"x0", "U"}, {"x1", "tU"}, {"y1", "M1"}})
	return st
}

// receiptCredentialIssuanceProofNew generates a poksho issuance proof.
func receiptCredentialIssuanceProofNew(
	keyPair *zkcredential.CredentialKeyPair,
	requestPublicKey *ristretto255.Element,
	request *receiptCredentialRequestCiphertext,
	blindedCred *blindedReceiptCredentialWithSecretNonce,
	receiptExpirationTime Timestamp,
	receiptLevel ReceiptLevel,
	sho *zkcredential.ShoExt,
) ([]byte, error) {
	legacySys := zkcredential.GetLegacySystemParams()
	priv := keyPair.PrivateKey()
	credPubKey := keyPair.PublicKey()

	m1Scalar := CalcReceiptM1(receiptExpirationTime, receiptLevel)

	scalarArgs := poksho.NewScalarArgs()
	scalarArgs.Add("w", priv.W)
	scalarArgs.Add("wprime", priv.Wprime)
	scalarArgs.Add("x0", priv.X0)
	scalarArgs.Add("x1", priv.X1)
	scalarArgs.Add("y1", priv.Y[0])
	scalarArgs.Add("y2", priv.Y[1])
	scalarArgs.Add("rprime", blindedCred.rprime)

	I := credPubKey.GetI(LegacyReceiptCredentialConfig.NumAttrs)
	GVminusI := new(ristretto255.Element).Subtract(legacySys.GV, I)
	tU := new(ristretto255.Element).ScalarMult(blindedCred.t, blindedCred.U)
	M1Point := new(ristretto255.Element).ScalarMult(m1Scalar, legacySys.Gm[0])

	pointArgs := poksho.NewPointArgs()
	pointArgs.Add("C_W", credPubKey.CW)
	pointArgs.Add("G_w", legacySys.Gw)
	pointArgs.Add("G_wprime", legacySys.Gwprime)
	pointArgs.Add("G_V-I", GVminusI)
	pointArgs.Add("G_x0", legacySys.Gx0)
	pointArgs.Add("G_x1", legacySys.Gx1)
	pointArgs.Add("G_y1", legacySys.Gy[0])
	pointArgs.Add("G_y2", legacySys.Gy[1])
	pointArgs.Add("S1", blindedCred.S1)
	pointArgs.Add("D1", request.D1)
	pointArgs.Add("S2", blindedCred.S2)
	pointArgs.Add("D2", request.D2)
	pointArgs.Add("Y", requestPublicKey)
	pointArgs.Add("U", blindedCred.U)
	pointArgs.Add("tU", tU)
	pointArgs.Add("M1", M1Point)

	proofRandomness := sho.SqueezeAndRatchet(RandomnessLen)
	st := receiptCredentialIssuanceStatement()
	return st.Prove(scalarArgs, pointArgs, nil, proofRandomness)
}

// receiptCredentialIssuanceProofVerify verifies a poksho issuance proof.
func receiptCredentialIssuanceProofVerify(
	proofBytes []byte,
	credPubKey *zkcredential.CredentialPublicKey,
	requestPublicKey *ristretto255.Element,
	request *receiptCredentialRequestCiphertext,
	blindedCred *blindedReceiptCredential,
	receiptStruct *ReceiptStruct,
) error {
	legacySys := zkcredential.GetLegacySystemParams()

	M := ConvertToPointsReceiptStruct(receiptStruct)

	I := credPubKey.GetI(LegacyReceiptCredentialConfig.NumAttrs)
	GVminusI := new(ristretto255.Element).Subtract(legacySys.GV, I)
	tU := new(ristretto255.Element).ScalarMult(blindedCred.t, blindedCred.U)

	pointArgs := poksho.NewPointArgs()
	pointArgs.Add("C_W", credPubKey.CW)
	pointArgs.Add("G_w", legacySys.Gw)
	pointArgs.Add("G_wprime", legacySys.Gwprime)
	pointArgs.Add("G_V-I", GVminusI)
	pointArgs.Add("G_x0", legacySys.Gx0)
	pointArgs.Add("G_x1", legacySys.Gx1)
	pointArgs.Add("G_y1", legacySys.Gy[0])
	pointArgs.Add("G_y2", legacySys.Gy[1])
	pointArgs.Add("S1", blindedCred.S1)
	pointArgs.Add("D1", request.D1)
	pointArgs.Add("S2", blindedCred.S2)
	pointArgs.Add("D2", request.D2)
	pointArgs.Add("Y", requestPublicKey)
	pointArgs.Add("U", blindedCred.U)
	pointArgs.Add("tU", tU)
	pointArgs.Add("M1", M[0])

	st := receiptCredentialIssuanceStatement()
	return st.VerifyProof(proofBytes, pointArgs, nil)
}
