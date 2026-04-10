package zkgroup

import (
	"github.com/gtank/ristretto255"
	"github.com/jeremyhahn/go-libsignal/pkg/poksho"
	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
)

// profileKeyCredentialRequestKeyPair is a key pair for blinding profile key
// struct points in a credential request. Matches Rust
// crypto::profile_key_credential_request::KeyPair.
type profileKeyCredentialRequestKeyPair struct {
	y *ristretto255.Scalar
	Y *ristretto255.Element // Y = y * G
}

// profileKeyCredentialRequestCiphertextWithSecretNonce is the blinded profile
// key struct with the secret nonces retained. Matches Rust
// crypto::profile_key_credential_request::CiphertextWithSecretNonce.
type profileKeyCredentialRequestCiphertextWithSecretNonce struct {
	r1 *ristretto255.Scalar
	r2 *ristretto255.Scalar
	D1 *ristretto255.Element // D1 = r1 * G
	D2 *ristretto255.Element // D2 = r1 * Y + M3
	E1 *ristretto255.Element // E1 = r2 * G
	E2 *ristretto255.Element // E2 = r2 * Y + M4
}

// profileKeyCredentialRequestCiphertext is the public portion of the blinded
// profile key struct. Matches Rust
// crypto::profile_key_credential_request::Ciphertext.
type profileKeyCredentialRequestCiphertext struct {
	D1 *ristretto255.Element
	D2 *ristretto255.Element
	E1 *ristretto255.Element
	E2 *ristretto255.Element
}

// blindedExpiringProfileKeyCredential is an expiring profile key credential
// blinded by the server. Matches Rust
// crypto::credentials::BlindedExpiringProfileKeyCredential.
type blindedExpiringProfileKeyCredential struct {
	t  *ristretto255.Scalar
	U  *ristretto255.Element
	S1 *ristretto255.Element
	S2 *ristretto255.Element
}

// blindedExpiringProfileKeyCredentialWithSecretNonce includes the secret nonce.
// Matches Rust crypto::credentials::BlindedExpiringProfileKeyCredentialWithSecretNonce.
type blindedExpiringProfileKeyCredentialWithSecretNonce struct {
	rprime *ristretto255.Scalar
	t      *ristretto255.Scalar
	U      *ristretto255.Element
	S1     *ristretto255.Element
	S2     *ristretto255.Element
}

// ProfileKeyCredentialRequest is a request for a profile key credential.
// This contains the public key, encrypted profile key points, and proof.
type ProfileKeyCredentialRequest struct {
	PublicKey  *ristretto255.Element
	Ciphertext *profileKeyCredentialRequestCiphertext
	Proof      []byte // poksho proof bytes
}

// ProfileKeyCredentialRequestContext holds the state needed to process a
// profile key credential response.
type ProfileKeyCredentialRequestContext struct {
	ACIBytes                  UIDBytes
	ProfileKeyBytes           ProfileKeyBytes
	KeyPair                   *profileKeyCredentialRequestKeyPair
	CiphertextWithSecretNonce *profileKeyCredentialRequestCiphertextWithSecretNonce
	Proof                     []byte // poksho proof bytes
}

// GetRequest returns the credential request to send to the server.
func (ctx *ProfileKeyCredentialRequestContext) GetRequest() *ProfileKeyCredentialRequest {
	return &ProfileKeyCredentialRequest{
		PublicKey: ctx.KeyPair.Y,
		Ciphertext: &profileKeyCredentialRequestCiphertext{
			D1: ctx.CiphertextWithSecretNonce.D1,
			D2: ctx.CiphertextWithSecretNonce.D2,
			E1: ctx.CiphertextWithSecretNonce.E1,
			E2: ctx.CiphertextWithSecretNonce.E2,
		},
		Proof: ctx.Proof,
	}
}

// ExpiringProfileKeyCredential is a profile key credential with an expiration
// time.
type ExpiringProfileKeyCredential struct {
	Credential              *zkcredential.Credential
	ACIBytes                UIDBytes
	ProfileKeyBytes         ProfileKeyBytes
	CredentialExpirationTime Timestamp
}

// GetExpirationTime returns the credential's expiration time.
func (c *ExpiringProfileKeyCredential) GetExpirationTime() Timestamp {
	return c.CredentialExpirationTime
}

// ACI returns the ACI as a ServiceID.
func (c *ExpiringProfileKeyCredential) ACI() ServiceID {
	return NewACI(c.ACIBytes)
}

// ExpiringProfileKeyCredentialResponse is the server's response containing a
// blinded expiring profile key credential.
type ExpiringProfileKeyCredentialResponse struct {
	BlindedCredential        *blindedExpiringProfileKeyCredential
	CredentialExpirationTime Timestamp
	Proof                    []byte // poksho proof bytes
}

// ExpiringProfileKeyCredentialPresentation is a presentation of an expiring
// profile key credential for verification.
type ExpiringProfileKeyCredentialPresentation struct {
	Cx0                     *ristretto255.Element
	Cx1                     *ristretto255.Element
	Cy1                     *ristretto255.Element
	Cy2                     *ristretto255.Element
	Cy3                     *ristretto255.Element
	Cy4                     *ristretto255.Element
	Cy5                     *ristretto255.Element
	CV                      *ristretto255.Element
	PokshoProof             []byte
	UIDEncCiphertext        *UUIDCiphertext
	ProfileKeyEncCiphertext *ProfileKeyCiphertext
	CredentialExpirationTime Timestamp
}

// GetUUIDCiphertext returns the encrypted UUID.
func (p *ExpiringProfileKeyCredentialPresentation) GetUUIDCiphertext() *UUIDCiphertext {
	return p.UIDEncCiphertext
}

// GetProfileKeyCiphertext returns the encrypted profile key.
func (p *ExpiringProfileKeyCredentialPresentation) GetProfileKeyCiphertext() *ProfileKeyCiphertext {
	return p.ProfileKeyEncCiphertext
}

// GetExpirationTime returns the credential's expiration time.
func (p *ExpiringProfileKeyCredentialPresentation) GetExpirationTime() Timestamp {
	return p.CredentialExpirationTime
}

// AnyProfileKeyCredentialPresentation holds any version of profile key
// credential presentation.
type AnyProfileKeyCredentialPresentation struct {
	Version      byte
	Presentation *ExpiringProfileKeyCredentialPresentation
}

// GetUUIDCiphertext returns the encrypted UUID from any version.
func (p *AnyProfileKeyCredentialPresentation) GetUUIDCiphertext() *UUIDCiphertext {
	if p.Presentation == nil {
		return nil
	}
	return p.Presentation.UIDEncCiphertext
}

// GetProfileKeyCiphertext returns the encrypted profile key from any version.
func (p *AnyProfileKeyCredentialPresentation) GetProfileKeyCiphertext() *ProfileKeyCiphertext {
	if p.Presentation == nil {
		return nil
	}
	return p.Presentation.ProfileKeyEncCiphertext
}

// CreateProfileKeyCredentialRequestContext creates a profile key credential
// request context. This is a client-side operation.
//
// Matches Rust ServerPublicParams::create_profile_key_credential_request_context.
func (pub *ServerPublicParams) CreateProfileKeyCredentialRequestContext(
	randomness RandomnessBytes,
	aci ServiceID,
	profileKey *ProfileKey,
) (*ProfileKeyCredentialRequestContext, error) {
	sho := zkcredential.NewShoHmacSha256Ext(
		"Signal_ZKGroup_20200424_Random_ServerPublicParams_CreateProfileKeyCredentialRequestContext",
	)
	sho.AbsorbAndRatchet(randomness[:])

	uidBytes := aci.RawUUID
	profileKeyStruct := NewProfileKeyStruct(profileKey.Bytes, uidBytes)

	commitmentWithSecretNonce := NewProfileKeyCommitmentWithSecretNonce(profileKeyStruct, uidBytes)

	// Generate request key pair: y, Y = y*G
	y := sho.MustGetScalar()
	Y := new(ristretto255.Element).ScalarBaseMult(y)

	// Encrypt profile key struct points: D1 = r1*G, D2 = r1*Y + M3, E1 = r2*G, E2 = r2*Y + M4
	r1 := sho.MustGetScalar()
	r2 := sho.MustGetScalar()
	D1 := new(ristretto255.Element).ScalarBaseMult(r1)
	E1 := new(ristretto255.Element).ScalarBaseMult(r2)

	D2 := new(ristretto255.Element).ScalarMult(r1, Y)
	D2 = D2.Add(D2, profileKeyStruct.M3)

	E2 := new(ristretto255.Element).ScalarMult(r2, Y)
	E2 = E2.Add(E2, profileKeyStruct.M4)

	ciphertextWithSecretNonce := &profileKeyCredentialRequestCiphertextWithSecretNonce{
		r1: r1,
		r2: r2,
		D1: D1,
		D2: D2,
		E1: E1,
		E2: E2,
	}

	// Generate ProfileKeyCredentialRequestProof
	proof, err := profileKeyCredentialRequestProofNew(
		&profileKeyCredentialRequestKeyPair{y: y, Y: Y},
		ciphertextWithSecretNonce,
		commitmentWithSecretNonce,
		sho,
	)
	if err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "profile key request proof: " + err.Error()}
	}

	return &ProfileKeyCredentialRequestContext{
		ACIBytes:                  uidBytes,
		ProfileKeyBytes:           profileKey.Bytes,
		KeyPair:                   &profileKeyCredentialRequestKeyPair{y: y, Y: Y},
		CiphertextWithSecretNonce: ciphertextWithSecretNonce,
		Proof:                     proof,
	}, nil
}

// IssueExpiringProfileKeyCredential creates a blinded expiring profile key
// credential response. This is a server-side operation.
//
// Matches Rust ServerSecretParams::issue_expiring_profile_key_credential.
func (s *ServerSecretParams) IssueExpiringProfileKeyCredential(
	randomness RandomnessBytes,
	request *ProfileKeyCredentialRequest,
	aci ServiceID,
	commitment *ProfileKeyCommitment,
	credentialExpirationTime Timestamp,
) (*ExpiringProfileKeyCredentialResponse, error) {
	sho := zkcredential.NewShoHmacSha256Ext(
		"Signal_ZKGroup_20220508_Random_ServerSecretParams_IssueExpiringProfileKeyCredential",
	)
	sho.AbsorbAndRatchet(randomness[:])

	// Verify the request proof.
	err := profileKeyCredentialRequestProofVerify(
		request.Proof,
		request.PublicKey,
		&profileKeyCredentialRequestCiphertext{
			D1: request.Ciphertext.D1,
			D2: request.Ciphertext.D2,
			E1: request.Ciphertext.E1,
			E2: request.Ciphertext.E2,
		},
		commitment.Commitment,
	)
	if err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "profile key request verification: " + err.Error()}
	}

	uid := NewUIDStructFromServiceID(aci)
	legacySys := zkcredential.GetLegacySystemParams()
	priv := s.ExpiringProfileKeyCredentialsKeyPair.PrivateKey()

	// Compute M points for UID (M1, M2 only)
	M := []*ristretto255.Element{uid.M1, uid.M2}

	// Create base credential over UID points
	cred, err := priv.CredentialCore(M, sho)
	if err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "expiring profile key credential core: " + err.Error()}
	}

	// Add expiration time contribution: V += y5 * M5
	m5Scalar := CalcTimestampM(credentialExpirationTime)
	M5 := new(ristretto255.Element).ScalarMult(m5Scalar, legacySys.Gm[4]) // G_m5
	y5M5 := new(ristretto255.Element).ScalarMult(priv.Y[4], M5)           // y[4] = y5 (0-indexed)
	Vprime := new(ristretto255.Element).Add(cred.V, y5M5)

	// Blind the credential: S1 = y3*D1 + y4*E1 + rprime*G, S2 = y3*D2 + y4*E2 + rprime*Y + Vprime
	rprime := sho.MustGetScalar()

	R1 := new(ristretto255.Element).ScalarBaseMult(rprime)
	R2 := new(ristretto255.Element).ScalarMult(rprime, request.PublicKey)
	R2 = R2.Add(R2, Vprime)

	y3 := priv.Y[2] // y[2] = y3 (0-indexed) - profile key M3 blinding
	y4 := priv.Y[3] // y[3] = y4 (0-indexed) - profile key M4 blinding

	S1 := new(ristretto255.Element).ScalarMult(y3, request.Ciphertext.D1)
	y4E1 := new(ristretto255.Element).ScalarMult(y4, request.Ciphertext.E1)
	S1 = S1.Add(S1, y4E1)
	S1 = S1.Add(S1, R1)

	S2 := new(ristretto255.Element).ScalarMult(y3, request.Ciphertext.D2)
	y4E2 := new(ristretto255.Element).ScalarMult(y4, request.Ciphertext.E2)
	S2 = S2.Add(S2, y4E2)
	S2 = S2.Add(S2, R2)

	blindedCred := &blindedExpiringProfileKeyCredentialWithSecretNonce{
		rprime: rprime,
		t:      cred.T,
		U:      cred.U,
		S1:     S1,
		S2:     S2,
	}

	// Generate issuance proof.
	proof, err := expiringProfileKeyCredentialIssuanceProofNew(
		s.ExpiringProfileKeyCredentialsKeyPair,
		request.PublicKey,
		request.Ciphertext,
		blindedCred,
		uid,
		credentialExpirationTime,
		sho,
	)
	if err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "expiring profile key issuance proof: " + err.Error()}
	}

	return &ExpiringProfileKeyCredentialResponse{
		BlindedCredential: &blindedExpiringProfileKeyCredential{
			t:  blindedCred.t,
			U:  blindedCred.U,
			S1: blindedCred.S1,
			S2: blindedCred.S2,
		},
		CredentialExpirationTime: credentialExpirationTime,
		Proof:                    proof,
	}, nil
}

// ReceiveExpiringProfileKeyCredential verifies the server's response and
// unblinds the credential. This is a client-side operation.
//
// Matches Rust ServerPublicParams::receive_expiring_profile_key_credential.
func (pub *ServerPublicParams) ReceiveExpiringProfileKeyCredential(
	ctx *ProfileKeyCredentialRequestContext,
	response *ExpiringProfileKeyCredentialResponse,
	currentTime Timestamp,
) (*ExpiringProfileKeyCredential, error) {
	// Verify the issuance proof.
	err := expiringProfileKeyCredentialIssuanceProofVerify(
		response.Proof,
		pub.ExpiringProfileKeyCredentialsPublicKey,
		ctx.KeyPair.Y,
		ctx.ACIBytes,
		&profileKeyCredentialRequestCiphertext{
			D1: ctx.CiphertextWithSecretNonce.D1,
			D2: ctx.CiphertextWithSecretNonce.D2,
			E1: ctx.CiphertextWithSecretNonce.E1,
			E2: ctx.CiphertextWithSecretNonce.E2,
		},
		response.BlindedCredential,
		response.CredentialExpirationTime,
	)
	if err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "expiring profile key credential verification: " + err.Error()}
	}

	// Check expiration time is day-aligned.
	if !response.CredentialExpirationTime.IsDayAligned() {
		return nil, &ZkGroupVerificationFailure{Context: "credential expiration time not day-aligned"}
	}

	// Check days remaining: must be 1..7.
	daysRemaining := response.CredentialExpirationTime.SaturatingSecondsSince(currentTime) / SecondsPerDay
	if daysRemaining == 0 || daysRemaining > 7 {
		return nil, &ZkGroupVerificationFailure{Context: "credential expiration time out of range"}
	}

	// Unblind: V = S2 - y * S1
	yS1 := new(ristretto255.Element).ScalarMult(ctx.KeyPair.y, response.BlindedCredential.S1)
	V := new(ristretto255.Element).Subtract(response.BlindedCredential.S2, yS1)

	return &ExpiringProfileKeyCredential{
		Credential: &zkcredential.Credential{
			T: response.BlindedCredential.t,
			U: response.BlindedCredential.U,
			V: V,
		},
		ACIBytes:                ctx.ACIBytes,
		ProfileKeyBytes:         ctx.ProfileKeyBytes,
		CredentialExpirationTime: response.CredentialExpirationTime,
	}, nil
}

// CreateExpiringProfileKeyCredentialPresentation creates a zero-knowledge
// presentation of an expiring profile key credential. This is a client-side
// operation.
//
// Matches Rust ServerPublicParams::create_expiring_profile_key_credential_presentation.
func (pub *ServerPublicParams) CreateExpiringProfileKeyCredentialPresentation(
	randomness RandomnessBytes,
	groupSecretParams *GroupSecretParams,
	credential *ExpiringProfileKeyCredential,
) (*ExpiringProfileKeyCredentialPresentation, error) {
	sho := zkcredential.NewShoHmacSha256Ext(
		"Signal_ZKGroup_20220508_Random_ServerPublicParams_CreateExpiringProfileKeyCredentialPresentation",
	)
	sho.AbsorbAndRatchet(randomness[:])

	legacySys := zkcredential.GetLegacySystemParams()
	credPubKey := pub.ExpiringProfileKeyCredentialsPublicKey

	aci := credential.ACI()
	uid := NewUIDStructFromServiceID(aci)
	profileKeyStruct := NewProfileKeyStruct(credential.ProfileKeyBytes, credential.ACIBytes)

	z := sho.MustGetScalar()
	cred := credential.Credential

	// Compute commitment points
	Cy1 := new(ristretto255.Element).ScalarMult(z, legacySys.Gy[0])
	Cy1 = Cy1.Add(Cy1, uid.M1)

	Cy2 := new(ristretto255.Element).ScalarMult(z, legacySys.Gy[1])
	Cy2 = Cy2.Add(Cy2, uid.M2)

	Cy3 := new(ristretto255.Element).ScalarMult(z, legacySys.Gy[2])
	Cy3 = Cy3.Add(Cy3, profileKeyStruct.M3)

	Cy4 := new(ristretto255.Element).ScalarMult(z, legacySys.Gy[3])
	Cy4 = Cy4.Add(Cy4, profileKeyStruct.M4)

	Cy5 := new(ristretto255.Element).ScalarMult(z, legacySys.Gy[4])

	I := credPubKey.GetI(LegacyExpiringProfileKeyCredentialConfig.NumAttrs)

	Cx0 := new(ristretto255.Element).ScalarMult(z, legacySys.Gx0)
	Cx0 = Cx0.Add(Cx0, cred.U)

	tU := new(ristretto255.Element).ScalarMult(cred.T, cred.U)
	Cx1 := new(ristretto255.Element).ScalarMult(z, legacySys.Gx1)
	Cx1 = Cx1.Add(Cx1, tU)

	CV := new(ristretto255.Element).ScalarMult(z, legacySys.GV)
	CV = CV.Add(CV, cred.V)

	Z := new(ristretto255.Element).ScalarMult(z, I)

	// Encryption ciphertexts
	uuidCiphertext := groupSecretParams.EncryptServiceID(aci)
	profileKeyCiphertext := groupSecretParams.EncryptProfileKeyBytes(credential.ProfileKeyBytes, aci)

	EA1 := uuidCiphertext.Ciphertext.EA1
	EA2 := uuidCiphertext.Ciphertext.EA2
	EB1 := profileKeyCiphertext.Ciphertext.EA1
	EB2 := profileKeyCiphertext.Ciphertext.EA2

	uidDomain := UIDEncryptionDomain{}
	pkDomain := ProfileKeyEncryptionDomain{}
	uidGa := uidDomain.Ga()
	pkGa := pkDomain.Ga()

	z0 := new(ristretto255.Scalar).Multiply(z, cred.T)
	z0 = z0.Negate(z0)
	z1 := new(ristretto255.Scalar).Multiply(z, groupSecretParams.UIDEncKeyPair.A1)
	z1 = z1.Negate(z1)
	z2 := new(ristretto255.Scalar).Multiply(z, groupSecretParams.ProfileKeyEncKeyPair.A1)
	z2 = z2.Negate(z2)

	// Scalar args
	scalarArgs := poksho.NewScalarArgs()
	scalarArgs.Add("z", z)
	scalarArgs.Add("t", cred.T)
	scalarArgs.Add("z0", z0)
	scalarArgs.Add("a1", groupSecretParams.UIDEncKeyPair.A1)
	scalarArgs.Add("a2", groupSecretParams.UIDEncKeyPair.A2)
	scalarArgs.Add("b1", groupSecretParams.ProfileKeyEncKeyPair.A1)
	scalarArgs.Add("b2", groupSecretParams.ProfileKeyEncKeyPair.A2)
	scalarArgs.Add("z1", z1)
	scalarArgs.Add("z2", z2)

	// Point args
	pointArgs := poksho.NewPointArgs()
	pointArgs.Add("Z", Z)
	pointArgs.Add("I", I)
	pointArgs.Add("C_x1", Cx1)
	pointArgs.Add("C_x0", Cx0)
	pointArgs.Add("G_x0", legacySys.Gx0)
	pointArgs.Add("G_x1", legacySys.Gx1)

	AplusB := new(ristretto255.Element).Add(
		groupSecretParams.UIDEncKeyPair.PublicKey.A,
		groupSecretParams.ProfileKeyEncKeyPair.PublicKey.A,
	)
	pointArgs.Add("A+B", AplusB)
	pointArgs.Add("G_a1", uidGa[0])
	pointArgs.Add("G_a2", uidGa[1])
	pointArgs.Add("G_b1", pkGa[0])
	pointArgs.Add("G_b2", pkGa[1])

	Cy2minusEA2 := new(ristretto255.Element).Subtract(Cy2, EA2)
	pointArgs.Add("C_y2-E_A2", Cy2minusEA2)
	pointArgs.Add("G_y2", legacySys.Gy[1])
	pointArgs.Add("-E_A1", new(ristretto255.Element).Negate(EA1))
	pointArgs.Add("E_A1", EA1)
	pointArgs.Add("C_y1", Cy1)
	pointArgs.Add("G_y1", legacySys.Gy[0])

	Cy4minusEB2 := new(ristretto255.Element).Subtract(Cy4, EB2)
	pointArgs.Add("C_y4-E_B2", Cy4minusEB2)
	pointArgs.Add("G_y4", legacySys.Gy[3])
	pointArgs.Add("-E_B1", new(ristretto255.Element).Negate(EB1))
	pointArgs.Add("E_B1", EB1)
	pointArgs.Add("C_y3", Cy3)
	pointArgs.Add("G_y3", legacySys.Gy[2])
	pointArgs.Add("0", ristretto255.NewIdentityElement())

	proofRandomness := sho.SqueezeAndRatchet(RandomnessLen)
	st := expiringProfileKeyCredentialPresentationStatement()
	proofBytes, err := st.Prove(scalarArgs, pointArgs, nil, proofRandomness)
	if err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "expiring profile key presentation proof: " + err.Error()}
	}

	return &ExpiringProfileKeyCredentialPresentation{
		Cx0:                     Cx0,
		Cx1:                     Cx1,
		Cy1:                     Cy1,
		Cy2:                     Cy2,
		Cy3:                     Cy3,
		Cy4:                     Cy4,
		Cy5:                     Cy5,
		CV:                      CV,
		PokshoProof:             proofBytes,
		UIDEncCiphertext:        uuidCiphertext,
		ProfileKeyEncCiphertext: profileKeyCiphertext,
		CredentialExpirationTime: credential.CredentialExpirationTime,
	}, nil
}

// VerifyExpiringProfileKeyCredentialPresentation verifies an expiring profile
// key credential presentation. This is a server-side operation.
//
// Matches Rust ServerSecretParams::verify_expiring_profile_key_credential_presentation.
func (s *ServerSecretParams) VerifyExpiringProfileKeyCredentialPresentation(
	groupPublicParams *GroupPublicParams,
	presentation *ExpiringProfileKeyCredentialPresentation,
	currentTime Timestamp,
) error {
	legacySys := zkcredential.GetLegacySystemParams()
	priv := s.ExpiringProfileKeyCredentialsKeyPair.PrivateKey()
	credPubKey := s.ExpiringProfileKeyCredentialsKeyPair.PublicKey()

	uidDomain := UIDEncryptionDomain{}
	pkDomain := ProfileKeyEncryptionDomain{}
	uidGa := uidDomain.Ga()
	pkGa := pkDomain.Ga()

	EA1 := presentation.UIDEncCiphertext.Ciphertext.EA1
	EA2 := presentation.UIDEncCiphertext.Ciphertext.EA2
	EB1 := presentation.ProfileKeyEncCiphertext.Ciphertext.EA1
	EB2 := presentation.ProfileKeyEncCiphertext.Ciphertext.EA2

	m5Scalar := CalcTimestampM(presentation.CredentialExpirationTime)
	M5 := new(ristretto255.Element).ScalarMult(m5Scalar, legacySys.Gm[4]) // G_m5

	// Reconstruct Z = C_V - W - x0*C_x0 - x1*C_x1 - y1*C_y1 - y2*C_y2 - y3*C_y3 - y4*C_y4 - y5*(C_y5 + M5)
	Z := new(ristretto255.Element).Set(presentation.CV)
	Z = Z.Subtract(Z, priv.Wpoint)

	x0Cx0 := new(ristretto255.Element).ScalarMult(priv.X0, presentation.Cx0)
	Z = Z.Subtract(Z, x0Cx0)

	x1Cx1 := new(ristretto255.Element).ScalarMult(priv.X1, presentation.Cx1)
	Z = Z.Subtract(Z, x1Cx1)

	y1Cy1 := new(ristretto255.Element).ScalarMult(priv.Y[0], presentation.Cy1)
	Z = Z.Subtract(Z, y1Cy1)

	y2Cy2 := new(ristretto255.Element).ScalarMult(priv.Y[1], presentation.Cy2)
	Z = Z.Subtract(Z, y2Cy2)

	y3Cy3 := new(ristretto255.Element).ScalarMult(priv.Y[2], presentation.Cy3)
	Z = Z.Subtract(Z, y3Cy3)

	y4Cy4 := new(ristretto255.Element).ScalarMult(priv.Y[3], presentation.Cy4)
	Z = Z.Subtract(Z, y4Cy4)

	Cy5plusM5 := new(ristretto255.Element).Add(presentation.Cy5, M5)
	y5Term := new(ristretto255.Element).ScalarMult(priv.Y[4], Cy5plusM5)
	Z = Z.Subtract(Z, y5Term)

	I := credPubKey.GetI(LegacyExpiringProfileKeyCredentialConfig.NumAttrs)

	pointArgs := poksho.NewPointArgs()
	pointArgs.Add("Z", Z)
	pointArgs.Add("I", I)
	pointArgs.Add("C_x1", presentation.Cx1)
	pointArgs.Add("C_x0", presentation.Cx0)
	pointArgs.Add("G_x0", legacySys.Gx0)
	pointArgs.Add("G_x1", legacySys.Gx1)

	AplusB := new(ristretto255.Element).Add(
		groupPublicParams.UIDEncPublicKey.A,
		groupPublicParams.ProfileKeyEncPublicKey.A,
	)
	pointArgs.Add("A+B", AplusB)
	pointArgs.Add("G_a1", uidGa[0])
	pointArgs.Add("G_a2", uidGa[1])
	pointArgs.Add("G_b1", pkGa[0])
	pointArgs.Add("G_b2", pkGa[1])

	Cy2minusEA2 := new(ristretto255.Element).Subtract(presentation.Cy2, EA2)
	pointArgs.Add("C_y2-E_A2", Cy2minusEA2)
	pointArgs.Add("G_y2", legacySys.Gy[1])
	pointArgs.Add("-E_A1", new(ristretto255.Element).Negate(EA1))
	pointArgs.Add("E_A1", EA1)
	pointArgs.Add("C_y1", presentation.Cy1)
	pointArgs.Add("G_y1", legacySys.Gy[0])

	Cy4minusEB2 := new(ristretto255.Element).Subtract(presentation.Cy4, EB2)
	pointArgs.Add("C_y4-E_B2", Cy4minusEB2)
	pointArgs.Add("G_y4", legacySys.Gy[3])
	pointArgs.Add("-E_B1", new(ristretto255.Element).Negate(EB1))
	pointArgs.Add("E_B1", EB1)
	pointArgs.Add("C_y3", presentation.Cy3)
	pointArgs.Add("G_y3", legacySys.Gy[2])
	pointArgs.Add("0", ristretto255.NewIdentityElement())

	st := expiringProfileKeyCredentialPresentationStatement()
	err := st.VerifyProof(presentation.PokshoProof, pointArgs, nil)
	if err != nil {
		return &ZkGroupVerificationFailure{Context: "expiring profile key presentation verification failed"}
	}

	// Check expiration time.
	if presentation.CredentialExpirationTime.EpochSeconds() <= currentTime.EpochSeconds() {
		return &ZkGroupVerificationFailure{Context: "credential has expired"}
	}

	return nil
}

// expiringProfileKeyCredentialPresentationStatement returns the poksho statement
// for expiring profile key credential presentations. Matches Rust
// ExpiringProfileKeyCredentialPresentationProof::get_poksho_statement.
func expiringProfileKeyCredentialPresentationStatement() *poksho.Statement {
	st := poksho.NewStatement()
	st.Add("Z", [][2]string{{"z", "I"}})
	st.Add("C_x1", [][2]string{{"t", "C_x0"}, {"z0", "G_x0"}, {"z", "G_x1"}})
	st.Add("A+B", [][2]string{{"a1", "G_a1"}, {"a2", "G_a2"}, {"b1", "G_b1"}, {"b2", "G_b2"}})
	st.Add("C_y2-E_A2", [][2]string{{"z", "G_y2"}, {"a2", "-E_A1"}})
	st.Add("E_A1", [][2]string{{"a1", "C_y1"}, {"z1", "G_y1"}})
	st.Add("C_y4-E_B2", [][2]string{{"z", "G_y4"}, {"b2", "-E_B1"}})
	st.Add("E_B1", [][2]string{{"b1", "C_y3"}, {"z2", "G_y3"}})
	st.Add("0", [][2]string{{"z1", "I"}, {"a1", "Z"}})
	st.Add("0", [][2]string{{"z2", "I"}, {"b1", "Z"}})
	return st
}

// expiringProfileKeyCredentialIssuanceStatement returns the poksho statement
// for expiring profile key credential issuance. Matches Rust
// ExpiringProfileKeyCredentialIssuanceProof::get_poksho_statement.
func expiringProfileKeyCredentialIssuanceStatement() *poksho.Statement {
	st := poksho.NewStatement()
	st.Add("C_W", [][2]string{{"w", "G_w"}, {"wprime", "G_wprime"}})
	st.Add("G_V-I", [][2]string{
		{"x0", "G_x0"}, {"x1", "G_x1"},
		{"y1", "G_y1"}, {"y2", "G_y2"},
		{"y3", "G_y3"}, {"y4", "G_y4"},
		{"y5", "G_y5"},
	})
	st.Add("S1", [][2]string{{"y3", "D1"}, {"y4", "E1"}, {"rprime", "G"}})
	st.Add("S2", [][2]string{
		{"y3", "D2"}, {"y4", "E2"},
		{"rprime", "Y"}, {"w", "G_w"},
		{"x0", "U"}, {"x1", "tU"},
		{"y1", "M1"}, {"y2", "M2"},
		{"y5", "M5"},
	})
	return st
}

// expiringProfileKeyCredentialIssuanceProofNew generates a poksho issuance proof
// for expiring profile key credentials.
func expiringProfileKeyCredentialIssuanceProofNew(
	keyPair *zkcredential.CredentialKeyPair,
	requestPublicKey *ristretto255.Element,
	request *profileKeyCredentialRequestCiphertext,
	blindedCred *blindedExpiringProfileKeyCredentialWithSecretNonce,
	uid *UIDStruct,
	credentialExpirationTime Timestamp,
	sho *zkcredential.ShoExt,
) ([]byte, error) {
	legacySys := zkcredential.GetLegacySystemParams()
	priv := keyPair.PrivateKey()
	credPubKey := keyPair.PublicKey()

	m5Scalar := CalcTimestampM(credentialExpirationTime)
	M5 := new(ristretto255.Element).ScalarMult(m5Scalar, legacySys.Gm[4]) // G_m5

	scalarArgs := poksho.NewScalarArgs()
	scalarArgs.Add("w", priv.W)
	scalarArgs.Add("wprime", priv.Wprime)
	scalarArgs.Add("x0", priv.X0)
	scalarArgs.Add("x1", priv.X1)
	scalarArgs.Add("y1", priv.Y[0])
	scalarArgs.Add("y2", priv.Y[1])
	scalarArgs.Add("y3", priv.Y[2])
	scalarArgs.Add("y4", priv.Y[3])
	scalarArgs.Add("y5", priv.Y[4])
	scalarArgs.Add("rprime", blindedCred.rprime)

	I := credPubKey.GetI(LegacyExpiringProfileKeyCredentialConfig.NumAttrs)
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
	pointArgs.Add("G_y3", legacySys.Gy[2])
	pointArgs.Add("G_y4", legacySys.Gy[3])
	pointArgs.Add("G_y5", legacySys.Gy[4])
	pointArgs.Add("S1", blindedCred.S1)
	pointArgs.Add("D1", request.D1)
	pointArgs.Add("E1", request.E1)
	pointArgs.Add("S2", blindedCred.S2)
	pointArgs.Add("D2", request.D2)
	pointArgs.Add("E2", request.E2)
	pointArgs.Add("Y", requestPublicKey)
	pointArgs.Add("U", blindedCred.U)
	pointArgs.Add("tU", tU)
	pointArgs.Add("M1", uid.M1)
	pointArgs.Add("M2", uid.M2)
	pointArgs.Add("M5", M5)

	proofRandomness := sho.SqueezeAndRatchet(RandomnessLen)
	st := expiringProfileKeyCredentialIssuanceStatement()
	return st.Prove(scalarArgs, pointArgs, nil, proofRandomness)
}

// expiringProfileKeyCredentialIssuanceProofVerify verifies a poksho issuance
// proof for expiring profile key credentials.
func expiringProfileKeyCredentialIssuanceProofVerify(
	proofBytes []byte,
	credPubKey *zkcredential.CredentialPublicKey,
	requestPublicKey *ristretto255.Element,
	aciBytes UIDBytes,
	request *profileKeyCredentialRequestCiphertext,
	blindedCred *blindedExpiringProfileKeyCredential,
	credentialExpirationTime Timestamp,
) error {
	legacySys := zkcredential.GetLegacySystemParams()

	aci := NewACI(aciBytes)
	uid := NewUIDStructFromServiceID(aci)

	m5Scalar := CalcTimestampM(credentialExpirationTime)
	M5 := new(ristretto255.Element).ScalarMult(m5Scalar, legacySys.Gm[4]) // G_m5

	I := credPubKey.GetI(LegacyExpiringProfileKeyCredentialConfig.NumAttrs)
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
	pointArgs.Add("G_y3", legacySys.Gy[2])
	pointArgs.Add("G_y4", legacySys.Gy[3])
	pointArgs.Add("G_y5", legacySys.Gy[4])
	pointArgs.Add("S1", blindedCred.S1)
	pointArgs.Add("D1", request.D1)
	pointArgs.Add("E1", request.E1)
	pointArgs.Add("S2", blindedCred.S2)
	pointArgs.Add("D2", request.D2)
	pointArgs.Add("E2", request.E2)
	pointArgs.Add("Y", requestPublicKey)
	pointArgs.Add("U", blindedCred.U)
	pointArgs.Add("tU", tU)
	pointArgs.Add("M1", uid.M1)
	pointArgs.Add("M2", uid.M2)
	pointArgs.Add("M5", M5)

	st := expiringProfileKeyCredentialIssuanceStatement()
	return st.VerifyProof(proofBytes, pointArgs, nil)
}

// profileKeyCredentialRequestProofStatement returns the poksho statement for
// profile key credential request proofs. Matches Rust
// ProfileKeyCredentialRequestProof::get_poksho_statement.
func profileKeyCredentialRequestProofStatement() *poksho.Statement {
	st := poksho.NewStatement()
	st.Add("Y", [][2]string{{"y", "G"}})
	st.Add("D1", [][2]string{{"r1", "G"}})
	st.Add("E1", [][2]string{{"r2", "G"}})
	st.Add("J3", [][2]string{{"j3", "G_j3"}})
	st.Add("D2-J1", [][2]string{{"r1", "Y"}, {"j3", "-G_j1"}})
	st.Add("E2-J2", [][2]string{{"r2", "Y"}, {"j3", "-G_j2"}})
	return st
}

// profileKeyCredentialRequestProofNew generates a poksho proof for a profile
// key credential request.
func profileKeyCredentialRequestProofNew(
	keyPair *profileKeyCredentialRequestKeyPair,
	ciphertext *profileKeyCredentialRequestCiphertextWithSecretNonce,
	commitment *ProfileKeyCommitmentWithSecretNonce,
	sho *zkcredential.ShoExt,
) ([]byte, error) {
	commitmentSystem := GenerateProfileKeyCommitmentSystemParams()

	scalarArgs := poksho.NewScalarArgs()
	scalarArgs.Add("y", keyPair.y)
	scalarArgs.Add("r1", ciphertext.r1)
	scalarArgs.Add("r2", ciphertext.r2)
	scalarArgs.Add("j3", commitment.J3s)

	D2minusJ1 := new(ristretto255.Element).Subtract(ciphertext.D2, commitment.J1)
	E2minusJ2 := new(ristretto255.Element).Subtract(ciphertext.E2, commitment.J2)

	pointArgs := poksho.NewPointArgs()
	pointArgs.Add("Y", keyPair.Y)
	pointArgs.Add("D1", ciphertext.D1)
	pointArgs.Add("E1", ciphertext.E1)
	pointArgs.Add("J3", commitment.J3)
	pointArgs.Add("G_j3", commitmentSystem.GJ3)
	pointArgs.Add("D2-J1", D2minusJ1)
	pointArgs.Add("-G_j1", new(ristretto255.Element).Negate(commitmentSystem.GJ1))
	pointArgs.Add("E2-J2", E2minusJ2)
	pointArgs.Add("-G_j2", new(ristretto255.Element).Negate(commitmentSystem.GJ2))

	proofRandomness := sho.SqueezeAndRatchet(RandomnessLen)
	st := profileKeyCredentialRequestProofStatement()
	return st.Prove(scalarArgs, pointArgs, nil, proofRandomness)
}

// profileKeyCredentialRequestProofVerify verifies a poksho proof for a profile
// key credential request.
func profileKeyCredentialRequestProofVerify(
	proofBytes []byte,
	publicKey *ristretto255.Element,
	ciphertext *profileKeyCredentialRequestCiphertext,
	commitment *ProfileKeyCommitmentInternal,
) error {
	commitmentSystem := GenerateProfileKeyCommitmentSystemParams()

	D2minusJ1 := new(ristretto255.Element).Subtract(ciphertext.D2, commitment.J1)
	E2minusJ2 := new(ristretto255.Element).Subtract(ciphertext.E2, commitment.J2)

	pointArgs := poksho.NewPointArgs()
	pointArgs.Add("Y", publicKey)
	pointArgs.Add("D1", ciphertext.D1)
	pointArgs.Add("E1", ciphertext.E1)
	pointArgs.Add("J3", commitment.J3)
	pointArgs.Add("G_j3", commitmentSystem.GJ3)
	pointArgs.Add("D2-J1", D2minusJ1)
	pointArgs.Add("-G_j1", new(ristretto255.Element).Negate(commitmentSystem.GJ1))
	pointArgs.Add("E2-J2", E2minusJ2)
	pointArgs.Add("-G_j2", new(ristretto255.Element).Negate(commitmentSystem.GJ2))

	st := profileKeyCredentialRequestProofStatement()
	return st.VerifyProof(proofBytes, pointArgs, nil)
}
