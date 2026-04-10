package zkgroup

import (
	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
)

// authCredentialWithPniZkcLabel is the credential label for zkcredential-based
// auth credentials. Matches Rust CREDENTIAL_LABEL in zkc.rs.
var authCredentialWithPniZkcLabel = []byte("20240222_Signal_AuthCredentialZkc")

// Presentation version constants.
const (
	PresentationVersion1 = 0
	PresentationVersion2 = 1
	PresentationVersion3 = 2
	PresentationVersion4 = 3
)

// AuthCredentialWithPniVersion identifies the version of an auth credential.
type AuthCredentialWithPniVersion byte

const (
	// AuthCredentialWithPniVersionZkc is the current (zkcredential-based) version.
	AuthCredentialWithPniVersionZkc AuthCredentialWithPniVersion = 3
)

// AuthCredentialWithPniZkc is an auth credential issued via the zkcredential
// system, binding an ACI and PNI together with a redemption time.
type AuthCredentialWithPniZkc struct {
	Credential     *zkcredential.Credential
	ACI            *UIDStruct
	PNI            *UIDStruct
	RedemptionTime Timestamp
}

// AuthCredentialWithPniZkcResponse is the server's response for a
// zkcredential-based auth credential.
type AuthCredentialWithPniZkcResponse struct {
	Proof          *zkcredential.IssuanceProof
	RedemptionTime Timestamp
}

// AuthCredentialWithPniZkcPresentation is a presentation of a zkcredential-based
// auth credential.
type AuthCredentialWithPniZkcPresentation struct {
	Proof              *zkcredential.PresentationProof
	ACICiphertext      *UUIDCiphertext
	PNICiphertext      *UUIDCiphertext
	RedemptionTimeSecs Timestamp
}

// ACICiphertextValue returns the ACI ciphertext.
func (p *AuthCredentialWithPniZkcPresentation) ACICiphertextValue() *UUIDCiphertext {
	return p.ACICiphertext
}

// PNICiphertextValue returns the PNI ciphertext.
func (p *AuthCredentialWithPniZkcPresentation) PNICiphertextValue() *UUIDCiphertext {
	return p.PNICiphertext
}

// RedemptionTime returns the redemption time.
func (p *AuthCredentialWithPniZkcPresentation) RedemptionTime() Timestamp {
	return p.RedemptionTimeSecs
}

// AuthCredentialWithPni wraps the different versions of auth credentials
// with PNI.
type AuthCredentialWithPni struct {
	Version    AuthCredentialWithPniVersion
	Credential *AuthCredentialWithPniZkc
}

// AuthCredentialWithPniResponse wraps the different versions of auth credential
// responses.
type AuthCredentialWithPniResponse struct {
	Version  AuthCredentialWithPniVersion
	Response *AuthCredentialWithPniZkcResponse
}

// AnyAuthCredentialPresentation holds any version of auth credential
// presentation.
type AnyAuthCredentialPresentation struct {
	Version      byte
	Presentation *AuthCredentialWithPniZkcPresentation
}

// GetACICiphertext returns the ACI ciphertext from any presentation version.
func (p *AnyAuthCredentialPresentation) GetACICiphertext() *UUIDCiphertext {
	return p.Presentation.ACICiphertext
}

// GetPNICiphertext returns the PNI ciphertext from any presentation version.
func (p *AnyAuthCredentialPresentation) GetPNICiphertext() *UUIDCiphertext {
	return p.Presentation.PNICiphertext
}

// GetRedemptionTime returns the redemption time from any presentation version.
func (p *AnyAuthCredentialPresentation) GetRedemptionTime() Timestamp {
	return p.Presentation.RedemptionTimeSecs
}

// IssueAuthCredentialWithPniZkc issues an auth credential with PNI using the
// zkcredential system. This is a server-side operation.
//
// Matches Rust AuthCredentialWithPniZkcResponse::issue_credential.
func (s *ServerSecretParams) IssueAuthCredentialWithPniZkc(
	aci ServiceID,
	pni ServiceID,
	redemptionTime Timestamp,
	randomness RandomnessBytes,
) (*AuthCredentialWithPniZkcResponse, error) {
	aciStruct := NewUIDStructFromServiceID(aci)
	pniStruct := NewUIDStructFromServiceID(pni)

	builder := zkcredential.NewIssuanceProofBuilder(authCredentialWithPniZkcLabel)
	if err := builder.AddAttribute(aciStruct); err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "auth zkc issue: add aci attribute: " + err.Error()}
	}
	if err := builder.AddAttribute(pniStruct); err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "auth zkc issue: add pni attribute: " + err.Error()}
	}
	builder.AddPublicAttribute(redemptionTime)

	proof, err := builder.Issue(s.GenericCredentialKeyPair, randomness)
	if err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "auth zkc issue: " + err.Error()}
	}

	return &AuthCredentialWithPniZkcResponse{
		Proof:          proof,
		RedemptionTime: redemptionTime,
	}, nil
}

// ReceiveAuthCredentialWithPniZkc verifies and receives an auth credential
// with PNI. This is a client-side operation.
//
// Matches Rust AuthCredentialWithPniZkcResponse::receive.
func (pub *ServerPublicParams) ReceiveAuthCredentialWithPniZkc(
	aci ServiceID,
	pni ServiceID,
	redemptionTime Timestamp,
	response *AuthCredentialWithPniZkcResponse,
) (*AuthCredentialWithPniZkc, error) {
	if !redemptionTime.IsDayAligned() {
		return nil, &ZkGroupVerificationFailure{Context: "auth zkc receive: redemption time not day-aligned"}
	}

	aciStruct := NewUIDStructFromServiceID(aci)
	pniStruct := NewUIDStructFromServiceID(pni)

	builder := zkcredential.NewIssuanceProofBuilder(authCredentialWithPniZkcLabel)
	if err := builder.AddAttribute(aciStruct); err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "auth zkc receive: add aci attribute: " + err.Error()}
	}
	if err := builder.AddAttribute(pniStruct); err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "auth zkc receive: add pni attribute: " + err.Error()}
	}
	builder.AddPublicAttribute(redemptionTime)

	credential, err := builder.Verify(pub.GenericCredentialPublicKey, response.Proof)
	if err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "auth zkc receive: verification failed"}
	}

	return &AuthCredentialWithPniZkc{
		Credential:     credential,
		ACI:            aciStruct,
		PNI:            pniStruct,
		RedemptionTime: redemptionTime,
	}, nil
}

// CreateAuthCredentialWithPniZkcPresentation creates a zero-knowledge
// presentation of an auth credential with PNI. This is a client-side operation.
//
// Matches Rust AuthCredentialWithPniZkc::present.
func (pub *ServerPublicParams) CreateAuthCredentialWithPniZkcPresentation(
	credential *AuthCredentialWithPniZkc,
	groupSecretParams *GroupSecretParams,
	randomness RandomnessBytes,
) (*AuthCredentialWithPniZkcPresentation, error) {
	builder := zkcredential.NewPresentationProofBuilder(authCredentialWithPniZkcLabel)
	builder.AddAttribute(credential.ACI, groupSecretParams.UIDEncKeyPair)
	builder.AddAttribute(credential.PNI, groupSecretParams.UIDEncKeyPair)

	proof, err := builder.Present(
		pub.GenericCredentialPublicKey,
		credential.Credential,
		randomness,
	)
	if err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "auth zkc present: " + err.Error()}
	}

	// Encrypt the UIDStructs directly using the key pair,
	// matching how Rust does it.
	aciCT := &UUIDCiphertext{Ciphertext: groupSecretParams.UIDEncKeyPair.Encrypt(credential.ACI)}
	pniCT := &UUIDCiphertext{Ciphertext: groupSecretParams.UIDEncKeyPair.Encrypt(credential.PNI)}

	return &AuthCredentialWithPniZkcPresentation{
		Proof:              proof,
		ACICiphertext:      aciCT,
		PNICiphertext:      pniCT,
		RedemptionTimeSecs: credential.RedemptionTime,
	}, nil
}

// VerifyAuthCredentialWithPniZkcPresentation verifies an auth credential
// with PNI presentation. This is a server-side operation.
//
// Matches Rust AuthCredentialWithPniZkcPresentation::verify.
func (s *ServerSecretParams) VerifyAuthCredentialWithPniZkcPresentation(
	groupPublicParams *GroupPublicParams,
	presentation *AuthCredentialWithPniZkcPresentation,
	redemptionTime Timestamp,
) error {
	verifier := zkcredential.NewPresentationProofVerifier(authCredentialWithPniZkcLabel)
	verifier.AddAttribute(
		presentation.ACICiphertext.Ciphertext,
		groupPublicParams.UIDEncPublicKey,
	)
	verifier.AddAttribute(
		presentation.PNICiphertext.Ciphertext,
		groupPublicParams.UIDEncPublicKey,
	)
	verifier.AddPublicAttribute(redemptionTime)

	if err := verifier.Verify(s.GenericCredentialKeyPair, presentation.Proof); err != nil {
		return &ZkGroupVerificationFailure{Context: "auth zkc verify: verification failed"}
	}

	return nil
}
