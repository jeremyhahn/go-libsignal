package zkgroup

import (
	"github.com/gtank/ristretto255"
	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
)

// CallLinkSecretParams contains the secret parameters for a call link.
type CallLinkSecretParams struct {
	UIDEncKeyPair *zkcredential.KeyPair
}

// CallLinkRootKeyMaxBytesForSHO is the maximum number of root key bytes used.
const CallLinkRootKeyMaxBytesForSHO = 16

// DeriveCallLinkSecretParams derives call link secret parameters from a root key.
func DeriveCallLinkSecretParams(rootKey []byte) (*CallLinkSecretParams, error) {
	byteCount := CallLinkRootKeyMaxBytesForSHO
	if len(rootKey) < byteCount {
		byteCount = len(rootKey)
	}
	sho := zkcredential.NewShoHmacSha256Ext(
		"Signal_ZKGroup_20230419_CallLinkSecretParams_DeriveFromRootKey",
	)
	sho.AbsorbAndRatchet(rootKey[:byteCount])

	uidDomain := UIDEncryptionDomain{}
	kp, err := zkcredential.DeriveKeyPair(sho, uidDomain)
	if err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "failed to derive call link uid enc key pair: " + err.Error()}
	}

	return &CallLinkSecretParams{
		UIDEncKeyPair: kp,
	}, nil
}

// GetPublicParams returns the public parameters for the call link.
func (s *CallLinkSecretParams) GetPublicParams() *CallLinkPublicParams {
	return &CallLinkPublicParams{
		UIDEncPublicKey: s.UIDEncKeyPair.PublicKey,
	}
}

// EncryptUID encrypts a user's ACI under the call link UID encryption key.
func (s *CallLinkSecretParams) EncryptUID(userID ServiceID) *UUIDCiphertext {
	uid := NewUIDStructFromServiceID(userID)
	ct := s.UIDEncKeyPair.Encrypt(uid)
	return &UUIDCiphertext{Ciphertext: ct}
}

// CallLinkPublicParams contains the public parameters for a call link.
type CallLinkPublicParams struct {
	UIDEncPublicKey *zkcredential.PublicKey
}

var callLinkAuthCredentialLabel = []byte("20230421_Signal_CallLinkAuthCredential")
var createCallLinkCredentialLabel = []byte("20230413_Signal_CreateCallLinkCredential")

// callLinkRoomIDPoint derives a ristretto255 point from a room ID.
type callLinkRoomIDPoint struct {
	point *ristretto255.Element
}

func newCallLinkRoomIDPoint(roomID []byte) *callLinkRoomIDPoint {
	sho := zkcredential.NewShoHmacSha256Ext("20230413_Signal_CallLinkRoomId")
	sho.AbsorbAndRatchet(roomID)
	return &callLinkRoomIDPoint{point: sho.MustGetPoint()}
}

// AsPoint implements zkcredential.RevealedAttribute.
func (r *callLinkRoomIDPoint) AsPoint() *ristretto255.Element {
	return r.point
}

// CallLinkAuthCredentialResponse is the server's response for a call link auth
// credential.
type CallLinkAuthCredentialResponse struct {
	Proof *zkcredential.IssuanceProof
}

// IssueCallLinkAuthCredential issues a call link auth credential for a user.
func IssueCallLinkAuthCredential(
	userID ServiceID,
	redemptionTime Timestamp,
	params *GenericServerSecretParams,
	randomness RandomnessBytes,
) (*CallLinkAuthCredentialResponse, error) {
	uid := NewUIDStructFromServiceID(userID)
	builder := zkcredential.NewIssuanceProofBuilder(callLinkAuthCredentialLabel)
	if err := builder.AddAttribute(uid); err != nil {
		return nil, err
	}
	builder.AddPublicAttribute(redemptionTime)

	proof, err := builder.Issue(params.CredentialKey, randomness)
	if err != nil {
		return nil, err
	}

	return &CallLinkAuthCredentialResponse{Proof: proof}, nil
}

// ReceiveCallLinkAuthCredential validates and returns a CallLinkAuthCredential.
func ReceiveCallLinkAuthCredential(
	response *CallLinkAuthCredentialResponse,
	userID ServiceID,
	redemptionTime Timestamp,
	params *GenericServerPublicParams,
) (*CallLinkAuthCredential, error) {
	if !redemptionTime.IsDayAligned() {
		return nil, ErrVerificationFailure
	}

	uid := NewUIDStructFromServiceID(userID)
	builder := zkcredential.NewIssuanceProofBuilder(callLinkAuthCredentialLabel)
	if err := builder.AddAttribute(uid); err != nil {
		return nil, err
	}
	builder.AddPublicAttribute(redemptionTime)

	credential, err := builder.Verify(params.CredentialKey, response.Proof)
	if err != nil {
		return nil, ErrVerificationFailure
	}

	return &CallLinkAuthCredential{Credential: credential}, nil
}

// CallLinkAuthCredential is a credential authenticating a user's access to a
// call link.
type CallLinkAuthCredential struct {
	Credential *zkcredential.Credential
}

// Present creates a presentation of this credential.
func (c *CallLinkAuthCredential) Present(
	userID ServiceID,
	redemptionTime Timestamp,
	serverParams *GenericServerPublicParams,
	callLinkParams *CallLinkSecretParams,
	randomness RandomnessBytes,
) (*CallLinkAuthCredentialPresentation, error) {
	uid := NewUIDStructFromServiceID(userID)
	builder := zkcredential.NewPresentationProofBuilder(callLinkAuthCredentialLabel)
	builder.AddAttribute(uid, callLinkParams.UIDEncKeyPair)

	proof, err := builder.Present(serverParams.CredentialKey, c.Credential, randomness)
	if err != nil {
		return nil, err
	}

	ct := callLinkParams.UIDEncKeyPair.Encrypt(uid)
	return &CallLinkAuthCredentialPresentation{
		Proof:          proof,
		Ciphertext:     ct,
		RedemptionTime: redemptionTime,
	}, nil
}

// CallLinkAuthCredentialPresentation is a presentation of a call link auth
// credential.
type CallLinkAuthCredentialPresentation struct {
	Proof          *zkcredential.PresentationProof
	Ciphertext     *zkcredential.Ciphertext
	RedemptionTime Timestamp
}

// Verify verifies this presentation.
func (p *CallLinkAuthCredentialPresentation) Verify(
	currentTime Timestamp,
	serverParams *GenericServerSecretParams,
	callLinkParams *CallLinkPublicParams,
) error {
	if err := CheckAuthCredentialRedemptionTime(p.RedemptionTime, currentTime); err != nil {
		return err
	}

	verifier := zkcredential.NewPresentationProofVerifier(callLinkAuthCredentialLabel)
	verifier.AddAttribute(
		p.Ciphertext,
		callLinkParams.UIDEncPublicKey,
	)
	verifier.AddPublicAttribute(p.RedemptionTime)

	return verifier.Verify(serverParams.CredentialKey, p.Proof)
}

// GetUserID returns the encrypted user ID.
func (p *CallLinkAuthCredentialPresentation) GetUserID() *UUIDCiphertext {
	return &UUIDCiphertext{Ciphertext: p.Ciphertext}
}

// CreateCallLinkCredentialRequestContext holds the state needed to process a
// create call link credential response.
type CreateCallLinkCredentialRequestContext struct {
	BlindedRoomID *zkcredential.BlindedPoint
	KeyPair       *zkcredential.BlindingKeyPair
}

// NewCreateCallLinkCredentialRequestContext creates a new request context.
func NewCreateCallLinkCredentialRequestContext(
	roomID []byte,
	randomness RandomnessBytes,
) (*CreateCallLinkCredentialRequestContext, error) {
	sho := zkcredential.NewShoHmacSha256Ext(
		"20230413_Signal_CreateCallLinkCredentialRequest",
	)
	sho.AbsorbAndRatchet(randomness[:])

	keyPair, err := zkcredential.GenerateBlindingKeyPair(sho)
	if err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "failed to generate blinding key pair: " + err.Error()}
	}

	roomIDPoint := newCallLinkRoomIDPoint(roomID)
	blindedRoomID, err := keyPair.Blind(roomIDPoint, sho)
	if err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "failed to blind room ID: " + err.Error()}
	}

	return &CreateCallLinkCredentialRequestContext{
		BlindedRoomID: blindedRoomID,
		KeyPair:       keyPair,
	}, nil
}

// GetRequest returns the request to send to the server.
func (ctx *CreateCallLinkCredentialRequestContext) GetRequest() *CreateCallLinkCredentialRequest {
	return &CreateCallLinkCredentialRequest{
		BlindedRoomID: ctx.BlindedRoomID,
		PublicKey:     ctx.KeyPair.PubKey,
	}
}

// CreateCallLinkCredentialRequest is the request sent to the server.
type CreateCallLinkCredentialRequest struct {
	BlindedRoomID *zkcredential.BlindedPoint
	PublicKey     *zkcredential.BlindingPublicKey
}

// Issue creates a blinded create call link credential.
func (r *CreateCallLinkCredentialRequest) Issue(
	userID ServiceID,
	timestamp Timestamp,
	params *GenericServerSecretParams,
	randomness RandomnessBytes,
) (*CreateCallLinkCredentialResponse, error) {
	uid := NewUIDStructFromServiceID(userID)
	builder := zkcredential.NewIssuanceProofBuilder(createCallLinkCredentialLabel)
	builder.AddPublicAttribute(timestamp)
	if err := builder.AddAttribute(uid); err != nil {
		return nil, err
	}

	blindedBuilder := zkcredential.NewBlindedIssuanceProofBuilder(builder)
	blindedPoint := r.BlindedRoomID.StripNonce()
	if err := blindedBuilder.AddBlindedRevealedAttribute(blindedPoint); err != nil {
		return nil, err
	}

	proof, err := blindedBuilder.Issue(params.CredentialKey, r.PublicKey, randomness)
	if err != nil {
		return nil, err
	}

	return &CreateCallLinkCredentialResponse{
		Timestamp:         timestamp,
		BlindedCredential: proof,
	}, nil
}

// CreateCallLinkCredentialResponse is the server's response.
type CreateCallLinkCredentialResponse struct {
	Timestamp         Timestamp
	BlindedCredential *zkcredential.BlindedIssuanceProof
}

// Receive validates the response and returns a CreateCallLinkCredential.
func (ctx *CreateCallLinkCredentialRequestContext) Receive(
	response *CreateCallLinkCredentialResponse,
	userID ServiceID,
	params *GenericServerPublicParams,
) (*CreateCallLinkCredential, error) {
	if !response.Timestamp.IsDayAligned() {
		return nil, ErrVerificationFailure
	}

	uid := NewUIDStructFromServiceID(userID)
	builder := zkcredential.NewIssuanceProofBuilder(createCallLinkCredentialLabel)
	builder.AddPublicAttribute(response.Timestamp)
	if err := builder.AddAttribute(uid); err != nil {
		return nil, err
	}

	blindedBuilder := zkcredential.NewBlindedIssuanceProofBuilder(builder)
	blindedPoint := ctx.BlindedRoomID.StripNonce()
	if err := blindedBuilder.AddBlindedRevealedAttribute(blindedPoint); err != nil {
		return nil, err
	}

	credential, err := blindedBuilder.Verify(
		params.CredentialKey,
		ctx.KeyPair,
		response.BlindedCredential,
	)
	if err != nil {
		return nil, ErrVerificationFailure
	}

	return &CreateCallLinkCredential{
		Timestamp:  response.Timestamp,
		Credential: credential,
	}, nil
}

// CreateCallLinkCredential is a credential for creating a call link.
type CreateCallLinkCredential struct {
	Timestamp  Timestamp
	Credential *zkcredential.Credential
}

// Present creates a presentation of this credential.
func (c *CreateCallLinkCredential) Present(
	roomID []byte,
	userID ServiceID,
	serverParams *GenericServerPublicParams,
	callLinkParams *CallLinkSecretParams,
	randomness RandomnessBytes,
) (*CreateCallLinkCredentialPresentation, error) {
	uid := NewUIDStructFromServiceID(userID)
	encryptedUserID := callLinkParams.UIDEncKeyPair.Encrypt(uid)

	builder := zkcredential.NewPresentationProofBuilder(createCallLinkCredentialLabel)
	builder.AddAttribute(uid, callLinkParams.UIDEncKeyPair)
	builder.AddRevealedAttribute(newCallLinkRoomIDPoint(roomID))

	proof, err := builder.Present(serverParams.CredentialKey, c.Credential, randomness)
	if err != nil {
		return nil, err
	}

	return &CreateCallLinkCredentialPresentation{
		Timestamp:  c.Timestamp,
		UserID:     encryptedUserID,
		Proof:      proof,
	}, nil
}

// CreateCallLinkCredentialPresentation is a presentation of a create call link
// credential.
type CreateCallLinkCredentialPresentation struct {
	UserID    *zkcredential.Ciphertext
	Timestamp Timestamp
	Proof     *zkcredential.PresentationProof
}

// Verify verifies this presentation.
func (p *CreateCallLinkCredentialPresentation) Verify(
	roomID []byte,
	currentTime Timestamp,
	serverParams *GenericServerSecretParams,
	callLinkParams *CallLinkPublicParams,
) error {
	expiration, ok := p.Timestamp.CheckedAddSeconds(30 * 60 * 60) // 30 hours
	if !ok {
		return ErrVerificationFailure
	}

	if currentTime.EpochSeconds() < p.Timestamp.EpochSeconds() ||
		currentTime.EpochSeconds() >= expiration.EpochSeconds() {
		return ErrVerificationFailure
	}

	verifier := zkcredential.NewPresentationProofVerifier(createCallLinkCredentialLabel)
	verifier.AddPublicAttribute(p.Timestamp)
	verifier.AddAttribute(p.UserID, callLinkParams.UIDEncPublicKey)
	verifier.AddRevealedAttribute(newCallLinkRoomIDPoint(roomID))

	return verifier.Verify(serverParams.CredentialKey, p.Proof)
}

// GetUserID returns the encrypted user ID.
func (p *CreateCallLinkCredentialPresentation) GetUserID() *UUIDCiphertext {
	return &UUIDCiphertext{Ciphertext: p.UserID}
}

// SerializeCreateCallLinkCredentialRequest serializes a
// CreateCallLinkCredentialRequest to bytes with a leading reserved byte.
// The serialized form is: reserved(1) + BlindedRoomID(64) + BlindingPublicKey(32) = 97 bytes.
func SerializeCreateCallLinkCredentialRequest(r *CreateCallLinkCredentialRequest) []byte {
	inner := make([]byte, 0, 96)
	inner = append(inner, zkcredential.EncodeBlindedPoint(r.BlindedRoomID)...)
	inner = append(inner, zkcredential.EncodeBlindingPublicKey(r.PublicKey)...)
	return Serialize(inner)
}

// DeserializeCreateCallLinkCredentialRequest deserializes a
// CreateCallLinkCredentialRequest from raw bytes.
// The serialized form is BlindedRoomID (64 bytes: D1+D2) + BlindingPublicKey (32 bytes).
func DeserializeCreateCallLinkCredentialRequest(data []byte) (*CreateCallLinkCredentialRequest, error) {
	if len(data) < 96 {
		return nil, &ZkGroupVerificationFailure{Context: "create call link credential request too short"}
	}

	blindedRoomID, err := zkcredential.DecodeBlindedPoint(data[0:64])
	if err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "failed to decode blinded room ID: " + err.Error()}
	}

	publicKey, err := zkcredential.DecodeBlindingPublicKey(data[64:96])
	if err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "failed to decode blinding public key: " + err.Error()}
	}

	return &CreateCallLinkCredentialRequest{
		BlindedRoomID: blindedRoomID,
		PublicKey:     publicKey,
	}, nil
}

// EncodeCreateCallLinkCredentialResponse serializes a CreateCallLinkCredentialResponse.
// The serialized form is Timestamp (8 bytes big-endian) + BlindedIssuanceProof (variable).
func EncodeCreateCallLinkCredentialResponse(r *CreateCallLinkCredentialResponse) []byte {
	tsBytes := r.Timestamp.ToBeBytes()
	proof := zkcredential.EncodeBlindedIssuanceProof(r.BlindedCredential)
	out := make([]byte, 0, 8+len(proof))
	out = append(out, tsBytes[:]...)
	out = append(out, proof...)
	return out
}
