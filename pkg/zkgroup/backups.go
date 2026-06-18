package zkgroup

import (
	"github.com/gtank/ristretto255"
	"github.com/jeremyhahn/go-libsignal/pkg/accountkeys"
	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
)

// BackupLevel identifies the tier of backup service.
type BackupLevel byte

const (
	// BackupLevelFree is the free tier.
	BackupLevelFree BackupLevel = 200
	// BackupLevelPaid is the paid tier.
	BackupLevelPaid BackupLevel = 201
)

// BackupCredentialType identifies the type of backup credential.
type BackupCredentialType byte

const (
	// BackupCredentialTypeMessages is for message backups.
	BackupCredentialTypeMessages BackupCredentialType = 1
	// BackupCredentialTypeMedia is for media backups.
	BackupCredentialTypeMedia BackupCredentialType = 2
)

var backupCredentialLabel = []byte("20231003_Signal_BackupAuthCredential")

// BackupID is a 16-byte backup identifier derived from the client's account
// entropy pool.
type BackupID [16]byte

// backupIDPoint derives a ristretto255 point from a BackupID.
type backupIDPoint struct {
	point *ristretto255.Element
}

func newBackupIDPoint(id BackupID) *backupIDPoint {
	sho := zkcredential.NewShoHmacSha256Ext("20231003_Signal_BackupId")
	sho.AbsorbAndRatchet(id[:])
	return &backupIDPoint{point: sho.MustGetPoint()}
}

// AsPoint implements zkcredential.RevealedAttribute.
func (b *backupIDPoint) AsPoint() *ristretto255.Element {
	return b.point
}

// BackupAuthCredentialRequestContext holds the state needed to process a backup
// auth credential response.
type BackupAuthCredentialRequestContext struct {
	BlindedBackupID  *zkcredential.BlindedPoint
	BackupIdentifier BackupID
	KeyPair          *zkcredential.BlindingKeyPair
}

// NewBackupAuthCredentialRequestContext derives a BackupAuthCredentialRequestContext
// deterministically from (backupKey, aci) using the canonical SHO label
// "20231003_Signal_BackupAuthCredentialRequest". The ACI must have kind ACI
// (not PNI); Rust enforces this structurally via the type system.
//
// Mirrors Rust BackupAuthCredentialRequestContext::new at
// rust/zkgroup/src/api/backups/auth_credential.rs:118.
func NewBackupAuthCredentialRequestContext(backupKey [32]byte, aci ServiceID) (*BackupAuthCredentialRequestContext, error) {
	if aci.Type != ServiceIDTypeACI {
		return nil, &ErrInvalidServiceIDKind{Got: aci.Type}
	}

	// Derive the backup ID using the canonical HKDF derivation from
	// libsignal_account_keys::BackupKey::derive_backup_id.
	bk := accountkeys.NewBackupKey(backupKey)
	backupIdVal, err := bk.DeriveBackupId(aci.RawUUID[:])
	if err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "derive backup id: " + err.Error()}
	}
	var backupID BackupID
	rawBackupIdBytes := backupIdVal.Bytes()
	copy(backupID[:], rawBackupIdBytes[:])

	// Derive the blinding key pair and blinded backup ID from the SHO,
	// absorbing ACI bytes first, then backup key bytes — matching the Rust
	// field order: sho.absorb_and_ratchet(aci_bytes); sho.absorb_and_ratchet(backup_key).
	sho := zkcredential.NewShoHmacSha256Ext("20231003_Signal_BackupAuthCredentialRequest")
	sho.AbsorbAndRatchet(aci.RawUUID[:])
	sho.AbsorbAndRatchet(backupKey[:])

	keyPair, err := zkcredential.GenerateBlindingKeyPair(sho)
	if err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "generate blinding key pair: " + err.Error()}
	}

	idPoint := newBackupIDPoint(backupID)
	blindedBackupID, err := keyPair.Blind(idPoint, sho)
	if err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "blind backup id: " + err.Error()}
	}

	return &BackupAuthCredentialRequestContext{
		BlindedBackupID:  blindedBackupID,
		BackupIdentifier: backupID,
		KeyPair:          keyPair,
	}, nil
}

// GetRequest returns the request to send to the issuing server.
func (ctx *BackupAuthCredentialRequestContext) GetRequest() *BackupAuthCredentialRequest {
	return &BackupAuthCredentialRequest{
		BlindedBackupID: ctx.BlindedBackupID,
		PublicKey:       ctx.KeyPair.PubKey,
	}
}

// BackupAuthCredentialRequest is the request sent to the server for a backup
// auth credential.
type BackupAuthCredentialRequest struct {
	BlindedBackupID *zkcredential.BlindedPoint
	PublicKey       *zkcredential.BlindingPublicKey
}

// Issue creates a blinded backup auth credential.
func (r *BackupAuthCredentialRequest) Issue(
	redemptionTime Timestamp,
	backupLevel BackupLevel,
	credentialType BackupCredentialType,
	params *GenericServerSecretParams,
	randomness RandomnessBytes,
) (*BackupAuthCredentialResponse, error) {
	builder := zkcredential.NewIssuanceProofBuilder(backupCredentialLabel)
	builder.AddPublicAttribute(zkcredential.PublicAttributeU64(redemptionTime.EpochSeconds()))
	builder.AddPublicAttribute(zkcredential.PublicAttributeU64(uint64(backupLevel)))
	builder.AddPublicAttribute(zkcredential.PublicAttributeU64(uint64(credentialType)))

	blindedBuilder := zkcredential.NewBlindedIssuanceProofBuilder(builder)
	blindedPoint := r.BlindedBackupID.StripNonce()
	if err := blindedBuilder.AddBlindedRevealedAttribute(blindedPoint); err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "failed to add blinded attribute: " + err.Error()}
	}

	proof, err := blindedBuilder.Issue(params.CredentialKey, r.PublicKey, randomness)
	if err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "failed to issue backup credential: " + err.Error()}
	}

	return &BackupAuthCredentialResponse{
		RedemptionTime:    redemptionTime,
		Level:             backupLevel,
		CredType:          credentialType,
		BlindedCredential: proof,
	}, nil
}

// BackupAuthCredentialResponse is the server's response containing a blinded
// backup auth credential.
type BackupAuthCredentialResponse struct {
	RedemptionTime    Timestamp
	Level             BackupLevel
	CredType          BackupCredentialType
	BlindedCredential *zkcredential.BlindedIssuanceProof
}

// Receive validates the response and returns a BackupAuthCredential.
func (ctx *BackupAuthCredentialRequestContext) Receive(
	response *BackupAuthCredentialResponse,
	params *GenericServerPublicParams,
	expectedRedemptionTime Timestamp,
) (*BackupAuthCredential, error) {
	if response.RedemptionTime != expectedRedemptionTime ||
		!response.RedemptionTime.IsDayAligned() {
		return nil, ErrVerificationFailure
	}

	builder := zkcredential.NewIssuanceProofBuilder(backupCredentialLabel)
	builder.AddPublicAttribute(zkcredential.PublicAttributeU64(response.RedemptionTime.EpochSeconds()))
	builder.AddPublicAttribute(zkcredential.PublicAttributeU64(uint64(response.Level)))
	builder.AddPublicAttribute(zkcredential.PublicAttributeU64(uint64(response.CredType)))

	blindedBuilder := zkcredential.NewBlindedIssuanceProofBuilder(builder)
	blindedPoint := ctx.BlindedBackupID.StripNonce()
	if err := blindedBuilder.AddBlindedRevealedAttribute(blindedPoint); err != nil {
		return nil, ErrVerificationFailure
	}

	credential, err := blindedBuilder.Verify(
		params.CredentialKey,
		ctx.KeyPair,
		response.BlindedCredential,
	)
	if err != nil {
		return nil, ErrVerificationFailure
	}

	return &BackupAuthCredential{
		RedemptionTime:   response.RedemptionTime,
		Level:            response.Level,
		CredType:         response.CredType,
		Credential:       credential,
		BackupIdentifier: ctx.BackupIdentifier,
	}, nil
}

// BackupAuthCredential is a backup auth credential bound to a backup ID,
// redemption time, and backup level.
type BackupAuthCredential struct {
	RedemptionTime   Timestamp
	Level            BackupLevel
	CredType         BackupCredentialType
	Credential       *zkcredential.Credential
	BackupIdentifier BackupID
}

// Present creates a presentation of this credential.
func (c *BackupAuthCredential) Present(
	serverParams *GenericServerPublicParams,
	randomness RandomnessBytes,
) (*BackupAuthCredentialPresentation, error) {
	builder := zkcredential.NewPresentationProofBuilder(backupCredentialLabel)
	builder.AddRevealedAttribute(newBackupIDPoint(c.BackupIdentifier))

	proof, err := builder.Present(serverParams.CredentialKey, c.Credential, randomness)
	if err != nil {
		return nil, err
	}

	return &BackupAuthCredentialPresentation{
		RedemptionTime:   c.RedemptionTime,
		Level:            c.Level,
		CredType:         c.CredType,
		BackupIdentifier: c.BackupIdentifier,
		Proof:            proof,
	}, nil
}

// GetBackupID returns the backup ID.
func (c *BackupAuthCredential) GetBackupID() BackupID {
	return c.BackupIdentifier
}

// GetBackupLevel returns the backup level.
func (c *BackupAuthCredential) GetBackupLevel() BackupLevel {
	return c.Level
}

// GetCredentialType returns the credential type.
func (c *BackupAuthCredential) GetCredentialType() BackupCredentialType {
	return c.CredType
}

// BackupAuthCredentialPresentation is a presentation of a backup auth credential
// for verification.
type BackupAuthCredentialPresentation struct {
	Level            BackupLevel
	CredType         BackupCredentialType
	RedemptionTime   Timestamp
	Proof            *zkcredential.PresentationProof
	BackupIdentifier BackupID
}

// Verify verifies this presentation.
func (p *BackupAuthCredentialPresentation) Verify(
	currentTime Timestamp,
	serverParams *GenericServerSecretParams,
) error {
	if err := CheckAuthCredentialRedemptionTime(p.RedemptionTime, currentTime); err != nil {
		return err
	}

	verifier := zkcredential.NewPresentationProofVerifier(backupCredentialLabel)
	verifier.AddPublicAttribute(zkcredential.PublicAttributeU64(p.RedemptionTime.EpochSeconds()))
	verifier.AddPublicAttribute(zkcredential.PublicAttributeU64(uint64(p.Level)))
	verifier.AddPublicAttribute(zkcredential.PublicAttributeU64(uint64(p.CredType)))
	verifier.AddRevealedAttribute(newBackupIDPoint(p.BackupIdentifier))

	return verifier.Verify(serverParams.CredentialKey, p.Proof)
}

// GetBackupLevel returns the backup level.
func (p *BackupAuthCredentialPresentation) GetBackupLevel() BackupLevel {
	return p.Level
}

// GetCredentialType returns the credential type.
func (p *BackupAuthCredentialPresentation) GetCredentialType() BackupCredentialType {
	return p.CredType
}

// GetBackupID returns the backup ID.
func (p *BackupAuthCredentialPresentation) GetBackupID() BackupID {
	return p.BackupIdentifier
}
