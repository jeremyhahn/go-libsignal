package zkgroup

import (
	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
)

// ServerSecretParams holds the server's secret credential parameters; the leading reserved field makes a serializer emit Rust bincode's 0x00 byte.
type ServerSecretParams struct {
	//lint:ignore U1000 matches Rust reserved field (rust/zkgroup/src/api/server_params.rs ReservedByte)
	reserved                             byte // always 0x00; bincode ReservedByte
	SigKeyPair                           *SignatureKeyPair
	AuthCredentialsKeyPair               *zkcredential.CredentialKeyPair
	ProfileKeyCredentialsKeyPair         *zkcredential.CredentialKeyPair
	PniCredentialsKeyPair                *zkcredential.CredentialKeyPair
	AuthCredentialsWithPniKeyPair        *zkcredential.CredentialKeyPair
	ReceiptCredentialsKeyPair            *zkcredential.CredentialKeyPair
	ExpiringProfileKeyCredentialsKeyPair *zkcredential.CredentialKeyPair
	GenericCredentialKeyPair             *zkcredential.CredentialKeyPair
	EndorsementKeyPair                   *zkcredential.ServerRootKeyPair
}

// GenerateServerSecretParams creates new server secret parameters from
// randomness.
func GenerateServerSecretParams(randomness RandomnessBytes) (*ServerSecretParams, error) {
	// Create a single SHO instance and chain all legacy key pair generations
	// through it sequentially. This matches the Rust reference implementation
	// where sho state is consumed in order by each GenerateKeyPair call.
	sho := zkcredential.NewShoHmacSha256Ext(
		"Signal_ZKGroup_20200424_Random_ServerSecretParams_Generate",
	)
	sho.AbsorbAndRatchet(randomness[:])

	// Legacy credential key pairs drawn from the shared SHO in the exact order
	// matching the Rust reference implementation. All key pairs are retained
	// to expose their public keys in ServerPublicParams.
	authKP := zkcredential.GenerateCredentialKeyPairFromSHOWithStorage(sho,
		LegacyAuthCredentialConfig.StorageLen,
		LegacyAuthCredentialConfig.NumAttrs)
	profileKeyKP := zkcredential.GenerateCredentialKeyPairFromSHOWithStorage(sho,
		LegacyProfileKeyCredentialConfig.StorageLen,
		LegacyProfileKeyCredentialConfig.NumAttrs)

	sigKeyPair, err := GenerateSignatureKeyPair(sho)
	if err != nil {
		return nil, &ErrGeneratingSignatureKeyPair{Err: err}
	}

	receiptKP := zkcredential.GenerateCredentialKeyPairFromSHOWithStorage(sho,
		LegacyReceiptCredentialConfig.StorageLen,
		LegacyReceiptCredentialConfig.NumAttrs)
	pniKP := zkcredential.GenerateCredentialKeyPairFromSHOWithStorage(sho,
		LegacyPNICredentialConfig.StorageLen,
		LegacyPNICredentialConfig.NumAttrs)
	expiringProfileKeyKP := zkcredential.GenerateCredentialKeyPairFromSHOWithStorage(sho,
		LegacyExpiringProfileKeyCredentialConfig.StorageLen,
		LegacyExpiringProfileKeyCredentialConfig.NumAttrs)
	authWithPniKP := zkcredential.GenerateCredentialKeyPairFromSHOWithStorage(sho,
		LegacyAuthWithPNICredentialConfig.StorageLen,
		LegacyAuthWithPNICredentialConfig.NumAttrs)

	// Generic and endorsement key pairs use randomness directly (independent SHO),
	// matching Rust where these are NOT chained through the shared sho.
	genericKP := zkcredential.GenerateCredentialKeyPair(randomness)

	endorsementKP, err := zkcredential.GenerateServerRootKeyPair(randomness)
	if err != nil {
		return nil, &ErrGeneratingEndorsementKeyPair{Err: err}
	}

	return &ServerSecretParams{
		SigKeyPair:                           sigKeyPair,
		AuthCredentialsKeyPair:               authKP,
		ProfileKeyCredentialsKeyPair:         profileKeyKP,
		PniCredentialsKeyPair:                pniKP,
		AuthCredentialsWithPniKeyPair:        authWithPniKP,
		ReceiptCredentialsKeyPair:            receiptKP,
		ExpiringProfileKeyCredentialsKeyPair: expiringProfileKeyKP,
		GenericCredentialKeyPair:             genericKP,
		EndorsementKeyPair:                   endorsementKP,
	}, nil
}

// GetPublicParams derives the public parameters from the secret parameters.
func (s *ServerSecretParams) GetPublicParams() *ServerPublicParams {
	return &ServerPublicParams{
		SigPublicKey:                           s.SigKeyPair.GetPublicKey(),
		AuthCredentialsPublicKey:               s.AuthCredentialsKeyPair.PublicKey(),
		ProfileKeyCredentialsPublicKey:         s.ProfileKeyCredentialsKeyPair.PublicKey(),
		PniCredentialsPublicKey:                s.PniCredentialsKeyPair.PublicKey(),
		AuthCredentialsWithPniPublicKey:        s.AuthCredentialsWithPniKeyPair.PublicKey(),
		ReceiptCredentialsPublicKey:            s.ReceiptCredentialsKeyPair.PublicKey(),
		ExpiringProfileKeyCredentialsPublicKey: s.ExpiringProfileKeyCredentialsKeyPair.PublicKey(),
		GenericCredentialPublicKey:             s.GenericCredentialKeyPair.PublicKey(),
		EndorsementPublicKey:                   s.EndorsementKeyPair.PublicKey(),
	}
}

// GetEndorsementRootKeyPair returns the endorsement root key pair.
func (s *ServerSecretParams) GetEndorsementRootKeyPair() *EndorsementServerRootKeyPair {
	return &EndorsementServerRootKeyPair{
		KeyPair: s.EndorsementKeyPair,
	}
}

// Sign returns a NotarySignature over message, seeding the nonce from randomness (Rust ServerSecretParams::sign).
func (s *ServerSecretParams) Sign(randomness RandomnessBytes, message []byte) ([]byte, error) {
	sho := zkcredential.NewShoHmacSha256Ext("Signal_ZKGroup_20200424_Random_ServerSecretParams_Sign")
	sho.AbsorbAndRatchet(randomness[:])
	innerRandomness := sho.SqueezeAndRatchet(32)
	return s.SigKeyPair.Sign(message, innerRandomness)
}

// CheckAuthCredentialRedemptionTime checks that currentTime is within the
// validity window defined by redemptionTime.
func CheckAuthCredentialRedemptionTime(
	redemptionTime Timestamp,
	currentTime Timestamp,
) error {
	acceptableStart, ok := redemptionTime.CheckedSubSeconds(SecondsPerDay)
	if !ok {
		return ErrVerificationFailure
	}
	acceptableEnd, ok := redemptionTime.CheckedAddSeconds(2 * SecondsPerDay)
	if !ok {
		return ErrVerificationFailure
	}

	if currentTime.EpochSeconds() < acceptableStart.EpochSeconds() ||
		currentTime.EpochSeconds() > acceptableEnd.EpochSeconds() {
		return ErrVerificationFailure
	}
	return nil
}

// ServerPublicParams holds the server's public credential parameters; the leading reserved field makes a serializer emit Rust bincode's 0x00 byte.
type ServerPublicParams struct {
	//lint:ignore U1000 matches Rust reserved field (rust/zkgroup/src/api/server_params.rs ReservedByte)
	reserved                               byte // always 0x00; bincode ReservedByte
	SigPublicKey                           *SignaturePublicKey
	AuthCredentialsPublicKey               *zkcredential.CredentialPublicKey
	ProfileKeyCredentialsPublicKey         *zkcredential.CredentialPublicKey
	PniCredentialsPublicKey                *zkcredential.CredentialPublicKey
	AuthCredentialsWithPniPublicKey        *zkcredential.CredentialPublicKey
	ReceiptCredentialsPublicKey            *zkcredential.CredentialPublicKey
	ExpiringProfileKeyCredentialsPublicKey *zkcredential.CredentialPublicKey
	GenericCredentialPublicKey             *zkcredential.CredentialPublicKey
	EndorsementPublicKey                   *zkcredential.ServerRootPublicKey
}

// GetEndorsementPublicKey returns the endorsement public key wrapped in the
// versioned type.
func (p *ServerPublicParams) GetEndorsementPublicKey() *EndorsementPublicKey {
	return &EndorsementPublicKey{
		PublicKey: p.EndorsementPublicKey,
	}
}

// GenericServerSecretParams holds a generic credential key pair; the leading reserved field makes a serializer emit Rust bincode's 0x00 byte.
type GenericServerSecretParams struct {
	//lint:ignore U1000 matches Rust reserved field (rust/zkgroup/src/api/generic_server_params.rs ReservedByte)
	reserved      byte // always 0x00; bincode ReservedByte
	CredentialKey *zkcredential.CredentialKeyPair
}

// GenerateGenericServerSecretParams creates new generic server secret parameters.
func GenerateGenericServerSecretParams(randomness RandomnessBytes) *GenericServerSecretParams {
	return &GenericServerSecretParams{
		CredentialKey: zkcredential.GenerateCredentialKeyPair(randomness),
	}
}

// GetPublicParams derives the generic public parameters.
func (g *GenericServerSecretParams) GetPublicParams() *GenericServerPublicParams {
	return &GenericServerPublicParams{
		CredentialKey: g.CredentialKey.PublicKey(),
	}
}

// GenericServerPublicParams holds a generic credential public key; the leading reserved field makes a serializer emit Rust bincode's 0x00 byte.
type GenericServerPublicParams struct {
	//lint:ignore U1000 matches Rust reserved field (rust/zkgroup/src/api/generic_server_params.rs ReservedByte)
	reserved      byte // always 0x00; bincode ReservedByte
	CredentialKey *zkcredential.CredentialPublicKey
}

// EndorsementServerRootKeyPair wraps the endorsement root key pair; the leading reserved field makes a serializer emit Rust bincode's 0x00 byte.
type EndorsementServerRootKeyPair struct {
	//lint:ignore U1000 matches Rust reserved field (rust/zkgroup/src/api/server_params.rs ReservedByte)
	reserved byte // always 0x00; bincode ReservedByte
	KeyPair  *zkcredential.ServerRootKeyPair
}

// PublicKey returns the public key portion.
func (e *EndorsementServerRootKeyPair) PublicKey() *EndorsementPublicKey {
	return &EndorsementPublicKey{
		PublicKey: e.KeyPair.PublicKey(),
	}
}

// EndorsementPublicKey wraps the endorsement root public key; the leading reserved field makes a serializer emit Rust bincode's 0x00 byte.
type EndorsementPublicKey struct {
	//lint:ignore U1000 matches Rust reserved field (rust/zkgroup/src/api/server_params.rs ReservedByte)
	reserved  byte // always 0x00; bincode ReservedByte
	PublicKey *zkcredential.ServerRootPublicKey
}
