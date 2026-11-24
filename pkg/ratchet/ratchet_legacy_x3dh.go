//go:build legacy_x3dh

// Legacy X3DH session derivation, built only with -tags=legacy_x3dh for symmetric sessions and Java test vectors.
package ratchet

import (
	"bytes"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/kdf"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/chain"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/root"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/session"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
)

// CalculateSymmetricSession derives a session from exchanged KeyExchange messages over the legacy X3DH v3 path; requires legacy_x3dh.
func CalculateSymmetricSession(parameters *SymmetricParameters) (*session.KeyPair, error) {
	// Compare the base public keys so we can deterministically know whether we should
	// be setting up a sender or receiver session. If our key converted to an integer is
	// less than the other user's, act as a sender.
	if isSender(parameters.OurBaseKey.PublicKey(), parameters.TheirBaseKey) {
		senderParams := &SenderParameters{
			ourBaseKey:         parameters.OurBaseKey,
			ourIdentityKeyPair: parameters.OurIdentityKeyPair,
			theirRatchetKey:    parameters.TheirRatchetKey,
			theirIdentityKey:   parameters.TheirIdentityKey,
			theirSignedPreKey:  parameters.TheirBaseKey,
		}
		return CalculateLegacySenderSession(senderParams)
	}

	receiverParams := &ReceiverParameters{
		ourIdentityKeyPair: parameters.OurIdentityKeyPair,
		ourRatchetKey:      parameters.OurRatchetKey,
		ourSignedPreKey:    parameters.OurBaseKey,
		theirBaseKey:       parameters.TheirBaseKey,
		theirIdentityKey:   parameters.TheirIdentityKey,
	}
	return CalculateLegacyReceiverSession(receiverParams)
}

// calculateLegacyDH computes the legacy X3DH DH master secret for the sender
// side (Alice). This is used by CalculateSymmetricSession and exposed for testing
// cross-implementation X3DH vector compatibility.
func calculateLegacyDH(parameters *SenderParameters) ([]byte, error) {
	var secret [32]byte
	var publicKey [32]byte
	var privateKey [32]byte
	masterSecret := make([]byte, 0, 32*5)
	defer crypto.ZeroizeArray32(&secret)
	defer crypto.ZeroizeArray32(&publicKey)
	defer crypto.ZeroizeArray32(&privateKey)
	discontinuity := genDiscontinuity()
	masterSecret = append(masterSecret, discontinuity[:]...)

	publicKey = parameters.TheirSignedPreKey().PublicKey()
	privateKey = parameters.OurIdentityKey().PrivateKey().Serialize()
	secret, err := kdf.CalculateSharedSecret(publicKey, privateKey)
	if err != nil {
		return nil, err
	}
	masterSecret = append(masterSecret, secret[:]...)

	publicKey = parameters.TheirIdentityKey().PublicKey().PublicKey()
	privateKey = parameters.OurBaseKey().PrivateKey().Serialize()
	secret, err = kdf.CalculateSharedSecret(publicKey, privateKey)
	if err != nil {
		return nil, err
	}
	masterSecret = append(masterSecret, secret[:]...)

	publicKey = parameters.TheirSignedPreKey().PublicKey()
	privateKey = parameters.OurBaseKey().PrivateKey().Serialize()
	secret, err = kdf.CalculateSharedSecret(publicKey, privateKey)
	if err != nil {
		return nil, err
	}
	masterSecret = append(masterSecret, secret[:]...)

	if parameters.TheirOneTimePreKey() != nil {
		publicKey = parameters.TheirOneTimePreKey().PublicKey()
		privateKey = parameters.OurBaseKey().PrivateKey().Serialize()
		secret, err = kdf.CalculateSharedSecret(publicKey, privateKey)
		if err != nil {
			return nil, err
		}
		masterSecret = append(masterSecret, secret[:]...)
	}

	return masterSecret, nil
}

// CalculateLegacySenderSession derives a legacy X3DH sender session without Kyber; new sessions use CalculateSenderSession. Requires legacy_x3dh.
func CalculateLegacySenderSession(parameters *SenderParameters) (*session.KeyPair, error) {
	masterSecret, err := calculateLegacyDH(parameters)
	if err != nil {
		return nil, err
	}
	defer func() { crypto.Zeroize(masterSecret) }()

	derivedKeysBytes, err := kdf.DeriveSecrets(masterSecret, nil, []byte(root.KdfInfo), root.ChainDerivedSecretsSize)
	if err != nil {
		return nil, err
	}

	rootKeyBytes := make([]byte, 32)
	copy(rootKeyBytes, derivedKeysBytes[:32])
	chainKeyBytes := make([]byte, 32)
	copy(chainKeyBytes, derivedKeysBytes[32:64])
	crypto.Zeroize(derivedKeysBytes)

	chainKey := chain.NewKey(kdf.DeriveSecrets, chainKeyBytes, 0)
	rootKey := root.NewKey(kdf.DeriveSecrets, rootKeyBytes)

	return session.NewKeyPair(rootKey, chainKey), nil
}

// CalculateLegacyReceiverSession derives a legacy X3DH receiver session without Kyber; new sessions use CalculateReceiverSession. Requires legacy_x3dh.
func CalculateLegacyReceiverSession(parameters *ReceiverParameters) (*session.KeyPair, error) {
	var secret [32]byte
	var publicKey [32]byte
	var privateKey [32]byte
	masterSecret := make([]byte, 0, 32*5)
	defer crypto.ZeroizeArray32(&secret)
	defer crypto.ZeroizeArray32(&publicKey)
	defer crypto.ZeroizeArray32(&privateKey)
	defer func() { crypto.Zeroize(masterSecret) }()
	discontinuity := genDiscontinuity()
	masterSecret = append(masterSecret, discontinuity[:]...)

	publicKey = parameters.TheirIdentityKey().PublicKey().PublicKey()
	privateKey = parameters.OurSignedPreKey().PrivateKey().Serialize()
	secret, err := kdf.CalculateSharedSecret(publicKey, privateKey)
	if err != nil {
		return nil, err
	}
	masterSecret = append(masterSecret, secret[:]...)

	publicKey = parameters.TheirBaseKey().PublicKey()
	privateKey = parameters.OurIdentityKeyPair().PrivateKey().Serialize()
	secret, err = kdf.CalculateSharedSecret(publicKey, privateKey)
	if err != nil {
		return nil, err
	}
	masterSecret = append(masterSecret, secret[:]...)

	publicKey = parameters.TheirBaseKey().PublicKey()
	privateKey = parameters.OurSignedPreKey().PrivateKey().Serialize()
	secret, err = kdf.CalculateSharedSecret(publicKey, privateKey)
	if err != nil {
		return nil, err
	}
	masterSecret = append(masterSecret, secret[:]...)

	if parameters.OurOneTimePreKey() != nil {
		publicKey = parameters.TheirBaseKey().PublicKey()
		privateKey = parameters.OurOneTimePreKey().PrivateKey().Serialize()
		secret, err = kdf.CalculateSharedSecret(publicKey, privateKey)
		if err != nil {
			return nil, err
		}
		masterSecret = append(masterSecret, secret[:]...)
	}

	derivedKeysBytes, err := kdf.DeriveSecrets(masterSecret, nil, []byte(root.KdfInfo), root.ChainDerivedSecretsSize)
	if err != nil {
		return nil, err
	}

	rootKeyBytes := make([]byte, 32)
	copy(rootKeyBytes, derivedKeysBytes[:32])
	chainKeyBytes := make([]byte, 32)
	copy(chainKeyBytes, derivedKeysBytes[32:64])
	crypto.Zeroize(derivedKeysBytes)

	chainKey := chain.NewKey(kdf.DeriveSecrets, chainKeyBytes, 0)
	rootKey := root.NewKey(kdf.DeriveSecrets, rootKeyBytes)

	return session.NewKeyPair(rootKey, chainKey), nil
}

// isSender is a private function for determining if a symmetric session should
// be calculated as the sender or receiver. It does so by converting the given
// keys into integers and comparing the size of those integers.
func isSender(ourKey, theirKey ecc.ECPublicKeyable) bool {
	ourBytes := ourKey.Serialize()
	theirBytes := theirKey.Serialize()
	return bytes.Compare(ourBytes, theirBytes) < 0
}
