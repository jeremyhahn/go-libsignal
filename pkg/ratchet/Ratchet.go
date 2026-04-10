// Package ratchet provides the methods necessary to establish a new double
// ratchet session.
package ratchet

import (
	"encoding/base64"
	"bytes"
	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/kdf"
	"github.com/jeremyhahn/go-libsignal/pkg/kem"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/chain"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/root"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/session"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
)

var b64 = base64.StdEncoding.EncodeToString

func genDiscontinuity() [32]byte {
	var discontinuity [32]byte
	for i := range discontinuity {
		discontinuity[i] = 0xFF
	}
	return discontinuity
}

// CalculateSenderSession calculates the PQXDH key agreement for a recipient.
// This should be used when we are trying to send a message to someone for the
// first time. Returns the session key pair (including InitialPQRKey for SPQR),
// the Kyber ciphertext, and an error.
//
// S-C3: Kyber parameters are mandatory. The KDF label is always KdfInfoPQXDH,
// matching the Rust derive_keys function which unconditionally uses the PQXDH
// label. Returns ErrMissingKyberPreKey if the Kyber pre-key is nil.
func CalculateSenderSession(parameters *SenderParameters) (*session.KeyPair, *kem.Ciphertext, error) {
	var secret [32]byte
	var publicKey [32]byte
	var privateKey [32]byte
	masterSecret := make([]byte, 0, 32*6) // Create a master shared secret (up to 6 components with PQXDH)
	defer crypto.ZeroizeArray32(&secret)
	defer crypto.ZeroizeArray32(&publicKey)
	defer crypto.ZeroizeArray32(&privateKey)
	defer func() { crypto.Zeroize(masterSecret) }()
	discontinuity := genDiscontinuity()
	masterSecret = append(masterSecret, discontinuity[:]...)

	// Calculate the agreement using their signed prekey and our identity key.
	publicKey = parameters.TheirSignedPreKey().PublicKey()
	privateKey = parameters.OurIdentityKey().PrivateKey().Serialize()
	secret, err := kdf.CalculateSharedSecret(publicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}
	masterSecret = append(masterSecret, secret[:]...)

	// Calculate the agreement using their identity key and our base key.
	publicKey = parameters.TheirIdentityKey().PublicKey().PublicKey()
	privateKey = parameters.OurBaseKey().PrivateKey().Serialize()
	secret, err = kdf.CalculateSharedSecret(publicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}
	masterSecret = append(masterSecret, secret[:]...)

	// Calculate the agreement using their signed prekey and our base key.
	publicKey = parameters.TheirSignedPreKey().PublicKey()
	privateKey = parameters.OurBaseKey().PrivateKey().Serialize()
	secret, err = kdf.CalculateSharedSecret(publicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}
	masterSecret = append(masterSecret, secret[:]...)

	// If they have a one-time prekey, use it to calculate the shared secret with their
	// one time key and our base key.
	if parameters.TheirOneTimePreKey() != nil {
		publicKey = parameters.TheirOneTimePreKey().PublicKey()
		privateKey = parameters.OurBaseKey().PrivateKey().Serialize()
		secret, err = kdf.CalculateSharedSecret(publicKey, privateKey)
		if err != nil {
			return nil, nil, err
		}
		masterSecret = append(masterSecret, secret[:]...)
	}

	// S-C3: PQXDH Kyber encapsulation is mandatory for v4 sessions.
	// Matches Rust where AliceSignalProtocolParameters.their_kyber_pre_key is
	// non-optional (not Option<>) and derive_keys always uses KdfInfoPQXDH.
	if parameters.TheirKyberPreKey() == nil {
		return nil, nil, ErrMissingKyberPreKey
	}
	kemImpl := kem.NewKyber1024KEM()
	ss, kyberCiphertext, kemErr := kemImpl.Encapsulate(parameters.TheirKyberPreKey())
	if kemErr != nil {
		return nil, nil, kemErr
	}
	// Defer zeroization of the Kyber shared secret so it is cleared
	// even if a subsequent operation fails.
	defer crypto.ZeroizeArray32((*[32]byte)(ss))
	masterSecret = append(masterSecret, (*ss)[:]...)

	// S-C3: Always use KdfInfoPQXDH label, matching Rust derive_keys which
	// unconditionally uses "WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024".
	kdfInfo := root.KdfInfoPQXDH

	// Derive the root, chain, and initial PQR keys based on the master secret.
	// The 96-byte output produces three 32-byte keys: RootKey + ChainKey + InitialPQRKey.
	derivedKeysBytes, err := kdf.DeriveSecrets(masterSecret, nil, []byte(kdfInfo), root.DerivedSecretsSize)
	if err != nil {
		return nil, nil, err
	}
	derivedKeys := session.NewDerivedSecrets(derivedKeysBytes)

	// Copy bytes out of guarded memory before passing to constructors,
	// since constructors move data into new guarded memory and zeroize the source.
	rootKeyBytes := make([]byte, 32)
	copy(rootKeyBytes, derivedKeys.RootKey())
	chainKeyBytes := make([]byte, 32)
	copy(chainKeyBytes, derivedKeys.ChainKey())

	// Extract the InitialPQRKey for SPQR initialization.
	var pqrKeyBytes []byte
	if pqrBytes := derivedKeys.InitialPQRKey(); pqrBytes != nil {
		pqrKeyBytes = make([]byte, 32)
		copy(pqrKeyBytes, pqrBytes)
	}
	derivedKeys.Zeroize()

	chainKey := chain.NewKey(kdf.DeriveSecrets, chainKeyBytes, 0)
	rootKey := root.NewKey(kdf.DeriveSecrets, rootKeyBytes)

	// Add the root and chain keys to a structure that will hold both keys,
	// along with the InitialPQRKey for SPQR initialization.
	// NewKeyPairWithPQR moves pqrKeyBytes into guarded memory and zeroizes the source.
	sessionKeys, pqrErr := session.NewKeyPairWithPQR(rootKey, chainKey, pqrKeyBytes)
	if pqrErr != nil {
		return nil, nil, pqrErr
	}

	return sessionKeys, kyberCiphertext, nil
}

// CalculateReceiverSession calculates the PQXDH key agreement for a sender.
// This should be used when we are receiving a message from someone for the first time.
//
// PQ-C3: Validates that TheirBaseKey is canonical before any DH operations,
// matching the Rust initialize_bob_session check.
//
// S-C3: Kyber parameters are mandatory. Both OurKyberPreKeyPair and
// TheirKyberCiphertext must be present. Returns ErrMissingKyberPreKey or
// ErrMissingKyberCiphertext if either is nil.
func CalculateReceiverSession(parameters *ReceiverParameters) (*session.KeyPair, error) {
	// Guard: TheirBaseKey must be present before any further validation or DH
	// operations. A nil interface value would panic at the IsCanonical call and
	// at every PublicKey() dereference below.
	if parameters.TheirBaseKey() == nil {
		return nil, ErrNilBaseKey
	}

	// PQ-C3: Validate the sender's base key is canonical before performing
	// any DH operations. This matches the Rust check at the top of
	// initialize_bob_session: if !parameters.their_base_key().is_canonical()
	if !parameters.TheirBaseKey().IsCanonical() {
		return nil, ErrNonCanonicalBaseKey
	}

	var secret [32]byte
	var publicKey [32]byte
	var privateKey [32]byte
	masterSecret := make([]byte, 0, 32*6) // Create a master shared secret (up to 6 components with PQXDH)
	defer crypto.ZeroizeArray32(&secret)
	defer crypto.ZeroizeArray32(&publicKey)
	defer crypto.ZeroizeArray32(&privateKey)
	defer func() { crypto.Zeroize(masterSecret) }()
	discontinuity := genDiscontinuity()
	masterSecret = append(masterSecret, discontinuity[:]...)

	// Calculate the agreement using their identity key and our signed pre key.
	publicKey = parameters.TheirIdentityKey().PublicKey().PublicKey()
	privateKey = parameters.OurSignedPreKey().PrivateKey().Serialize()
	secret, err := kdf.CalculateSharedSecret(publicKey, privateKey)
	if err != nil {
		return nil, err
	}
	masterSecret = append(masterSecret, secret[:]...)

	// Calculate the agreement using their base key and our identity key.
	publicKey = parameters.TheirBaseKey().PublicKey()
	privateKey = parameters.OurIdentityKeyPair().PrivateKey().Serialize()
	secret, err = kdf.CalculateSharedSecret(publicKey, privateKey)
	if err != nil {
		return nil, err
	}
	masterSecret = append(masterSecret, secret[:]...)

	// Calculate the agreement using their base key and our signed prekey.
	publicKey = parameters.TheirBaseKey().PublicKey()
	privateKey = parameters.OurSignedPreKey().PrivateKey().Serialize()
	secret, err = kdf.CalculateSharedSecret(publicKey, privateKey)
	if err != nil {
		return nil, err
	}
	masterSecret = append(masterSecret, secret[:]...)

	// If we had a one-time prekey, use it to calculate the shared secret with our
	// one time key and their base key.
	if parameters.OurOneTimePreKey() != nil {
		publicKey = parameters.TheirBaseKey().PublicKey()
		privateKey = parameters.OurOneTimePreKey().PrivateKey().Serialize()
		secret, err = kdf.CalculateSharedSecret(publicKey, privateKey)
		if err != nil {
			return nil, err
		}
		masterSecret = append(masterSecret, secret[:]...)
	}

	// S-C3: PQXDH Kyber decapsulation is mandatory for v4 sessions.
	// Matches Rust where BobSignalProtocolParameters.our_kyber_pre_key_pair and
	// their_kyber_ciphertext are non-optional and derive_keys always uses KdfInfoPQXDH.
	if parameters.OurKyberPreKeyPair() == nil {
		return nil, ErrMissingKyberPreKey
	}
	if parameters.TheirKyberCiphertext() == nil {
		return nil, ErrMissingKyberCiphertext
	}
	guardedKEM := kem.NewGuardedKyber1024()
	guardedSS, kemErr := guardedKEM.Decapsulate(parameters.OurKyberPreKeyPair().Secret, parameters.TheirKyberCiphertext())
	if kemErr != nil {
		return nil, kemErr
	}
	// Copy shared secret bytes out of guarded memory before appending,
	// then destroy the guarded shared secret.
	ssBytes := guardedSS.Array()
	masterSecret = append(masterSecret, ssBytes[:]...)
	crypto.ZeroizeArray32(&ssBytes)
	guardedSS.Destroy()

	// S-C3: Always use KdfInfoPQXDH label, matching Rust derive_keys which
	// unconditionally uses "WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024".
	kdfInfo := root.KdfInfoPQXDH

	// Derive the root, chain, and initial PQR keys based on the master secret.
	// The 96-byte output produces three 32-byte keys: RootKey + ChainKey + InitialPQRKey.
	derivedKeysBytes, err := kdf.DeriveSecrets(masterSecret, nil, []byte(kdfInfo), root.DerivedSecretsSize)
	if err != nil {
		return nil, err
	}
	derivedKeys := session.NewDerivedSecrets(derivedKeysBytes)

	// Copy bytes out of guarded memory before passing to constructors,
	// since constructors move data into new guarded memory and zeroize the source.
	rootKeyBytes := make([]byte, 32)
	copy(rootKeyBytes, derivedKeys.RootKey())
	chainKeyBytes := make([]byte, 32)
	copy(chainKeyBytes, derivedKeys.ChainKey())

	// Extract the InitialPQRKey for SPQR initialization.
	var pqrKeyBytes []byte
	if pqrBytes := derivedKeys.InitialPQRKey(); pqrBytes != nil {
		pqrKeyBytes = make([]byte, 32)
		copy(pqrKeyBytes, pqrBytes)
	}
	derivedKeys.Zeroize()

	chainKey := chain.NewKey(kdf.DeriveSecrets, chainKeyBytes, 0)
	rootKey := root.NewKey(kdf.DeriveSecrets, rootKeyBytes)

	// Add the root and chain keys to a structure that will hold both keys,
	// along with the InitialPQRKey for SPQR initialization.
	// NewKeyPairWithPQR moves pqrKeyBytes into guarded memory and zeroizes the source.
	sessionKeys, pqrErr := session.NewKeyPairWithPQR(rootKey, chainKey, pqrKeyBytes)
	if pqrErr != nil {
		return nil, pqrErr
	}

	return sessionKeys, nil
}

// CalculateSymmetricSession calculates the key agreement between two users. This
// works by both clients exchanging KeyExchange messages to first establish a session.
// This is useful for establishing a session if both users are online.
//
// Note: Symmetric sessions use the legacy X3DH path (v3) with the "WhisperRatchet"
// KDF label. This path does not exist in the Rust reference and does not require Kyber.
// It is retained for backward compatibility with existing KeyExchange-based sessions.
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

// CalculateLegacySenderSession performs the legacy X3DH sender-side session
// derivation using the "WhisperRatchet" KDF label without Kyber. This is used
// for symmetric sessions and for verifying cross-implementation X3DH test vectors.
// New sessions MUST use CalculateSenderSession which enforces PQXDH.
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

// CalculateLegacyReceiverSession performs the legacy X3DH receiver-side session
// derivation using the "WhisperRatchet" KDF label without Kyber. This is used
// for symmetric sessions and for verifying cross-implementation X3DH test vectors.
// New sessions MUST use CalculateReceiverSession which enforces PQXDH.
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

// isSender is a private method for determining if a symmetric session should
// be calculated as the sender or receiver. It does so by converting the given
// keys into integers and comparing the size of those integers.
func isSender(ourKey, theirKey ecc.ECPublicKeyable) bool {
	ourBytes := ourKey.Serialize()
	theirBytes := theirKey.Serialize()
	return bytes.Compare(ourBytes, theirBytes) < 0
}
