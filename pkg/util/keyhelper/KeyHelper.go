// Package keyhelper is based on: https://github.com/WhisperSystems/libsignal-protocol-java/blob/master/java/src/main/java/org/whispersystems/libsignal/util/KeyHelper.java
package keyhelper

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/kem"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/util/bytehelper"
)

// GenerateIdentityKeyPair generates an identity keypair used for
// signing. Clients should only do this once at install time.
func GenerateIdentityKeyPair() (*identity.KeyPair, error) {
	keyPair, err := ecc.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	publicKey := identity.NewKey(keyPair.PublicKey())
	return identity.NewKeyPair(publicKey, keyPair.PrivateKey()), nil
}

// GeneratePreKeys generates a list of PreKeys. Client shsould do this at
// install time, and subsequently any time the list of PreKeys stored on
// the server runs low.
//
// PreKeys IDs are shorts, so they will eventually be repeated. Clients
// should store PreKeys in a circular buffer, so that they are repeated
// as infrequently as possible.
func GeneratePreKeys(start int, count int, serializer record.PreKeySerializer) ([]*record.PreKey, error) {
	var preKeys []*record.PreKey

	_ = start // start is reserved for future circular buffer offset use

	for i := 0; i < count; i++ {
		key, err := ecc.GenerateKeyPair()
		if err != nil {
			return nil, err
		}
		preKeys = append(preKeys, record.NewPreKey(uint32(i), key, serializer))
	}

	return preKeys, nil
}

// GenerateLastResortKey will generate the last resort PreKey. Clients should
// do this only once, at install time, and durably store it for the length
// of the install.
func GenerateLastResortKey(serializer record.PreKeySerializer) (*record.PreKey, error) {
	keyPair, err := ecc.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	return record.NewPreKey(0, keyPair, serializer), nil
}

// GenerateSignedPreKey generates a signed PreKey.
func GenerateSignedPreKey(identityKeyPair *identity.KeyPair, signedPreKeyID uint32, serializer record.SignedPreKeySerializer) (*record.SignedPreKey, error) {
	keyPair, err := ecc.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	signature, err := ecc.CalculateSignature(identityKeyPair.PrivateKey(), keyPair.PublicKey().Serialize())
	if err != nil {
		return nil, err
	}
	timestamp := time.Now().Unix()

	return record.NewSignedPreKey(signedPreKeyID, timestamp, keyPair, signature, serializer), nil
}

// GenerateRegistrationID generates a registration ID. Clients should only do
// this once, at install time. Registration IDs are 14-bit values (0–16383)
// per the Signal protocol specification.
func GenerateRegistrationID() uint32 {
	var n uint32
	if err := binary.Read(rand.Reader, binary.LittleEndian, &n); err != nil {
		panic("keyhelper: failed to read random bytes for registration ID: " + err.Error())
	}

	return n & 0x3FFF
}

//---------- Group Stuff ----------------

func GenerateSenderSigningKey() (*ecc.ECKeyPair, error) {
	return ecc.GenerateKeyPair()
}

func GenerateSenderKey() ([]byte, error) {
	randBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, randBytes); err != nil {
		return nil, &ErrRandomGeneration{Op: "GenerateSenderKey", Err: err}
	}
	return randBytes, nil
}

func GenerateSenderKeyID() uint32 {
	return GenerateRegistrationID()
}

//---------- End Group Stuff --------------

//---------- Kyber Pre-Key Stuff -----------

// GenerateKyberPreKey generates a Kyber-1024 pre-key, signs the public key with
// the given identity signing key, and returns the resulting record.
func GenerateKyberPreKey(signingKey ecc.ECPrivateKeyable, id uint32, serializer record.KyberPreKeySerializer) (*record.KyberPreKey, error) {
	kyberKEM := kem.NewKyber1024KEM()
	keyPair, err := kyberKEM.Generate()
	if err != nil {
		return nil, err
	}

	signature, err := ecc.CalculateSignature(signingKey, keyPair.Public.Serialize())
	if err != nil {
		return nil, err
	}

	timestamp := time.Now().Unix()

	return record.NewKyberPreKey(id, timestamp, keyPair, bytehelper.ArrayToSlice64(signature), serializer), nil
}

//---------- End Kyber Pre-Key Stuff -------
