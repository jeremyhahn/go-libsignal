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
	"github.com/jeremyhahn/go-libsignal/pkg/util/medium"
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

// GeneratePreKeys generates count pre-keys with IDs ((start-1+i) % (medium.MaxValue-1)) + 1, as Java KeyHelper does; start 0 gives 0..count-1.
func GeneratePreKeys(start int, count int, serializer record.PreKeySerializer) ([]*record.PreKey, error) {
	var preKeys []*record.PreKey
	for i := 0; i < count; i++ {
		// Signed modulo matches the Java reference: for start=0, i=0 the
		// dividend is -1, Go's truncated modulo yields -1, and +1 gives ID 0
		// (the long-standing zero-based behavior). All other inputs are >= 1.
		id := uint32(((start - 1 + i) % (int(medium.MaxValue) - 1)) + 1)
		key, err := ecc.GenerateKeyPair()
		if err != nil {
			return nil, err
		}
		preKeys = append(preKeys, record.NewPreKey(id, key, serializer))
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

// GenerateRegistrationID returns a registration ID in [1, 16380], as Java KeyHelper does; generate it once at install.
func GenerateRegistrationID() uint32 {
	var n uint32
	if err := binary.Read(rand.Reader, binary.LittleEndian, &n); err != nil {
		panic("keyhelper: failed to read random bytes for registration ID: " + err.Error())
	}

	return (n % 16380) + 1
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

// GenerateSenderKeyID returns a random 31-bit sender key chain ID, as Rust does.
func GenerateSenderKeyID() uint32 {
	var n uint32
	if err := binary.Read(rand.Reader, binary.LittleEndian, &n); err != nil {
		panic("keyhelper: failed to read random bytes for sender key ID: " + err.Error())
	}
	return n >> 1
}

//---------- End Group Stuff --------------

//---------- Kyber Pre-Key Stuff -----------

// GenerateKyberPreKey generates a Kyber-1024 pre-key in locked memory and signs its public key with the identity key.
func GenerateKyberPreKey(signingKey ecc.ECPrivateKeyable, id uint32, serializer record.KyberPreKeySerializer) (*record.KyberPreKey, error) {
	kyberKEM := kem.NewGuardedKyber1024()
	keyPair, err := kyberKEM.Generate()
	if err != nil {
		return nil, err
	}

	signature, err := ecc.CalculateSignature(signingKey, keyPair.Public.Serialize())
	if err != nil {
		keyPair.Destroy()
		return nil, err
	}

	timestamp := time.Now().Unix()

	return record.NewKyberPreKey(id, timestamp, keyPair, bytehelper.ArrayToSlice64(signature), serializer), nil
}

//---------- End Kyber Pre-Key Stuff -------
