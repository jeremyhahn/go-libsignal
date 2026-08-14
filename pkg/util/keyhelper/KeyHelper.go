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

// GeneratePreKeys generates a list of PreKeys. Clients should do this at
// install time, and subsequently any time the list of PreKeys stored on
// the server runs low.
//
// PreKey IDs follow the Java reference formula
// id = ((start-1+i) % (medium.MaxValue-1)) + 1 (signed arithmetic), which
// honors the start offset so successive batches do not collide and wraps at
// medium.MaxValue. start=0 reproduces the historical zero-based sequence
// [0, 1, ..., count-1]; start=K (K>=1) yields [K, K+1, ...].
//
// Java ref: libsignal-protocol-java KeyHelper.generatePreKeys.
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

// GenerateRegistrationID generates a registration ID. Clients should only do
// this once, at install time. Registration IDs are in the range [1, 16380],
// matching the Java reference implementation (% 16380 + 1). Values 0 and
// 16381–16383 are never emitted; 0 is the "unset" sentinel and the upper
// three values are excluded for compatibility with the Java implementation.
//
// Java ref: libsignal-protocol-java KeyHelper.generateRegistrationId.
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

// GenerateSenderKeyID generates a random sender key chain ID.
// Rust uses `(csprng.random::<u32>()) >> 1`, producing a 31-bit value
// (~2 billion possible values). This is intentionally different from
// GenerateRegistrationID (14-bit), which serves a distinct protocol concept.
func GenerateSenderKeyID() uint32 {
	var n uint32
	if err := binary.Read(rand.Reader, binary.LittleEndian, &n); err != nil {
		panic("keyhelper: failed to read random bytes for sender key ID: " + err.Error())
	}
	return n >> 1
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
