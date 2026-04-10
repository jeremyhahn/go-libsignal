package ecc

import (
	"crypto/rand"
	"io"

	"github.com/jeremyhahn/go-libsignal/pkg/logger"
	crypto "github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"golang.org/x/crypto/curve25519"
)

// VXEdDSASign signs a message using VXEdDSA, producing a 96-byte signature
// and a 64-byte VRF output. The VRF output is deterministic for a given
// (key, message) pair, providing verifiable randomness.
func VXEdDSASign(key ECPrivateKeyable, message []byte) ([]byte, []byte, error) {
	if key == nil {
		return nil, nil, ErrNilPrivateKey
	}

	var random [64]byte
	defer crypto.Zeroize(random[:])
	_, err := io.ReadFull(rand.Reader, random[:])
	if err != nil {
		return nil, nil, err
	}

	privateKey := key.Serialize()
	defer crypto.Zeroize(privateKey[:])

	sig, vrf, err := vxeddsaSign(&privateKey, message, random)
	if err != nil {
		return nil, nil, err
	}
	return sig[:], vrf, nil
}

// VXEdDSAVerify verifies a VXEdDSA signature and returns whether the signature
// is valid along with the VRF output. The VRF output is only meaningful when
// the signature is valid.
func VXEdDSAVerify(key ECPublicKeyable, message, signature []byte) (bool, []byte, error) {
	if key == nil {
		return false, nil, ErrNilPublicKey
	}
	if len(signature) != VXEdDSASignatureSize {
		return false, nil, &ErrVXEdDSAInvalidSignatureLength{Got: len(signature)}
	}

	var sig [96]byte
	copy(sig[:], signature)

	publicKey := key.PublicKey()
	valid, vrf := vxeddsaVerify(publicKey, message, &sig)
	return valid, vrf, nil
}

// DjbType is the Diffie-Hellman curve type (curve25519) created by D. J. Bernstein.
const DjbType = 0x05

// DecodePoint will take the given bytes and offset and return an ECPublicKeyable object.
// This is used to check the byte at the given offset in the byte array for a special
// "type" byte that will determine the key type. Currently only DJB EC keys are supported.
func DecodePoint(bytes []byte, offset int) (ECPublicKeyable, error) {
	if offset < 0 || offset >= len(bytes) {
		return nil, ErrInputTooShort
	}

	keyType := bytes[offset] & 0xFF

	switch keyType {
	case DjbType:
		if offset+1+32 > len(bytes) {
			return nil, ErrBadKeyLength
		}
		keyBytes := [32]byte{}
		copy(keyBytes[:], bytes[offset+1:offset+1+32])
		return NewDjbECPublicKey(keyBytes), nil
	default:
		return nil, &ErrBadKeyType{KeyType: keyType}
	}
}

// GenerateKeyPair returns an EC Key Pair.
func GenerateKeyPair() (*ECKeyPair, error) {
	logger.Debug("Generating EC Key Pair...")
	// Get cryptographically secure random numbers.
	random := rand.Reader

	// Create a byte array for our public and private keys.
	var private, public [32]byte

	// Generate some random data
	_, err := io.ReadFull(random, private[:])
	if err != nil {
		return nil, err
	}

	// Documented at: http://cr.yp.to/ecdh.html
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64

	curve25519.ScalarBaseMult(&public, &private)

	// Put data into our keypair struct
	djbECPub := NewDjbECPublicKey(public)
	// Use GuardedECPrivateKey for memguard-protected storage.
	// NewGuardedECPrivateKey zeroizes the source array (move semantics).
	guardedPriv, gErr := NewGuardedECPrivateKey(private)
	if gErr != nil {
		return nil, gErr
	}
	keypair := NewECKeyPair(djbECPub, guardedPriv)

	return keypair, nil
}

// VerifySignature verifies that the message was signed with the given key.
func VerifySignature(signingKey ECPublicKeyable, message []byte, signature [64]byte) bool {
	publicKey := signingKey.PublicKey()
	return verify(publicKey, message, &signature)
}

// CalculateSignature signs a message with the given private key.
func CalculateSignature(signingKey ECPrivateKeyable, message []byte) ([64]byte, error) {
	logger.Debug("Signing bytes with signing key")
	// Get cryptographically secure random numbers.
	var random [64]byte
	defer crypto.Zeroize(random[:])

	_, err := io.ReadFull(rand.Reader, random[:])
	if err != nil {
		return [64]byte{}, err
	}

	// Get the private key.
	privateKey := signingKey.Serialize()
	defer crypto.Zeroize(privateKey[:])

	// Sign the message.
	signature := sign(&privateKey, message, random)
	if signature == nil {
		return [64]byte{}, ErrSignFailed
	}

	return *signature, nil
}
