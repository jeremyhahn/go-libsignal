package ecc

import (
	"crypto/rand"
	"io"

	"github.com/jeremyhahn/go-libsignal/pkg/logger"
	crypto "github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"golang.org/x/crypto/curve25519"
)

// VXEdDSASign signs a message using VXEdDSA, producing a 96-byte signature
// and a 32-byte VRF output. The VRF output is deterministic for a given
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

	privateKey, err := privateKeyArray(key)
	if err != nil {
		return nil, nil, err
	}
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

// DecodePoint decodes a type-prefixed public key from bytes starting at offset.
// It validates only the type byte (0x05 = DjbType / Curve25519) and key length;
// full curve-point validation is deferred to first cryptographic use (key
// agreement, signature verify, etc.), matching Rust's behavior in curve.rs:84-105.
// Currently only DJB (Curve25519) keys are supported.
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
	// Use GuardedECPrivateKey for locked-memory-protected storage.
	// NewGuardedECPrivateKey zeroizes the source array (move semantics).
	guardedPriv, gErr := NewGuardedECPrivateKey(private)
	if gErr != nil {
		return nil, gErr
	}
	keypair := NewECKeyPair(djbECPub, guardedPriv)

	return keypair, nil
}

// KeyPairFromBytes constructs an ECKeyPair from raw 33-byte public key bytes
// (1 type byte + 32 key bytes) and a 32-byte private key.  The private key is
// clamped before storage, matching Rust KeyPair::from_public_and_private
// (rust/core/src/curve.rs:350-360) and PrivateKey::deserialize clamping
// (rust/core/src/curve/curve25519.rs:172).
//
// Rust source: rust/core/src/curve.rs:350-360.
func KeyPairFromBytes(pubBytes []byte, privBytes [32]byte) (*ECKeyPair, error) {
	pub, err := DecodePoint(pubBytes, 0)
	if err != nil {
		return nil, err
	}
	guardedPriv, err := NewGuardedECPrivateKey(privBytes)
	if err != nil {
		return nil, err
	}
	return NewECKeyPair(pub, guardedPriv), nil
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
	privateKey, err := privateKeyArray(signingKey)
	if err != nil {
		return [64]byte{}, err
	}
	defer crypto.Zeroize(privateKey[:])

	// Sign the message.
	signature := sign(&privateKey, message, random)
	if signature == nil {
		return [64]byte{}, ErrSignFailed
	}

	return *signature, nil
}

// CalculateSignatureWithRandomness signs a message with the given private key
// using the provided 64-byte randomness. This allows deterministic signing for
// test vectors and explicit randomness control (e.g., PNI alternate-identity).
func CalculateSignatureWithRandomness(signingKey ECPrivateKeyable, message []byte, randomness [64]byte) ([64]byte, error) {
	privateKey, err := privateKeyArray(signingKey)
	if err != nil {
		return [64]byte{}, err
	}
	defer crypto.Zeroize(privateKey[:])

	signature := sign(&privateKey, message, randomness)
	if signature == nil {
		return [64]byte{}, ErrSignFailed
	}
	return *signature, nil
}
