// Package kdf provides a key derivation function to calculate key output
// and negotiate shared secrets for curve X25519 keys.
package kdf

import (
	"crypto/sha256"
	"crypto/subtle"
	"io"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// HKDF is a hashed key derivation function type that can be used to derive keys.
type HKDF func(inputKeyMaterial, salt, info []byte, outputLength int) ([]byte, error)

// DeriveSecrets derives the requested number of bytes using HKDF with the given
// input, salt, and info.
func DeriveSecrets(inputKeyMaterial, salt, info []byte, outputLength int) ([]byte, error) {
	kdf := hkdf.New(sha256.New, inputKeyMaterial, salt, info)

	secrets := make([]byte, outputLength)
	length, err := io.ReadFull(kdf, secrets)
	if err != nil {
		crypto.Zeroize(secrets)
		return nil, &ErrHKDFReadFull{Err: err}
	}
	if length != outputLength {
		return nil, &ErrShortRead{Expected: outputLength, Got: length}
	}

	return secrets, nil
}

// CalculateSharedSecret uses DH Curve25519 to find a shared secret. The result of this function
// should be used in `DeriveSecrets` to output the Root and Chain keys.
//
// Uses curve25519.X25519 which validates inputs and rejects low-order points
// that would produce an all-zero shared secret.
func CalculateSharedSecret(theirKey, ourKey [32]byte) ([32]byte, error) {
	// Zeroize the local copies of key material when done.
	defer crypto.ZeroizeArray32(&ourKey)
	defer crypto.ZeroizeArray32(&theirKey)

	result, err := curve25519.X25519(ourKey[:], theirKey[:])
	if err != nil {
		return [32]byte{}, &ErrLowOrderPoint{Err: err}
	}

	return validateAndCopySharedSecret(result)
}

// validateAndCopySharedSecret rejects all-zero DH results in constant time and
// copies the raw bytes into a fixed-size output, zeroizing the source slice.
//
// An all-zero result indicates a low-order peer public key that would compromise
// security. This matches the Rust reference CurveError::InvalidKeyAgreement.
// In practice curve25519.X25519 already rejects known low-order points via error,
// so this check is a defence-in-depth guard against future API changes.
func validateAndCopySharedSecret(result []byte) ([32]byte, error) {
	var allZero [32]byte
	if subtle.ConstantTimeCompare(result, allZero[:]) == 1 {
		crypto.Zeroize(result)
		return [32]byte{}, &ErrAllZeroSharedSecret{}
	}

	var sharedSecret [32]byte
	copy(sharedSecret[:], result)
	crypto.Zeroize(result)

	return sharedSecret, nil
}

// KeyMaterial is a structure for representing a cipherkey, mac, and iv
type KeyMaterial struct {
	CipherKey []byte
	MacKey    []byte
	IV        []byte
}

// Zeroize overwrites all key material fields with zeros to prevent sensitive
// data from lingering in memory. Call this (via defer) when the key material
// is no longer needed.
func (k *KeyMaterial) Zeroize() {
	crypto.Zeroize(k.CipherKey)
	crypto.Zeroize(k.MacKey)
	crypto.Zeroize(k.IV)
}
