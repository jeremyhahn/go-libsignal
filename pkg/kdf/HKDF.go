// Package kdf provides a key derivation function to calculate key output
// and negotiate shared secrets for curve X25519 keys.
package kdf

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"io"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// HKDF is a hashed key derivation function type that can be used to derive keys.
type HKDF func(inputKeyMaterial, salt, info []byte, outputLength int) ([]byte, error)

// Extract returns the 32-byte PRK = HMAC-SHA256(salt, ikm) (RFC 5869 §2.2); an empty salt is HashLen zero bytes.
func Extract(ikm, salt []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

// Expand derives outputLength bytes (at most 8160) from a PRK of at least 32 bytes and info (RFC 5869 §2.3).
func Expand(prk, info []byte, outputLength int) ([]byte, error) {
	if len(prk) < sha256.Size {
		return nil, &ErrHKDFInvalidPRK{Got: len(prk)}
	}
	r := hkdf.Expand(sha256.New, prk, info)
	out := make([]byte, outputLength)
	if _, err := io.ReadFull(r, out); err != nil {
		crypto.Zeroize(out)
		return nil, &ErrHKDFExpand{Err: err}
	}
	return out, nil
}

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

// CalculateSharedSecret returns the X25519 shared secret, rejecting low-order points; feed it to DeriveSecrets.
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

// validateAndCopySharedSecret rejects an all-zero DH result in constant time and copies it out, zeroizing the source.
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

// Zeroize overwrites all key material with zeros.
func (k *KeyMaterial) Zeroize() {
	crypto.Zeroize(k.CipherKey)
	crypto.Zeroize(k.MacKey)
	crypto.Zeroize(k.IV)
}
