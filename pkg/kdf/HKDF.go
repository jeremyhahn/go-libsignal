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

// Extract performs the HKDF extract step (RFC 5869 §2.2), computing the
// pseudorandom key PRK = HMAC-SHA256(salt, ikm).
//
// If salt is nil or empty, HMAC-SHA256 is computed with a zero-valued key
// of HashLen bytes, matching the RFC 5869 §2.2 default.
//
// The returned PRK is 32 bytes. Pass it to Expand or ExpandFromPRK for
// multi-expansion use cases — this avoids re-running the extract step.
//
// Mirrors Rust Hkdf::<Sha256>::extract(salt, ikm).
// Rust source: rust/crypto/src/hpke/provider.rs:55
func Extract(ikm, salt []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

// Expand performs the HKDF expand step (RFC 5869 §2.3) using a PRK previously
// returned by Extract. It derives outputLength bytes keyed by info.
//
// prk must be at least 32 bytes (one HMAC-SHA256 output block).
// outputLength must not exceed 255 * 32 = 8160 bytes (HKDF-SHA256 limit).
//
// Mirrors Rust Hkdf::<Sha256>::from_prk(prk).expand(info, out).
// Rust source: rust/crypto/src/hpke/provider.rs:69-72
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
