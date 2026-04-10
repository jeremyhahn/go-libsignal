// Package svr implements Secure Value Recovery (SVR) for the Signal protocol.
// SVR allows users to back up and restore secrets (such as master keys) using
// a PIN, with server-side rate limiting to prevent brute-force attacks.
//
// This package provides v4 backup/restore request construction, master key
// derivation from PINs and SVR secrets, and encryption/decryption of secrets
// using AES-256-GCM-SIV.
package svr

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/jeremyhahn/go-libsignal/pkg/cipher"
	ucrypto "github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	cryptosecret "github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

const (
	// secretSize is the size of an SVR secret in bytes.
	secretSize = 32

	// entropySize is the size of random entropy for backup requests.
	entropySize = 32

	// requestIDSize is the size of the request identifier.
	requestIDSize = 32

	// masterKeyInfo is the HKDF info string for master key derivation.
	masterKeyInfo = "20221003_Signal_SVR_MasterKey"

	// storageKeyInfo is the HKDF info string for storage key derivation.
	storageKeyInfo = "20231003_Signal_SVR_StorageKey"
)

// Secret is a 32-byte key for SVR operations.
type Secret [secretSize]byte

// EvaluationResult contains the result of an SVR evaluation.
type EvaluationResult struct {
	Value          Secret
	TriesRemaining uint32
}

// Backup4 represents a v4 SVR backup request.
type Backup4 struct {
	RequestID []byte
	Entropy   []byte // 32 bytes random
	Secret    Secret
	MaxTries  uint32
}

// NewBackup4 creates a new v4 backup request with the given secret and maximum
// number of allowed PIN attempts. It generates cryptographically random entropy
// and a request identifier.
func NewBackup4(secret Secret, maxTries uint32) (*Backup4, error) {
	if maxTries == 0 {
		return nil, &Error{kind: errBadData}
	}

	entropy := make([]byte, entropySize)
	if _, err := io.ReadFull(rand.Reader, entropy); err != nil {
		return nil, &Error{kind: errBadData, cause: err}
	}

	requestID := make([]byte, requestIDSize)
	if _, err := io.ReadFull(rand.Reader, requestID); err != nil {
		return nil, &Error{kind: errBadData, cause: err}
	}

	return &Backup4{
		RequestID: requestID,
		Entropy:   entropy,
		Secret:    secret,
		MaxTries:  maxTries,
	}, nil
}

// Restore4 represents a v4 SVR restore request.
type Restore4 struct {
	RequestID []byte
	Entropy   []byte
}

// MasterKey derives a master key from a PIN and SVR secret using HKDF-SHA256.
// The PIN is hashed with SHA-256 to produce input key material, and the secret
// is used as the HKDF salt. The info string is "20221003_Signal_SVR_MasterKey".
//
// SECURITY: The returned [32]byte lives on the caller's stack. Callers should
// defer ucrypto.ZeroizeArray32(&result) after receiving the value, or prefer
// MasterKeyGuarded which returns the key in guarded memory.
func MasterKey(pin string, secret Secret) ([32]byte, error) {
	var result [32]byte

	if len(pin) == 0 {
		return result, ErrEmptyPIN
	}

	// Derive input key material from the PIN using SHA-256.
	pinHash := sha256.Sum256([]byte(pin))
	defer ucrypto.ZeroizeArray32(&pinHash)

	// Use HKDF-SHA256 to derive the master key.
	kdf := hkdf.New(sha256.New, pinHash[:], secret[:], []byte(masterKeyInfo))
	if _, err := io.ReadFull(kdf, result[:]); err != nil {
		return result, &Error{kind: errHKDFExpansion, cause: err}
	}

	return result, nil
}

// MasterKeyGuarded derives a master key from a PIN and SVR secret using
// HKDF-SHA256, returning the result in guarded memory. The caller must call
// Destroy() on the returned secret when it is no longer needed.
func MasterKeyGuarded(pin string, svrSecret Secret) (*cryptosecret.Secret, error) {
	raw, err := MasterKey(pin, svrSecret)
	if err != nil {
		return nil, err
	}
	defer ucrypto.ZeroizeArray32(&raw)
	s, serr := cryptosecret.New(raw[:])
	if serr != nil {
		return nil, &Error{kind: errBadData, cause: serr}
	}
	return s, nil
}

// EncryptSecret encrypts a secret using AES-256-GCM-SIV with a zero nonce.
// The key is expected to be a one-time derived key, making nonce reuse safe
// due to the misuse-resistance property of GCM-SIV.
func EncryptSecret(key [32]byte, secret Secret) ([]byte, error) {
	aead, err := cipher.NewAESGCMSIV(key[:])
	if err != nil {
		return nil, &Error{kind: errCipherCreate, cause: err}
	}

	nonce := make([]byte, aead.NonceSize()) // zero nonce: SVR uses a unique key per encryption, so a fixed nonce is safe
	ciphertext := aead.Seal(nil, nonce, secret[:], nil) // #nosec G407 -- zero nonce is intentional: each key is used exactly once

	return ciphertext, nil
}

// DecryptSecret decrypts a secret using AES-256-GCM-SIV with a zero nonce.
// Returns an error if the ciphertext is invalid or authentication fails.
func DecryptSecret(key [32]byte, encrypted []byte) (Secret, error) {
	var result Secret

	aead, err := cipher.NewAESGCMSIV(key[:])
	if err != nil {
		return result, &Error{kind: errCipherCreate, cause: err}
	}

	nonce := make([]byte, aead.NonceSize()) // zero nonce
	plaintext, err := aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return result, &Error{kind: errDecryption, cause: err}
	}
	defer ucrypto.Zeroize(plaintext)

	if len(plaintext) != secretSize {
		return result, &Error{
			kind:   errSecretSize,
			detail: fmt.Sprintf("got %d, want %d", len(plaintext), secretSize),
		}
	}

	copy(result[:], plaintext)
	return result, nil
}

// DeriveStorageKey derives a storage key for SVR operations from a master
// secret using HKDF-SHA256 with the info string "20231003_Signal_SVR_StorageKey".
func DeriveStorageKey(masterSecret []byte) ([32]byte, error) {
	var result [32]byte

	if len(masterSecret) == 0 {
		return result, &Error{kind: errBadData}
	}

	kdf := hkdf.New(sha256.New, masterSecret, nil, []byte(storageKeyInfo))
	if _, err := io.ReadFull(kdf, result[:]); err != nil {
		return result, &Error{kind: errHKDFExpansion, cause: err}
	}

	return result, nil
}
