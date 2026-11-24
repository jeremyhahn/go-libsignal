// Package svr implements Secure Value Recovery v4: PIN-protected backup and restore of secrets with server-side rate limiting, master key derivation and AES-256-GCM-SIV encryption.
package svr

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
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

// Serialize encodes tries_remaining as a big-endian uint32 followed by the 32-byte value, as Rust does.
func (er *EvaluationResult) Serialize() []byte {
	out := make([]byte, 4+secretSize)
	binary.BigEndian.PutUint32(out[:4], er.TriesRemaining)
	copy(out[4:], er.Value[:])
	return out
}

// Backup4 represents a v4 SVR backup request. Both secret-bearing fields are
// held in guarded memory for the lifetime of the request: the entropy seeds the
// backup's key derivation, and Secret is the value being backed up.
type Backup4 struct {
	RequestID []byte
	Entropy   *cryptosecret.Secret // 32 bytes random
	Secret    *cryptosecret.Secret32
	MaxTries  uint32
}

// Destroy releases the guarded entropy and backup secret. It is idempotent and
// safe to call on a Backup4 that carries neither.
func (b *Backup4) Destroy() {
	b.Entropy.Destroy()
	b.Secret.Destroy()
}

// NewBackup4 creates a v4 backup request for secret with maxTries PIN attempts; secret is copied into guarded memory, so zeroize your copy.
func NewBackup4(secret Secret, maxTries uint32) (*Backup4, error) {
	if maxTries == 0 {
		return nil, &Error{kind: errBadData}
	}

	// Generate the entropy directly into guarded memory so that it never
	// exists on the Go heap.
	entropy, err := cryptosecret.NewRandom(entropySize)
	if err != nil {
		return nil, &Error{kind: errBadData, cause: err}
	}

	// Move the secret into guarded memory, zeroizing this copy; Zeroize covers allocation failure.
	guardedSecret, sErr := cryptosecret.NewSecret32FromSlice(secret[:])
	ucrypto.Zeroize(secret[:])
	if sErr != nil {
		entropy.Destroy()
		return nil, &Error{kind: errBadData, cause: sErr}
	}

	requestID := make([]byte, requestIDSize)
	if _, rErr := io.ReadFull(rand.Reader, requestID); rErr != nil {
		entropy.Destroy()
		guardedSecret.Destroy()
		return nil, &Error{kind: errBadData, cause: rErr}
	}

	return &Backup4{
		RequestID: requestID,
		Entropy:   entropy,
		Secret:    guardedSecret,
		MaxTries:  maxTries,
	}, nil
}

// Restore4 represents a v4 SVR restore request. As with Backup4, the entropy
// is held in guarded memory.
type Restore4 struct {
	RequestID []byte
	Entropy   *cryptosecret.Secret
}

// Destroy releases the guarded entropy. It is idempotent and safe to call on a
// Restore4 that carries no entropy.
func (r *Restore4) Destroy() {
	r.Entropy.Destroy()
}

// EncryptSecret encrypts a secret using AES-256-GCM-SIV with a zero nonce.
// The key is expected to be a one-time derived key, making nonce reuse safe
// due to the misuse-resistance property of GCM-SIV.
func EncryptSecret(key [32]byte, secret Secret) ([]byte, error) {
	aead, err := cipher.NewAESGCMSIV(key[:])
	if err != nil {
		return nil, &Error{kind: errCipherCreate, cause: err}
	}

	nonce := make([]byte, aead.NonceSize())             // zero nonce: SVR uses a unique key per encryption, so a fixed nonce is safe
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

// MasterKey derives a key by HKDF-SHA256 with SHA-256(pin) as IKM, secret as salt and info "20221003_Signal_SVR_MasterKey"; zeroize the result, or use MasterKeyGuarded.
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

// MasterKeyGuarded derives the MasterKey value in guarded memory; the caller destroys it.
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
