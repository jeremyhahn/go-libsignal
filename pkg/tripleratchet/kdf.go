package tripleratchet

import (
	"github.com/jeremyhahn/go-libsignal/pkg/kdf"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

const (
	// TripleRatchetInfo is the HKDF info string for hybrid EC+PQ key derivation.
	// Matches the Rust reference implementation which uses "WhisperMessageKeys"
	// for both hybrid and EC-only paths.
	TripleRatchetInfo = "WhisperMessageKeys"

	// TripleRatchetECOnlyInfo is the HKDF info string for EC-only fallback
	// when the SPQR has not yet produced a key for the current epoch.
	// The Rust reference uses the same info string regardless of whether
	// a PQ key is present; the paths differ only in the salt value.
	TripleRatchetECOnlyInfo = "WhisperMessageKeys"

	// HybridKeySize is the total output length of the hybrid KDF:
	// CipherKey(32) + MacKey(32) + IV(16) = 80 bytes.
	HybridKeySize = 80

	// CipherKeySize is the size of the AES cipher key in bytes.
	CipherKeySize = 32

	// MacKeySize is the size of the MAC key in bytes.
	MacKeySize = 32

	// IVSize is the size of the initialization vector in bytes.
	IVSize = 16
)

// zeroSalt returns a fresh 32-byte zero slice for use as HKDF salt.
// A function is used instead of a package-level variable to prevent
// accidental mutation of shared state.
func zeroSalt() []byte {
	return make([]byte, 32)
}

// HybridKeys holds the combined EC+PQ derived keys used for encrypting
// and authenticating a single message. All fields are backed by memguard
// protected memory.
type HybridKeys struct {
	CipherKey *secret.Secret // 32 bytes - AES-256 encryption key
	MacKey    *secret.Secret // 32 bytes - HMAC authentication key
	IV        *secret.Secret // 16 bytes - initialization vector
}

// Zeroize destroys all guarded key material. This method is idempotent
// and safe to call multiple times.
func (hk *HybridKeys) Zeroize() {
	if hk == nil {
		return
	}
	if hk.CipherKey != nil {
		hk.CipherKey.Destroy()
	}
	if hk.MacKey != nil {
		hk.MacKey.Destroy()
	}
	if hk.IV != nil {
		hk.IV.Destroy()
	}
}

// KDFHybrid combines an EC message key and a PQ message key using HKDF-SHA256
// to produce the final encryption keys. The PQ key is used as the salt and
// the EC key as the input key material, ensuring both contribute to the output.
//
// Output: HKDF(salt=pqMK, ikm=ecMK, info="WhisperMessageKeys", length=80)
// Split: CipherKey(32) || MacKey(32) || IV(16)
func KDFHybrid(ecMK, pqMK []byte) (*HybridKeys, error) {
	if len(ecMK) == 0 {
		return nil, &ErrInvalidInput{Field: "ecMK", Reason: "must not be empty"}
	}
	if len(pqMK) == 0 {
		return nil, &ErrInvalidInput{Field: "pqMK", Reason: "must not be empty"}
	}

	output, err := kdf.DeriveSecrets(ecMK, pqMK, []byte(TripleRatchetInfo), HybridKeySize)
	if err != nil {
		return nil, &ErrHybridKDFFailed{Err: err}
	}

	keys, splitErr := splitHybridOutput(output)
	// Zeroize the raw HKDF output regardless of split outcome.
	for i := range output {
		output[i] = 0
	}
	if splitErr != nil {
		return nil, splitErr
	}

	return keys, nil
}

// KDFHybridECOnly derives encryption keys from only the EC message key,
// using a zero salt. This is the fallback path when the SPQR has not yet
// produced a PQ key for the current epoch.
//
// Output: HKDF(salt=zeros(32), ikm=ecMK, info="WhisperMessageKeys", length=80)
// Split: CipherKey(32) || MacKey(32) || IV(16)
func KDFHybridECOnly(ecMK []byte) (*HybridKeys, error) {
	if len(ecMK) == 0 {
		return nil, &ErrInvalidInput{Field: "ecMK", Reason: "must not be empty"}
	}

	output, err := kdf.DeriveSecrets(ecMK, zeroSalt(), []byte(TripleRatchetECOnlyInfo), HybridKeySize)
	if err != nil {
		return nil, &ErrHybridKDFFailed{Err: err}
	}

	keys, splitErr := splitHybridOutput(output)
	// Zeroize the raw HKDF output regardless of split outcome.
	for i := range output {
		output[i] = 0
	}
	if splitErr != nil {
		return nil, splitErr
	}

	return keys, nil
}

// splitHybridOutput splits an 80-byte HKDF output into CipherKey, MacKey, and IV,
// creating each as a memguard-backed Secret. The caller must zeroize the raw
// output after this function returns.
func splitHybridOutput(output []byte) (*HybridKeys, error) {
	cipherKeyBytes := make([]byte, CipherKeySize)
	copy(cipherKeyBytes, output[:CipherKeySize])

	macKeyBytes := make([]byte, MacKeySize)
	copy(macKeyBytes, output[CipherKeySize:CipherKeySize+MacKeySize])

	ivBytes := make([]byte, IVSize)
	copy(ivBytes, output[CipherKeySize+MacKeySize:])

	cipherKey, err := secret.New(cipherKeyBytes)
	if err != nil {
		return nil, &ErrHybridKDFFailed{Err: err}
	}

	macKey, err := secret.New(macKeyBytes)
	if err != nil {
		cipherKey.Destroy()
		return nil, &ErrHybridKDFFailed{Err: err}
	}

	iv, err := secret.New(ivBytes)
	if err != nil {
		cipherKey.Destroy()
		macKey.Destroy()
		return nil, &ErrHybridKDFFailed{Err: err}
	}

	return &HybridKeys{
		CipherKey: cipherKey,
		MacKey:    macKey,
		IV:        iv,
	}, nil
}
