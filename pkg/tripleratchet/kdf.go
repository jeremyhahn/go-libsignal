package tripleratchet

import (
	"github.com/jeremyhahn/go-libsignal/pkg/kdf"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

const (
	// kdfInfoHybrid is the HKDF info string for hybrid key derivation.
	// Matches the Rust reference: "WhisperMessageKeys" used in
	// ratchet/keys.rs and confirmed by the triple ratchet hybrid path.
	kdfInfoHybrid = "WhisperMessageKeys"

	// HybridKeySize is the total output length: CipherKey(32) + MacKey(32) + IV(16).
	HybridKeySize = 80

	// HMACSize is the HMAC-SHA256 tag size.
	HMACSize = 32

	cipherKeySize = 32
	macKeySize    = 32
	ivSize        = 16
)

// HybridKeys holds the output of KDFHybrid or KDFHybridECOnly.
// All fields are memguard-backed Secrets and must be destroyed after use.
//
// CipherKey: 32 bytes, AES-256 encryption key.
// MacKey:    32 bytes, HMAC-SHA256 key.
// IV:        16 bytes, AES initialization vector.
type HybridKeys struct {
	CipherKey *secret.Secret
	MacKey    *secret.Secret
	IV        *secret.Secret
}

// Zeroize destroys all key material in the HybridKeys.
func (h *HybridKeys) Zeroize() {
	if h.CipherKey != nil {
		h.CipherKey.Destroy()
	}
	if h.MacKey != nil {
		h.MacKey.Destroy()
	}
	if h.IV != nil {
		h.IV.Destroy()
	}
}

// KDFHybrid combines an EC message key and a PQ message key into hybrid keys
// using HKDF-SHA256.
//
// HKDF parameters:
//   - salt:   pqMK (32 bytes) — the PQ message key
//   - ikm:    ecMK           — the EC message key
//   - info:   "WhisperMessageKeys"
//   - length: 80 bytes
//
// Output split: CipherKey(32) || MacKey(32) || IV(16)
//
// The PQ key is the HKDF salt and the EC key is the IKM, so both contribute
// to the output. Matches the Rust reference hybrid KDF path.
func KDFHybrid(ecMK, pqMK *secret.Secret) (*HybridKeys, error) {
	if ecMK == nil || ecMK.IsDestroyed() {
		return nil, &ErrInvalidInput{Field: "ecMK", Reason: "must not be nil or destroyed"}
	}
	if pqMK == nil || pqMK.IsDestroyed() {
		return nil, &ErrInvalidInput{Field: "pqMK", Reason: "must not be nil or destroyed"}
	}

	output, err := kdf.DeriveSecrets(ecMK.Bytes(), pqMK.Bytes(), []byte(kdfInfoHybrid), HybridKeySize)
	if err != nil { // coverage-exempt: DeriveSecrets only fails when outputLen > HKDF max (8160); HybridKeySize=80 is well below that
		return nil, &ErrHybridKDFFailed{Cause: err}
	}

	return splitHybridOutput(output)
}

// KDFHybridECOnly derives hybrid keys using only the EC message key.
// Used before the SPQR has produced a PQ key (epoch 0, counter 0).
//
// HKDF parameters:
//   - salt:   zeros(32)
//   - ikm:    ecMK
//   - info:   "WhisperMessageKeys"
//   - length: 80 bytes
//
// Same output split as KDFHybrid. The Rust reference uses the same info string
// for both paths; only the salt differs.
func KDFHybridECOnly(ecMK *secret.Secret) (*HybridKeys, error) {
	if ecMK == nil || ecMK.IsDestroyed() {
		return nil, &ErrInvalidInput{Field: "ecMK", Reason: "must not be nil or destroyed"}
	}

	salt := make([]byte, 32)
	output, err := kdf.DeriveSecrets(ecMK.Bytes(), salt, []byte(kdfInfoHybrid), HybridKeySize)
	if err != nil { // coverage-exempt: DeriveSecrets only fails when outputLen > HKDF max (8160); HybridKeySize=80 is well below that
		return nil, &ErrHybridKDFFailed{Cause: err}
	}

	return splitHybridOutput(output)
}

// splitHybridOutput splits an 80-byte HKDF output into CipherKey(32), MacKey(32), IV(16).
func splitHybridOutput(output []byte) (*HybridKeys, error) {
	if len(output) < HybridKeySize {
		return nil, &ErrHybridKDFFailed{Cause: &ErrInvalidInput{
			Field:  "output",
			Reason: "output too short",
		}}
	}

	// Wrap the raw output so it is zeroized when we finish splitting.
	raw, err := secret.New(output)
	if err != nil { // coverage-exempt: only reachable on memguard OOM
		return nil, &ErrHybridKDFFailed{Cause: err}
	}
	defer raw.Destroy()

	rawBytes := raw.Bytes()

	ckBytes := make([]byte, cipherKeySize)
	copy(ckBytes, rawBytes[:cipherKeySize])
	ck, err := secret.New(ckBytes)
	if err != nil { // coverage-exempt: only reachable on memguard OOM
		return nil, &ErrHybridKDFFailed{Cause: err}
	}

	mkBytes := make([]byte, macKeySize)
	copy(mkBytes, rawBytes[cipherKeySize:cipherKeySize+macKeySize])
	mk, err := secret.New(mkBytes)
	if err != nil { // coverage-exempt: only reachable on memguard OOM
		ck.Destroy()
		return nil, &ErrHybridKDFFailed{Cause: err}
	}

	ivBytes := make([]byte, ivSize)
	copy(ivBytes, rawBytes[cipherKeySize+macKeySize:])
	iv, err := secret.New(ivBytes)
	if err != nil { // coverage-exempt: only reachable on memguard OOM
		ck.Destroy()
		mk.Destroy()
		return nil, &ErrHybridKDFFailed{Cause: err}
	}

	return &HybridKeys{
		CipherKey: ck,
		MacKey:    mk,
		IV:        iv,
	}, nil
}
