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

// HybridKeys holds CipherKey (32), MacKey (32) and IV (16) as locked-memory Secrets; destroy them after use.
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

// KDFHybrid derives CipherKey || MacKey || IV (80 bytes) by HKDF-SHA256 with pqMK as salt, ecMK as IKM and info "WhisperMessageKeys".
func KDFHybrid(ecMK, pqMK *secret.Secret) (*HybridKeys, error) {
	if ecMK == nil || ecMK.IsDestroyed() {
		return nil, &ErrInvalidInput{Field: "ecMK", Reason: "must not be nil or destroyed"}
	}
	if pqMK == nil || pqMK.IsDestroyed() {
		return nil, &ErrInvalidInput{Field: "pqMK", Reason: "must not be nil or destroyed"}
	}

	var output []byte
	err := ecMK.WithBytes(func(ec []byte) error {
		return pqMK.WithBytes(func(pq []byte) error {
			var deriveErr error
			output, deriveErr = kdf.DeriveSecrets(ec, pq, []byte(kdfInfoHybrid), HybridKeySize)
			return deriveErr
		})
	})
	if err != nil { // coverage-exempt: DeriveSecrets only fails when outputLen > HKDF max (8160); HybridKeySize=80 is well below that
		return nil, &ErrHybridKDFFailed{Cause: err}
	}

	return splitHybridOutput(output)
}

// KDFHybridECOnly derives HybridKeys from ecMK alone with a zero salt, before SPQR has a PQ key.
func KDFHybridECOnly(ecMK *secret.Secret) (*HybridKeys, error) {
	if ecMK == nil || ecMK.IsDestroyed() {
		return nil, &ErrInvalidInput{Field: "ecMK", Reason: "must not be nil or destroyed"}
	}

	salt := make([]byte, 32)
	var output []byte
	err := ecMK.WithBytes(func(ec []byte) error {
		var deriveErr error
		output, deriveErr = kdf.DeriveSecrets(ec, salt, []byte(kdfInfoHybrid), HybridKeySize)
		return deriveErr
	})
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
	if err != nil { // coverage-exempt: only reachable on locked-memory allocation failure
		return nil, &ErrHybridKDFFailed{Cause: err}
	}
	defer raw.Destroy()

	// Each part is copied out of the read-only view into its own slice, which
	// secret.New wipes as it moves the part into locked memory.
	var ck, mk, iv *secret.Secret
	err = raw.WithBytes(func(rawBytes []byte) error {
		var newErr error
		ckBytes := make([]byte, cipherKeySize)
		copy(ckBytes, rawBytes[:cipherKeySize])
		if ck, newErr = secret.New(ckBytes); newErr != nil { // coverage-exempt: only reachable on locked-memory allocation failure
			return newErr
		}
		mkBytes := make([]byte, macKeySize)
		copy(mkBytes, rawBytes[cipherKeySize:cipherKeySize+macKeySize])
		if mk, newErr = secret.New(mkBytes); newErr != nil { // coverage-exempt: only reachable on locked-memory allocation failure
			return newErr
		}
		ivBytes := make([]byte, ivSize)
		copy(ivBytes, rawBytes[cipherKeySize+macKeySize:])
		iv, newErr = secret.New(ivBytes)
		return newErr
	})
	if err != nil { // coverage-exempt: only reachable on locked-memory allocation failure
		ck.Destroy()
		mk.Destroy()
		iv.Destroy()
		return nil, &ErrHybridKDFFailed{Cause: err}
	}

	return &HybridKeys{
		CipherKey: ck,
		MacKey:    mk,
		IV:        iv,
	}, nil
}
