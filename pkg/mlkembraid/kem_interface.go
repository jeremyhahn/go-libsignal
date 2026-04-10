package mlkembraid

import (
	"crypto/subtle"

	"github.com/jeremyhahn/go-libsignal/pkg/kem"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"golang.org/x/crypto/sha3"
)

// IncrementalKEM defines the interface for an incremental KEM supporting the
// SCKA protocol per spec Section 1.2.
//
// The standard KEM encapsulation key is split into:
//   - ek_seed: first 32 bytes (the seed)
//   - ek_vector: remaining bytes (the noisy vector)
//
// The standard ciphertext is split into:
//   - ct1: first CT1Size bytes
//   - ct2: remaining CT2Size bytes (reconciliation message)
type IncrementalKEM interface {
	// KeyGen creates a new KEM key pair. Returns the decapsulation key,
	// the 32-byte ek_seed, and the ek_vector (remaining encapsulation key bytes).
	KeyGen() (dk []byte, ekSeed []byte, ekVector []byte, err error)

	// Encaps1 performs the first phase of encapsulation using just the ek_seed
	// and the hash of the full encapsulation key (hek). Returns an opaque
	// encaps_secret for completing encapsulation, the first ciphertext ct1,
	// and the shared secret.
	Encaps1(ekSeed []byte, hek []byte) (encapsSecret []byte, ct1 []byte, sharedSecret []byte, err error)

	// Encaps2 completes encapsulation using the encaps_secret from Encaps1
	// and the full encapsulation key components. Returns the reconciliation
	// ciphertext ct2.
	Encaps2(encapsSecret []byte, ekSeed []byte, ekVector []byte) (ct2 []byte, err error)

	// Decaps recovers the shared secret from the complete ciphertext (ct1 || ct2)
	// using the decapsulation key.
	Decaps(dk []byte, ct1 []byte, ct2 []byte) (sharedSecret []byte, err error)

	// EKSize returns the ek_vector size (without ek_seed).
	EKSize() int

	// CT1Size returns the first ciphertext size.
	CT1Size() int

	// CT2Size returns the second ciphertext (reconciliation) size.
	CT2Size() int

	// HeaderSize returns the header size: ek_seed(32) || hek(32).
	HeaderSize() int
}

// MLKEM768IncrementalKEM implements IncrementalKEM by wrapping the standard
// ML-KEM-768 KEM and splitting keys/ciphertexts per the spec.
type MLKEM768IncrementalKEM struct {
	inner kem.KEM
}

// NewMLKEM768IncrementalKEM creates a new incremental KEM backed by ML-KEM-768.
func NewMLKEM768IncrementalKEM() *MLKEM768IncrementalKEM {
	return &MLKEM768IncrementalKEM{
		inner: kem.NewMLKEM768KEM(),
	}
}

// KeyGen creates an ML-KEM-768 key pair and splits the encapsulation key into
// ek_seed (first 32 bytes) and ek_vector (remaining bytes).
func (k *MLKEM768IncrementalKEM) KeyGen() ([]byte, []byte, []byte, error) {
	kp, err := k.inner.Generate()
	if err != nil {
		return nil, nil, nil, &ErrKEMOperation{Op: "KeyGen", Err: err}
	}

	// Get raw public key data (without type prefix).
	ekFull := kp.Public.Data()
	if len(ekFull) < EKSeedSize {
		return nil, nil, nil, &ErrKEMOperation{Op: "KeyGen", Err: &ErrInvalidInput{
			Field:  "ekFull",
			Reason: "encapsulation key too short to split into seed and vector",
		}}
	}

	ekSeed := make([]byte, EKSeedSize)
	copy(ekSeed, ekFull[:EKSeedSize])

	ekVector := make([]byte, len(ekFull)-EKSeedSize)
	copy(ekVector, ekFull[EKSeedSize:])

	dk := kp.Secret.Data()

	return dk, ekSeed, ekVector, nil
}

// Header builds a header from ek_seed and ek_vector per spec Section 1.2.1:
// header = ek_seed(32) || SHA3-256(ek_seed || ek_vector)(32)
func Header(ekSeed, ekVector []byte) []byte {
	hek := computeHEK(ekSeed, ekVector)
	header := make([]byte, HeaderSize)
	copy(header[:EKSeedSize], ekSeed)
	copy(header[EKSeedSize:], hek)
	return header
}

// computeHEK computes hek = SHA3-256(ek_seed || ek_vector).
func computeHEK(ekSeed, ekVector []byte) []byte {
	h := sha3.New256()
	h.Write(ekSeed)
	h.Write(ekVector)
	return h.Sum(nil)
}

// Encaps1 performs the first phase of two-phase incremental encapsulation.
//
// Since the standard ML-KEM-768 API (circl/mlkem768) does not expose split
// encapsulation internals (ct1 requires the A matrix from ek_seed, but ct2
// requires the t vector from ek_vector), the actual cryptographic encapsulation
// is deferred to Encaps2. Encaps1 captures ek_seed and hek into an opaque
// encapsSecret token and returns nil for ct1 and sharedSecret.
//
// The state machine uses this to transition Bob into a "pending encapsulation"
// state at the spec-correct time (HeaderReceived.Send), with the actual crypto
// completing when ek_vector arrives via Encaps2.
//
// Per spec Section 1.2: Encaps1(ek_seed, hek) -> (encaps_secret, ct1, shared_secret).
// Our implementation: encaps_secret = ek_seed(32) || hek(32), ct1 = nil, shared_secret = nil.
func (k *MLKEM768IncrementalKEM) Encaps1(ekSeed []byte, hek []byte) ([]byte, []byte, []byte, error) {
	if len(ekSeed) != EKSeedSize {
		return nil, nil, nil, &ErrInvalidInput{Field: "ekSeed", Reason: "must be 32 bytes"}
	}
	if len(hek) != 32 {
		return nil, nil, nil, &ErrInvalidInput{Field: "hek", Reason: "must be 32 bytes"}
	}

	// Bundle ek_seed and hek into encapsSecret for Encaps2.
	encapsSecret := make([]byte, EKSeedSize+32)
	copy(encapsSecret[:EKSeedSize], ekSeed)
	copy(encapsSecret[EKSeedSize:], hek)

	return encapsSecret, nil, nil, nil
}

// FullEncaps performs a complete encapsulation when both ek_seed and ek_vector
// are available. Returns ct1, ct2, and shared_secret.
func (k *MLKEM768IncrementalKEM) FullEncaps(ekSeed, ekVector []byte) ([]byte, []byte, []byte, error) {
	if len(ekSeed) != EKSeedSize {
		return nil, nil, nil, &ErrInvalidInput{Field: "ekSeed", Reason: "must be 32 bytes"}
	}
	if len(ekVector) == 0 {
		return nil, nil, nil, &ErrInvalidInput{Field: "ekVector", Reason: "must not be empty"}
	}

	// Reconstruct full public key and encapsulate.
	fullEK := make([]byte, len(ekSeed)+len(ekVector))
	copy(fullEK, ekSeed)
	copy(fullEK[len(ekSeed):], ekVector)

	pk := kem.NewPublicKey(kem.KeyTypeKyber768, fullEK)

	ss, ct, err := k.inner.Encapsulate(pk)
	if err != nil {
		return nil, nil, nil, &ErrKEMOperation{Op: "FullEncaps", Err: err}
	}

	ctRaw := ct.Data()
	if len(ctRaw) != MLKEM768FullCTSize {
		return nil, nil, nil, &ErrKEMOperation{Op: "FullEncaps", Err: &ErrInvalidInput{
			Field:  "ciphertext",
			Reason: "unexpected ciphertext size",
		}}
	}

	ct1 := make([]byte, MLKEM768CT1Size)
	copy(ct1, ctRaw[:MLKEM768CT1Size])

	ct2 := make([]byte, MLKEM768CT2Size)
	copy(ct2, ctRaw[MLKEM768CT1Size:])

	sharedSecret := make([]byte, 32)
	copy(sharedSecret, ss[:])

	crypto.Zeroize(fullEK)
	return ct1, ct2, sharedSecret, nil
}

// Encaps2 completes the second phase of two-phase incremental encapsulation.
//
// Given the encapsSecret from Encaps1 (containing ek_seed || hek) and the
// full key components (ekSeed, ekVector), it verifies the hek matches, then
// performs a full ML-KEM-768 encapsulation.
//
// Per spec Section 1.2: Encaps2(encaps_secret, ek_seed, ek_vector) -> ct2.
// This method returns only ct2, matching the interface contract. The ct1 and
// sharedSecret produced internally are discarded. Use CompleteEncaps2 instead
// when all three outputs are needed (which is the case for the state machine).
//
// NOTE: In practice, the state machine always calls CompleteEncaps2 directly
// (via bobCompleteEncapsulation) to obtain ct1, ct2, and sharedSecret
// together. This interface method exists for spec completeness but is not
// used in the main protocol flow.
func (k *MLKEM768IncrementalKEM) Encaps2(encapsSecret []byte, ekSeed []byte, ekVector []byte) ([]byte, error) {
	if len(encapsSecret) != EKSeedSize+32 {
		return nil, &ErrKEMOperation{Op: "Encaps2", Err: &ErrInvalidInput{
			Field:  "encapsSecret",
			Reason: "must be 64 bytes (ek_seed || hek from Encaps1)",
		}}
	}
	if len(ekSeed) != EKSeedSize {
		return nil, &ErrKEMOperation{Op: "Encaps2", Err: &ErrInvalidInput{
			Field:  "ekSeed",
			Reason: "must be 32 bytes",
		}}
	}
	if len(ekVector) == 0 {
		return nil, &ErrKEMOperation{Op: "Encaps2", Err: &ErrInvalidInput{
			Field:  "ekVector",
			Reason: "must not be empty",
		}}
	}

	// Extract stored hek from encapsSecret and verify against actual ek_vector.
	storedHek := encapsSecret[EKSeedSize:]
	computedHek := computeHEK(ekSeed, ekVector)
	if subtle.ConstantTimeCompare(storedHek, computedHek) != 1 {
		return nil, &ErrHeaderFormat{Reason: "hek from Encaps1 does not match ek_vector in Encaps2"}
	}

	// Perform the full encapsulation now that we have all inputs.
	_, ct2, _, err := k.FullEncaps(ekSeed, ekVector)
	if err != nil {
		return nil, &ErrKEMOperation{Op: "Encaps2", Err: err}
	}

	// The interface only returns ct2. Use CompleteEncaps2 for the full result.
	return ct2, nil
}

// CompleteEncaps2 performs the second phase of two-phase incremental encapsulation
// and returns all outputs: ct1, ct2, and sharedSecret.
//
// This is the practical API used by the state machine, since the crypto for both
// ct1 and sharedSecret is deferred from Encaps1 due to ML-KEM-768 requiring
// the full encapsulation key.
func (k *MLKEM768IncrementalKEM) CompleteEncaps2(encapsSecret []byte, ekSeed []byte, ekVector []byte) ([]byte, []byte, []byte, error) {
	if len(encapsSecret) != EKSeedSize+32 {
		return nil, nil, nil, &ErrKEMOperation{Op: "CompleteEncaps2", Err: &ErrInvalidInput{
			Field:  "encapsSecret",
			Reason: "must be 64 bytes (ek_seed || hek from Encaps1)",
		}}
	}
	if len(ekSeed) != EKSeedSize {
		return nil, nil, nil, &ErrKEMOperation{Op: "CompleteEncaps2", Err: &ErrInvalidInput{
			Field:  "ekSeed",
			Reason: "must be 32 bytes",
		}}
	}
	if len(ekVector) == 0 {
		return nil, nil, nil, &ErrKEMOperation{Op: "CompleteEncaps2", Err: &ErrInvalidInput{
			Field:  "ekVector",
			Reason: "must not be empty",
		}}
	}

	// Extract stored hek from encapsSecret and verify against actual ek_vector.
	storedHek := encapsSecret[EKSeedSize:]
	computedHek := computeHEK(ekSeed, ekVector)
	if subtle.ConstantTimeCompare(storedHek, computedHek) != 1 {
		return nil, nil, nil, &ErrHeaderFormat{Reason: "hek from Encaps1 does not match ek_vector in CompleteEncaps2"}
	}

	// Perform the deferred full encapsulation.
	ct1, ct2, ss, err := k.FullEncaps(ekSeed, ekVector)
	if err != nil {
		return nil, nil, nil, &ErrKEMOperation{Op: "CompleteEncaps2", Err: err}
	}

	return ct1, ct2, ss, nil
}

// Decaps recovers the shared secret from the split ciphertext (ct1, ct2) using
// the decapsulation key. The two parts are concatenated to form the full ciphertext.
func (k *MLKEM768IncrementalKEM) Decaps(dk []byte, ct1 []byte, ct2 []byte) ([]byte, error) {
	if len(dk) == 0 {
		return nil, &ErrInvalidInput{Field: "dk", Reason: "must not be empty"}
	}
	if len(ct1) != MLKEM768CT1Size {
		return nil, &ErrInvalidInput{Field: "ct1", Reason: "wrong size"}
	}
	if len(ct2) != MLKEM768CT2Size {
		return nil, &ErrInvalidInput{Field: "ct2", Reason: "wrong size"}
	}

	// Reconstruct full ciphertext.
	fullCT := make([]byte, MLKEM768FullCTSize)
	copy(fullCT, ct1)
	copy(fullCT[MLKEM768CT1Size:], ct2)

	sk, skErr := kem.NewSecretKey(kem.KeyTypeKyber768, dk)
	if skErr != nil {
		return nil, &ErrKEMOperation{Op: "NewSecretKey", Err: skErr}
	}
	ciphertext := kem.NewCiphertext(kem.KeyTypeKyber768, fullCT)

	ss, err := k.inner.Decapsulate(sk, ciphertext)
	if err != nil {
		return nil, &ErrKEMOperation{Op: "Decaps", Err: err}
	}

	result := make([]byte, 32)
	copy(result, ss[:])
	crypto.Zeroize(fullCT)
	return result, nil
}

// EKSize returns the ek_vector size for ML-KEM-768 (without ek_seed).
func (k *MLKEM768IncrementalKEM) EKSize() int {
	return MLKEM768EKSize
}

// CT1Size returns the first ciphertext size for ML-KEM-768.
func (k *MLKEM768IncrementalKEM) CT1Size() int {
	return MLKEM768CT1Size
}

// CT2Size returns the second ciphertext (reconciliation) size for ML-KEM-768.
func (k *MLKEM768IncrementalKEM) CT2Size() int {
	return MLKEM768CT2Size
}

// HeaderSize returns the header size: ek_seed(32) || hek(32) = 64.
func (k *MLKEM768IncrementalKEM) HeaderSize() int {
	return HeaderSize
}
