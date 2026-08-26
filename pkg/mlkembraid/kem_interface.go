// Package mlkembraid implements the ML-KEM Braid SCKA protocol using the
// libcrux-compatible incremental ML-KEM-768 API.
//
// The preferred implementation is IncrementalMLKEM768KEM, which uses
// internal/incremental_mlkem768 for a wire-compatible port of the Rust SPQR
// incremental_mlkem768 module. The legacy MLKEM768IncrementalKEM is retained
// for backward compatibility but does not produce Rust-compatible wire bytes.
package mlkembraid

import (
	"crypto/rand"
	"crypto/sha3"
	"crypto/subtle"
	"hash"

	"github.com/jeremyhahn/go-libsignal/pkg/kem"
	imlkem "github.com/jeremyhahn/go-libsignal/pkg/mlkembraid/internal/incremental_mlkem768"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
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
	var h hash.Hash = sha3.New256()
	h.Write(ekSeed)
	h.Write(ekVector)
	return h.Sum(nil)
}

// Encaps1 performs the first phase of two-phase incremental encapsulation.
//
// Since the standard ML-KEM-768 API (crypto/mlkem) does not expose split
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

	pk := kem.NewPublicKey(kem.KeyTypeMLKEM768, fullEK)

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

	sk, skErr := kem.NewSecretKey(kem.KeyTypeMLKEM768, dk)
	if skErr != nil {
		return nil, &ErrKEMOperation{Op: "NewSecretKey", Err: skErr}
	}
	// kem.NewSecretKey holds the 64-byte ML-KEM-768 decapsulation-key seed in a
	// plain heap buffer. Bound it to this call rather than leaving it resident
	// until the GC happens to reclaim the page. Whole-lifetime locked-memory
	// storage is not reachable here: crypto/mlkem.NewDecapsulationKey768 takes a
	// []byte seed and expands it on its own heap, and that stdlib call is the
	// FIPS-validated primitive the protected-memory mandate yields to
	// (conventions/security-review.md, 2026-08-25). Bounding our copy is the
	// mitigation that boundary leaves available.
	defer sk.Zeroize()
	ciphertext := kem.NewCiphertext(kem.KeyTypeMLKEM768, fullCT)

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

// headerAwareKEM is an internal interface for KEMs that encode and parse the
// wire header differently from the legacy ek_seed(32) || SHA3-256(ek_seed||ek_vector)(32)
// layout. Implemented by IncrementalMLKEM768KEM, NOT by MLKEM768IncrementalKEM.
//
// State machine functions detect this interface to build and parse headers correctly
// so that both KEM types work end-to-end without changing the MLKEM768IncrementalKEM
// wire format.
type headerAwareKEM interface {
	// BuildHeader returns the complete wire header bytes from the given key material.
	// For IncrementalMLKEM768KEM this is simply pk1 (the header IS pk1).
	BuildHeader(ekSeed, ekVector []byte) []byte

	// EKSeedFromHeader extracts the full ek_seed from a received wire header.
	// For IncrementalMLKEM768KEM this is the full 64-byte pk1 (the header IS pk1).
	EKSeedFromHeader(header []byte) []byte
}

// kemCompleter is an internal interface for performing the deferred Bob-side
// full encapsulation. Both MLKEM768IncrementalKEM and IncrementalMLKEM768KEM
// implement it so that state.go's bobCompleteEncapsulationDeferred can
// accept either without a concrete type assertion.
type kemCompleter interface {
	// CompleteEncaps2 completes encapsulation given the opaque encapsSecret
	// from Encaps1 and the full key components. Returns ct1, ct2, ss.
	CompleteEncaps2(encapsSecret []byte, ekSeed []byte, ekVector []byte) ([]byte, []byte, []byte, error)

	// FullEncaps performs a complete single-step encapsulation when ek_seed
	// and ek_vector are both available. Returns ct1, ct2, ss.
	FullEncaps(ekSeed, ekVector []byte) ([]byte, []byte, []byte, error)
}

// IncrementalMLKEM768KEM implements IncrementalKEM using the pure-Go
// incremental ML-KEM-768 port (internal/incremental_mlkem768). It is
// wire-compatible with the Rust sparsepostquantumratchet crate's
// incremental_mlkem768 module.
//
// Key layout:
//   - ekSeed  (pk1, 64 bytes): seed_for_A(32) || H(ek)(32)
//   - ekVector (pk2, 1152 bytes): ByteEncode12(t_as_ntt)
//   - dk  (2400 bytes): compressed decapsulation key (libcrux format)
//
// Rust: sparsepostquantumratchet::incremental_mlkem768::generate / encaps1 / encaps2 / decaps
type IncrementalMLKEM768KEM struct{}

// NewIncrementalMLKEM768KEM creates a new KEM backed by the pure-Go
// incremental ML-KEM-768 implementation. This is the production-grade
// replacement for MLKEM768IncrementalKEM.
func NewIncrementalMLKEM768KEM() *IncrementalMLKEM768KEM {
	return &IncrementalMLKEM768KEM{}
}

// KeyGen generates a new incremental ML-KEM-768 key pair.
//
// Returns:
//   - dk:       2400-byte compressed decapsulation key
//   - ekSeed:   64-byte pk1 = seed_for_A(32) || H(ek)(32)
//   - ekVector: 1152-byte pk2 = ByteEncode12(t_as_ntt)
func (k *IncrementalMLKEM768KEM) KeyGen() (dk []byte, ekSeed []byte, ekVector []byte, err error) {
	pk1, pk2, dkArr, genErr := imlkem.GenerateKey()
	if genErr != nil {
		return nil, nil, nil, &ErrKEMOperation{Op: "IncrementalMLKEM768KEM.KeyGen", Err: genErr}
	}
	dkSlice := make([]byte, len(dkArr))
	copy(dkSlice, dkArr[:])
	return dkSlice, pk1[:], pk2[:], nil
}

// Encaps1 performs the first phase of incremental encapsulation.
//
// ekSeed is pk1 (64 bytes = seed_for_A || H(ek)).
// hek is redundant (pk1[32:64] already contains H(ek)) and is ignored.
//
// The returned encapsSecret is a 3072-byte packed blob: es(2080) || ct1(960) || ss(32).
// This packing allows state.go to store encapsSecret and recover all three values
// in CompleteEncaps2 without requiring additional state fields.
//
// Returns:
//   - encapsSecret: 3072-byte packed blob = es || ct1 || ss
//   - ct1:          960-byte first ciphertext (also embedded in encapsSecret)
//   - sharedSecret: 32-byte shared secret (also embedded in encapsSecret)
func (k *IncrementalMLKEM768KEM) Encaps1(ekSeed []byte, hek []byte) (encapsSecret []byte, ct1 []byte, sharedSecret []byte, err error) {
	if len(ekSeed) != imlkem.PublicKey1Size {
		return nil, nil, nil, &ErrInvalidInput{
			Field:  "ekSeed",
			Reason: "must be 64 bytes (pk1 = seed_for_A || H(ek))",
		}
	}

	var randomness [imlkem.SharedSecretSize]byte
	if _, err = rand.Read(randomness[:]); err != nil {
		return nil, nil, nil, &ErrKEMOperation{Op: "IncrementalMLKEM768KEM.Encaps1", Err: err}
	}

	ct1Arr, esArr, ssArr, encErr := imlkem.Encaps1(ekSeed, randomness)
	if encErr != nil {
		return nil, nil, nil, &ErrKEMOperation{Op: "IncrementalMLKEM768KEM.Encaps1", Err: encErr}
	}

	// Pack es || ct1 || ss into encapsSecret so CompleteEncaps2 can reconstruct them.
	packed := make([]byte, imlkem.EncapsStateSize+imlkem.Ciphertext1Size+imlkem.SharedSecretSize)
	copy(packed[:imlkem.EncapsStateSize], esArr[:])
	copy(packed[imlkem.EncapsStateSize:], ct1Arr[:])
	copy(packed[imlkem.EncapsStateSize+imlkem.Ciphertext1Size:], ssArr[:])

	ct1Slice := make([]byte, imlkem.Ciphertext1Size)
	copy(ct1Slice, ct1Arr[:])
	ssSlice := make([]byte, imlkem.SharedSecretSize)
	copy(ssSlice, ssArr[:])

	return packed, ct1Slice, ssSlice, nil
}

// Encaps2 returns ct2 for the interface contract. Use CompleteEncaps2 internally.
// encapsSecret is the 2080-byte EncapsulationState from Encaps1.
// ekSeed is pk1, ekVector is pk2.
func (k *IncrementalMLKEM768KEM) Encaps2(encapsSecret []byte, ekSeed []byte, ekVector []byte) ([]byte, error) {
	ct2Arr, err := imlkem.Encaps2(encapsSecret, ekVector)
	if err != nil {
		return nil, &ErrKEMOperation{Op: "IncrementalMLKEM768KEM.Encaps2", Err: err}
	}
	ct2 := make([]byte, len(ct2Arr))
	copy(ct2, ct2Arr[:])
	return ct2, nil
}

// CompleteEncaps2 completes encapsulation and returns ct1, ct2, and ss.
//
// In the real incremental implementation, ct1 and ss were already produced
// by Encaps1. The encapsSecret IS the 2080-byte EncapsulationState. ct1 is
// embedded in the state (it was returned by Encaps1 and stored separately).
//
// Since the state machine stores ct1 from Encaps1 in bobCt1, this method
// only needs to produce ct2 using Encaps2. However, to satisfy the
// kemCompleter interface which returns ct1, ct2, ss — and because the
// state machine in the two-phase path already has ct1 and ss from the
// Encaps1 call — we cannot easily reconstruct ct1 here without storing it.
//
// For this reason, the state machine (state.go) is updated to use the new
// three-output Encaps1 path directly, and CompleteEncaps2 is only called
// on the old MLKEM768IncrementalKEM path.
//
// In the new path (IncrementalMLKEM768KEM), sendHeaderReceived calls Encaps1
// which returns ct1 and ss immediately, so CompleteEncaps2 is not needed.
// This method is provided for kemCompleter compliance.
func (k *IncrementalMLKEM768KEM) CompleteEncaps2(encapsSecret []byte, ekSeed []byte, ekVector []byte) ([]byte, []byte, []byte, error) {
	// encapsSecret for IncrementalMLKEM768KEM is structured as:
	//   es (2080B) || ct1 (960B) || ss (32B)
	// This packing is done by the adapted sendHeaderReceived path.
	const esSize = imlkem.EncapsStateSize
	const ct1Size = imlkem.Ciphertext1Size
	const ssSize = imlkem.SharedSecretSize
	const packedSize = esSize + ct1Size + ssSize

	if len(encapsSecret) != packedSize {
		return nil, nil, nil, &ErrKEMOperation{Op: "IncrementalMLKEM768KEM.CompleteEncaps2", Err: &ErrInvalidInput{
			Field:  "encapsSecret",
			Reason: "must be 3072 bytes (es||ct1||ss)",
		}}
	}

	es := encapsSecret[:esSize]
	ct1 := make([]byte, ct1Size)
	copy(ct1, encapsSecret[esSize:esSize+ct1Size])
	ss := make([]byte, ssSize)
	copy(ss, encapsSecret[esSize+ct1Size:])

	ct2Arr, err := imlkem.Encaps2(es, ekVector)
	if err != nil {
		return nil, nil, nil, &ErrKEMOperation{Op: "IncrementalMLKEM768KEM.CompleteEncaps2", Err: err}
	}
	ct2 := make([]byte, len(ct2Arr))
	copy(ct2, ct2Arr[:])

	return ct1, ct2, ss, nil
}

// FullEncaps performs a complete single-step encapsulation using pk1 (ekSeed)
// and pk2 (ekVector). This is the path when Encaps1 was not called ahead of time.
//
// It generates fresh randomness internally and calls Encaps1 + Encaps2.
func (k *IncrementalMLKEM768KEM) FullEncaps(ekSeed, ekVector []byte) ([]byte, []byte, []byte, error) {
	if len(ekSeed) != imlkem.PublicKey1Size {
		return nil, nil, nil, &ErrInvalidInput{Field: "ekSeed", Reason: "must be 64 bytes"}
	}
	if len(ekVector) != imlkem.PublicKey2Size {
		return nil, nil, nil, &ErrInvalidInput{Field: "ekVector", Reason: "must be 1152 bytes"}
	}

	var randomness [imlkem.SharedSecretSize]byte
	if _, err := rand.Read(randomness[:]); err != nil {
		return nil, nil, nil, &ErrKEMOperation{Op: "IncrementalMLKEM768KEM.FullEncaps", Err: err}
	}

	ct1Arr, esArr, ssArr, err := imlkem.Encaps1(ekSeed, randomness)
	if err != nil {
		return nil, nil, nil, &ErrKEMOperation{Op: "IncrementalMLKEM768KEM.FullEncaps/Encaps1", Err: err}
	}

	ct2Arr, err := imlkem.Encaps2(esArr[:], ekVector)
	if err != nil {
		return nil, nil, nil, &ErrKEMOperation{Op: "IncrementalMLKEM768KEM.FullEncaps/Encaps2", Err: err}
	}

	ct1 := make([]byte, len(ct1Arr))
	copy(ct1, ct1Arr[:])
	ct2 := make([]byte, len(ct2Arr))
	copy(ct2, ct2Arr[:])
	ss := make([]byte, len(ssArr))
	copy(ss, ssArr[:])
	return ct1, ct2, ss, nil
}

// Decaps recovers the shared secret from ct1 and ct2 using the 2400-byte dk.
func (k *IncrementalMLKEM768KEM) Decaps(dk []byte, ct1 []byte, ct2 []byte) ([]byte, error) {
	ssArr, err := imlkem.Decaps(dk, ct1, ct2)
	if err != nil {
		return nil, &ErrKEMOperation{Op: "IncrementalMLKEM768KEM.Decaps", Err: err}
	}
	ss := make([]byte, len(ssArr))
	copy(ss, ssArr[:])
	return ss, nil
}

// EKSize returns the pk2 (ek_vector) size for incremental ML-KEM-768.
func (k *IncrementalMLKEM768KEM) EKSize() int {
	return imlkem.PublicKey2Size // 1152
}

// CT1Size returns the first ciphertext size for incremental ML-KEM-768.
func (k *IncrementalMLKEM768KEM) CT1Size() int {
	return imlkem.Ciphertext1Size // 960
}

// CT2Size returns the second ciphertext size for incremental ML-KEM-768.
func (k *IncrementalMLKEM768KEM) CT2Size() int {
	return imlkem.Ciphertext2Size // 128
}

// HeaderSize returns the header size = pk1 size = 64 bytes.
func (k *IncrementalMLKEM768KEM) HeaderSize() int {
	return imlkem.PublicKey1Size // 64
}

// BuildHeader returns the wire header for IncrementalMLKEM768KEM.
// The header is simply pk1 (seed_for_A(32) || H(ek)(32)); ekVector is not used
// in the header itself (it is transmitted separately as the ek_vector).
// Implements headerAwareKEM.
func (k *IncrementalMLKEM768KEM) BuildHeader(ekSeed, _ []byte) []byte {
	return IncrementalHeader(ekSeed)
}

// EKSeedFromHeader extracts pk1 from a received wire header.
// For IncrementalMLKEM768KEM the header IS pk1 so the entire header is returned.
// Implements headerAwareKEM.
func (k *IncrementalMLKEM768KEM) EKSeedFromHeader(header []byte) []byte {
	out := make([]byte, len(header))
	copy(out, header)
	return out
}

// IncrementalHeader builds a header from pk1 directly (it IS the header).
// For IncrementalMLKEM768KEM, ekSeed = pk1 = rho || H(ek), so the header
// is simply pk1. The ekVector is used to verify consistency via ValidatePKBytes.
//
// This replaces the legacy Header() function for the new KEM implementation.
func IncrementalHeader(pk1 []byte) []byte {
	h := make([]byte, len(pk1))
	copy(h, pk1)
	return h
}

// IncrementalVerifyEKVector verifies that pk2 (ekVector) is consistent with pk1 (ekSeed).
// It calls ValidatePKBytes which checks H(ek) and the modulus domain of pk2.
func IncrementalVerifyEKVector(pk1, pk2 []byte) error {
	return imlkem.ValidatePKBytes(pk1, pk2)
}
