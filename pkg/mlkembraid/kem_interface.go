// Package mlkembraid implements the ML-KEM Braid SCKA protocol; IncrementalMLKEM768KEM is Rust-wire-compatible, MLKEM768IncrementalKEM is not.
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

// IncrementalKEM is an incremental KEM for SCKA (spec §1.2): the key splits into ek_seed and ek_vector, the ciphertext into ct1 and ct2.
type IncrementalKEM interface {
	// KeyGen creates a new KEM key pair. Returns the decapsulation key,
	// the 32-byte ek_seed, and the ek_vector (remaining encapsulation key bytes).
	KeyGen() (dk []byte, ekSeed []byte, ekVector []byte, err error)

	// Encaps1 encapsulates from ek_seed and hek, returning encaps_secret, ct1 and the shared secret.
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
	// The caller gets its own copy of dk; wipe the key pair's copy.
	defer kp.Secret.Zeroize()

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

// Encaps1 stores ek_seed || hek as encapsSecret and defers the encapsulation to Encaps2, since crypto/mlkem cannot split it; ct1 and the secret are nil.
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

// Encaps2 checks hek and encapsulates, returning only ct2 (spec §1.2); the state machine uses CompleteEncaps2.
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

// CompleteEncaps2 checks hek, encapsulates and returns ct1, ct2 and the shared secret.
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
	// Bound the heap copy of the decapsulation seed to this call; crypto/mlkem expands it on its own heap.
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

// headerAwareKEM is implemented by KEMs whose wire header differs from the legacy ek_seed || SHA3-256 layout.
type headerAwareKEM interface {
	// BuildHeader returns the complete wire header bytes from the given key material.
	// For IncrementalMLKEM768KEM this is simply pk1 (the header IS pk1).
	BuildHeader(ekSeed, ekVector []byte) []byte

	// EKSeedFromHeader extracts the full ek_seed from a received wire header.
	// For IncrementalMLKEM768KEM this is the full 64-byte pk1 (the header IS pk1).
	EKSeedFromHeader(header []byte) []byte
}

// kemCompleter performs Bob's deferred encapsulation for either KEM type.
type kemCompleter interface {
	// CompleteEncaps2 completes encapsulation given the opaque encapsSecret
	// from Encaps1 and the full key components. Returns ct1, ct2, ss.
	CompleteEncaps2(encapsSecret []byte, ekSeed []byte, ekVector []byte) ([]byte, []byte, []byte, error)

	// FullEncaps performs a complete single-step encapsulation when ek_seed
	// and ek_vector are both available. Returns ct1, ct2, ss.
	FullEncaps(ekSeed, ekVector []byte) ([]byte, []byte, []byte, error)
}

// IncrementalMLKEM768KEM implements IncrementalKEM with internal/incremental_mlkem768, wire-compatible with Rust SPQR incremental_mlkem768.
type IncrementalMLKEM768KEM struct{}

// NewIncrementalMLKEM768KEM creates a new KEM backed by the pure-Go
// incremental ML-KEM-768 implementation. This is the production-grade
// replacement for MLKEM768IncrementalKEM.
func NewIncrementalMLKEM768KEM() *IncrementalMLKEM768KEM {
	return &IncrementalMLKEM768KEM{}
}

// KeyGen returns the 2400-byte dk, ekSeed (pk1, 64 bytes) and ekVector (pk2, 1152 bytes).
func (k *IncrementalMLKEM768KEM) KeyGen() (dk []byte, ekSeed []byte, ekVector []byte, err error) {
	pk1, pk2, dkArr, genErr := imlkem.GenerateKey()
	if genErr != nil {
		return nil, nil, nil, &ErrKEMOperation{Op: "IncrementalMLKEM768KEM.KeyGen", Err: genErr}
	}
	dkSlice := make([]byte, len(dkArr))
	copy(dkSlice, dkArr[:])
	return dkSlice, pk1[:], pk2[:], nil
}

// Encaps1 encapsulates from pk1, returning encapsSecret = es || ct1 || ss (3072 bytes), ct1 and the shared secret; hek is ignored.
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

// CompleteEncaps2 unpacks es, ct1 and ss from encapsSecret and runs Encaps2; it exists for kemCompleter.
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

// FullEncaps encapsulates in one step from pk1 and pk2 with fresh randomness.
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

// BuildHeader returns pk1 as the wire header; implements headerAwareKEM.
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

// IncrementalHeader returns pk1 as the header after checking it against ekVector with ValidatePKBytes.
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
