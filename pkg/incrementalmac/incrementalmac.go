// Package incrementalmac provides streaming MAC computation and validation
// for large data such as message backups. It splits data into fixed-size
// chunks, computing HMAC-SHA256 over ever-growing prefixes of the input
// so that each intermediate MAC covers all data from the beginning.
//
// The chaining semantics match the Rust libsignal reference:
//
//   - MAC_0 = HMAC(key, chunk_0)
//   - MAC_1 = HMAC(key, chunk_0 || chunk_1)
//   - MAC_2 = HMAC(key, chunk_0 || chunk_1 || chunk_2)
//   - ...
//   - MAC_final = HMAC(key, all_data)
//
// At each chunk boundary, the inner hash state is cloned and the HMAC is
// completed for that prefix. The inner hash continues accumulating data.
package incrementalmac

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding"
	"hash"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
)

const (
	// DigestLength is the MAC output length (SHA-256 = 32 bytes).
	DigestLength = sha256.Size

	// MinChunkSize is the minimum allowed chunk size (64 KB).
	MinChunkSize = 64 * 1024

	// MaxChunkSize is the maximum allowed chunk size (2 MB).
	MaxChunkSize = 2 * 1024 * 1024

	// targetTotalDigestSize controls the target total size of all MACs
	// combined. For SHA-256 this yields 256 target chunks.
	targetTotalDigestSize = 8 * 1024

	// sha256BlockSize is the block size of SHA-256.
	sha256BlockSize = 64
)

// clonableHMAC holds the decomposed HMAC state: the running inner hash and
// the pre-computed outer padding hash. This allows cloning the inner hash
// (SHA-256 supports encoding.BinaryMarshaler) at chunk boundaries to
// produce intermediate MACs without disrupting the running computation.
type clonableHMAC struct {
	inner    hash.Hash // H(ipad || data...) — accumulates all input
	outerKey []byte    // K XOR opad, pre-computed for the outer hash pass
}

// newClonableHMAC constructs a clonableHMAC from the given key.
// It follows the standard HMAC construction (RFC 2104).
func newClonableHMAC(key []byte) *clonableHMAC {
	// If key is longer than block size, hash it first.
	if len(key) > sha256BlockSize {
		h := sha256.New()
		h.Write(key)
		key = h.Sum(nil)
	}

	// Pad key to block size.
	paddedKey := make([]byte, sha256BlockSize)
	copy(paddedKey, key)
	defer crypto.Zeroize(paddedKey)

	ipad := make([]byte, sha256BlockSize)
	opad := make([]byte, sha256BlockSize)
	for i := 0; i < sha256BlockSize; i++ {
		ipad[i] = paddedKey[i] ^ 0x36
		opad[i] = paddedKey[i] ^ 0x5c
	}

	inner := sha256.New()
	inner.Write(ipad)
	crypto.Zeroize(ipad)

	return &clonableHMAC{
		inner:    inner,
		outerKey: opad,
	}
}

// Write feeds data into the inner hash.
func (h *clonableHMAC) Write(p []byte) {
	h.inner.Write(p)
}

// cloneAndFinalize clones the current inner hash state, finalizes the
// clone, and completes the outer hash pass to produce the HMAC digest.
// The original inner hash state is not modified.
func (h *clonableHMAC) cloneAndFinalize() []byte {
	// Clone the inner hash state.
	marshaler := h.inner.(encoding.BinaryMarshaler)
	state, err := marshaler.MarshalBinary()
	if err != nil {
		panic("incrementalmac: failed to marshal inner hash state: " + err.Error())
	}

	clone := sha256.New()
	unmarshaler := clone.(encoding.BinaryUnmarshaler)
	if err := unmarshaler.UnmarshalBinary(state); err != nil {
		panic("incrementalmac: failed to unmarshal inner hash state: " + err.Error())
	}

	innerDigest := clone.Sum(nil)

	// Outer pass: H(opad || innerDigest).
	outer := sha256.New()
	outer.Write(h.outerKey)
	outer.Write(innerDigest)
	return outer.Sum(nil)
}

// sum finalizes the inner hash and completes the outer pass.
// This consumes the inner hash state.
func (h *clonableHMAC) sum() []byte {
	innerDigest := h.inner.Sum(nil)
	outer := sha256.New()
	outer.Write(h.outerKey)
	outer.Write(innerDigest)
	return outer.Sum(nil)
}

// Incremental computes MACs incrementally over fixed-size chunks of data.
// A single HMAC state accumulates all input; at each chunk boundary
// the state is cloned and finalized to produce an intermediate MAC.
type Incremental struct {
	hmac      *clonableHMAC
	chunkSize int
	unused    int // bytes remaining in the current chunk
	macs      [][]byte
	finalized bool
}

// New creates a new Incremental MAC with the given HMAC key and chunk size.
// The chunk size must be between MinChunkSize and MaxChunkSize inclusive.
func New(key []byte, chunkSize int) (*Incremental, error) {
	if chunkSize < MinChunkSize {
		return nil, ErrChunkSizeTooSmall
	}
	if chunkSize > MaxChunkSize {
		return nil, ErrChunkSizeTooLarge
	}
	return &Incremental{
		hmac:      newClonableHMAC(key),
		chunkSize: chunkSize,
		unused:    chunkSize,
	}, nil
}

// Update feeds data into the incremental MAC. When a chunk boundary is
// reached, the HMAC state is cloned and finalized to produce an intermediate
// MAC. Returns the number of MACs produced during this call.
// Returns ErrAlreadyFinalized if called after Finalize.
func (inc *Incremental) Update(data []byte) (int, error) {
	if inc.finalized {
		return 0, ErrAlreadyFinalized
	}
	produced := 0
	for len(data) > 0 {
		n := inc.unused
		if len(data) < n {
			n = len(data)
		}

		inc.hmac.Write(data[:n])
		data = data[n:]
		inc.unused -= n

		if inc.unused == 0 {
			digest := inc.hmac.cloneAndFinalize()
			inc.macs = append(inc.macs, digest)
			produced++
			inc.unused = inc.chunkSize
		}
	}
	return produced, nil
}

// Finalize completes the MAC computation. It always produces one final MAC
// covering all data fed so far (including any partial trailing chunk).
// Returns all accumulated MACs: intermediate MACs from chunk boundaries
// followed by the final MAC.
// Returns ErrAlreadyFinalized if called after a previous Finalize.
func (inc *Incremental) Finalize() ([][]byte, error) {
	if inc.finalized {
		return nil, ErrAlreadyFinalized
	}
	inc.finalized = true
	digest := inc.hmac.sum()
	inc.macs = append(inc.macs, digest)
	inc.unused = 0
	return inc.macs, nil
}

// Bytes returns all MACs concatenated as a single byte slice.
// Finalize must be called before Bytes to include the final MAC.
func (inc *Incremental) Bytes() []byte {
	out := make([]byte, 0, len(inc.macs)*DigestLength)
	for _, m := range inc.macs {
		out = append(out, m...)
	}
	return out
}

// Destroy zeroizes the HMAC outer key to prevent sensitive key material
// from lingering in memory. It should be called when the Incremental is
// no longer needed.
func (inc *Incremental) Destroy() {
	if inc.hmac != nil {
		crypto.Zeroize(inc.hmac.outerKey)
	}
}

// Validating validates data against pre-computed MACs as the data is fed
// in. It mirrors the accumulating HMAC logic of Incremental so that each
// chunk boundary triggers a constant-time comparison with the next expected
// MAC.
type Validating struct {
	inc  *Incremental
	macs [][]byte // expected MACs in forward order
	idx  int      // index of next expected MAC
}

// NewValidating creates a new validating instance that checks data against
// the given pre-computed MACs.
func NewValidating(key []byte, chunkSize int, macs [][]byte) (*Validating, error) {
	inc, err := New(key, chunkSize)
	if err != nil {
		return nil, err
	}
	return &Validating{
		inc:  inc,
		macs: macs,
	}, nil
}

// Update feeds data and validates MACs at each chunk boundary. It
// continues processing all chunks even after a mismatch is detected,
// deferring the error return until all data in this call has been
// consumed. This matches the Rust reference behavior where mismatches
// are accumulated and returned after processing completes.
//
// ErrTooFewMACs is returned immediately if expected MACs are exhausted
// since that indicates a structural error that prevents further
// validation.
//
// Only bytes from chunks with matching MACs contribute to the
// validated byte count.
func (v *Validating) Update(data []byte) error {
	var mismatch bool
	for len(data) > 0 {
		n := v.inc.unused
		if len(data) < n {
			n = len(data)
		}

		v.inc.hmac.Write(data[:n])
		data = data[n:]
		v.inc.unused -= n

		if v.inc.unused == 0 {
			if v.idx >= len(v.macs) {
				return ErrTooFewMACs
			}
			digest := v.inc.hmac.cloneAndFinalize()
			if subtle.ConstantTimeCompare(digest, v.macs[v.idx]) != 1 {
				mismatch = true
			}
			// NOTE: Unlike Rust which misaligns the expected index after a mismatch (causing
			// all subsequent chunks to also fail), Go continues advancing the index. Both
			// implementations return a mismatch error. This is an accepted behavioral difference
			// with equivalent security properties.
			v.idx++
			v.inc.unused = v.inc.chunkSize
		}
	}
	if mismatch {
		return ErrMACMismatch
	}
	return nil
}

// Finalize validates the final MAC and verifies that all expected MACs
// have been consumed. Returns ErrMACMismatch if the final MAC does not
// match. Returns ErrTooFewMACs or ErrUnconsumedMACs for structural errors.
func (v *Validating) Finalize() error {
	remaining := len(v.macs) - v.idx
	if remaining != 1 {
		if remaining == 0 {
			return ErrTooFewMACs
		}
		return ErrUnconsumedMACs
	}

	digest := v.inc.hmac.sum()
	if subtle.ConstantTimeCompare(digest, v.macs[v.idx]) != 1 {
		return ErrMACMismatch
	}
	v.idx++

	return nil
}

// Destroy zeroizes the underlying HMAC outer key to prevent sensitive key
// material from lingering in memory. It should be called when the
// Validating instance is no longer needed.
func (v *Validating) Destroy() {
	if v.inc != nil {
		v.inc.Destroy()
	}
}

// CalculateChunkSize returns an appropriate chunk size for a given data
// length. The algorithm matches the Rust libsignal reference:
//
//   - target_chunk_count = TARGET_TOTAL_DIGEST_SIZE / DigestLength (= 256 for SHA-256)
//   - If data_size < target_chunk_count * MINIMUM_CHUNK_SIZE: return MINIMUM_CHUNK_SIZE
//   - If data_size < target_chunk_count * MAXIMUM_CHUNK_SIZE: return ceil(data_size / target_chunk_count)
//   - Otherwise: return MAXIMUM_CHUNK_SIZE
func CalculateChunkSize(dataLength int64) int {
	if dataLength <= 0 {
		return MinChunkSize
	}

	targetChunkCount := int64(targetTotalDigestSize / DigestLength) // 256

	if dataLength < targetChunkCount*int64(MinChunkSize) {
		return MinChunkSize
	}
	if dataLength < targetChunkCount*int64(MaxChunkSize) {
		// div_ceil: (dataLength + targetChunkCount - 1) / targetChunkCount
		return int((dataLength + targetChunkCount - 1) / targetChunkCount)
	}
	return MaxChunkSize
}
