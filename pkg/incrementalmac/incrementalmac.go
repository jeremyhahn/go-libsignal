// Package incrementalmac provides streaming MAC computation and validation
// for large data such as message backups. It splits data into fixed-size
// chunks, computing HMAC over ever-growing prefixes of the input so that
// each intermediate MAC covers all data from the beginning.
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
//
// By default the package uses HMAC-SHA256. Pass crypto.SHA512 to
// NewWithHash or NewValidatingWithHash to use HMAC-SHA512 instead.
// Rust source: rust/protocol/src/incremental_mac.rs
package incrementalmac

import (
	gocrypto "crypto"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding"
	"hash"

	_ "crypto/sha512" // registers crypto.SHA512

	utilcrypto "github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
)

const (
	// DigestLength is the MAC output length for the default SHA-256 hash (32 bytes).
	DigestLength = sha256.Size

	// MinChunkSize is the minimum allowed chunk size (64 KB).
	MinChunkSize = 64 * 1024

	// MaxChunkSize is the maximum allowed chunk size (2 MB).
	MaxChunkSize = 2 * 1024 * 1024

	// targetTotalDigestSize controls the target total size of all MACs
	// combined. For SHA-256 this yields 256 target chunks; for SHA-512,
	// 128 target chunks.
	targetTotalDigestSize = 8 * 1024
)

// hashParams bundles the constructor and geometry for a supported hash.
type hashParams struct {
	// newHash returns a fresh hash.Hash instance.
	newHash func() hash.Hash
	// blockSize is the HMAC block size (key-padding width) in bytes.
	blockSize int
	// digestSize is the output length in bytes.
	digestSize int
}

// hashParamsFor returns the hashParams for h, or ErrUnsupportedHash if h is
// not a supported hash function.
func hashParamsFor(h gocrypto.Hash) (hashParams, error) {
	switch h {
	case gocrypto.SHA256:
		return hashParams{newHash: sha256.New, blockSize: 64, digestSize: sha256.Size}, nil
	case gocrypto.SHA512:
		return hashParams{newHash: sha512.New, blockSize: 128, digestSize: sha512.Size}, nil
	default:
		return hashParams{}, ErrUnsupportedHash
	}
}

// clonableHMAC holds the decomposed HMAC state: the running inner hash and
// the pre-computed outer padding hash. This allows cloning the inner hash
// (SHA-256 and SHA-512 both implement encoding.BinaryMarshaler) at chunk
// boundaries to produce intermediate MACs without disrupting the running
// computation.
type clonableHMAC struct {
	inner  hash.Hash  // H(ipad || data...) — accumulates all input
	outer  []byte     // K XOR opad, pre-computed for the outer hash pass
	params hashParams // hash constructor and geometry
}

// newClonableHMAC constructs a clonableHMAC from the given key and hash params.
// It follows the standard HMAC construction (RFC 2104).
func newClonableHMAC(key []byte, p hashParams) *clonableHMAC {
	// If key is longer than block size, hash it first.
	if len(key) > p.blockSize {
		h := p.newHash()
		h.Write(key)
		key = h.Sum(nil)
	}

	// Pad key to block size.
	paddedKey := make([]byte, p.blockSize)
	copy(paddedKey, key)
	defer utilcrypto.Zeroize(paddedKey)

	ipad := make([]byte, p.blockSize)
	opad := make([]byte, p.blockSize)
	for i := 0; i < p.blockSize; i++ {
		ipad[i] = paddedKey[i] ^ 0x36
		opad[i] = paddedKey[i] ^ 0x5c
	}

	inner := p.newHash()
	inner.Write(ipad)
	utilcrypto.Zeroize(ipad)

	return &clonableHMAC{
		inner:  inner,
		outer:  opad,
		params: p,
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
	// Clone the inner hash state via the encoding.BinaryMarshaler interface.
	marshaler := h.inner.(encoding.BinaryMarshaler)
	state, err := marshaler.MarshalBinary()
	if err != nil {
		panic("incrementalmac: failed to marshal inner hash state: " + err.Error())
	}

	clone := h.params.newHash()
	unmarshaler := clone.(encoding.BinaryUnmarshaler)
	if err := unmarshaler.UnmarshalBinary(state); err != nil {
		panic("incrementalmac: failed to unmarshal inner hash state: " + err.Error())
	}

	innerDigest := clone.Sum(nil)

	// Outer pass: H(opad || innerDigest).
	out := h.params.newHash()
	out.Write(h.outer)
	out.Write(innerDigest)
	return out.Sum(nil)
}

// sum finalizes the inner hash and completes the outer pass.
// This consumes the inner hash state.
func (h *clonableHMAC) sum() []byte {
	innerDigest := h.inner.Sum(nil)
	out := h.params.newHash()
	out.Write(h.outer)
	out.Write(innerDigest)
	return out.Sum(nil)
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

// New creates a new Incremental MAC with the given HMAC key and chunk size
// using HMAC-SHA256.
//
// The chunk size must be positive and at most MaxChunkSize. This matches the
// Rust reference which asserts only chunk_size > 0 (incremental_mac.rs:50).
// MinChunkSize is a recommended minimum for production use (good chunk-count
// vs. overhead trade-off) but is no longer enforced here, allowing callers
// and tests to use small chunk sizes such as the Rust test constant of 32.
func New(key []byte, chunkSize int) (*Incremental, error) {
	return NewWithHash(key, chunkSize, gocrypto.SHA256)
}

// NewWithHash creates a new Incremental MAC with the given HMAC key, chunk
// size, and hash function. Supported hashes: crypto.SHA256, crypto.SHA512.
// Rust source: rust/protocol/src/incremental_mac.rs:48-56
func NewWithHash(key []byte, chunkSize int, h gocrypto.Hash) (*Incremental, error) {
	if chunkSize <= 0 {
		return nil, ErrChunkSizeTooSmall
	}
	if chunkSize > MaxChunkSize {
		return nil, ErrChunkSizeTooLarge
	}
	p, err := hashParamsFor(h)
	if err != nil {
		return nil, err
	}
	return &Incremental{
		hmac:      newClonableHMAC(key, p),
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
	digestLen := DigestLength
	if inc.hmac != nil {
		digestLen = inc.hmac.params.digestSize
	}
	out := make([]byte, 0, len(inc.macs)*digestLen)
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
		utilcrypto.Zeroize(inc.hmac.outer)
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
// the given pre-computed MACs using HMAC-SHA256.
func NewValidating(key []byte, chunkSize int, macs [][]byte) (*Validating, error) {
	return NewValidatingWithHash(key, chunkSize, macs, gocrypto.SHA256)
}

// NewValidatingWithHash creates a new validating instance that checks data
// against the given pre-computed MACs using the specified hash function.
// Supported hashes: crypto.SHA256, crypto.SHA512.
// Rust source: rust/protocol/src/incremental_mac.rs:58-76
func NewValidatingWithHash(key []byte, chunkSize int, macs [][]byte, h gocrypto.Hash) (*Validating, error) {
	inc, err := NewWithHash(key, chunkSize, h)
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
//
// Deprecated: Use UpdateValidated which also returns the count of validated
// bytes, matching Rust's Validating::update -> Result<usize, MacError>.
func (v *Validating) Update(data []byte) error {
	_, err := v.UpdateValidated(data)
	return err
}

// UpdateValidated feeds data and validates MACs at each chunk boundary,
// returning the number of bytes validated by complete chunk MAC comparisons.
// This mirrors Rust's Validating::update -> Result<usize, MacError>, where
// the returned usize is whole_chunks * chunk_size.
// Rust source: rust/protocol/src/incremental_mac.rs:110-127
//
// ErrTooFewMACs is returned immediately if expected MACs are exhausted.
// ErrMACMismatch is returned (with validated=0) if any chunk MAC mismatches.
func (v *Validating) UpdateValidated(data []byte) (validated int, err error) {
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
				return 0, ErrTooFewMACs
			}
			digest := v.inc.hmac.cloneAndFinalize()
			if subtle.ConstantTimeCompare(digest, v.macs[v.idx]) != 1 {
				mismatch = true
			} else {
				validated += v.inc.chunkSize
			}
			v.idx++
			v.inc.unused = v.inc.chunkSize
		}
	}
	if mismatch {
		return 0, ErrMACMismatch
	}
	return validated, nil
}

// FinalizeValidated validates the final MAC and returns the count of pending
// (not yet chunk-boundary-validated) bytes, matching Rust's
// Validating::finalize -> Result<usize, MacError> which returns
// pending_bytes_size on success.
// Rust source: rust/protocol/src/incremental_mac.rs:130-138
//
// Returns ErrMACMismatch if the final MAC does not match.
// Returns ErrTooFewMACs or ErrUnconsumedMACs for structural errors.
//
// Deprecated: Use UpdateValidated/FinalizeValidated together for full parity
// with Rust's byte-count return semantics.
func (v *Validating) FinalizeValidated() (pending int, err error) {
	remaining := len(v.macs) - v.idx
	if remaining != 1 {
		if remaining == 0 {
			return 0, ErrTooFewMACs
		}
		return 0, ErrUnconsumedMACs
	}

	pending = v.inc.chunkSize - v.inc.unused
	digest := v.inc.hmac.sum()
	if subtle.ConstantTimeCompare(digest, v.macs[v.idx]) != 1 {
		return 0, ErrMACMismatch
	}
	v.idx++
	return pending, nil
}

// Finalize validates the final MAC and verifies that all expected MACs
// have been consumed. Returns ErrMACMismatch if the final MAC does not
// match. Returns ErrTooFewMACs or ErrUnconsumedMACs for structural errors.
//
// Deprecated: Use FinalizeValidated which also returns the count of pending
// bytes, matching Rust's Validating::finalize -> Result<usize, MacError>.
func (v *Validating) Finalize() error {
	_, err := v.FinalizeValidated()
	return err
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
// length using SHA-256. The algorithm matches the Rust libsignal reference:
//
//   - target_chunk_count = TARGET_TOTAL_DIGEST_SIZE / DigestLength (= 256 for SHA-256)
//   - If data_size < target_chunk_count * MINIMUM_CHUNK_SIZE: return MINIMUM_CHUNK_SIZE
//   - If data_size < target_chunk_count * MAXIMUM_CHUNK_SIZE: return ceil(data_size / target_chunk_count)
//   - Otherwise: return MAXIMUM_CHUNK_SIZE
//
// Deprecated: Use CalculateChunkSizeForHash(dataLength, crypto.SHA256) for
// explicit hash selection. This wrapper exists for backwards compatibility.
// Rust source: rust/protocol/src/incremental_mac.rs:29-46
func CalculateChunkSize(dataLength int64) int {
	return CalculateChunkSizeForHash(dataLength, gocrypto.SHA256)
}

// CalculateChunkSizeForHash returns an appropriate chunk size for a given data
// length and hash function. The algorithm is generic over the digest output
// size, matching Rust's calculate_chunk_size::<D>(data_size) where D: FixedOutput.
// Supported hashes: crypto.SHA256 (output 32 B → 256 target chunks),
// crypto.SHA512 (output 64 B → 128 target chunks).
//
// Rust source: rust/protocol/src/incremental_mac.rs:29-46
func CalculateChunkSizeForHash(dataLength int64, h gocrypto.Hash) int {
	p, err := hashParamsFor(h)
	if err != nil {
		// Mirror Rust's compile-time assertion at runtime for unsupported hashes.
		panic("incrementalmac: unsupported hash for CalculateChunkSizeForHash")
	}

	if targetTotalDigestSize%p.digestSize != 0 {
		// Rust asserts this at compile time; panic here mirrors that guarantee.
		panic("incrementalmac: targetTotalDigestSize must be a multiple of the digest size")
	}

	if dataLength <= 0 {
		return MinChunkSize
	}

	targetChunkCount := int64(targetTotalDigestSize / p.digestSize)

	if dataLength < targetChunkCount*int64(MinChunkSize) {
		return MinChunkSize
	}
	if dataLength < targetChunkCount*int64(MaxChunkSize) {
		// div_ceil: (dataLength + targetChunkCount - 1) / targetChunkCount
		return int((dataLength + targetChunkCount - 1) / targetChunkCount)
	}
	return MaxChunkSize
}
