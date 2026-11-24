// Package incrementalmac computes and validates chunked HMACs over growing prefixes (HMAC-SHA256 by default), as rust/protocol/src/incremental_mac.rs.
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

// clonableHMAC holds the running inner hash and outer pad hash, so intermediate MACs can be cloned at chunk boundaries.
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

// New returns an HMAC-SHA256 Incremental MAC; chunkSize must be in (0, MaxChunkSize], as Rust.
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

// Update feeds data and returns the number of MACs produced at chunk boundaries, or ErrAlreadyFinalized.
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

// Finalize returns the chunk MACs followed by the MAC over all data, or ErrAlreadyFinalized.
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

// Destroy zeroizes the HMAC outer key.
func (inc *Incremental) Destroy() {
	if inc.hmac != nil {
		utilcrypto.Zeroize(inc.hmac.outer)
	}
}

// Validating checks data against pre-computed MACs in constant time at each chunk boundary.
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

// NewValidatingWithHash returns a Validating for SHA-256 or SHA-512 MACs.
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

// Update validates MACs at each chunk boundary, processing all data before returning a mismatch.
//
// Deprecated: Use UpdateValidated, which also returns the validated byte count.
func (v *Validating) Update(data []byte) error {
	_, err := v.UpdateValidated(data)
	return err
}

// UpdateValidated validates MACs at each chunk boundary and returns the bytes validated, as Rust Validating::update.
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

// FinalizeValidated validates the final MAC and returns the pending byte count, as Rust Validating::finalize.
//
// Deprecated: Use UpdateValidated and FinalizeValidated together.
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

// Finalize validates the final MAC and that every expected MAC was consumed.
//
// Deprecated: Use FinalizeValidated, which also returns the pending byte count.
func (v *Validating) Finalize() error {
	_, err := v.FinalizeValidated()
	return err
}

// Destroy zeroizes the HMAC outer key.
func (v *Validating) Destroy() {
	if v.inc != nil {
		v.inc.Destroy()
	}
}

// CalculateChunkSize returns the SHA-256 chunk size for a data length, as Rust calculate_chunk_size.
//
// Deprecated: Use CalculateChunkSizeForHash(dataLength, crypto.SHA256).
func CalculateChunkSize(dataLength int64) int {
	return CalculateChunkSizeForHash(dataLength, gocrypto.SHA256)
}

// CalculateChunkSizeForHash returns the chunk size for a data length and SHA-256 or SHA-512, as Rust calculate_chunk_size.
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
