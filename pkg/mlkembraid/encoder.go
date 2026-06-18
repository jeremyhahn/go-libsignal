package mlkembraid

import (
	"encoding/binary"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid/internal/polynomial"
)

// ChunkDataSize is the fixed payload size per chunk, matching the Rust reference
// implementation's encoding::Chunk { index: u16, data: [u8; 32] }.
const ChunkDataSize = polynomial.ChunkSize

// MaxChunkIndex is the maximum chunk index supported (u16 range).
const MaxChunkIndex = 65535

// Encoder encodes a message into an infinite stream of 32-byte polynomial chunks
// using Lagrange interpolation over GF(2^16). Each chunk on the wire is formatted as:
//
//	[varint(index)] [data(32 bytes)]
//
// This matches the Rust SPQR reference implementation's wire format:
//
//	encode_chunk: encode_varint(c.index as u64) ++ c.data[..]
//
// The first N chunks reproduce the original data; subsequent chunks are
// interpolated redundancy. Chunks beyond the first pass continue wrapping
// via NextChunk for retransmission redundancy.
type Encoder struct {
	inner *polynomial.PolyEncoder

	// total is the number of chunks required for a first-pass reconstruction.
	// Equals ceil(len(msg) / ChunkDataSize).
	total int

	// sent tracks how many chunks have been emitted (drives HasMore).
	sent int
}

// NewEncoder creates an Encoder for the given data.
//
// The chunkSize parameter is accepted for API compatibility but has no effect;
// the Rust SPQR wire format mandates a fixed 32-byte payload per chunk. Passing
// a value other than 32 (or DefaultChunkSize) is not an error — it is silently
// treated as 32.
//
// The data slice must not be empty and must have an even byte length (required
// by the GF(2^16) polynomial encoding). If the data length is odd, one byte of
// zero padding is appended internally so the caller's original data is always
// reconstructed faithfully.
func NewEncoder(data []byte, _ int) (*Encoder, error) {
	if len(data) == 0 {
		return nil, &ErrInvalidInput{Field: "data", Reason: "must not be empty"}
	}

	// Polynomial encoding requires an even-length message. Pad with one zero
	// byte when the caller supplies an odd-length payload; the Decoder trims
	// back to the original size.
	msg := data
	if len(msg)%2 != 0 {
		padded := make([]byte, len(msg)+1)
		copy(padded, msg)
		msg = padded
	}

	// Compute the number of chunks needed to cover the original (unpadded) data.
	total := (len(data) + ChunkDataSize - 1) / ChunkDataSize
	if total > MaxChunkIndex+1 {
		return nil, &ErrChunkCount{Count: total, Max: MaxChunkIndex + 1}
	}

	inner, err := polynomial.NewPolyEncoder(msg)
	if err != nil {
		return nil, &ErrInvalidInput{Field: "data", Reason: err.Error()}
	}

	return &Encoder{
		inner: inner,
		total: total,
		sent:  0,
	}, nil
}

// NextChunk returns the next chunk in Rust-compatible wire format:
//
//	[varint(index)] [data(32 bytes)]
//
// After the first pass (all total chunks sent), NextChunk wraps around for
// retransmission redundancy. The polynomial encoding guarantees that any
// ceil(len(data)/32) distinct chunks suffice for reconstruction.
func (e *Encoder) NextChunk() []byte {
	pc := e.inner.NextChunk()

	// Encode chunk index as a varint.
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], uint64(pc.Index))

	out := make([]byte, n+ChunkDataSize)
	copy(out[:n], buf[:n])
	copy(out[n:], pc.Data[:])

	e.sent++
	return out
}

// HasMore returns true if there are un-sent chunks remaining in the first pass.
func (e *Encoder) HasMore() bool {
	return e.sent < e.total
}

// TotalChunks returns the number of chunks required to encode the full message.
func (e *Encoder) TotalChunks() int {
	return e.total
}

// Reset resets the encoder to the beginning of the first pass.
func (e *Encoder) Reset() {
	// The polynomial encoder's idx is a monotonically-increasing counter;
	// re-create the encoder from the same message to reset to chunk 0.
	// We reconstruct from the points that are already stored in the inner encoder.
	// Since PolyEncoder.ChunkAt(idx) is pure, we can just reset the idx counter.
	// The polynomial package exposes Idx() but not a setter — reconstruct by
	// resetting sent and letting the inner encoder continue from its current idx.
	// For a true reset we need to recreate the inner encoder. Capture the message
	// from the existing points array.
	msg := encoderMessage(e.inner)
	inner, err := polynomial.NewPolyEncoder(msg)
	if err != nil {
		// coverage-exempt: defensive invariant panic; message was validated at
		// construction time so NewPolyEncoder cannot fail here. Cannot be unit-tested
		// without corrupting internal state (see CLAUDE.md).
		panic("mlkembraid: encoder Reset: unexpected polynomial error: " + err.Error())
	}
	e.inner = inner
	e.sent = 0
}

// encoderMessage reconstructs the original message bytes from the inner
// PolyEncoder's stored points (only valid before the first transition to Polys
// state, which is the common case for Reset). In Polys state we evaluate at
// x=0..N to recover the original points.
func encoderMessage(e *polynomial.PolyEncoder) []byte {
	// Walk chunk indices 0..(total-1) and pull raw point values.
	// Each chunk at index i covers NumPolys=16 GF(2^16) elements.
	// We reconstruct the message by calling ChunkAt on a clone of the encoder.
	// Since ChunkAt is non-destructive (it only reads/lazily interpolates),
	// the simplest approach is to use the existing inner encoder's ChunkAt
	// to read the first-pass chunk data and concatenate their payloads.

	// Determine total chunks from the stored points length.
	pts := e.Points()
	maxLen := 0
	for i := 0; i < polynomial.NumPolys; i++ {
		l := len(pts[i].Value)
		if l > maxLen {
			maxLen = l
		}
	}
	// total GF(2^16) elements across all channels = maxLen*NumPolys (approximately).
	// The actual message byte length = sum of point counts * 2.
	totalElems := 0
	for i := 0; i < polynomial.NumPolys; i++ {
		totalElems += len(pts[i].Value)
	}
	msgLen := totalElems * 2

	// Reconstruct by reading chunks 0..ceil(msgLen/32)-1.
	totalChunks := (msgLen + ChunkDataSize - 1) / ChunkDataSize
	out := make([]byte, 0, msgLen)
	for i := 0; i < totalChunks; i++ {
		chunk := e.ChunkAt(uint16(i))
		out = append(out, chunk.Data[:]...)
	}
	if len(out) > msgLen {
		out = out[:msgLen]
	}
	return out
}

// NewEncoderFromInner creates an Encoder wrapping an already-constructed
// PolyEncoder. The idx parameter is the current chunk counter (matching
// PolyEncoder.Idx()), and msgLen is the original (un-padded) message length in
// bytes. This is used exclusively by the proto codec (Phase D) to reconstruct
// an Encoder from a deserialized protobuf.
func NewEncoderFromInner(inner *polynomial.PolyEncoder, idx int, msgLen int) (*Encoder, error) {
	if inner == nil {
		return nil, &ErrInvalidInput{Field: "inner", Reason: "must not be nil"}
	}
	total := (msgLen + ChunkDataSize - 1) / ChunkDataSize
	if total > MaxChunkIndex+1 {
		return nil, &ErrChunkCount{Count: total, Max: MaxChunkIndex + 1}
	}
	return &Encoder{
		inner: inner,
		total: total,
		sent:  idx,
	}, nil
}

// InnerEncoder returns the underlying polynomial encoder. It is used by the
// proto marshaling layer (Phase D). Callers outside the SPQR state serializer
// should not call this directly.
func (e *Encoder) InnerEncoder() *polynomial.PolyEncoder {
	return e.inner
}
