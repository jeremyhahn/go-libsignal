package mlkembraid

import "encoding/binary"

// ChunkDataSize is the fixed payload size per chunk, matching the Rust reference
// implementation's encoding::Chunk { index: u16, data: [u8; 32] }.
const ChunkDataSize = 32

// MaxChunkIndex is the maximum chunk index supported (u16 range).
const MaxChunkIndex = 65535

// Encoder provides indexed erasure encoding by splitting a message into
// fixed-size 32-byte chunks. Each chunk on the wire is formatted as:
//
//	[varint(index)] [data(32 bytes)]
//
// This matches the Rust SPQR reference implementation's wire format:
//
//	encode_chunk: encode_varint(c.index as u64) ++ c.data[..]
//
// Chunks are produced sequentially until all data is sent, then the
// encoder wraps around for retransmission redundancy.
type Encoder struct {
	data   []byte
	offset int
	total  int
}

// NewEncoder creates a new encoder that will split data into fixed 32-byte
// chunks. The data must not be empty and must not require more than 65535
// chunks.
func NewEncoder(data []byte, chunkSize int) (*Encoder, error) {
	if len(data) == 0 {
		return nil, &ErrInvalidInput{Field: "data", Reason: "must not be empty"}
	}

	// chunkSize is accepted but ignored for backward API compatibility;
	// the Rust wire format mandates a fixed 32-byte payload per chunk.
	_ = chunkSize

	total := (len(data) + ChunkDataSize - 1) / ChunkDataSize

	if total > MaxChunkIndex+1 {
		return nil, &ErrChunkCount{Count: total, Max: MaxChunkIndex + 1}
	}

	return &Encoder{
		data:   data,
		offset: 0,
		total:  total,
	}, nil
}

// NextChunk returns the next chunk in Rust-compatible wire format:
//
//	[varint(index)] [data(32 bytes, zero-padded if last chunk)]
//
// After all chunks have been produced once, the encoder wraps around to
// enable retransmission.
func (e *Encoder) NextChunk() []byte {
	idx := e.offset % e.total
	start := idx * ChunkDataSize
	end := start + ChunkDataSize
	if end > len(e.data) {
		end = len(e.data)
	}

	// Encode the varint index.
	var varintBuf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(varintBuf[:], uint64(idx))

	// Build the wire chunk: varint(index) || data(32 bytes, zero-padded).
	chunk := make([]byte, n+ChunkDataSize)
	copy(chunk[:n], varintBuf[:n])
	copy(chunk[n:], e.data[start:end])
	// Remaining bytes in chunk[n+payloadLen:] are already zero (zero-padded).

	e.offset++
	// Prevent unbounded offset growth during retransmission. After the first
	// pass completes (offset >= total), reset offset to total when it reaches
	// 2*total. This keeps HasMore() returning false and idx still wraps
	// correctly via the modular arithmetic above.
	if e.offset >= 2*e.total {
		e.offset = e.total
	}
	return chunk
}

// HasMore returns true if there are unsent chunks remaining in the first pass.
func (e *Encoder) HasMore() bool {
	return e.offset < e.total
}

// TotalChunks returns the number of chunks needed to encode the full message.
func (e *Encoder) TotalChunks() int {
	return e.total
}

// Reset resets the encoder to the beginning.
func (e *Encoder) Reset() {
	e.offset = 0
}
