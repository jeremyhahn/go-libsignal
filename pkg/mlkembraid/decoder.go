package mlkembraid

import "encoding/binary"

// Decoder collects indexed chunks and reconstructs the original message
// once all chunks have been received. Chunks may arrive in any order and
// duplicates are silently ignored.
//
// The wire format for each chunk matches the Rust SPQR reference:
//
//	[varint(index)] [data(32 bytes)]
type Decoder struct {
	expectedSize int
	chunks       map[uint16][]byte
	totalChunks  uint16
}

// NewDecoder creates a decoder expecting a message of expectedSize bytes.
// The chunkSize parameter is accepted for API compatibility but is not used;
// the Rust wire format mandates fixed 32-byte chunk payloads.
func NewDecoder(expectedSize, chunkSize int) (*Decoder, error) {
	if expectedSize <= 0 {
		return nil, &ErrInvalidInput{Field: "expectedSize", Reason: "must be positive"}
	}

	// chunkSize is accepted but ignored; Rust uses fixed 32-byte chunks.
	_ = chunkSize

	totalChunks := (expectedSize + ChunkDataSize - 1) / ChunkDataSize

	if totalChunks > MaxChunkIndex+1 {
		return nil, &ErrChunkCount{Count: totalChunks, Max: MaxChunkIndex + 1}
	}

	return &Decoder{
		expectedSize: expectedSize,
		chunks:       make(map[uint16][]byte, totalChunks),
		totalChunks:  uint16(totalChunks),
	}, nil
}

// AddChunk parses a Rust-compatible wire chunk:
//
//	[varint(index)] [data(32 bytes)]
//
// The varint-encoded index is decoded first, then exactly 32 bytes of
// payload data follow. Duplicate chunks for the same index are silently
// ignored.
func (d *Decoder) AddChunk(chunk []byte) error {
	if len(chunk) == 0 {
		return &ErrChunkFormat{Reason: "chunk is empty"}
	}

	// Decode varint index.
	index64, n := binary.Uvarint(chunk)
	if n <= 0 {
		return &ErrChunkFormat{Reason: "invalid varint index encoding"}
	}
	if index64 > MaxChunkIndex {
		return &ErrChunkFormat{Reason: "chunk index exceeds u16 range"}
	}

	// Remaining bytes must be exactly ChunkDataSize.
	remaining := chunk[n:]
	if len(remaining) != ChunkDataSize {
		return &ErrChunkFormat{
			Reason: "chunk data must be exactly 32 bytes, got " + uitoa(len(remaining)),
		}
	}

	index := uint16(index64)

	if index >= d.totalChunks {
		return &ErrChunkFormat{
			Reason: "chunk index " + uitoa(int(index)) +
				" out of range [0, " + uitoa(int(d.totalChunks)) + ")",
		}
	}

	// Silently ignore duplicate chunks.
	if _, exists := d.chunks[index]; exists {
		return nil
	}

	// Store a copy of the payload data.
	payload := make([]byte, ChunkDataSize)
	copy(payload, remaining)
	d.chunks[index] = payload

	return nil
}

// HasMessage returns true if all required chunks have been received.
func (d *Decoder) HasMessage() bool {
	return len(d.chunks) == int(d.totalChunks)
}

// Message returns the reconstructed message by concatenating chunks in index
// order. Returns an error if the decoder has not yet received all required
// chunks.
func (d *Decoder) Message() ([]byte, error) {
	if !d.HasMessage() {
		return nil, &ErrDecoderIncomplete{
			Received: len(d.chunks),
			Required: int(d.totalChunks),
		}
	}

	result := make([]byte, 0, d.expectedSize)
	for i := uint16(0); i < d.totalChunks; i++ {
		result = append(result, d.chunks[i]...)
	}

	// Truncate to expected size since the last chunk may have been zero-padded.
	if len(result) > d.expectedSize {
		result = result[:d.expectedSize]
	}

	return result, nil
}

// ReceivedCount returns the number of unique chunks received so far.
func (d *Decoder) ReceivedCount() int {
	return len(d.chunks)
}

// TotalChunks returns the total number of chunks required.
func (d *Decoder) TotalChunks() int {
	return int(d.totalChunks)
}

// Reset clears the decoder state for reuse with a new message of the same size.
func (d *Decoder) Reset() {
	d.chunks = make(map[uint16][]byte, d.totalChunks)
}

// uitoa converts a small non-negative integer to a string without importing
// strconv, keeping the package dependency footprint minimal.
func uitoa(i int) string {
	if i == 0 {
		return "0"
	}
	buf := [20]byte{}
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
