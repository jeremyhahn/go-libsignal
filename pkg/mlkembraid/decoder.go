package mlkembraid

import (
	"encoding/binary"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid/internal/polynomial"
)

// Decoder collects polynomial-encoded chunks and reconstructs the original
// message once enough chunks have been received for interpolation. Chunks may
// arrive in any order and duplicates are silently ignored.
//
// The wire format for each chunk matches the Rust SPQR reference:
//
//	[varint(index)] [data(32 bytes)]
type Decoder struct {
	inner *polynomial.PolyDecoder

	// originalLen is the original (caller-supplied) message length in bytes.
	// It may differ from inner.PtsNeeded*2 when the message was odd-length
	// padded by the Encoder.
	originalLen int

	// totalChunksNeeded is the number of distinct chunk indices required for
	// reconstruction (ceil(originalLen/ChunkDataSize)). Chunk indices at or
	// beyond this value are rejected as out-of-range, matching the protocol
	// expectation that senders do not emit redundancy beyond the first pass
	// unless explicitly retransmitting.
	totalChunksNeeded int

	// seenIndices tracks which chunk indices have been accepted, for duplicate
	// detection and unique-count reporting.
	seenIndices map[uint16]bool

	// chunkLog records each distinct wire chunk that was accepted by AddChunk
	// (in order of first arrival, deduped). Used by the serialization layer
	// to replay decoder state without accessing polynomial internals.
	chunkLog [][]byte

	// decoded caches the result of the first successful DecodedMessage call.
	decoded []byte

	// complete is true once the message has been decoded.
	complete bool
}

// NewDecoder creates a decoder expecting a message of originalLen bytes.
//
// The chunkSize parameter is accepted for API compatibility but has no effect;
// the Rust SPQR wire format mandates fixed 32-byte chunk payloads.
func NewDecoder(originalLen, _ int) (*Decoder, error) {
	if originalLen <= 0 {
		return nil, &ErrInvalidInput{Field: "expectedSize", Reason: "must be positive"}
	}

	totalChunks := (originalLen + ChunkDataSize - 1) / ChunkDataSize
	if totalChunks > MaxChunkIndex+1 {
		return nil, &ErrChunkCount{Count: totalChunks, Max: MaxChunkIndex + 1}
	}

	// Polynomial encoding requires even-length messages. Round up to preserve
	// parity with the Encoder's padding behaviour.
	innerLen := originalLen
	if innerLen%2 != 0 {
		innerLen++
	}

	inner, err := polynomial.NewPolyDecoder(innerLen)
	if err != nil {
		return nil, &ErrInvalidInput{Field: "expectedSize", Reason: err.Error()}
	}

	return &Decoder{
		inner:             inner,
		originalLen:       originalLen,
		totalChunksNeeded: totalChunks,
		seenIndices:       make(map[uint16]bool, totalChunks),
	}, nil
}

// AddChunk parses a Rust-compatible wire chunk:
//
//	[varint(index)] [data(32 bytes)]
//
// The varint-encoded index is decoded first, then exactly 32 bytes of payload
// data follow. Duplicate chunks for the same index are silently ignored.
// Chunk indices at or beyond TotalChunks are rejected as out of range.
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

	remaining := chunk[n:]
	if len(remaining) != ChunkDataSize {
		return &ErrChunkFormat{
			Reason: "chunk data must be exactly 32 bytes, got " + uitoa(len(remaining)),
		}
	}

	index := uint16(index64)

	// Silently ignore duplicate chunk indices.
	if d.seenIndices[index] {
		return nil
	}
	d.seenIndices[index] = true

	var data [ChunkDataSize]byte
	copy(data[:], remaining)

	d.inner.AddChunk(polynomial.Chunk{
		Index: index,
		Data:  data,
	})

	// Log a copy of the wire chunk for serialization replay.
	logged := make([]byte, len(chunk))
	copy(logged, chunk)
	d.chunkLog = append(d.chunkLog, logged)

	return nil
}

// HasMessage returns true if enough chunks have been received to reconstruct
// the message.
func (d *Decoder) HasMessage() bool {
	if d.complete {
		return true
	}
	msg, ok := d.inner.DecodedMessage()
	if ok {
		// Trim padding introduced by the Encoder for odd-length messages.
		if len(msg) > d.originalLen {
			msg = msg[:d.originalLen]
		}
		d.decoded = msg
		d.complete = true
		return true
	}
	return false
}

// Message returns the reconstructed message. Returns an error if the decoder
// has not yet received enough chunks.
func (d *Decoder) Message() ([]byte, error) {
	if d.complete {
		return d.decoded, nil
	}

	// Try to decode.
	if !d.HasMessage() {
		return nil, &ErrDecoderIncomplete{
			Received: d.ReceivedCount(),
			Required: d.totalChunksNeeded,
		}
	}

	return d.decoded, nil
}

// ReceivedCount returns the number of unique chunk indices accepted so far.
// Duplicate chunks for the same index are not counted.
func (d *Decoder) ReceivedCount() int {
	return len(d.seenIndices)
}

// TotalChunks returns the number of distinct chunks required for reconstruction.
func (d *Decoder) TotalChunks() int {
	return d.totalChunksNeeded
}

// Reset clears the decoder state for reuse with a new message of the same size.
func (d *Decoder) Reset() {
	inner, err := polynomial.NewPolyDecoder(d.inner.PtsNeeded * 2)
	if err != nil {
		// coverage-exempt: defensive invariant panic; parameters were validated at
		// construction time so NewPolyDecoder cannot fail here. Cannot be unit-tested
		// without corrupting internal state (see CLAUDE.md).
		panic("mlkembraid: decoder Reset: unexpected polynomial error: " + err.Error())
	}
	d.inner = inner
	d.seenIndices = make(map[uint16]bool, d.totalChunksNeeded)
	d.chunkLog = nil
	d.decoded = nil
	d.complete = false
}

// NewDecoderFromInner creates a Decoder wrapping an already-constructed
// PolyDecoder. The originalLen is the original (un-padded) message length in
// bytes. This is used exclusively by the proto codec (Phase D) to reconstruct
// a Decoder from a deserialized protobuf.
func NewDecoderFromInner(inner *polynomial.PolyDecoder, originalLen int) *Decoder {
	totalChunks := (originalLen + ChunkDataSize - 1) / ChunkDataSize
	// Reconstruct seenIndices from the chunkLog (empty here — the proto decoder
	// path does not replay wire chunks, only the polynomial points).
	return &Decoder{
		inner:             inner,
		originalLen:       originalLen,
		totalChunksNeeded: totalChunks,
		seenIndices:       make(map[uint16]bool, totalChunks),
		complete:          inner.IsComplete,
	}
}

// InnerDecoder returns the underlying polynomial decoder. It is used by the
// proto marshaling layer (Phase D). Callers outside the SPQR state serializer
// should not call this directly.
func (d *Decoder) InnerDecoder() *polynomial.PolyDecoder {
	return d.inner
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
