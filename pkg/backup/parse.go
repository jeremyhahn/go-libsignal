package backup

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

const (
	varintMaxLength = 10

	// maxFrameSize is the maximum allowed declared frame size in bytes.
	// Rust's VarintDelimitedReader accepts frames up to u32::MAX
	// (rust/message-backup/src/parse.rs: read_raw_varint32 returns u32).
	// We match that range here. The whole-stream io.LimitReader applied
	// in DecryptFrames (maxBackupSize = 100 GiB) bounds actual memory
	// use: a declared length larger than the remaining stream bytes causes
	// io.ReadFull to return an UnexpectedEOF error rather than allocating
	// the full declared amount.
	maxFrameSize = 1<<32 - 1 // u32::MAX = 4 294 967 295
)

// FrameTooLargeError is returned when a varint-delimited frame exceeds the
// maximum allowed size, preventing excessive memory allocation from malicious
// or corrupted input.
type FrameTooLargeError struct {
	Size uint64
	Max  int
}

func (e *FrameTooLargeError) Error() string {
	return fmt.Sprintf("backup: frame size %d exceeds maximum %d", e.Size, e.Max)
}

// VarintDelimitedReader reads varint-length-prefixed messages from an
// underlying io.Reader. Each message is preceded by a protobuf-style
// varint encoding of its byte length.
type VarintDelimitedReader struct {
	reader io.Reader
	buf    [varintMaxLength]byte
	bufLen int // number of valid bytes in buf
}

// NewVarintDelimitedReader creates a new reader that reads varint-delimited
// messages from r.
func NewVarintDelimitedReader(r io.Reader) *VarintDelimitedReader {
	return &VarintDelimitedReader{reader: r}
}

// ReadNext reads the next varint-delimited message. It returns the message
// bytes and nil error on success, nil and nil at EOF, or nil and an error
// if reading fails or the message is truncated.
func (v *VarintDelimitedReader) ReadNext() ([]byte, error) {
	length, err := v.readNextVarint()
	if err != nil {
		return nil, err
	}
	if length < 0 {
		// EOF
		return nil, nil
	}

	if length > maxFrameSize {
		return nil, &FrameTooLargeError{Size: uint64(length), Max: maxFrameSize}
	}

	// Read `length` bytes: first whatever is already buffered, then the
	// remainder from the reader. The remainder is read incrementally rather
	// than pre-allocating the attacker-declared `length`. maxFrameSize is
	// u32::MAX (to match Rust's acceptance range), so a single make([]byte,
	// length) would let one bogus frame header force a multi-GiB allocation
	// before the (short) stream is even read. io.ReadAll over a bounded
	// LimitReader instead grows in proportion to bytes actually delivered.
	bufferedCount := length
	if bufferedCount > v.bufLen {
		bufferedCount = v.bufLen
	}
	msg := make([]byte, bufferedCount)
	copy(msg, v.buf[:bufferedCount])
	v.consumeBuffer(bufferedCount)

	if bufferedCount < length {
		remaining := int64(length - bufferedCount)
		rest, readErr := io.ReadAll(io.LimitReader(v.reader, remaining))
		if readErr != nil {
			return nil, &ErrReadingDelimitedMessage{Err: readErr}
		}
		if int64(len(rest)) != remaining {
			return nil, &ErrReadingDelimitedMessage{Err: io.ErrUnexpectedEOF}
		}
		msg = append(msg, rest...)
	}

	return msg, nil
}

// readNextVarint reads a varint from the buffered data, refilling from the
// reader as needed. Returns -1 on EOF (no more data), or the decoded length.
func (v *VarintDelimitedReader) readNextVarint() (int, error) {
	if err := v.fillBuffer(); err != nil {
		return 0, err
	}
	if v.bufLen == 0 {
		return -1, nil
	}

	val, consumed := binary.Uvarint(v.buf[:v.bufLen])
	if consumed <= 0 {
		return 0, &ErrInvalidVarint{}
	}

	// Check the cap while val is still uint64, before any int() conversion.
	// On 32-bit platforms int is 32 bits and values in [2^31, u32::MAX] would
	// silently wrap to negative after int(val), triggering a false EOF. The
	// math.MaxInt constant is platform-specific: 2^63-1 on 64-bit (so this
	// check never fires there) and 2^31-1 on 32-bit (catches the overflow).
	if val > uint64(maxVarintValue) {
		return 0, &ErrVarintOverflow{Value: val, Max: uint64(maxVarintValue)}
	}
	if val > uint64(math.MaxInt) {
		// val is in (math.MaxInt, u32::MAX] on this platform; int(val) would
		// overflow. Return the same typed error so callers handle it uniformly.
		return 0, &ErrVarintOverflow{Value: val, Max: uint64(math.MaxInt)}
	}

	v.consumeBuffer(consumed)
	return int(val), nil
}

// maxVarintValue is the maximum protobuf varint32 value we accept.
const maxVarintValue = 1<<32 - 1

// fillBuffer reads bytes from the reader into the buffer until the buffer
// is full or the reader is exhausted.
func (v *VarintDelimitedReader) fillBuffer() error {
	for v.bufLen < varintMaxLength {
		n, err := v.reader.Read(v.buf[v.bufLen:])
		v.bufLen += n
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return &ErrReadingVarint{Err: err}
		}
		if n == 0 {
			return nil
		}
	}
	return nil
}

// consumeBuffer removes the first n bytes from the buffer.
func (v *VarintDelimitedReader) consumeBuffer(n int) {
	copy(v.buf[:], v.buf[n:v.bufLen])
	v.bufLen -= n
}

// WriteVarintDelimited writes a varint-length-prefixed message to w.
func WriteVarintDelimited(w io.Writer, data []byte) error {
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], uint64(len(data)))
	if _, err := w.Write(buf[:n]); err != nil {
		return &ErrWritingVarintLength{Err: err}
	}
	if _, err := w.Write(data); err != nil {
		return &ErrWritingDelimitedMessage{Err: err}
	}
	return nil
}
