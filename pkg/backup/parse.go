package backup

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	varintMaxLength = 10

	// maxFrameSize is the maximum allowed frame size in bytes (10 MiB).
	// This prevents a malicious varint from triggering a multi-GiB allocation
	// that could exhaust memory. Normal backup frames are well below this limit.
	maxFrameSize = 10 * 1024 * 1024
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

	// Read `length` bytes, first from the buffer, then from the reader.
	msg := make([]byte, length)
	bufferedCount := length
	if bufferedCount > v.bufLen {
		bufferedCount = v.bufLen
	}
	copy(msg, v.buf[:bufferedCount])
	v.consumeBuffer(bufferedCount)

	if bufferedCount < length {
		_, err := io.ReadFull(v.reader, msg[bufferedCount:])
		if err != nil {
			return nil, &ErrReadingDelimitedMessage{Err: err}
		}
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
	if val > uint64(maxVarintValue) {
		return 0, &ErrVarintOverflow{Value: val, Max: uint64(maxVarintValue)}
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
