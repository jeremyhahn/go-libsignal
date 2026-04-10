package backup

import (
	"fmt"
	"io"
	"math"
	"strings"
)

// Error represents an error encountered during backup reading or validation.
type Error struct {
	Kind    ErrorKind
	Message string
	Err     error
}

// ErrorKind categorizes backup errors.
type ErrorKind int

const (
	// ErrorKindValidation indicates a backup validation failure.
	ErrorKindValidation ErrorKind = iota
	// ErrorKindParse indicates a protobuf parsing or I/O error.
	ErrorKindParse
	// ErrorKindNoFrames indicates no frames were found in the backup.
	ErrorKindNoFrames
	// ErrorKindInvalidProtobuf indicates malformed protobuf data.
	ErrorKindInvalidProtobuf
	// ErrorKindHMACMismatch indicates the HMAC did not match.
	ErrorKindHMACMismatch
)

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("backup: %s: %v", e.Message, e.Err)
	}
	return fmt.Sprintf("backup: %s", e.Message)
}

func (e *Error) Unwrap() error {
	return e.Err
}

// FoundUnknownField records an unknown protobuf field found during backup
// parsing, including the frame index and the path within the protobuf message
// where the unknown field was found.
type FoundUnknownField struct {
	FrameIndex int
	Path       []PathPart
	Value      UnknownValue
}

// String returns a human-readable description of the unknown field.
func (f *FoundUnknownField) String() string {
	return fmt.Sprintf("in frame %d, %s has unknown %s",
		f.FrameIndex, FormatPath(f.Path), f.Value)
}

// ReadResult wraps the result of reading a backup along with any unknown
// fields encountered during parsing.
type ReadResult struct {
	Err                error
	FoundUnknownFields []FoundUnknownField
}

// BackupReader reads and parses frames from an encrypted or unencrypted
// backup stream. It wraps a VarintDelimitedReader and keeps track of the
// backup's intended purpose.
type BackupReader struct {
	Purpose Purpose
	reader  *VarintDelimitedReader
}

// NewBackupReader creates a BackupReader over a plaintext (unencrypted)
// reader with the given purpose. The reader should yield varint-delimited
// protobuf frames.
func NewBackupReader(r io.Reader, purpose Purpose) *BackupReader {
	return &BackupReader{
		Purpose: purpose,
		reader:  NewVarintDelimitedReader(r),
	}
}

// NewEncryptedBackupReader creates a BackupReader that first decrypts the
// encrypted backup from r using the provided key, then yields the decrypted
// frames. It verifies the HMAC before returning.
func NewEncryptedBackupReader(key *MessageBackupKey, r io.Reader, purpose Purpose) (*BackupReader, error) {
	fd := NewFrameDecryptor(key)
	frames, err := fd.DecryptFrames(r)
	if err != nil {
		return nil, &ErrDecryptingBackup{Err: err}
	}

	// Reconstruct varint-delimited stream from frames.
	fr := newFrameSliceReader(frames)
	return &BackupReader{
		Purpose: purpose,
		reader:  NewVarintDelimitedReader(fr),
	}, nil
}

// ReadNext reads the next raw frame from the backup. It returns nil, nil at
// the end of the stream.
func (br *BackupReader) ReadNext() ([]byte, error) {
	return br.reader.ReadNext()
}

// ReadAll reads all remaining frames from the backup and returns them.
func (br *BackupReader) ReadAll() ([][]byte, error) {
	var frames [][]byte
	for {
		frame, err := br.ReadNext()
		if err != nil {
			return frames, err
		}
		if frame == nil {
			return frames, nil
		}
		frames = append(frames, frame)
	}
}

// frameSliceReader is an io.Reader that yields pre-decrypted frames as a
// varint-delimited byte stream.
type frameSliceReader struct {
	frames [][]byte
	buf    []byte
}

func newFrameSliceReader(frames [][]byte) *frameSliceReader {
	return &frameSliceReader{frames: frames}
}

func (r *frameSliceReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if len(r.buf) > 0 {
			copied := copy(p[n:], r.buf)
			r.buf = r.buf[copied:]
			n += copied
			continue
		}
		if len(r.frames) == 0 {
			if n > 0 {
				return n, nil
			}
			return 0, io.EOF
		}
		// Encode next frame as varint-delimited.
		frame := r.frames[0]
		r.frames = r.frames[1:]
		r.buf = encodeVarintDelimited(frame)
	}
	return n, nil
}

func encodeVarintDelimited(data []byte) []byte {
	length := len(data)
	var buf [10]byte
	n := 0
	for length >= 0x80 {
		buf[n] = byte(length) | 0x80
		length >>= 7
		n++
	}
	buf[n] = byte(length)
	n++
	result := make([]byte, n+len(data))
	copy(result, buf[:n])
	copy(result[n:], data)
	return result
}

// PaddedLength rounds contentLength up to obscure the exact size of a backup.
// This matches the Rust reference: log_base(content_length, 1.05).ceil() -> 1.05^exp -> floor.
// Uses Go's IEEE 754 compliant math.Log and math.Pow, matching Rust's f64::log and f64::powf.
func PaddedLength(contentLength uint32) uint32 {
	const base = 1.05
	exp := math.Ceil(math.Log(float64(contentLength)) / math.Log(base))
	result := uint32(math.Floor(math.Pow(base, exp)))
	if result < 541 {
		return 541
	}
	return result
}

// PathPart represents a component of a protobuf message path.
type PathPart struct {
	// Kind is the type of path component.
	Kind PathPartKind
	// FieldName is the protobuf field name.
	FieldName string
	// Index is the repeated field index (for PathPartRepeated).
	Index int
	// Key is the map key string (for PathPartMapValue).
	Key string
}

// PathPartKind identifies the type of a PathPart.
type PathPartKind int

const (
	// PathPartField is a simple field reference.
	PathPartField PathPartKind = iota
	// PathPartRepeated is a repeated field element reference.
	PathPartRepeated
	// PathPartMapValue is a map field value reference.
	PathPartMapValue
)

// String returns a human-readable representation of the path part.
func (p PathPart) String() string {
	switch p.Kind {
	case PathPartField:
		return p.FieldName
	case PathPartRepeated:
		return fmt.Sprintf("%s[%d]", p.FieldName, p.Index)
	case PathPartMapValue:
		return fmt.Sprintf("%s[%s]", p.FieldName, p.Key)
	default:
		return p.FieldName
	}
}

// FormatPath formats a sequence of PathParts as a dot-separated string.
func FormatPath(parts []PathPart) string {
	strs := make([]string, len(parts))
	for i, p := range parts {
		strs[i] = p.String()
	}
	return strings.Join(strs, ".")
}

// UnknownValue represents an unknown value found in a protobuf message.
type UnknownValue struct {
	// Kind is the type of unknown value.
	Kind UnknownValueKind
	// Number is the enum value number (for UnknownValueEnumValue).
	Number int32
	// Tag is the field tag (for UnknownValueField).
	Tag uint32
}

// UnknownValueKind identifies the type of an UnknownValue.
type UnknownValueKind int

const (
	// UnknownValueEnumValue indicates an unknown enum variant.
	UnknownValueEnumValue UnknownValueKind = iota
	// UnknownValueField indicates an unknown field tag.
	UnknownValueField
)

// String returns a human-readable representation of the unknown value.
func (u UnknownValue) String() string {
	switch u.Kind {
	case UnknownValueEnumValue:
		return fmt.Sprintf("enum value %d", u.Number)
	case UnknownValueField:
		return fmt.Sprintf("field with tag %d", u.Tag)
	default:
		return "unknown"
	}
}
