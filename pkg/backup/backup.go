package backup

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// mediaRootBackupKeyLen is the required length of BackupInfo.mediaRootBackupKey.
const mediaRootBackupKeyLen = 32

// BackupInfoVersion1 is the only supported BackupInfo version.
// Rust libsignal ref: rust/message-backup/src/backup.rs BackupInfo.version
const BackupInfoVersion1 = uint64(1)

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

// BackupInfoRaw holds the decoded first frame of a backup stream (rust/message-backup/src/backup.rs BackupInfo).
type BackupInfoRaw struct {
	// Version is the backup format version (must be 1).
	Version uint64
	// BackupTimeMs is the backup creation timestamp in milliseconds since epoch.
	BackupTimeMs uint64
	// MediaRootBackupKey is the 32-byte media root key, kept in guarded memory.
	MediaRootBackupKey *secret.Secret
}

// Destroy releases the guarded media root backup key. It is idempotent and
// safe to call on a nil BackupInfoRaw or one that carries no key.
func (b *BackupInfoRaw) Destroy() {
	if b == nil {
		return
	}
	b.MediaRootBackupKey.Destroy()
}

// ValidatedReadResult is the result of ValidatedReadAll; it owns guarded key memory, so callers must Destroy it.
type ValidatedReadResult struct {
	// Info is the parsed first-frame BackupInfo.
	Info *BackupInfoRaw
	// Frames contains the raw bytes of all subsequent frames (excluding BackupInfo).
	Frames [][]byte
	// FoundUnknownFields records unknown protobuf field numbers encountered
	// in any frame.
	FoundUnknownFields []FoundUnknownField
}

// Destroy releases the guarded key material the result carries. It is
// idempotent and safe to call on a nil result or one that carries no key, so
// `defer result.Destroy()` may be taken before the error is checked.
func (r *ValidatedReadResult) Destroy() {
	if r == nil {
		return
	}
	r.Info.Destroy()
}

// ValidatedReadAll parses and validates every frame against the Purpose, records unknown fields, and returns a result the caller must Destroy.
func (br *BackupReader) ValidatedReadAll(purpose Purpose) (_ *ValidatedReadResult, err error) {
	result := &ValidatedReadResult{}

	// Read and parse the first frame as BackupInfo.
	firstRaw, err := br.ReadNext()
	if err != nil {
		return nil, &ErrInvalidBackupInfo{Err: err}
	}
	if firstRaw == nil {
		return nil, &ErrInvalidBackupInfo{Err: nil}
	}

	info, unknownFields, err := parseBackupInfo(firstRaw)
	if err != nil {
		return nil, &ErrInvalidBackupInfo{Err: err}
	}
	// From here on the parsed info owns guarded key material. Release it unless
	// it reaches the caller in a successful result, so that a malformed backup
	// cannot strand mlock'd pages.
	defer func() {
		if err != nil {
			info.Destroy()
		}
	}()

	for i, f := range unknownFields {
		f.FrameIndex = 0
		unknownFields[i] = f
	}
	result.FoundUnknownFields = append(result.FoundUnknownFields, unknownFields...)

	// Validate version.
	if info.Version != BackupInfoVersion1 {
		return nil, &ErrInvalidBackupInfo{
			Err: &ErrUnsupportedBackupInfoVersion{Got: info.Version, Want: BackupInfoVersion1},
		}
	}

	// Validate purpose: the Purpose field is passed by the caller; for remote
	// backups we require that mediaRootBackupKey is present (32 bytes).
	// Device-transfer backups do not require the key.
	if purpose == PurposeRemoteBackup && info.MediaRootBackupKey.Size() != mediaRootBackupKeyLen {
		return nil, &ErrPurposeMismatch{Want: purpose, Got: br.Purpose}
	}

	result.Info = info

	// Read and parse all subsequent frames.
	for frameIdx := 1; ; frameIdx++ {
		raw, err := br.ReadNext()
		if err != nil {
			return nil, &ErrInvalidFrame{Index: frameIdx, Err: err}
		}
		if raw == nil {
			break
		}

		unknown, err := parseFrame(raw)
		if err != nil {
			return nil, &ErrInvalidFrame{Index: frameIdx, Err: err}
		}
		for _, f := range unknown {
			result.FoundUnknownFields = append(result.FoundUnknownFields, FoundUnknownField{
				FrameIndex: frameIdx,
				Path:       f.Path,
				Value:      f.Value,
			})
		}

		result.Frames = append(result.Frames, raw)
	}

	return result, nil
}

// parseBackupInfo decodes a BackupInfo protobuf (rust/message-backup/src/proto/backup.proto) and returns its unknown field numbers.
func parseBackupInfo(b []byte) (_ *BackupInfoRaw, unknowns []FoundUnknownField, err error) {
	info := &BackupInfoRaw{}
	data := b

	// Release the guarded key already decoded if parsing fails further along,
	// so that malformed input cannot strand mlock'd pages.
	defer func() {
		if err != nil {
			info.Destroy()
		}
	}()

	for len(data) > 0 {
		tag, n := binary.Uvarint(data)
		if n <= 0 {
			return nil, nil, &ErrInvalidProtoWireFormat{WireType: 0, Reason: "truncated tag varint in BackupInfo"}
		}
		data = data[n:]
		fieldNum := tag >> 3
		wireType := tag & 7

		switch fieldNum {
		case 1: // version, varint
			if wireType != 0 {
				return nil, nil, &ErrUnexpectedWireType{Field: "BackupInfo.version", WireType: wireType}
			}
			val, n := binary.Uvarint(data)
			if n <= 0 {
				return nil, nil, &ErrInvalidProtoWireFormat{WireType: wireType, Reason: "truncated varint for BackupInfo.version"}
			}
			data = data[n:]
			info.Version = val
		case 2: // backupTimeMs, varint
			if wireType != 0 {
				return nil, nil, &ErrUnexpectedWireType{Field: "BackupInfo.backupTimeMs", WireType: wireType}
			}
			val, n := binary.Uvarint(data)
			if n <= 0 {
				return nil, nil, &ErrInvalidProtoWireFormat{WireType: wireType, Reason: "truncated varint for BackupInfo.backupTimeMs"}
			}
			data = data[n:]
			info.BackupTimeMs = val
		case 3: // mediaRootBackupKey, bytes
			if wireType != 2 {
				return nil, nil, &ErrUnexpectedWireType{Field: "BackupInfo.mediaRootBackupKey", WireType: wireType}
			}
			length, n := binary.Uvarint(data)
			if n <= 0 {
				return nil, nil, &ErrInvalidProtoWireFormat{WireType: wireType, Reason: "truncated length varint for BackupInfo.mediaRootBackupKey"}
			}
			data = data[n:]
			if uint64(len(data)) < length {
				return nil, nil, &ErrTruncatedField{Field: "BackupInfo.mediaRootBackupKey"}
			}
			key := make([]byte, length)
			copy(key, data[:length])
			guarded, gErr := secret.NewOptional(key)
			if gErr != nil {
				return nil, nil, gErr
			}
			// A singular protobuf field may legally repeat, last one wins.
			// Release the superseded allocation rather than abandoning it.
			info.MediaRootBackupKey.Destroy()
			info.MediaRootBackupKey = guarded
			data = data[length:]
		case 4: // currentAppVersion, string (length-delimited)
			if wireType != 2 {
				return nil, nil, &ErrUnexpectedWireType{Field: "BackupInfo.currentAppVersion", WireType: wireType}
			}
			var err error
			data, err = skipBackupProtoField(data, wireType)
			if err != nil {
				return nil, nil, err
			}
		case 5: // firstAppVersion, string (length-delimited)
			if wireType != 2 {
				return nil, nil, &ErrUnexpectedWireType{Field: "BackupInfo.firstAppVersion", WireType: wireType}
			}
			var err error
			data, err = skipBackupProtoField(data, wireType)
			if err != nil {
				return nil, nil, err
			}
		case 6: // debugInfo, bytes (length-delimited)
			if wireType != 2 {
				return nil, nil, &ErrUnexpectedWireType{Field: "BackupInfo.debugInfo", WireType: wireType}
			}
			var err error
			data, err = skipBackupProtoField(data, wireType)
			if err != nil {
				return nil, nil, err
			}
		default:
			// Unknown field: record it and skip.
			unknowns = append(unknowns, FoundUnknownField{
				Value: UnknownValue{Kind: UnknownValueField, Tag: uint32(tag)},
			})
			var err error
			data, err = skipBackupProtoField(data, wireType)
			if err != nil {
				return nil, nil, err
			}
		}
	}
	return info, unknowns, nil
}

// parseFrame reports unknown top-level Frame fields without validating sub-messages; frameKnownFieldNames names fields 1-8.
var frameKnownFieldNames = map[uint64]string{
	1: "Frame.account",
	2: "Frame.recipient",
	3: "Frame.chat",
	4: "Frame.chatItem",
	5: "Frame.stickerPack",
	6: "Frame.adHocCall",
	7: "Frame.notificationProfile",
	8: "Frame.chatFolder",
}

func parseFrame(b []byte) ([]FoundUnknownField, error) {
	const maxKnownField = 8
	var unknowns []FoundUnknownField
	data := b
	for len(data) > 0 {
		tag, n := binary.Uvarint(data)
		if n <= 0 {
			return nil, &ErrInvalidProtoWireFormat{WireType: 0, Reason: "truncated tag varint in Frame"}
		}
		data = data[n:]
		fieldNum := tag >> 3
		wireType := tag & 7

		if fieldName, known := frameKnownFieldNames[fieldNum]; known {
			// All Frame oneof branches are submessages: wire type 2 is required.
			if wireType != 2 {
				return nil, &ErrUnexpectedWireType{Field: fieldName, WireType: wireType}
			}
		}

		var err error
		data, err = skipBackupProtoField(data, wireType)
		if err != nil {
			return nil, err
		}
		if fieldNum > maxKnownField {
			unknowns = append(unknowns, FoundUnknownField{
				Value: UnknownValue{Kind: UnknownValueField, Tag: uint32(tag)},
			})
		}
	}
	return unknowns, nil
}

// skipBackupProtoField skips one protobuf field value of the given wire type.
// Returns the remaining bytes after the field, or an *ErrInvalidProtoWireFormat
// if the wire type is unsupported or the encoded value is truncated.
func skipBackupProtoField(b []byte, wireType uint64) ([]byte, error) {
	switch wireType {
	case 0: // varint
		_, n := binary.Uvarint(b)
		if n <= 0 {
			return b, &ErrInvalidProtoWireFormat{WireType: wireType, Reason: "truncated varint"}
		}
		return b[n:], nil
	case 1: // 64-bit
		if len(b) < 8 {
			return b, &ErrInvalidProtoWireFormat{WireType: wireType, Reason: "truncated 64-bit field"}
		}
		return b[8:], nil
	case 2: // length-delimited
		length, n := binary.Uvarint(b)
		if n <= 0 {
			return b, &ErrInvalidProtoWireFormat{WireType: wireType, Reason: "truncated length varint"}
		}
		b = b[n:]
		if uint64(len(b)) < length {
			return b, &ErrInvalidProtoWireFormat{WireType: wireType, Reason: "length-delimited field truncated"}
		}
		return b[length:], nil
	case 5: // 32-bit
		if len(b) < 4 {
			return b, &ErrInvalidProtoWireFormat{WireType: wireType, Reason: "truncated 32-bit field"}
		}
		return b[4:], nil
	default:
		return b, &ErrInvalidProtoWireFormat{WireType: wireType, Reason: "unsupported wire type"}
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

// PaddedLength rounds contentLength up to the next power of 1.05, as Rust message-backup padded_length.
func PaddedLength(contentLength uint32) uint32 {
	const base = 1.05
	exp := math.Ceil(math.Log(float64(contentLength)) / math.Log(base))
	v := math.Floor(math.Pow(base, exp))
	// Clamp to MaxUint32 before the cast, matching Rust's saturating cast.
	if v >= math.MaxUint32 {
		return math.MaxUint32
	}
	result := uint32(v)
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
