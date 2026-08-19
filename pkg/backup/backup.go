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

// BackupInfoRaw contains the decoded fields of the first frame (BackupInfo
// protobuf) of a backup stream.
//
// Rust libsignal ref: rust/message-backup/src/backup.rs BackupInfo / BackupMeta
type BackupInfoRaw struct {
	// Version is the backup format version (must be 1).
	Version uint64
	// BackupTimeMs is the backup creation timestamp in milliseconds since epoch.
	BackupTimeMs uint64
	// MediaRootBackupKey is the 32-byte media root backup key, held in guarded
	// memory: it is long-lived key material that derives every media
	// encryption key in the backup, so it is kept out of the Go heap for the
	// same reasons as the session state in pkg/state/record.
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

// ValidatedReadResult is the result of ValidatedReadAll.
//
// The result owns the guarded media root backup key reached through Info, so
// callers must Destroy it once they are done — nothing reclaims guarded memory
// on its own. Info is a pointer so that copying the result cannot produce two
// apparent owners of the same locked buffer.
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

// ValidatedReadAll reads all frames, parses the first frame as BackupInfo,
// parses each subsequent frame as a Frame protobuf, and enforces the Purpose.
// It returns ErrInvalidBackupInfo if the first frame cannot be decoded or
// fails basic validation, ErrInvalidFrame for subsequent frame parse errors,
// and ErrPurposeMismatch if the BackupInfo version does not correspond to the
// expected purpose constraints.
//
// Unknown field numbers in any frame are recorded in ValidatedReadResult.FoundUnknownFields
// rather than causing an error, matching proto3 forward-compatibility rules.
//
// On success the caller owns the returned result, which carries the media root
// backup key in guarded memory, and must call Destroy on it. A failed call
// leaves nothing behind to release.
//
// Rust libsignal ref: rust/message-backup/src/backup.rs BackupReader::read_all
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

// parseBackupInfo decodes the BackupInfo protobuf from raw bytes.
// It returns the decoded fields, any unknown field numbers found, and any
// parse error.
//
// BackupInfo wire format (rust/message-backup/src/proto/backup.proto):
//
//	message BackupInfo {
//	  uint64 version = 1;           // varint
//	  uint64 backupTimeMs = 2;      // varint
//	  bytes mediaRootBackupKey = 3; // bytes (32 bytes)
//	  string currentAppVersion = 4; // bytes
//	  string firstAppVersion = 5;   // bytes
//	  bytes debugInfo = 6;          // bytes
//	}
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

// parseFrame performs a minimal parse of a Frame protobuf to detect unknown
// field numbers at the top level. It does not recursively validate sub-messages.
//
// Frame wire format (rust/message-backup/src/proto/backup.proto):
//
//	message Frame {
//	  oneof item {
//	    AccountData account = 1;
//	    Recipient recipient = 2;
//	    Chat chat = 3;
//	    ChatItem chatItem = 4;
//	    StickerPack stickerPack = 5;
//	    AdHocCall adHocCall = 6;
//	    NotificationProfile notificationProfile = 7;
//	    ChatFolder chatFolder = 8;
//	  }
//	}
//
// frameKnownFieldNames maps Frame oneof field numbers (1-8) to their proto
// names for use in *ErrUnexpectedWireType messages.
//
// Rust libsignal ref: rust/message-backup/src/proto/backup.proto Frame.item
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

// PaddedLength rounds contentLength up to obscure the exact size of a backup.
// This matches the Rust reference: log_base(content_length, 1.05).ceil() -> 1.05^exp -> floor.
// Uses Go's IEEE 754 compliant math.Log and math.Pow, matching Rust's f64::log and f64::powf.
//
// Rust libsignal ref: rust/message-backup/src/lib.rs padded_length
func PaddedLength(contentLength uint32) uint32 {
	const base = 1.05
	exp := math.Ceil(math.Log(float64(contentLength)) / math.Log(base))
	v := math.Floor(math.Pow(base, exp))
	// Clamp to [0, math.MaxUint32] before converting to uint32. Near 4 GiB the
	// float64 result can exceed math.MaxUint32, and Go's float64→uint32 cast is
	// implementation-defined in that range (Rust uses saturating_cast which
	// returns u32::MAX). Explicit clamping matches Rust's saturating behavior.
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
