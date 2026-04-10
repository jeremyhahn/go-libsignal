package backup

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/accountkeys"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
)

func newPNIForTest(uuid [16]byte) protocol.ServiceId {
	return protocol.NewPNI(uuid)
}

func TestErrorWithWrappedError(t *testing.T) {
	inner := io.ErrUnexpectedEOF
	e := &Error{Kind: ErrorKindParse, Message: "reading frame", Err: inner}
	got := e.Error()
	if !strings.Contains(got, "reading frame") || !strings.Contains(got, "unexpected EOF") {
		t.Errorf("Error() = %q, want to contain both message and wrapped error", got)
	}
	if e.Unwrap() != inner {
		t.Error("Unwrap() should return the inner error")
	}
}

func TestErrorWithoutWrappedError(t *testing.T) {
	e := &Error{Kind: ErrorKindNoFrames, Message: "no frames found"}
	got := e.Error()
	if !strings.Contains(got, "no frames found") {
		t.Errorf("Error() = %q, want to contain message", got)
	}
	if got := e.Unwrap(); got != nil {
		t.Errorf("Unwrap() = %v, want nil", got)
	}
}

func TestFoundUnknownFieldString(t *testing.T) {
	f := &FoundUnknownField{
		FrameIndex: 5,
		Path: []PathPart{
			{Kind: PathPartField, FieldName: "chat"},
			{Kind: PathPartRepeated, FieldName: "messages", Index: 3},
		},
		Value: UnknownValue{Kind: UnknownValueField, Tag: 42},
	}
	got := f.String()
	if !strings.Contains(got, "frame 5") {
		t.Errorf("String() = %q, missing frame index", got)
	}
	if !strings.Contains(got, "chat.messages[3]") {
		t.Errorf("String() = %q, missing path", got)
	}
	if !strings.Contains(got, "field with tag 42") {
		t.Errorf("String() = %q, missing unknown value", got)
	}
}

func TestPathPartString(t *testing.T) {
	tests := []struct {
		name string
		part PathPart
		want string
	}{
		{"field", PathPart{Kind: PathPartField, FieldName: "name"}, "name"},
		{"repeated", PathPart{Kind: PathPartRepeated, FieldName: "items", Index: 7}, "items[7]"},
		{"map", PathPart{Kind: PathPartMapValue, FieldName: "tags", Key: "foo"}, "tags[foo]"},
		{"unknown kind", PathPart{Kind: PathPartKind(99), FieldName: "fallback"}, "fallback"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.part.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatPath(t *testing.T) {
	parts := []PathPart{
		{Kind: PathPartField, FieldName: "a"},
		{Kind: PathPartField, FieldName: "b"},
	}
	got := FormatPath(parts)
	if got != "a.b" {
		t.Errorf("FormatPath() = %q, want %q", got, "a.b")
	}

	got = FormatPath(nil)
	if got != "" {
		t.Errorf("FormatPath(nil) = %q, want empty", got)
	}
}

func TestUnknownValueString(t *testing.T) {
	tests := []struct {
		name string
		val  UnknownValue
		want string
	}{
		{"enum", UnknownValue{Kind: UnknownValueEnumValue, Number: 3}, "enum value 3"},
		{"field", UnknownValue{Kind: UnknownValueField, Tag: 99}, "field with tag 99"},
		{"unknown", UnknownValue{Kind: UnknownValueKind(99)}, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.val.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewBackupReaderAndReadAll(t *testing.T) {
	// Build a varint-delimited stream with two messages.
	var buf bytes.Buffer
	if err := WriteVarintDelimited(&buf, []byte("frame1")); err != nil {
		t.Fatalf("WriteVarintDelimited failed: %v", err)
	}
	if err := WriteVarintDelimited(&buf, []byte("frame2")); err != nil {
		t.Fatalf("WriteVarintDelimited failed: %v", err)
	}

	br := NewBackupReader(&buf, PurposeRemoteBackup)
	if br.Purpose != PurposeRemoteBackup {
		t.Errorf("Purpose = %v, want PurposeRemoteBackup", br.Purpose)
	}

	frames, err := br.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(frames) != 2 {
		t.Fatalf("got %d frames, want 2", len(frames))
	}
	if string(frames[0]) != "frame1" || string(frames[1]) != "frame2" {
		t.Errorf("frames = %q %q, want frame1 frame2", frames[0], frames[1])
	}
}

func TestNewBackupReaderReadNext(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteVarintDelimited(&buf, []byte("only")); err != nil {
		t.Fatal(err)
	}

	br := NewBackupReader(&buf, PurposeDeviceTransfer)
	frame, err := br.ReadNext()
	if err != nil {
		t.Fatalf("ReadNext: %v", err)
	}
	if string(frame) != "only" {
		t.Errorf("got %q, want %q", frame, "only")
	}

	frame, err = br.ReadNext()
	if err != nil {
		t.Fatalf("ReadNext at EOF: %v", err)
	}
	if frame != nil {
		t.Errorf("expected nil at EOF, got %v", frame)
	}
}

func TestNewEncryptedBackupReader(t *testing.T) {
	key := testKey()
	frames := [][]byte{[]byte("encrypted frame 1"), []byte("encrypted frame 2")}

	var buf bytes.Buffer
	enc := NewFrameEncryptor(key)
	if err := enc.EncryptFrames(&buf, frames); err != nil {
		t.Fatalf("EncryptFrames: %v", err)
	}

	br, err := NewEncryptedBackupReader(key, bytes.NewReader(buf.Bytes()), PurposeRemoteBackup)
	if err != nil {
		t.Fatalf("NewEncryptedBackupReader: %v", err)
	}

	got, err := br.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(got) != len(frames) {
		t.Fatalf("frame count: got %d, want %d", len(got), len(frames))
	}
	for i := range frames {
		if !bytes.Equal(got[i], frames[i]) {
			t.Errorf("frame %d: got %q, want %q", i, got[i], frames[i])
		}
	}
}

func TestNewEncryptedBackupReaderError(t *testing.T) {
	key := testKey()
	_, err := NewEncryptedBackupReader(key, bytes.NewReader([]byte("too short")), PurposeRemoteBackup)
	if err == nil {
		t.Fatal("expected error for short data")
	}
}

func TestPaddedLength(t *testing.T) {
	tests := []struct {
		input uint32
		min   uint32
	}{
		{0, 541},
		{1, 541},
		{540, 541},
		{541, 541},
		{542, 542},      // should be >= 542
		{1000, 1000},     // should be >= 1000
		{10000, 10000},   // should be >= 10000
		{100000, 100000}, // should be >= 100000
	}
	for _, tt := range tests {
		got := PaddedLength(tt.input)
		if got < tt.min {
			t.Errorf("PaddedLength(%d) = %d, want >= %d", tt.input, got, tt.min)
		}
		// Must be at least as large as input.
		if got < tt.input {
			t.Errorf("PaddedLength(%d) = %d, smaller than input", tt.input, got)
		}
	}
}

func TestPaddedLengthMonotonic(t *testing.T) {
	// PaddedLength should be >= input for a range of values
	prev := uint32(0)
	for i := uint32(0); i < 2000; i += 10 {
		got := PaddedLength(i)
		if got < i {
			t.Errorf("PaddedLength(%d) = %d, less than input", i, got)
		}
		if got < prev {
			t.Errorf("PaddedLength(%d) = %d < PaddedLength earlier = %d, not monotonic", i, got, prev)
		}
		prev = got
	}
}

func TestFrameSliceReaderSmallBuffer(t *testing.T) {
	// Test reading frame slice with a very small read buffer to exercise partial reads.
	frames := [][]byte{[]byte("hello"), []byte("world")}
	fsr := newFrameSliceReader(frames)

	var result bytes.Buffer
	buf := make([]byte, 2) // very small buffer
	for {
		n, err := fsr.Read(buf)
		if n > 0 {
			result.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
	}

	// Should be able to read back the frames via varint reader.
	vr := NewVarintDelimitedReader(&result)
	for _, expected := range frames {
		got, err := vr.ReadNext()
		if err != nil {
			t.Fatalf("ReadNext: %v", err)
		}
		if !bytes.Equal(got, expected) {
			t.Errorf("got %q, want %q", got, expected)
		}
	}
}

func TestEncodeVarintDelimitedLargeMessage(t *testing.T) {
	// Test encoding a message larger than 127 bytes (requires multi-byte varint).
	msg := make([]byte, 300)
	for i := range msg {
		msg[i] = byte(i % 256)
	}
	encoded := encodeVarintDelimited(msg)
	// The varint for 300 needs 2 bytes (300 = 0xAC 0x02)
	if len(encoded) != 2+300 {
		t.Errorf("encoded length = %d, want %d", len(encoded), 2+300)
	}

	// Verify round-trip through reader.
	vr := NewVarintDelimitedReader(bytes.NewReader(encoded))
	got, err := vr.ReadNext()
	if err != nil {
		t.Fatalf("ReadNext: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Error("round-trip failed for large message")
	}
}

// --- purpose.go ---

func TestPurposeString(t *testing.T) {
	tests := []struct {
		p    Purpose
		want string
	}{
		{PurposeDeviceTransfer, "DeviceTransfer"},
		{PurposeRemoteBackup, "RemoteBackup"},
		{Purpose(99), "Purpose(99)"},
	}
	for _, tt := range tests {
		if got := tt.p.String(); got != tt.want {
			t.Errorf("Purpose(%d).String() = %q, want %q", int(tt.p), got, tt.want)
		}
	}
}

func TestParsePurpose(t *testing.T) {
	tests := []struct {
		input   string
		want    Purpose
		wantErr bool
	}{
		{"backup", PurposeRemoteBackup, false},
		{"remote_backup", PurposeRemoteBackup, false},
		{"remote-backup", PurposeRemoteBackup, false},
		{"transfer", PurposeDeviceTransfer, false},
		{"device_transfer", PurposeDeviceTransfer, false},
		{"device-transfer", PurposeDeviceTransfer, false},
		{"unknown", 0, true},
		{"", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParsePurpose(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParsePurpose(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Errorf("ParsePurpose(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// --- validation.go ---

func TestValidationError(t *testing.T) {
	t.Run("with frame index", func(t *testing.T) {
		e := &ValidationError{FrameIndex: 42, Message: "bad field"}
		got := e.Error()
		if !strings.Contains(got, "42") || !strings.Contains(got, "bad field") {
			t.Errorf("Error() = %q, want frame index and message", got)
		}
	})
	t.Run("negative frame index", func(t *testing.T) {
		e := &ValidationError{FrameIndex: -1, Message: "global error"}
		got := e.Error()
		if strings.Contains(got, "frame") && !strings.Contains(got, "global error") {
			t.Errorf("Error() = %q, unexpected format", got)
		}
		if !strings.Contains(got, "global error") {
			t.Errorf("Error() = %q, should contain message", got)
		}
	})
}

func TestItoa(t *testing.T) {
	tests := []struct {
		input int
		want  string
	}{
		{0, "0"},
		{1, "1"},
		{42, "42"},
		{-7, "-7"},
		{12345, "12345"},
		{-99, "-99"},
	}
	for _, tt := range tests {
		got := itoa(tt.input)
		if got != tt.want {
			t.Errorf("itoa(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// --- frame.go HMACMismatchError ---

func TestHMACMismatchErrorString(t *testing.T) {
	e := &HMACMismatchError{}
	got := e.Error()
	if !strings.Contains(got, "HMAC verification failed") {
		t.Errorf("Error() = %q, want to contain 'HMAC verification failed'", got)
	}
}

// --- frame.go pkcs7Unpad edge cases ---

func TestPkcs7UnpadErrors(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		_, err := pkcs7Unpad(nil, 16)
		if err == nil {
			t.Fatal("expected error for nil data")
		}
	})
	t.Run("not multiple of block size", func(t *testing.T) {
		_, err := pkcs7Unpad(make([]byte, 15), 16)
		if err == nil {
			t.Fatal("expected error for non-multiple data")
		}
	})
	t.Run("zero padding", func(t *testing.T) {
		data := make([]byte, 16)
		data[15] = 0 // padding byte = 0
		_, err := pkcs7Unpad(data, 16)
		if err == nil {
			t.Fatal("expected error for zero padding")
		}
	})
	t.Run("padding too large", func(t *testing.T) {
		data := make([]byte, 16)
		data[15] = 17 // padding byte > block size
		_, err := pkcs7Unpad(data, 16)
		if err == nil {
			t.Fatal("expected error for padding too large")
		}
	})
	t.Run("inconsistent padding bytes", func(t *testing.T) {
		data := make([]byte, 16)
		data[15] = 3 // says 3 bytes of padding
		data[14] = 3
		data[13] = 1 // inconsistent
		_, err := pkcs7Unpad(data, 16)
		if err == nil {
			t.Fatal("expected error for inconsistent padding")
		}
	})
}

// --- frame.go VerifyHMAC short data ---

func TestVerifyHMACTooShort(t *testing.T) {
	key := testKey()
	err := VerifyHMAC(key, bytes.NewReader([]byte("short")))
	if err == nil {
		t.Fatal("expected error for short data")
	}
}

// --- key.go BackupID.Bytes ---

func TestBackupIDBytes(t *testing.T) {
	id := &BackupID{id: [BackupIDLen]byte{1, 2, 3}}
	b := id.Bytes()
	if len(b) != BackupIDLen {
		t.Fatalf("Bytes() length = %d, want %d", len(b), BackupIDLen)
	}
	if b[0] != 1 || b[1] != 2 || b[2] != 3 {
		t.Error("Bytes() content mismatch")
	}
}

// --- key.go DeriveBackupKey invalid pool ---

func TestDeriveBackupKeyInvalidPool(t *testing.T) {
	pool := accountkeys.AccountEntropyPool("short")
	_, err := DeriveBackupKey(pool)
	if err == nil {
		t.Fatal("expected error for short entropy pool")
	}
}

// --- key.go DeriveBackupID with non-ACI ---

func TestDeriveBackupIDNonACI(t *testing.T) {
	pool := accountkeys.AccountEntropyPool(fakeAccountEntropyPool)
	bk, err := DeriveBackupKey(pool)
	if err != nil {
		t.Fatalf("DeriveBackupKey: %v", err)
	}

	// Create a PNI service ID (kind != ACI).
	var uuid [16]byte
	pni := newPNIForTest(uuid)
	_, err = bk.DeriveBackupID(pni)
	if err == nil {
		t.Fatal("expected error for PNI service ID")
	}
}

// --- ReadAll with error ---

func TestReadAllWithError(t *testing.T) {
	// Create a reader that returns an error after some data.
	errReader := &errorAfterReader{data: []byte{5, 'h', 'e', 'l', 'l', 'o'}, errAfter: 6}
	br := NewBackupReader(errReader, PurposeRemoteBackup)
	_, err := br.ReadAll()
	// Should successfully read one frame and then get EOF.
	if err != nil {
		t.Fatalf("ReadAll: unexpected error %v", err)
	}
}

type errorAfterReader struct {
	data     []byte
	pos      int
	errAfter int
}

func (r *errorAfterReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	if r.pos >= r.errAfter {
		return n, io.EOF
	}
	return n, nil
}
