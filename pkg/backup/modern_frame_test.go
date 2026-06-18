package backup

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// TestModernFormatRoundTrip verifies that EncryptFramesModern produces a
// stream that DecryptFrames can decode, exercising the full modern
// SBACKUP\x01 encode/decode path.
func TestModernFormatRoundTrip(t *testing.T) {
	key := testKey()
	defer key.Zeroize()

	meta := TestMetadata()
	frames := [][]byte{
		[]byte("modern frame one"),
		[]byte("modern frame two"),
	}

	var buf bytes.Buffer
	enc := NewFrameEncryptor(key)
	if err := enc.EncryptFramesModern(&buf, frames, meta); err != nil {
		t.Fatalf("EncryptFramesModern: %v", err)
	}

	// Verify that the output starts with the SBACKUP\x01 magic.
	data := buf.Bytes()
	if !IsMagicNumber(data) {
		t.Fatalf("output does not start with SBACKUP\\x01 magic (got %x)", data[:8])
	}

	dec := NewFrameDecryptor(key)
	got, err := dec.DecryptFrames(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("DecryptFrames: %v", err)
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

// TestModernFormatRoundTripSinglePair tests modern format with metadata
// that has only one forward secrecy pair (the first-backup case).
func TestModernFormatRoundTripSinglePair(t *testing.T) {
	key := testKey()
	defer key.Zeroize()

	meta := &BackupMetadata{
		IV: make([]byte, backupMetadataIVLen),
		Pairs: []ForwardSecrecyPair{
			{
				CT:     bytes.Repeat([]byte{0xAA}, expectedCTLen),
				PWSalt: bytes.Repeat([]byte{0xBB}, expectedPWSaltLen),
			},
		},
	}
	frames := [][]byte{[]byte("single pair frame")}

	var buf bytes.Buffer
	enc := NewFrameEncryptor(key)
	if err := enc.EncryptFramesModern(&buf, frames, meta); err != nil {
		t.Fatalf("EncryptFramesModern: %v", err)
	}

	dec := NewFrameDecryptor(key)
	got, err := dec.DecryptFrames(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("DecryptFrames: %v", err)
	}
	if len(got) != 1 || string(got[0]) != "single pair frame" {
		t.Fatalf("got %v, want [%q]", got, "single pair frame")
	}
}

// TestModernFormatInvalidMetadata verifies that DecryptFrames rejects a
// modern stream with malformed metadata (e.g., wrong IV length).
func TestModernFormatInvalidMetadata(t *testing.T) {
	key := testKey()
	defer key.Zeroize()

	// Build a modern header with an invalid metadata (bad IV length).
	badMeta := &BackupMetadata{
		IV: make([]byte, 5), // should be 12 bytes
		Pairs: []ForwardSecrecyPair{
			{
				CT:     bytes.Repeat([]byte{1}, expectedCTLen),
				PWSalt: bytes.Repeat([]byte{2}, expectedPWSaltLen),
			},
		},
	}

	// Encode the bad metadata manually (bypassing ValidateMetadata).
	metaBytes, _ := encodeMetadataPb(badMeta)

	var buf bytes.Buffer
	buf.WriteString(MagicNumber)
	if err := WriteVarintDelimited(&buf, metaBytes); err != nil {
		t.Fatalf("WriteVarintDelimited: %v", err)
	}
	// Append some dummy payload bytes so size checks pass.
	buf.Write(make([]byte, AESIVSize+64+HMACLen))

	dec := NewFrameDecryptor(key)
	_, err := dec.DecryptFrames(bytes.NewReader(buf.Bytes()))
	if err == nil {
		t.Fatal("expected error for invalid metadata")
	}
	var metaErr *ErrMetadataValidation
	if !errors.As(err, &metaErr) {
		t.Fatalf("expected *ErrMetadataValidation, got %T: %v", err, err)
	}
}

// TestModernFormatCloseToMagicRejected verifies that a stream starting with
// "SBACKUP\x02" (close but not a valid magic) is rejected.
func TestModernFormatCloseToMagicRejected(t *testing.T) {
	key := testKey()
	defer key.Zeroize()

	data := append([]byte("SBACKUP\x02"), make([]byte, 100)...)
	dec := NewFrameDecryptor(key)
	_, err := dec.DecryptFrames(bytes.NewReader(data))
	if err == nil {
		t.Fatal("expected error for close-to-magic stream")
	}
	var magicErr *ErrInvalidBackupMagic
	if !errors.As(err, &magicErr) {
		t.Fatalf("expected *ErrInvalidBackupMagic, got %T: %v", err, err)
	}
}

// TestModernFormatMetadataPbRoundTrip tests the encode/decode cycle of the
// minimal MetadataPb protobuf codec.
func TestModernFormatMetadataPbRoundTrip(t *testing.T) {
	original := TestMetadata()

	encoded, err := encodeMetadataPb(original)
	if err != nil {
		t.Fatalf("encodeMetadataPb: %v", err)
	}

	decoded, err := decodeMetadataPb(encoded)
	if err != nil {
		t.Fatalf("decodeMetadataPb: %v", err)
	}

	if len(decoded.Pairs) != len(original.Pairs) {
		t.Fatalf("pairs count: got %d, want %d", len(decoded.Pairs), len(original.Pairs))
	}
	for i, pair := range original.Pairs {
		if !bytes.Equal(decoded.Pairs[i].CT, pair.CT) {
			t.Errorf("pair[%d].CT mismatch", i)
		}
		if !bytes.Equal(decoded.Pairs[i].PWSalt, pair.PWSalt) {
			t.Errorf("pair[%d].PWSalt mismatch", i)
		}
	}
	if !bytes.Equal(decoded.IV, original.IV) {
		t.Errorf("IV mismatch: got %x, want %x", decoded.IV, original.IV)
	}
}

// TestEncryptFramesModernInvalidMetadata verifies that EncryptFramesModern
// rejects metadata that fails ValidateMetadata.
func TestEncryptFramesModernInvalidMetadata(t *testing.T) {
	key := testKey()
	defer key.Zeroize()

	badMeta := &BackupMetadata{
		IV:    make([]byte, backupMetadataIVLen),
		Pairs: nil, // no pairs: invalid
	}

	var buf bytes.Buffer
	enc := NewFrameEncryptor(key)
	err := enc.EncryptFramesModern(&buf, nil, badMeta)
	if err == nil {
		t.Fatal("expected error for invalid metadata")
	}
	var metaErr *ErrMetadataValidation
	if !errors.As(err, &metaErr) {
		t.Fatalf("expected *ErrMetadataValidation, got %T: %v", err, err)
	}
}

// TestErrInvalidBackupMagic checks the error message format.
func TestErrInvalidBackupMagic(t *testing.T) {
	e := &ErrInvalidBackupMagic{Got: []byte("SBACKUP\x02")}
	msg := e.Error()
	if msg == "" {
		t.Error("Error() returned empty string")
	}
	// Should contain some representation of the bad bytes and the expected magic.
	if len(msg) < 10 {
		t.Errorf("Error() message too short: %q", msg)
	}
}

// TestErrMetadataValidation checks wrapping and Unwrap.
func TestErrMetadataValidation(t *testing.T) {
	inner := &ForwardSecrecyError{Kind: ForwardSecrecyErrorMissingField, Message: "missing pair"}
	e := &ErrMetadataValidation{Err: inner}
	if e.Unwrap() != inner {
		t.Error("Unwrap() should return inner error")
	}
	if !errors.Is(e, inner) {
		t.Error("errors.Is should find inner error through ErrMetadataValidation")
	}
	msg := e.Error()
	if !strings.Contains(msg, "metadata") {
		t.Errorf("ErrMetadataValidation.Error() = %q, want 'metadata'", msg)
	}
}

// TestDecodeMetadataPbEmptyBytes verifies that an empty byte slice returns
// an empty BackupMetadata without error (proto3 allows all fields absent).
func TestDecodeMetadataPbEmptyBytes(t *testing.T) {
	meta, err := decodeMetadataPb(nil)
	if err != nil {
		t.Fatalf("decodeMetadataPb(nil): %v", err)
	}
	if meta == nil {
		t.Fatal("expected non-nil BackupMetadata")
	}
	if len(meta.Pairs) != 0 {
		t.Errorf("expected 0 pairs, got %d", len(meta.Pairs))
	}
}

// TestLegacyFormatStillDecrypts verifies that the legacy path is not broken
// by the modern format detection.
func TestLegacyFormatStillDecrypts(t *testing.T) {
	key := testKey()
	defer key.Zeroize()

	frames := [][]byte{[]byte("legacy frame")}

	var buf bytes.Buffer
	enc := NewFrameEncryptor(key)
	if err := enc.EncryptFrames(&buf, frames); err != nil {
		t.Fatalf("EncryptFrames: %v", err)
	}

	// The output should NOT start with the magic.
	data := buf.Bytes()
	if IsMagicNumber(data) {
		t.Fatal("legacy output should not start with SBACKUP\\x01 magic")
	}

	dec := NewFrameDecryptor(key)
	got, err := dec.DecryptFrames(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("DecryptFrames (legacy): %v", err)
	}
	if len(got) != 1 || string(got[0]) != "legacy frame" {
		t.Fatalf("got %v, want [legacy frame]", got)
	}
}
