package backup

import (
	"bytes"
	"errors"
	"testing"
)

// buildTestBackupStream builds a varint-delimited stream with a minimal
// BackupInfo frame (first) followed by zero or more Frame bytes (subsequent).
// The BackupInfo is encoded with the provided version and mediaRootBackupKey.
func buildTestBackupStream(t *testing.T, version uint64, mediaRootBackupKey []byte, frames ...[]byte) []byte {
	t.Helper()
	var buf bytes.Buffer

	// Encode minimal BackupInfo proto:
	//   field 1 (version), varint
	//   field 3 (mediaRootBackupKey), bytes (if non-nil)
	var backupInfo bytes.Buffer
	writeTestVarintField(&backupInfo, 1, version)
	if mediaRootBackupKey != nil {
		writeTestLenField(&backupInfo, 3, mediaRootBackupKey)
	}

	if err := WriteVarintDelimited(&buf, backupInfo.Bytes()); err != nil {
		t.Fatalf("WriteVarintDelimited(backupInfo): %v", err)
	}

	for _, frame := range frames {
		if err := WriteVarintDelimited(&buf, frame); err != nil {
			t.Fatalf("WriteVarintDelimited(frame): %v", err)
		}
	}
	return buf.Bytes()
}

// writeTestVarintField writes field_num (wire type 0, varint) to w.
func writeTestVarintField(w *bytes.Buffer, fieldNum, val uint64) {
	var tagBuf [10]byte
	n := putUvarint(tagBuf[:], fieldNum<<3)
	w.Write(tagBuf[:n])
	n = putUvarint(tagBuf[:], val)
	w.Write(tagBuf[:n])
}

// writeTestLenField writes field_num (wire type 2, length-delimited) to w.
func writeTestLenField(w *bytes.Buffer, fieldNum uint64, val []byte) {
	var tagBuf [10]byte
	n := putUvarint(tagBuf[:], fieldNum<<3|2)
	w.Write(tagBuf[:n])
	n = putUvarint(tagBuf[:], uint64(len(val)))
	w.Write(tagBuf[:n])
	w.Write(val)
}

// putUvarint encodes a varint into buf and returns the number of bytes used.
func putUvarint(buf []byte, x uint64) int {
	n := 0
	for x >= 0x80 {
		buf[n] = byte(x) | 0x80
		x >>= 7
		n++
	}
	buf[n] = byte(x)
	return n + 1
}

// TestValidatedReadAllSuccess verifies the happy path: a valid BackupInfo
// followed by two Frame bytes. The Purpose is RemoteBackup and the
// mediaRootBackupKey is 32 bytes.
func TestValidatedReadAllSuccess(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, 32)
	// Build two minimal Frame protobufs (field 1, account: empty bytes).
	frame1 := buildMinimalFrame()
	frame2 := buildMinimalFrame()

	stream := buildTestBackupStream(t, BackupInfoVersion1, key, frame1, frame2)
	br := NewBackupReader(bytes.NewReader(stream), PurposeRemoteBackup)

	result, err := br.ValidatedReadAll(PurposeRemoteBackup)
	if err != nil {
		t.Fatalf("ValidatedReadAll: %v", err)
	}
	defer result.Destroy()
	if result.Info.Version != BackupInfoVersion1 {
		t.Errorf("Version = %d, want %d", result.Info.Version, BackupInfoVersion1)
	}
	if !result.Info.MediaRootBackupKey.EqualTo(key) {
		t.Errorf("MediaRootBackupKey mismatch")
	}
	if len(result.Frames) != 2 {
		t.Fatalf("Frames count = %d, want 2", len(result.Frames))
	}
	if len(result.FoundUnknownFields) != 0 {
		t.Errorf("unexpected unknown fields: %v", result.FoundUnknownFields)
	}
}

// TestValidatedReadAllNoFirstFrame verifies that an empty stream returns
// ErrInvalidBackupInfo.
func TestValidatedReadAllNoFirstFrame(t *testing.T) {
	br := NewBackupReader(bytes.NewReader(nil), PurposeRemoteBackup)
	_, err := br.ValidatedReadAll(PurposeRemoteBackup)
	if err == nil {
		t.Fatal("expected error for empty stream")
	}
	var biErr *ErrInvalidBackupInfo
	if !errors.As(err, &biErr) {
		t.Fatalf("expected *ErrInvalidBackupInfo, got %T: %v", err, err)
	}
}

// TestValidatedReadAllBadVersion verifies that a BackupInfo with an
// unrecognised version returns ErrInvalidBackupInfo.
func TestValidatedReadAllBadVersion(t *testing.T) {
	stream := buildTestBackupStream(t, 99, bytes.Repeat([]byte{0}, 32))
	br := NewBackupReader(bytes.NewReader(stream), PurposeRemoteBackup)
	_, err := br.ValidatedReadAll(PurposeRemoteBackup)
	if err == nil {
		t.Fatal("expected error for bad version")
	}
	var biErr *ErrInvalidBackupInfo
	if !errors.As(err, &biErr) {
		t.Fatalf("expected *ErrInvalidBackupInfo, got %T: %v", err, err)
	}
}

// TestValidatedReadAllPurposeMismatchMissingKey verifies that a RemoteBackup
// without a 32-byte mediaRootBackupKey returns ErrPurposeMismatch.
func TestValidatedReadAllPurposeMismatchMissingKey(t *testing.T) {
	// No key: should fail purpose enforcement for RemoteBackup.
	stream := buildTestBackupStream(t, BackupInfoVersion1, nil)
	br := NewBackupReader(bytes.NewReader(stream), PurposeRemoteBackup)
	_, err := br.ValidatedReadAll(PurposeRemoteBackup)
	if err == nil {
		t.Fatal("expected ErrPurposeMismatch for missing mediaRootBackupKey")
	}
	var pmErr *ErrPurposeMismatch
	if !errors.As(err, &pmErr) {
		t.Fatalf("expected *ErrPurposeMismatch, got %T: %v", err, err)
	}
}

// TestValidatedReadAllDeviceTransferNoKey verifies that a DeviceTransfer
// backup without a mediaRootBackupKey does NOT return ErrPurposeMismatch.
func TestValidatedReadAllDeviceTransferNoKey(t *testing.T) {
	stream := buildTestBackupStream(t, BackupInfoVersion1, nil)
	br := NewBackupReader(bytes.NewReader(stream), PurposeDeviceTransfer)
	result, err := br.ValidatedReadAll(PurposeDeviceTransfer)
	if err != nil {
		t.Fatalf("ValidatedReadAll for DeviceTransfer: %v", err)
	}
	defer result.Destroy()
	if result.Info.Version != BackupInfoVersion1 {
		t.Errorf("Version = %d, want %d", result.Info.Version, BackupInfoVersion1)
	}
}

// TestValidatedReadAllUnknownFields verifies that unknown frame fields are
// recorded in FoundUnknownFields rather than causing an error.
func TestValidatedReadAllUnknownFields(t *testing.T) {
	key := bytes.Repeat([]byte{0xCC}, 32)

	// Build a Frame with an unknown field (field number 99).
	var unknownFrame bytes.Buffer
	writeTestLenField(&unknownFrame, 99, []byte{0xDE, 0xAD})

	stream := buildTestBackupStream(t, BackupInfoVersion1, key, unknownFrame.Bytes())
	br := NewBackupReader(bytes.NewReader(stream), PurposeRemoteBackup)
	result, err := br.ValidatedReadAll(PurposeRemoteBackup)
	if err != nil {
		t.Fatalf("ValidatedReadAll: %v", err)
	}
	defer result.Destroy()
	if len(result.FoundUnknownFields) == 0 {
		t.Error("expected unknown fields to be recorded")
	}
}

// TestErrInvalidBackupInfo checks error message and Unwrap.
func TestErrInvalidBackupInfo(t *testing.T) {
	t.Run("with inner error", func(t *testing.T) {
		e := &ErrInvalidBackupInfo{Err: &ErrInvalidVarint{}}
		if e.Error() == "" {
			t.Error("Error() returned empty string")
		}
		if e.Unwrap() == nil {
			t.Error("Unwrap() should return inner error")
		}
	})
	t.Run("nil inner error", func(t *testing.T) {
		e := &ErrInvalidBackupInfo{}
		if e.Error() == "" {
			t.Error("Error() returned empty string")
		}
		if e.Unwrap() != nil {
			t.Error("Unwrap() should return nil for nil Err")
		}
	})
}

// TestErrInvalidFrame checks error message and Unwrap.
func TestErrInvalidFrame(t *testing.T) {
	e := &ErrInvalidFrame{Index: 3, Err: &ErrInvalidVarint{}}
	msg := e.Error()
	if msg == "" {
		t.Error("Error() returned empty string")
	}
	if e.Unwrap() == nil {
		t.Error("Unwrap() should return inner error")
	}
}

// TestErrPurposeMismatch checks the error message.
func TestErrPurposeMismatch(t *testing.T) {
	e := &ErrPurposeMismatch{Want: PurposeRemoteBackup, Got: PurposeDeviceTransfer}
	msg := e.Error()
	if msg == "" {
		t.Error("Error() returned empty string")
	}
}

// TestParseBackupInfoRoundTrip builds a minimal BackupInfo proto, decodes it,
// and checks the fields.
func TestParseBackupInfoRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	writeTestVarintField(&buf, 1, 1)                           // version
	writeTestVarintField(&buf, 2, 1_700_000_000_000)           // backupTimeMs
	writeTestLenField(&buf, 3, bytes.Repeat([]byte{0xAB}, 32)) // mediaRootBackupKey

	info, unknowns, err := parseBackupInfo(buf.Bytes())
	if err != nil {
		t.Fatalf("parseBackupInfo: %v", err)
	}
	if info.Version != 1 {
		t.Errorf("Version = %d, want 1", info.Version)
	}
	if info.BackupTimeMs != 1_700_000_000_000 {
		t.Errorf("BackupTimeMs = %d, want 1700000000000", info.BackupTimeMs)
	}
	if info.MediaRootBackupKey.Size() != 32 {
		t.Errorf("MediaRootBackupKey length = %d, want 32", info.MediaRootBackupKey.Size())
	}
	if len(unknowns) != 0 {
		t.Errorf("unexpected unknowns: %v", unknowns)
	}
}

// TestParseBackupInfoUnknownField verifies that unknown fields are collected.
func TestParseBackupInfoUnknownField(t *testing.T) {
	var buf bytes.Buffer
	writeTestVarintField(&buf, 1, 1)   // version
	writeTestVarintField(&buf, 42, 99) // unknown field 42

	_, unknowns, err := parseBackupInfo(buf.Bytes())
	if err != nil {
		t.Fatalf("parseBackupInfo: %v", err)
	}
	if len(unknowns) == 0 {
		t.Error("expected unknown field to be recorded")
	}
}

// buildMinimalFrame encodes a Frame with an empty AccountData (field 1, empty bytes).
func buildMinimalFrame() []byte {
	var buf bytes.Buffer
	writeTestLenField(&buf, 1, []byte{})
	return buf.Bytes()
}
