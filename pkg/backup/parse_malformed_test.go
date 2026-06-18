package backup

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

// runWithTimeout wraps a parse call with a 5-second context deadline so that
// any future regression that re-introduces an infinite loop fails the test
// quickly rather than hanging the suite.
func runWithTimeout(t *testing.T, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("test timed out — parse loop did not terminate (possible infinite loop regression)")
	}
}

// TestParseBackupInfoMalformed verifies that parseBackupInfo returns typed
// errors and never hangs on malformed protobuf input.
func TestParseBackupInfoMalformed(t *testing.T) {
	t.Run("empty input", func(t *testing.T) {
		runWithTimeout(t, func() {
			_, _, err := parseBackupInfo([]byte{})
			// Empty input is valid proto3 (zero fields) — no error expected.
			if err != nil {
				t.Errorf("parseBackupInfo(empty): unexpected error: %v", err)
			}
		})
	})

	t.Run("unknown wire type 6 in skipped field", func(t *testing.T) {
		// Field 4 (currentAppVersion) with wire type 6 (unsupported).
		// tag = (4 << 3) | 6 = 38. Now wire-type validated: expect ErrUnexpectedWireType.
		input := []byte{38}
		runWithTimeout(t, func() {
			_, _, err := parseBackupInfo(input)
			if err == nil {
				t.Fatal("expected error for wrong wire type on known field 4")
			}
			var wt *ErrUnexpectedWireType
			if !errors.As(err, &wt) {
				t.Errorf("expected *ErrUnexpectedWireType, got %T: %v", err, err)
			}
		})
	})

	t.Run("unknown wire type 7 in unknown field", func(t *testing.T) {
		// Field 99 (unknown) with wire type 7.
		// tag = (99 << 3) | 7 = 799 → varint bytes: 0x9F 0x06
		var buf bytes.Buffer
		buf.Write([]byte{0x9F, 0x06})
		runWithTimeout(t, func() {
			_, _, err := parseBackupInfo(buf.Bytes())
			if err == nil {
				t.Fatal("expected error for unsupported wire type 7 in unknown field")
			}
			var wf *ErrInvalidProtoWireFormat
			if !errors.As(err, &wf) {
				t.Errorf("expected *ErrInvalidProtoWireFormat, got %T: %v", err, err)
			}
		})
	})

	t.Run("truncated varint at top level", func(t *testing.T) {
		// 0xFF begins a multi-byte varint but provides no continuation byte.
		input := []byte{0xFF}
		runWithTimeout(t, func() {
			_, _, err := parseBackupInfo(input)
			if err == nil {
				t.Fatal("expected error for truncated tag varint")
			}
			var wf *ErrInvalidProtoWireFormat
			if !errors.As(err, &wf) {
				t.Errorf("expected *ErrInvalidProtoWireFormat, got %T: %v", err, err)
			}
		})
	})

	t.Run("length-delimited field length exceeds remaining bytes", func(t *testing.T) {
		// Tag for field 4 (currentAppVersion), wire type 2: (4<<3)|2 = 34.
		// Length varint = 100, but no payload follows.
		input := []byte{34, 100}
		runWithTimeout(t, func() {
			_, _, err := parseBackupInfo(input)
			if err == nil {
				t.Fatal("expected error for truncated length-delimited field")
			}
			var wf *ErrInvalidProtoWireFormat
			if !errors.As(err, &wf) {
				t.Errorf("expected *ErrInvalidProtoWireFormat, got %T: %v", err, err)
			}
		})
	})
}

// TestParseFrameMalformed verifies that parseFrame returns typed errors and
// never hangs on malformed protobuf input.
func TestParseFrameMalformed(t *testing.T) {
	t.Run("empty input", func(t *testing.T) {
		runWithTimeout(t, func() {
			unknowns, err := parseFrame([]byte{})
			// Empty input is valid proto3 — no error expected.
			if err != nil {
				t.Errorf("parseFrame(empty): unexpected error: %v", err)
			}
			if len(unknowns) != 0 {
				t.Errorf("expected no unknown fields, got %d", len(unknowns))
			}
		})
	})

	t.Run("known field 1 wrong wire type 6", func(t *testing.T) {
		// Field 1 (Frame.account) with wire type 6: (1<<3)|6 = 14.
		// Known submessage fields require wire type 2; expect ErrUnexpectedWireType.
		input := []byte{14}
		runWithTimeout(t, func() {
			_, err := parseFrame(input)
			if err == nil {
				t.Fatal("expected error for wrong wire type on known field 1")
			}
			var wt *ErrUnexpectedWireType
			if !errors.As(err, &wt) {
				t.Errorf("expected *ErrUnexpectedWireType, got %T: %v", err, err)
			}
		})
	})

	t.Run("known field 1 wrong wire type 7", func(t *testing.T) {
		// Field 1 (Frame.account) with wire type 7: (1<<3)|7 = 15.
		// Known submessage fields require wire type 2; expect ErrUnexpectedWireType.
		input := []byte{15}
		runWithTimeout(t, func() {
			_, err := parseFrame(input)
			if err == nil {
				t.Fatal("expected error for wrong wire type on known field 1")
			}
			var wt *ErrUnexpectedWireType
			if !errors.As(err, &wt) {
				t.Errorf("expected *ErrUnexpectedWireType, got %T: %v", err, err)
			}
		})
	})

	t.Run("truncated varint tag", func(t *testing.T) {
		// 0xFF begins a multi-byte varint but provides no continuation byte.
		input := []byte{0xFF}
		runWithTimeout(t, func() {
			_, err := parseFrame(input)
			if err == nil {
				t.Fatal("expected error for truncated tag varint")
			}
			var wf *ErrInvalidProtoWireFormat
			if !errors.As(err, &wf) {
				t.Errorf("expected *ErrInvalidProtoWireFormat, got %T: %v", err, err)
			}
		})
	})

	t.Run("length-delimited field length exceeds remaining bytes", func(t *testing.T) {
		// Tag for field 1 wire type 2: (1<<3)|2 = 10. Length = 100, no payload.
		input := []byte{10, 100}
		runWithTimeout(t, func() {
			_, err := parseFrame(input)
			if err == nil {
				t.Fatal("expected error for truncated length-delimited field")
			}
			var wf *ErrInvalidProtoWireFormat
			if !errors.As(err, &wf) {
				t.Errorf("expected *ErrInvalidProtoWireFormat, got %T: %v", err, err)
			}
		})
	})
}

// TestParseFrame_AccountFieldWrongWireType_Varint verifies that a Frame with
// field 1 (account) encoded as a varint (wire type 0) is rejected with
// ErrUnexpectedWireType wrapped in ErrInvalidFrame.
//
// Rust libsignal ref: rust/message-backup/src/proto/backup.proto Frame.account
func TestParseFrame_AccountFieldWrongWireType_Varint(t *testing.T) {
	// Tag: field 1, wire type 0 (varint): (1<<3)|0 = 8. Value varint = 42.
	input := []byte{8, 42}
	runWithTimeout(t, func() {
		_, err := parseFrame(input)
		if err == nil {
			t.Fatal("expected error for Frame.account with varint wire type")
		}
		var wt *ErrUnexpectedWireType
		if !errors.As(err, &wt) {
			t.Errorf("expected *ErrUnexpectedWireType, got %T: %v", err, err)
		}
		if wt.Field != "Frame.account" {
			t.Errorf("expected Field=%q, got %q", "Frame.account", wt.Field)
		}
		if wt.WireType != 0 {
			t.Errorf("expected WireType=0, got %d", wt.WireType)
		}
	})
}

// TestParseFrame_KnownFieldsWrongWireType_Varint verifies that all Frame oneof
// branches (fields 1-8) reject varint wire type (0) with ErrUnexpectedWireType.
//
// Rust libsignal ref: rust/message-backup/src/proto/backup.proto Frame.item
func TestParseFrame_KnownFieldsWrongWireType_Varint(t *testing.T) {
	cases := []struct {
		fieldNum uint64
		name     string
	}{
		{1, "Frame.account"},
		{2, "Frame.recipient"},
		{3, "Frame.chat"},
		{4, "Frame.chatItem"},
		{5, "Frame.stickerPack"},
		{6, "Frame.adHocCall"},
		{7, "Frame.notificationProfile"},
		{8, "Frame.chatFolder"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name+"_varint_wt0", func(t *testing.T) {
			// Encode tag = (fieldNum << 3) with wire type 0 (varint), followed by value 1.
			tag := tc.fieldNum << 3 // wire type 0 is the zero bits
			var tagBuf [binary.MaxVarintLen64]byte
			n := binary.PutUvarint(tagBuf[:], tag)
			input := append(tagBuf[:n], 1) // value varint = 1
			runWithTimeout(t, func() {
				_, err := parseFrame(input)
				if err == nil {
					t.Fatalf("%s: expected error for varint wire type", tc.name)
				}
				var wt *ErrUnexpectedWireType
				if !errors.As(err, &wt) {
					t.Errorf("%s: expected *ErrUnexpectedWireType, got %T: %v", tc.name, err, err)
				}
				if errors.As(err, &wt) && wt.Field != tc.name {
					t.Errorf("%s: expected Field=%q, got %q", tc.name, tc.name, wt.Field)
				}
				if errors.As(err, &wt) && wt.WireType != 0 {
					t.Errorf("%s: expected WireType=0, got %d", tc.name, wt.WireType)
				}
			})
		})
	}
}

// TestParseFrame_UnknownFieldNumber_Skipped verifies that a frame with an
// unknown field number (99) is silently skipped for forward-compatibility.
//
// Rust libsignal ref: rust/message-backup/src/proto/backup.proto Frame
func TestParseFrame_UnknownFieldNumber_Skipped(t *testing.T) {
	// Field 99, wire type 2 (length-delimited): tag = (99<<3)|2 = 794.
	// Encode tag varint 794 = 0x31A → 0x9A 0x06, then length=0.
	input := []byte{0x9A, 0x06, 0x00}
	runWithTimeout(t, func() {
		unknowns, err := parseFrame(input)
		if err != nil {
			t.Fatalf("expected no error for unknown field 99, got: %v", err)
		}
		if len(unknowns) != 1 {
			t.Errorf("expected 1 unknown field, got %d", len(unknowns))
		}
	})
}

// TestParseBackupInfo_VersionFieldWrongWireType verifies that BackupInfo known
// fields reject wrong wire types with ErrUnexpectedWireType.
//
// Rust libsignal ref: rust/message-backup/src/proto/backup.proto BackupInfo
func TestParseBackupInfo_VersionFieldWrongWireType(t *testing.T) {
	cases := []struct {
		name     string
		fieldNum uint64
		wireType uint64
		value    []byte
		errField string
	}{
		{
			// BackupInfo.version is uint64 (wire type 0). Send it as wire type 2.
			name: "version_field_wire_type_2",
			// tag = (1<<3)|2 = 10, length=1, value=0x00
			value:    []byte{10, 1, 0},
			errField: "BackupInfo.version",
		},
		{
			// BackupInfo.backupTimeMs is uint64 (wire type 0). Send it as wire type 2.
			name: "backupTimeMs_field_wire_type_2",
			// tag = (2<<3)|2 = 18, length=1, value=0x00
			value:    []byte{18, 1, 0},
			errField: "BackupInfo.backupTimeMs",
		},
		{
			// BackupInfo.mediaRootBackupKey is bytes (wire type 2). Send it as wire type 0.
			name: "mediaRootBackupKey_field_wire_type_0",
			// tag = (3<<3)|0 = 24, value varint=0
			value:    []byte{24, 0},
			errField: "BackupInfo.mediaRootBackupKey",
		},
		{
			// BackupInfo.currentAppVersion is string (wire type 2). Send it as wire type 0.
			name: "currentAppVersion_field_wire_type_0",
			// tag = (4<<3)|0 = 32, value varint=0
			value:    []byte{32, 0},
			errField: "BackupInfo.currentAppVersion",
		},
		{
			// BackupInfo.firstAppVersion is string (wire type 2). Send it as wire type 0.
			name: "firstAppVersion_field_wire_type_0",
			// tag = (5<<3)|0 = 40, value varint=0
			value:    []byte{40, 0},
			errField: "BackupInfo.firstAppVersion",
		},
		{
			// BackupInfo.debugInfo is bytes (wire type 2). Send it as wire type 0.
			name: "debugInfo_field_wire_type_0",
			// tag = (6<<3)|0 = 48, value varint=0
			value:    []byte{48, 0},
			errField: "BackupInfo.debugInfo",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			runWithTimeout(t, func() {
				_, _, err := parseBackupInfo(tc.value)
				if err == nil {
					t.Fatalf("%s: expected error for wrong wire type, got nil", tc.name)
				}
				var wt *ErrUnexpectedWireType
				if !errors.As(err, &wt) {
					t.Errorf("%s: expected *ErrUnexpectedWireType, got %T: %v", tc.name, err, err)
				}
				if errors.As(err, &wt) && wt.Field != tc.errField {
					t.Errorf("%s: expected Field=%q, got %q", tc.name, tc.errField, wt.Field)
				}
			})
		})
	}
}

// TestValidatedReadAllMalformedFrame verifies that ValidatedReadAll surfaces
// *ErrInvalidFrame for frames with wrong wire types, and does not hang.
func TestValidatedReadAllMalformedFrame(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, 32)

	t.Run("frame with known field wrong wire type 6", func(t *testing.T) {
		// Tag for field 1 (Frame.account) with wire type 6: (1<<3)|6 = 14.
		// Now returns ErrUnexpectedWireType (not ErrInvalidProtoWireFormat)
		// but the outer error is still ErrInvalidFrame.
		malformedFrame := []byte{14}
		stream := buildTestBackupStream(t, BackupInfoVersion1, key, malformedFrame)
		br := NewBackupReader(bytes.NewReader(stream), PurposeRemoteBackup)
		runWithTimeout(t, func() {
			_, err := br.ValidatedReadAll(PurposeRemoteBackup)
			if err == nil {
				t.Fatal("expected error for malformed frame")
			}
			var frameErr *ErrInvalidFrame
			if !errors.As(err, &frameErr) {
				t.Errorf("expected *ErrInvalidFrame, got %T: %v", err, err)
			}
			var wt *ErrUnexpectedWireType
			if !errors.As(err, &wt) {
				t.Errorf("expected wrapped *ErrUnexpectedWireType, got: %v", err)
			}
		})
	})

	t.Run("frame with truncated varint field", func(t *testing.T) {
		// Tag for field 1 wire type 0: (1<<3)|0 = 8. No value follows.
		// Returns ErrUnexpectedWireType (field 1 requires wire type 2).
		malformedFrame := []byte{8}
		stream := buildTestBackupStream(t, BackupInfoVersion1, key, malformedFrame)
		br := NewBackupReader(bytes.NewReader(stream), PurposeRemoteBackup)
		runWithTimeout(t, func() {
			_, err := br.ValidatedReadAll(PurposeRemoteBackup)
			if err == nil {
				t.Fatal("expected error for truncated varint field")
			}
			var frameErr *ErrInvalidFrame
			if !errors.As(err, &frameErr) {
				t.Errorf("expected *ErrInvalidFrame, got %T: %v", err, err)
			}
		})
	})
}

// TestValidatedReadAllMalformedBackupInfo verifies that ValidatedReadAll
// surfaces *ErrInvalidBackupInfo for a malformed first frame.
func TestValidatedReadAllMalformedBackupInfo(t *testing.T) {
	t.Run("backupinfo with wrong wire type on field 4", func(t *testing.T) {
		// Field 4 (currentAppVersion) with wire type 7 (unsupported and wrong).
		// Tag = (4<<3)|7 = 39. Now returns ErrUnexpectedWireType.
		malformedInfo := []byte{39}
		var buf bytes.Buffer
		if err := WriteVarintDelimited(&buf, malformedInfo); err != nil {
			t.Fatalf("WriteVarintDelimited: %v", err)
		}
		br := NewBackupReader(bytes.NewReader(buf.Bytes()), PurposeRemoteBackup)
		runWithTimeout(t, func() {
			_, err := br.ValidatedReadAll(PurposeRemoteBackup)
			if err == nil {
				t.Fatal("expected error for malformed BackupInfo")
			}
			var biErr *ErrInvalidBackupInfo
			if !errors.As(err, &biErr) {
				t.Errorf("expected *ErrInvalidBackupInfo, got %T: %v", err, err)
			}
			var wt *ErrUnexpectedWireType
			if !errors.As(err, &wt) {
				t.Errorf("expected wrapped *ErrUnexpectedWireType, got: %v", err)
			}
		})
	})
}

// TestNewTypedErrors verifies the new typed error types satisfy their contracts.
func TestNewTypedErrors(t *testing.T) {
	t.Run("ErrInvalidProtoWireFormat", func(t *testing.T) {
		e := &ErrInvalidProtoWireFormat{WireType: 6, Reason: "unsupported wire type"}
		if e.Error() == "" {
			t.Error("Error() returned empty string")
		}
	})

	t.Run("ErrUnsupportedBackupInfoVersion", func(t *testing.T) {
		e := &ErrUnsupportedBackupInfoVersion{Got: 99, Want: 1}
		if e.Error() == "" {
			t.Error("Error() returned empty string")
		}
	})

	t.Run("ErrUnexpectedWireType", func(t *testing.T) {
		e := &ErrUnexpectedWireType{Field: "BackupInfo.version", WireType: 3}
		if e.Error() == "" {
			t.Error("Error() returned empty string")
		}
	})

	t.Run("ErrTruncatedField", func(t *testing.T) {
		e := &ErrTruncatedField{Field: "BackupInfo.mediaRootBackupKey"}
		if e.Error() == "" {
			t.Error("Error() returned empty string")
		}
	})
}
