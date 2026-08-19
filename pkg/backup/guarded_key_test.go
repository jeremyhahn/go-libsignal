package backup

import (
	"bytes"
	"testing"
)

// TestParseBackupInfoGuardsMediaRootBackupKey checks that the media root
// backup key lands in guarded memory and is released by Destroy.
func TestParseBackupInfoGuardsMediaRootBackupKey(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, 32)

	var buf bytes.Buffer
	writeTestVarintField(&buf, 1, 1)
	writeTestLenField(&buf, 3, key)

	info, _, err := parseBackupInfo(buf.Bytes())
	if err != nil {
		t.Fatalf("parseBackupInfo: %v", err)
	}
	if !info.MediaRootBackupKey.EqualTo(key) {
		t.Fatal("media root backup key did not load into guarded memory")
	}

	info.Destroy()
	if !info.MediaRootBackupKey.IsDestroyed() {
		t.Error("Destroy left the guarded key alive")
	}
	// Destroy is idempotent.
	info.Destroy()
}

// TestParseBackupInfoTruncatedAfterKey covers the failure path that runs after
// the key has already been moved into guarded memory: the parse must report the
// error and hand back nothing.
func TestParseBackupInfoTruncatedAfterKey(t *testing.T) {
	var buf bytes.Buffer
	writeTestVarintField(&buf, 1, 1)
	writeTestLenField(&buf, 3, bytes.Repeat([]byte{0xAB}, 32))
	// A length-delimited field whose payload is missing entirely.
	buf.Write([]byte{4<<3 | 2, 0x10})

	info, _, err := parseBackupInfo(buf.Bytes())
	if err == nil {
		t.Fatal("expected an error for a truncated trailing field")
	}
	if info != nil {
		t.Error("a failed parse must not return a BackupInfoRaw")
	}
}

// TestBackupInfoDestroyWithoutKey covers the device-transfer shape, where no
// media root backup key is present at all.
func TestBackupInfoDestroyWithoutKey(t *testing.T) {
	var buf bytes.Buffer
	writeTestVarintField(&buf, 1, 1)

	info, _, err := parseBackupInfo(buf.Bytes())
	if err != nil {
		t.Fatalf("parseBackupInfo: %v", err)
	}
	if info.MediaRootBackupKey != nil {
		t.Error("expected no media root backup key")
	}
	info.Destroy()
}

// TestParseBackupInfoDuplicateKeyFields covers a BackupInfo that repeats the
// singular mediaRootBackupKey field. Protobuf semantics are last-one-wins, and
// each occurrence allocates guarded memory, so the superseded allocation has to
// be released rather than abandoned.
func TestParseBackupInfoDuplicateKeyFields(t *testing.T) {
	first := bytes.Repeat([]byte{0x11}, 32)
	last := bytes.Repeat([]byte{0x22}, 32)

	var buf bytes.Buffer
	writeTestVarintField(&buf, 1, 1)
	writeTestLenField(&buf, 3, first)
	writeTestLenField(&buf, 3, last)

	info, _, err := parseBackupInfo(buf.Bytes())
	if err != nil {
		t.Fatalf("parseBackupInfo: %v", err)
	}
	defer info.Destroy()

	if !info.MediaRootBackupKey.EqualTo(last) {
		t.Error("the last mediaRootBackupKey occurrence should win")
	}
}

// TestValidatedReadAllFailsAfterInfo covers the error paths that run once the
// BackupInfo (and its guarded key) has been parsed: each must report the error
// and hand back no result.
func TestValidatedReadAllFailsAfterInfo(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, 32)

	t.Run("unsupported version", func(t *testing.T) {
		stream := buildTestBackupStream(t, 99, key, buildMinimalFrame())
		br := NewBackupReader(bytes.NewReader(stream), PurposeRemoteBackup)

		result, err := br.ValidatedReadAll(PurposeRemoteBackup)
		if err == nil {
			t.Fatal("expected an error for an unsupported version")
		}
		if result != nil {
			t.Error("a failed read must not return a result")
		}
	})

	t.Run("purpose mismatch", func(t *testing.T) {
		// A remote backup requires a 32-byte media root backup key.
		stream := buildTestBackupStream(t, BackupInfoVersion1, key[:16], buildMinimalFrame())
		br := NewBackupReader(bytes.NewReader(stream), PurposeRemoteBackup)

		result, err := br.ValidatedReadAll(PurposeRemoteBackup)
		if err == nil {
			t.Fatal("expected an error for a short media root backup key")
		}
		if result != nil {
			t.Error("a failed read must not return a result")
		}
	})

	t.Run("malformed later frame", func(t *testing.T) {
		stream := buildTestBackupStream(t, BackupInfoVersion1, key, []byte{0xFF, 0xFF, 0xFF})
		br := NewBackupReader(bytes.NewReader(stream), PurposeRemoteBackup)

		result, err := br.ValidatedReadAll(PurposeRemoteBackup)
		if err == nil {
			t.Fatal("expected an error for a malformed frame")
		}
		if result != nil {
			t.Error("a failed read must not return a result")
		}
	})
}

// A successful read hands the media root backup key to the caller, so the
// result has to be the thing that releases it: nothing else can, and nothing
// reclaims guarded memory on its own.
func TestValidatedReadResultDestroyReleasesTheKey(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, 32)
	stream := buildTestBackupStream(t, BackupInfoVersion1, key, buildMinimalFrame())
	br := NewBackupReader(bytes.NewReader(stream), PurposeRemoteBackup)

	result, err := br.ValidatedReadAll(PurposeRemoteBackup)
	if err != nil {
		t.Fatalf("ValidatedReadAll: %v", err)
	}
	if !result.Info.MediaRootBackupKey.EqualTo(key) {
		t.Fatal("the media root backup key did not survive the read")
	}

	result.Destroy()

	if !result.Info.MediaRootBackupKey.IsDestroyed() {
		t.Error("Destroy left the media root backup key in locked memory")
	}

	// Destroy is taken with defer next to the error check, so it has to
	// tolerate being called twice, and on a result that was never returned.
	result.Destroy()
	(*ValidatedReadResult)(nil).Destroy()
	(&ValidatedReadResult{}).Destroy()
}

// A device-transfer backup carries no media root backup key, so a result from
// one has nothing to release.
func TestValidatedReadResultDestroyWithoutKey(t *testing.T) {
	stream := buildTestBackupStream(t, BackupInfoVersion1, nil)
	br := NewBackupReader(bytes.NewReader(stream), PurposeDeviceTransfer)

	result, err := br.ValidatedReadAll(PurposeDeviceTransfer)
	if err != nil {
		t.Fatalf("ValidatedReadAll for DeviceTransfer: %v", err)
	}
	result.Destroy()
}
