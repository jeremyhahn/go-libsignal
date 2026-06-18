package backup

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"testing"
)

// loadCanonicalBackupFrames reads the canonical-backup.binproto from the
// Rust upstream test fixtures and parses it into raw varint-delimited frames.
//
// The fixture is at /mnt/vm-host-1/libsignal/rust/message-backup/tests/res/canonical-backup.binproto.
// If that path is unavailable the test is skipped.
const canonicalBackupPath = "/mnt/vm-host-1/libsignal/rust/message-backup/tests/res/canonical-backup.binproto"

func loadCanonicalBackupFrames(t *testing.T) [][]byte {
	t.Helper()
	data, err := os.ReadFile(canonicalBackupPath)
	if err != nil {
		t.Fatalf("canonical-backup.binproto not available at %s: %v", canonicalBackupPath, err)
	}
	r := NewVarintDelimitedReader(bytes.NewReader(data))
	var frames [][]byte
	for {
		frame, err := r.ReadNext()
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("reading frames: %v", err)
		}
		if frame == nil {
			break
		}
		frames = append(frames, frame)
	}
	if len(frames) == 0 {
		t.Fatal("canonical backup contains no frames")
	}
	return frames
}

// TestScrambleBackupSmoke is a port of the Rust scrambler_smoke_test.
// It loads the canonical backup, scrambles it with a fixed seed (0),
// and verifies:
//  1. The scrambled output differs from the input.
//  2. The scrambled backup is still structurally valid (parseable as frames).
//  3. ScrambleBackup is deterministic: calling it twice with the same frames
//     produces identical output.
//
// Rust libsignal ref: rust/message-backup/tests/test_cases.rs scrambler_smoke_test
func TestScrambleBackupSmoke(t *testing.T) {
	frames := loadCanonicalBackupFrames(t)

	scrambled, err := ScrambleBackup(frames)
	if err != nil {
		t.Fatalf("ScrambleBackup: %v", err)
	}
	if len(scrambled) != len(frames) {
		t.Fatalf("ScrambleBackup returned %d frames, want %d", len(scrambled), len(frames))
	}

	// At least one frame should differ from the original.
	anyDiffer := false
	for i, orig := range frames {
		if !bytes.Equal(orig, scrambled[i]) {
			anyDiffer = true
			break
		}
	}
	if !anyDiffer {
		t.Error("ScrambleBackup: output is identical to input; no field was scrambled")
	}

	// Verify the scrambled frames are still structurally valid by re-parsing
	// the first frame as BackupInfo and each subsequent frame as a Frame.
	if len(scrambled[0]) == 0 {
		t.Error("scrambled BackupInfo frame is empty")
	}
	// Re-parse each frame through walkMessage to confirm it is valid wire.
	for i, frame := range scrambled {
		if len(frame) == 0 {
			continue
		}
		_, err := walkMessage(frame, func(_ uint64, _ uint64, v []byte) ([]byte, error) {
			return v, nil
		})
		if err != nil {
			t.Errorf("scrambled frame %d is not valid protobuf wire: %v", i, err)
		}
	}

	// Verify determinism: scrambling the same input twice gives the same result.
	scrambled2, err := ScrambleBackup(frames)
	if err != nil {
		t.Fatalf("ScrambleBackup second call: %v", err)
	}
	for i := range scrambled {
		if !bytes.Equal(scrambled[i], scrambled2[i]) {
			t.Errorf("ScrambleBackup is not deterministic at frame %d", i)
		}
	}
}

// TestScrambleBackupEmptyInput verifies that an empty frame slice returns
// ErrScrambleInvalidBackup.
func TestScrambleBackupEmptyInput(t *testing.T) {
	_, err := ScrambleBackup(nil)
	if err == nil {
		t.Fatal("ScrambleBackup(nil) should return an error")
	}
	if _, ok := err.(*ErrScrambleInvalidBackup); !ok {
		t.Errorf("ScrambleBackup(nil) error type = %T, want *ErrScrambleInvalidBackup", err)
	}

	_, err = ScrambleBackup([][]byte{})
	if err == nil {
		t.Fatal("ScrambleBackup([]) should return an error")
	}
}

// TestErrScrambleInvalidBackup verifies the error type's Error() method.
func TestErrScrambleInvalidBackup(t *testing.T) {
	e := &ErrScrambleInvalidBackup{Reason: "test reason"}
	got := e.Error()
	want := "backup: scramble: invalid backup: test reason"
	if got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

// TestScrambleBackupInfoFrame verifies that the BackupInfo frame has its
// mediaRootBackupKey (field 3) randomized and that the version (field 1) is
// preserved.
//
// BackupInfo wire: field 1=version varint, field 2=backupTimeMs varint,
// field 3=mediaRootBackupKey bytes (32 bytes).
func TestScrambleBackupInfoFrame(t *testing.T) {
	// Build a minimal BackupInfo with version=1, backupTimeMs=9999,
	// mediaRootBackupKey=32 bytes of 0xAB.
	var raw bytes.Buffer
	// field 1, varint: version=1
	writeVarint(&raw, 1<<3) // tag
	writeVarint(&raw, 1)
	// field 2, varint: backupTimeMs=9999
	writeVarint(&raw, 2<<3)
	writeVarint(&raw, 9999)
	// field 3, bytes: mediaRootBackupKey = 32 × 0xAB
	key := bytes.Repeat([]byte{0xAB}, 32)
	writeVarint(&raw, (3<<3)|2)
	writeVarint(&raw, uint64(len(key)))
	raw.Write(key)

	frames := [][]byte{raw.Bytes()}
	out, err := ScrambleBackup(frames)
	if err != nil {
		t.Fatalf("ScrambleBackup: %v", err)
	}

	// Re-parse the scrambled BackupInfo to extract version and key.
	var gotVersion uint64
	var gotKey []byte
	_ = walkMessagePeek(out[0], func(fieldNum uint64, _ uint64, value []byte) {
		if fieldNum == 3 {
			gotKey = value
		}
	})

	// Extract varint fields manually.
	data := out[0]
	for len(data) > 0 {
		tag, n := uvarintFromBytes(data)
		if n <= 0 {
			break
		}
		data = data[n:]
		fn := tag >> 3
		wt := tag & 7
		if wt == 0 {
			val, vn := uvarintFromBytes(data)
			if vn <= 0 {
				break
			}
			data = data[vn:]
			if fn == 1 {
				gotVersion = val
			}
		} else {
			data = skipField(data, wt)
		}
	}

	if gotVersion != 1 {
		t.Errorf("version field should be preserved as 1, got %d", gotVersion)
	}
	if bytes.Equal(gotKey, key) {
		t.Error("mediaRootBackupKey should have been randomized")
	}
	if len(gotKey) != 32 {
		t.Errorf("scrambled key length = %d, want 32", len(gotKey))
	}
}

// TestScrambleBackupAccountDataFrame verifies that a Frame containing
// AccountData (field 1) has its givenName (field 4) scrambled.
func TestScrambleBackupAccountDataFrame(t *testing.T) {
	givenName := "Alice"
	accountData := buildStringField(4, givenName)
	frame := buildBytesField(1, accountData)

	// prepend a minimal BackupInfo
	info := buildVarintField(1, 1) // version=1

	out, err := ScrambleBackup([][]byte{info, frame})
	if err != nil {
		t.Fatalf("ScrambleBackup: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(out))
	}

	// Extract AccountData from scrambled frame then extract field 4.
	var accountDataBytes []byte
	_ = walkMessagePeek(out[1], func(fieldNum uint64, _ uint64, value []byte) {
		if fieldNum == 1 {
			accountDataBytes = value
		}
	})

	var scrambledName []byte
	_ = walkMessagePeek(accountDataBytes, func(fieldNum uint64, _ uint64, value []byte) {
		if fieldNum == 4 {
			scrambledName = value
		}
	})

	if string(scrambledName) == givenName {
		t.Error("givenName should have been scrambled")
	}
	if len(scrambledName) != len(givenName) {
		t.Errorf("scrambled name length = %d, want %d", len(scrambledName), len(givenName))
	}
}

// TestScrambleBackupContactE164 verifies that a Contact's e164 field (uint64 varint)
// is replaced with a mapping-consistent value starting at e164Start.
func TestScrambleBackupContactE164(t *testing.T) {
	e164 := uint64(12025551234)

	// Build Contact proto: field 4 = e164 varint
	var contactBuf bytes.Buffer
	writeVarint(&contactBuf, 4<<3) // field 4, wire type 0
	writeVarint(&contactBuf, e164)

	// Wrap in Recipient (field 2 = Contact)
	recipient := buildBytesField(2, contactBuf.Bytes())
	// Wrap in Frame (field 2 = Recipient)
	frame := buildBytesField(2, recipient)

	info := buildVarintField(1, 1)
	out, err := ScrambleBackup([][]byte{info, frame})
	if err != nil {
		t.Fatalf("ScrambleBackup: %v", err)
	}

	// Drill into the scrambled frame to extract the e164.
	var recipientBytes []byte
	_ = walkMessagePeek(out[1], func(fieldNum uint64, _ uint64, value []byte) {
		if fieldNum == 2 {
			recipientBytes = value
		}
	})

	var contactBytes []byte
	_ = walkMessagePeek(recipientBytes, func(fieldNum uint64, _ uint64, value []byte) {
		if fieldNum == 2 {
			contactBytes = value
		}
	})

	// Extract varint field 4 from contact.
	var scrambledE164 uint64
	data := contactBytes
	for len(data) > 0 {
		tag, n := uvarintFromBytes(data)
		if n <= 0 {
			break
		}
		data = data[n:]
		fn := tag >> 3
		wt := tag & 7
		if wt == 0 {
			val, vn := uvarintFromBytes(data)
			if vn <= 0 {
				break
			}
			data = data[vn:]
			if fn == 4 {
				scrambledE164 = val
			}
		} else {
			data = skipField(data, wt)
		}
	}

	if scrambledE164 == e164 {
		t.Error("e164 should have been replaced")
	}
	if scrambledE164 != e164Start {
		t.Errorf("first e164 replacement = %d, want %d", scrambledE164, e164Start)
	}
}

// TestWalkMessageRoundtrip verifies that walking a protobuf message with
// identity transforms produces identical bytes.
func TestWalkMessageRoundtrip(t *testing.T) {
	// Build a simple message with multiple field types.
	var msg bytes.Buffer
	writeVarint(&msg, 1<<3) // field 1 varint
	writeVarint(&msg, 42)
	writeVarint(&msg, (2<<3)|2) // field 2 bytes
	writeVarint(&msg, 5)
	msg.Write([]byte("hello"))
	writeVarint(&msg, 3<<3) // field 3 varint
	writeVarint(&msg, 999)

	raw := msg.Bytes()
	out, err := walkMessage(raw, func(_ uint64, _ uint64, v []byte) ([]byte, error) { return v, nil })
	if err != nil {
		t.Fatalf("walkMessage: %v", err)
	}
	if !bytes.Equal(out, raw) {
		t.Errorf("identity walk changed the message:\n  in:  %x\n  out: %x", raw, out)
	}
}

// TestWalkMessageInvalidVarint verifies that a truncated varint tag returns
// ErrScrambleInvalidBackup.
func TestWalkMessageInvalidVarint(t *testing.T) {
	// A single byte with the high bit set indicates a multi-byte varint
	// but there are no following bytes — malformed.
	raw := []byte{0x80}
	_, err := walkMessage(raw, func(_ uint64, _ uint64, v []byte) ([]byte, error) { return v, nil })
	if err == nil {
		t.Fatal("expected error for truncated varint, got nil")
	}
	if _, ok := err.(*ErrScrambleInvalidBackup); !ok {
		t.Errorf("error type = %T, want *ErrScrambleInvalidBackup", err)
	}
}

// TestScrambleBodyText verifies that message body text is replaced with the
// constant replacement text and that U+FFFC mention characters are preserved.
func TestScrambleBodyText(t *testing.T) {
	t.Run("short body replaced with prefix", func(t *testing.T) {
		body := []byte("Hello!")
		got := scrambleBodyText(body, false)
		if len(got) != len(body) {
			t.Errorf("length mismatch: got %d, want %d", len(got), len(body))
		}
		want := []byte(replacementBodyText[:len(body)])
		if !bytes.Equal(got, want) {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("empty body unchanged", func(t *testing.T) {
		got := scrambleBodyText(nil, false)
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("mention characters preserved", func(t *testing.T) {
		mention := "￼" // U+FFFC
		body := []byte("Hi " + mention + " there")
		got := scrambleBodyText(body, true)
		if !bytes.Contains(got, []byte(mention)) {
			t.Errorf("mention character not preserved in %q", got)
		}
	})
}

// TestScrambleBackupContactServiceID verifies that a Contact's ACI bytes
// (field 1) are replaced with a consistent UUID replacement.
func TestScrambleBackupContactServiceID(t *testing.T) {
	aci := bytes.Repeat([]byte{0xAA}, 16)

	// Build Contact proto: field 1 = aci bytes
	contactBytes := buildBytesField(1, aci)
	recipient := buildBytesField(2, contactBytes)
	frame := buildBytesField(2, recipient)
	info := buildVarintField(1, 1)

	out, err := ScrambleBackup([][]byte{info, frame})
	if err != nil {
		t.Fatalf("ScrambleBackup: %v", err)
	}

	var recipientBytes []byte
	_ = walkMessagePeek(out[1], func(fieldNum uint64, _ uint64, value []byte) {
		if fieldNum == 2 {
			recipientBytes = value
		}
	})
	var scrambledContactBytes []byte
	_ = walkMessagePeek(recipientBytes, func(fieldNum uint64, _ uint64, value []byte) {
		if fieldNum == 2 {
			scrambledContactBytes = value
		}
	})
	var scrambledACI []byte
	_ = walkMessagePeek(scrambledContactBytes, func(fieldNum uint64, _ uint64, value []byte) {
		if fieldNum == 1 {
			scrambledACI = value
		}
	})

	if bytes.Equal(scrambledACI, aci) {
		t.Error("ACI should have been replaced")
	}
	if len(scrambledACI) != 16 {
		t.Errorf("scrambled ACI length = %d, want 16", len(scrambledACI))
	}
	// Verify RFC 4122 v4 UUID format.
	if scrambledACI[6]&0xf0 != 0x40 {
		t.Errorf("UUID version nibble = 0x%x, want 0x40", scrambledACI[6]&0xf0)
	}
}

// TestScrambleReactionEmoji verifies that reaction emoji fields are replaced
// with the replacement emoji constant.
func TestScrambleReactionEmoji(t *testing.T) {
	emoji := "👋"
	reactionProto := buildStringField(1, emoji)

	scrambled, err := scrambleReaction(NewScrambler(), reactionProto)
	if err != nil {
		t.Fatalf("scrambleReaction: %v", err)
	}

	var gotEmoji []byte
	_ = walkMessagePeek(scrambled, func(fieldNum uint64, _ uint64, value []byte) {
		if fieldNum == 1 {
			gotEmoji = value
		}
	})

	if string(gotEmoji) != replacementEmoji {
		t.Errorf("emoji = %q, want %q", gotEmoji, replacementEmoji)
	}
}

// TestScrambleContentTypePreservesType verifies ScrambleContentType in context.
func TestScrambleFilePointerContentType(t *testing.T) {
	raw := buildStringField(2, "image/jpeg")

	scrambled, err := scrambleFilePointer(NewScrambler(), raw)
	if err != nil {
		t.Fatalf("scrambleFilePointer: %v", err)
	}

	var gotType []byte
	_ = walkMessagePeek(scrambled, func(fieldNum uint64, _ uint64, value []byte) {
		if fieldNum == 2 {
			gotType = value
		}
	})

	want := "image/unknown"
	if string(gotType) != want {
		t.Errorf("content type = %q, want %q", gotType, want)
	}
}

// TestScrambleBackupMalformedNestedMessage verifies that when a nested
// protobuf message inside a backup frame is malformed (truncated), ScrambleBackup
// returns an error instead of silently producing corrupted output.
//
// Before the fieldHandler signature change, scrambleX calls discarded their
// errors with `out, _ := scrambleX(...)`, causing the scrambler to "fail open"
// and serialize partial/unscrambled replacements. After the fix the error
// propagates to the caller.
func TestScrambleBackupMalformedNestedMessage(t *testing.T) {
	// Build a Frame that wraps an AccountData (field 1) whose inner bytes
	// are a length-delimited field that claims 100 bytes but only provides 3.
	// tag = (1<<3)|2 = 0x0a, length = 100, payload = [0x01, 0x02, 0x03]
	malformedAccountData := []byte{0x0a, 100, 0x01, 0x02, 0x03}
	frame := buildBytesField(1, malformedAccountData)

	info := buildVarintField(1, 1) // version=1
	_, err := ScrambleBackup([][]byte{info, frame})
	if err == nil {
		t.Fatal("ScrambleBackup with malformed nested message: expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func buildVarintField(fieldNum uint64, val uint64) []byte {
	var b bytes.Buffer
	writeVarint(&b, fieldNum<<3)
	writeVarint(&b, val)
	return b.Bytes()
}

func buildBytesField(fieldNum uint64, value []byte) []byte {
	var b bytes.Buffer
	writeVarint(&b, (fieldNum<<3)|2)
	writeVarint(&b, uint64(len(value)))
	b.Write(value)
	return b.Bytes()
}

func buildStringField(fieldNum uint64, s string) []byte {
	return buildBytesField(fieldNum, []byte(s))
}

func uvarintFromBytes(data []byte) (uint64, int) {
	return binary.Uvarint(data)
}

func skipField(data []byte, wireType uint64) []byte {
	switch wireType {
	case 0:
		for len(data) > 0 {
			b := data[0]
			data = data[1:]
			if b&0x80 == 0 {
				break
			}
		}
	case 1:
		if len(data) >= 8 {
			data = data[8:]
		}
	case 2:
		length, ln := uvarintFull(data)
		if ln > 0 && uint64(len(data[ln:])) >= length {
			data = data[ln+int(length):]
		}
	case 5:
		if len(data) >= 4 {
			data = data[4:]
		}
	}
	return data
}

func uvarintFull(data []byte) (uint64, int) {
	var x uint64
	var s uint
	for i, b := range data {
		if b < 0x80 {
			return x | uint64(b)<<s, i + 1
		}
		x |= uint64(b&0x7f) << s
		s += 7
		if s >= 64 {
			return 0, -1
		}
	}
	return 0, 0
}
