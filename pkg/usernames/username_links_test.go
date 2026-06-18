package usernames

import (
	"encoding/binary"
	"testing"
)

func TestUsernameLinksRoundTrip(t *testing.T) {
	expected := "test_username.42"
	entropy, encrypted, err := CreateForUsername(expected, nil)
	if err != nil {
		t.Fatalf("CreateForUsername error: %v", err)
	}

	actual, err := DecryptUsername(entropy, encrypted)
	if err != nil {
		t.Fatalf("DecryptUsername error: %v", err)
	}

	if actual != expected {
		t.Errorf("got %q, want %q", actual, expected)
	}
}

func TestUsernameLinksReuseEntropy(t *testing.T) {
	expected := "test_username.42"
	entropy, encrypted, err := CreateForUsername(expected, nil)
	if err != nil {
		t.Fatalf("first CreateForUsername error: %v", err)
	}

	actual, err := DecryptUsername(entropy, encrypted)
	if err != nil {
		t.Fatalf("first DecryptUsername error: %v", err)
	}
	if actual != expected {
		t.Errorf("first round: got %q, want %q", actual, expected)
	}

	// Reuse entropy for a second encryption.
	newEntropy, newEncrypted, err := CreateForUsername(expected, entropy[:])
	if err != nil {
		t.Fatalf("second CreateForUsername error: %v", err)
	}

	if newEntropy != entropy {
		t.Error("entropy should be the same when reused")
	}

	// Encrypted data should differ due to different IV.
	if len(newEncrypted) == len(encrypted) {
		same := true
		for i := range encrypted {
			if encrypted[i] != newEncrypted[i] {
				same = false
				break
			}
		}
		if same {
			t.Error("encrypted data should differ when IV changes")
		}
	}

	actual, err = DecryptUsername(entropy, newEncrypted)
	if err != nil {
		t.Fatalf("second DecryptUsername error: %v", err)
	}
	if actual != expected {
		t.Errorf("second round: got %q, want %q", actual, expected)
	}
}

func TestUsernameLinksDataTooShort(t *testing.T) {
	entropy := [UsernameLinkEntropySize]byte{}
	encrypted := make([]byte, usernameLinkIVSize+usernameLinkHMACLen)
	_, err := DecryptUsername(entropy, encrypted)
	if err != ErrUsernameLinkDataTooShort {
		t.Fatalf("expected ErrUsernameLinkDataTooShort, got %v", err)
	}
}

func TestUsernameLinksHmacMismatch(t *testing.T) {
	entropy := [UsernameLinkEntropySize]byte{}
	encrypted := make([]byte, usernameLinkIVSize+usernameLinkHMACLen+32)
	_, err := DecryptUsername(entropy, encrypted)
	if err != ErrHmacMismatch {
		t.Fatalf("expected ErrHmacMismatch, got %v", err)
	}
}

func TestUsernameLinksInputTooLong(t *testing.T) {
	longUsername := ""
	for i := 0; i < 130; i++ {
		longUsername += "a"
	}
	_, _, err := CreateForUsername(longUsername, nil)
	if err != ErrInputDataTooLong {
		t.Fatalf("expected ErrInputDataTooLong, got %v", err)
	}
}

func TestUsernameLinksLongestValid(t *testing.T) {
	// MaxNicknameLength 'a's with the largest discriminator.
	nickname := ""
	for i := 0; i < MaxNicknameLength; i++ {
		nickname += "a"
	}
	expected := nickname + ".999999999"

	entropy, encrypted, err := CreateForUsername(expected, nil)
	if err != nil {
		t.Fatalf("CreateForUsername error: %v", err)
	}

	actual, err := DecryptUsername(entropy, encrypted)
	if err != nil {
		t.Fatalf("DecryptUsername error: %v", err)
	}
	if actual != expected {
		t.Errorf("got %q, want %q", actual, expected)
	}
}

// TestDecodeUsernameData_SkipsFixed64WireType verifies that the protobuf
// decoder skips wire type 1 (64-bit fixed) unknown fields instead of
// returning an error, matching PROST's unknown-field behaviour.
// This guards against future upstream additions of fixed-width fields to
// UsernameData breaking backward compatibility.
//
// The tag byte must fit in a single byte; field numbers 1-15 with wire
// types 0-7 all encode as a single byte: (fieldNum<<3)|wireType.
// Field 3, wire type 1 encodes as byte 0x19.
func TestDecodeUsernameData_SkipsFixed64WireType(t *testing.T) {
	// Build a protobuf message with:
	//   field 1 (string username, wire type 2, tag=0x0a): "ab.01"
	//   field 3 (unknown, wire type 1 = 64-bit fixed, tag=0x19): 8 bytes of zeros
	var buf []byte
	// tag for field 1, wire type 2: (1<<3)|2 = 0x0a — single byte
	buf = append(buf, 0x0a)
	username := "ab.01"
	buf = appendVarint(buf, uint64(len(username)))
	buf = append(buf, []byte(username)...)
	// tag for field 3, wire type 1 (64-bit fixed): (3<<3)|1 = 0x19 — single byte
	buf = append(buf, 0x19)
	buf = append(buf, make([]byte, 8)...)

	got, err := decodeUsernameData(buf)
	if err != nil {
		t.Fatalf("decodeUsernameData returned unexpected error for wire type 1: %v", err)
	}
	if got != username {
		t.Errorf("got %q, want %q", got, username)
	}
}

// TestDecodeUsernameData_SkipsFixed32WireType verifies that the protobuf
// decoder skips wire type 5 (32-bit fixed) unknown fields instead of
// returning an error, matching PROST's unknown-field behaviour.
//
// Field 3, wire type 5 encodes as byte 0x1d.
func TestDecodeUsernameData_SkipsFixed32WireType(t *testing.T) {
	var buf []byte
	// tag for field 1, wire type 2: (1<<3)|2 = 0x0a
	buf = append(buf, 0x0a)
	username := "cd.02"
	buf = appendVarint(buf, uint64(len(username)))
	buf = append(buf, []byte(username)...)
	// tag for field 3, wire type 5 (32-bit fixed): (3<<3)|5 = 0x1d — single byte
	buf = append(buf, 0x1d)
	var fixed32 [4]byte
	binary.LittleEndian.PutUint32(fixed32[:], 0xdeadbeef)
	buf = append(buf, fixed32[:]...)

	got, err := decodeUsernameData(buf)
	if err != nil {
		t.Fatalf("decodeUsernameData returned unexpected error for wire type 5: %v", err)
	}
	if got != username {
		t.Errorf("got %q, want %q", got, username)
	}
}

// TestDecodeUsernameData_TruncatedFixed64 verifies that a truncated 64-bit
// fixed field returns an error rather than silently succeeding.
// Field 3, wire type 1 (tag byte 0x19) with only 3 payload bytes instead of 8.
func TestDecodeUsernameData_TruncatedFixed64(t *testing.T) {
	var buf []byte
	// tag for field 3, wire type 1: (3<<3)|1 = 0x19
	buf = append(buf, 0x19)
	buf = append(buf, 0x01, 0x02, 0x03) // only 3 bytes instead of 8

	_, err := decodeUsernameData(buf)
	if err == nil {
		t.Fatal("expected error for truncated 64-bit field, got nil")
	}
}

// TestDecodeUsernameData_TruncatedFixed32 verifies that a truncated 32-bit
// fixed field returns an error rather than silently succeeding.
// Field 3, wire type 5 (tag byte 0x1d) with only 2 payload bytes instead of 4.
func TestDecodeUsernameData_TruncatedFixed32(t *testing.T) {
	var buf []byte
	// tag for field 3, wire type 5: (3<<3)|5 = 0x1d
	buf = append(buf, 0x1d)
	buf = append(buf, 0x01, 0x02) // only 2 bytes instead of 4

	_, err := decodeUsernameData(buf)
	if err == nil {
		t.Fatal("expected error for truncated 32-bit field, got nil")
	}
}

func TestPkcs7Padding(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		blockSize int
		padLen    int
	}{
		{"empty", []byte{}, 16, 16},
		{"one byte", []byte{0x01}, 16, 15},
		{"full block", make([]byte, 16), 16, 16},
		{"partial", make([]byte, 10), 16, 6},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			padded := pkcs7Pad(tt.data, tt.blockSize)
			if len(padded)%tt.blockSize != 0 {
				t.Errorf("padded length %d not a multiple of block size %d", len(padded), tt.blockSize)
			}
			unpadded, err := pkcs7Unpad(padded)
			if err != nil {
				t.Fatalf("unpad error: %v", err)
			}
			if len(unpadded) != len(tt.data) {
				t.Errorf("unpadded length %d != original length %d", len(unpadded), len(tt.data))
			}
		})
	}
}
