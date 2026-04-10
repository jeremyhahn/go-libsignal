package usernames

import (
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
