package usernames

import (
	"testing"
)

func TestUsernameErrorMessages(t *testing.T) {
	tests := []struct {
		err      UsernameError
		contains string
	}{
		{ErrMissingSeparator, "'.'"},
		{ErrNicknameCannotBeEmpty, "empty"},
		{ErrNicknameCannotStartWithDigit, "digit"},
		{ErrBadNicknameCharacter, "disallowed"},
		{ErrNicknameTooShort, "too short"},
		{ErrNicknameTooLong, "too long"},
		{ErrDiscriminatorCannotBeEmpty, "empty"},
		{ErrDiscriminatorCannotBeZero, "zero"},
		{ErrDiscriminatorCannotBeSingleDigit, "single digit"},
		{ErrDiscriminatorCannotHaveLeadingZeros, "leading zeros"},
		{ErrBadDiscriminatorCharacter, "digits"},
		{ErrDiscriminatorTooLarge, "too large"},
	}
	for _, tt := range tests {
		t.Run(tt.err.Error(), func(t *testing.T) {
			msg := tt.err.Error()
			if msg == "" {
				t.Error("error message should not be empty")
			}
		})
	}
}

func TestUsernameErrorOutOfRange(t *testing.T) {
	e := UsernameError(999)
	msg := e.Error()
	if msg == "" {
		t.Fatal("out-of-range error should still produce a message")
	}
}

func TestProofVerificationFailureError(t *testing.T) {
	e := ProofVerificationFailure{}
	msg := e.Error()
	if msg != "username could not be verified" {
		t.Errorf("Error() = %q, want %q", msg, "username could not be verified")
	}
}

func TestUsernameLinkErrorMessages(t *testing.T) {
	tests := []struct {
		err UsernameLinkError
	}{
		{ErrInputDataTooLong},
		{ErrInvalidEntropyDataLength},
		{ErrUsernameLinkDataTooShort},
		{ErrHmacMismatch},
		{ErrBadCiphertext},
		{ErrInvalidDecryptedDataStructure},
	}
	for _, tt := range tests {
		t.Run(tt.err.Error(), func(t *testing.T) {
			msg := tt.err.Error()
			if msg == "" {
				t.Error("error message should not be empty")
			}
		})
	}
}

func TestUsernameLinkErrorOutOfRange(t *testing.T) {
	e := UsernameLinkError(999)
	msg := e.Error()
	if msg == "" {
		t.Fatal("out-of-range error should still produce a message")
	}
}

func TestNewNicknameLimitsPanicMaxTooLarge(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for maxLen > MaxNicknameLength")
		}
	}()
	NewNicknameLimits(3, MaxNicknameLength+10)
}

func TestNewNicknameLimitsPanicMinGeMax(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for minLen >= maxLen")
		}
	}()
	NewNicknameLimits(10, 10)
}

func TestValidateNicknameBadCharacter(t *testing.T) {
	err := validateNickname("hello!", DefaultNicknameLimits())
	if err != ErrBadNicknameCharacter {
		t.Errorf("expected ErrBadNicknameCharacter, got %v", err)
	}
}

func TestValidateNicknameEmpty(t *testing.T) {
	err := validateNickname("", DefaultNicknameLimits())
	if err != ErrNicknameCannotBeEmpty {
		t.Errorf("expected ErrNicknameCannotBeEmpty, got %v", err)
	}
}

func TestValidateNicknameTooShort(t *testing.T) {
	err := validateNickname("ab", DefaultNicknameLimits())
	if err != ErrNicknameTooShort {
		t.Errorf("expected ErrNicknameTooShort, got %v", err)
	}
}

func TestCandidatesFromInvalidNickname(t *testing.T) {
	_, err := CandidatesFrom("", DefaultNicknameLimits())
	if err == nil {
		t.Fatal("expected error for empty nickname")
	}
}

func TestCandidatesFromBadChar(t *testing.T) {
	_, err := CandidatesFrom("hello!", DefaultNicknameLimits())
	if err == nil {
		t.Fatal("expected error for bad character in nickname")
	}
}

func TestVerifyProofBadLength(t *testing.T) {
	u, _ := New("test.42")
	hash := u.Hash()
	// Proof is too short.
	err := VerifyProof([]byte{1, 2, 3}, hash)
	if err == nil {
		t.Fatal("expected error for bad proof length")
	}
}

func TestVerifyProofInvalidHash(t *testing.T) {
	// All-zero hash is not a valid ristretto point.
	var hash [32]byte
	// Wrong proof length but invalid hash should fail first.
	proof := make([]byte, 32*4)
	err := VerifyProof(proof, hash)
	if err == nil {
		t.Fatal("expected error for invalid hash point")
	}
}

func TestVerifyProofWrongProofData(t *testing.T) {
	u, _ := New("test.42")
	hash := u.Hash()
	// Correct length but garbage proof data.
	proof := make([]byte, 32*4)
	for i := range proof {
		proof[i] = byte(i)
	}
	err := VerifyProof(proof, hash)
	if err == nil {
		t.Fatal("expected error for wrong proof data")
	}
}

func TestCharToByteInvalid(t *testing.T) {
	invalid := []rune{'!', '@', '#', '$', ' ', '\n', '\t', 'A'}
	for _, c := range invalid {
		_, ok := charToByte(c)
		if ok {
			t.Errorf("charToByte(%c) should return false", c)
		}
	}
}

func TestDecodeUsernameDataUnsupportedWireType(t *testing.T) {
	// Wire type 5 (32-bit) is not supported.
	data := []byte{0x0d} // field 1, wire type 5
	_, err := decodeUsernameData(data)
	if err == nil {
		t.Fatal("expected error for unsupported wire type")
	}
}

func TestDecodeUsernameDataVarintField(t *testing.T) {
	// field 3, wire type 0 (varint), value 42
	data := []byte{0x18, 0x2a}
	username, err := decodeUsernameData(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if username != "" {
		t.Errorf("expected empty username, got %q", username)
	}
}

func TestDecodeUsernameDataFieldExtendsPastEnd(t *testing.T) {
	// field 1, wire type 2, length 100 but only 2 bytes of data
	data := []byte{0x0a, 0x64, 0x41, 0x42}
	_, err := decodeUsernameData(data)
	if err == nil {
		t.Fatal("expected error for field extending past end of data")
	}
}

func TestReadVarintTooLong(t *testing.T) {
	// 10 bytes with continuation bits set
	data := make([]byte, 10)
	for i := range data {
		data[i] = 0x80
	}
	_, _, err := readVarint(data)
	if err == nil {
		t.Fatal("expected error for varint too long")
	}
}

func TestReadVarintUnexpectedEnd(t *testing.T) {
	// Empty data
	_, _, err := readVarint([]byte{})
	if err == nil {
		t.Fatal("expected error for empty varint data")
	}
}

func TestReadVarintSingleByte(t *testing.T) {
	v, n, err := readVarint([]byte{0x2a})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != 42 || n != 1 {
		t.Errorf("readVarint = (%d, %d), want (42, 1)", v, n)
	}
}

func TestPkcs7UnpadEmpty(t *testing.T) {
	_, err := pkcs7Unpad([]byte{})
	if err == nil {
		t.Fatal("expected error for empty data")
	}
}

func TestPkcs7UnpadInvalidPaddingZero(t *testing.T) {
	data := make([]byte, 16)
	data[15] = 0 // padding byte = 0 is invalid
	_, err := pkcs7Unpad(data)
	if err == nil {
		t.Fatal("expected error for zero padding byte")
	}
}

func TestPkcs7UnpadInvalidPaddingTooLarge(t *testing.T) {
	data := make([]byte, 16)
	data[15] = 17 // padding byte > block size
	_, err := pkcs7Unpad(data)
	if err == nil {
		t.Fatal("expected error for padding byte > block size")
	}
}

func TestPkcs7UnpadInconsistentPadding(t *testing.T) {
	data := make([]byte, 16)
	data[15] = 3
	data[14] = 3
	data[13] = 5 // inconsistent
	_, err := pkcs7Unpad(data)
	if err == nil {
		t.Fatal("expected error for inconsistent padding bytes")
	}
}

func TestPkcs7UnpadNotBlockAligned(t *testing.T) {
	// Data that is not a multiple of the block size should fail.
	_, err := pkcs7Unpad([]byte{0x01, 0x02, 0x03})
	if err == nil {
		t.Fatal("expected error for non-block-aligned data")
	}
}

func TestPkcs7UnpadValidPadding(t *testing.T) {
	tests := []struct {
		name    string
		padLen  int
		dataLen int
	}{
		{"pad1", 1, 15},
		{"pad4", 4, 12},
		{"pad16_full_block", 16, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build a block-aligned slice with valid PKCS#7 padding.
			data := make([]byte, tt.dataLen+tt.padLen)
			for i := tt.dataLen; i < len(data); i++ {
				data[i] = byte(tt.padLen)
			}
			// Fill payload with identifiable bytes.
			for i := 0; i < tt.dataLen; i++ {
				data[i] = byte(i + 1)
			}
			result, err := pkcs7Unpad(data)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(result) != tt.dataLen {
				t.Errorf("unpadded length = %d, want %d", len(result), tt.dataLen)
			}
		})
	}
}

func TestPkcs7PadUnpadRoundTrip(t *testing.T) {
	// Verify that pad followed by unpad recovers the original data.
	original := []byte("hello, world!!")
	padded := pkcs7Pad(original, 16)
	unpadded, err := pkcs7Unpad(padded)
	if err != nil {
		t.Fatalf("pkcs7Unpad failed: %v", err)
	}
	if string(unpadded) != string(original) {
		t.Errorf("round-trip failed: got %q, want %q", unpadded, original)
	}
}

func TestAes256CBCDecryptNotMultipleOfBlockSize(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	_, err := aes256CBCDecrypt([]byte{1, 2, 3}, key, iv)
	if err == nil {
		t.Fatal("expected error for ciphertext not multiple of block size")
	}
}

func TestAes256CBCDecryptEmptyCiphertext(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	_, err := aes256CBCDecrypt([]byte{}, key, iv)
	if err == nil {
		t.Fatal("expected error for empty ciphertext")
	}
}

func TestCreateForUsernameInvalidEntropyLength(t *testing.T) {
	_, _, err := CreateForUsername("test.42", []byte{1, 2, 3})
	if err != ErrInvalidEntropyDataLength {
		t.Errorf("expected ErrInvalidEntropyDataLength, got %v", err)
	}
}

func TestDecryptUsernameBadCiphertext(t *testing.T) {
	// Create a valid encrypted link and then corrupt the ciphertext.
	entropy, encrypted, err := CreateForUsername("test.42", nil)
	if err != nil {
		t.Fatalf("CreateForUsername: %v", err)
	}
	// Corrupt ciphertext bytes (between IV and HMAC).
	for i := usernameLinkIVSize; i < len(encrypted)-usernameLinkHMACLen; i++ {
		encrypted[i] ^= 0xFF
	}
	// Re-compute HMAC to bypass HMAC check, so we test the decrypt path.
	macKey := hkdfDeriveKey(entropy[:], usernameLinkLabelAuthenticationKey)
	macOffset := len(encrypted) - usernameLinkHMACLen
	mac := computeHMAC(macKey[:], encrypted[:macOffset])
	copy(encrypted[macOffset:], mac)

	_, err = DecryptUsername(entropy, encrypted)
	if err == nil {
		t.Fatal("expected error for corrupted ciphertext")
	}
}

func TestEncodeDecodeUsernameDataRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		username string
		padding  int
	}{
		{"simple", "hello.42", 10},
		{"no padding", "test.01", 0},
		{"empty username", "", 5},
		{"long", "abcdefghijklmnopqrstuvwxyz.42", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := encodeUsernameData(tt.username, tt.padding)
			decoded, err := decodeUsernameData(encoded)
			if err != nil {
				t.Fatalf("decodeUsernameData: %v", err)
			}
			if decoded != tt.username {
				t.Errorf("got %q, want %q", decoded, tt.username)
			}
		})
	}
}

func TestDecodeUsernameDataVarintInFieldExtendsPastEnd(t *testing.T) {
	// Wire type 0 (varint) but varint is truncated
	data := []byte{0x08, 0x80} // field 1, wire type 0, continuation bit set but no more data
	_, err := decodeUsernameData(data)
	if err == nil {
		t.Fatal("expected error for truncated varint")
	}
}

func TestDecodeUsernameDataLengthDelimitedVarintError(t *testing.T) {
	// Wire type 2 (length-delimited) but length varint is truncated
	data := []byte{0x0a, 0x80} // field 1, wire type 2, continuation bit set but no more data
	_, err := decodeUsernameData(data)
	if err == nil {
		t.Fatal("expected error for truncated length varint")
	}
}

func TestNicknameScalarMaxLength(t *testing.T) {
	// Create a nickname at exactly MaxNicknameLength
	nickname := ""
	for i := 0; i < MaxNicknameLength; i++ {
		nickname += "a"
	}
	s, err := nicknameScalar(nickname)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s == nil {
		t.Fatal("scalar should not be nil")
	}
}

func TestNicknameScalarTooLong(t *testing.T) {
	// Create a nickname beyond MaxNicknameLength
	nickname := ""
	for i := 0; i < MaxNicknameLength+1; i++ {
		nickname += "a"
	}
	_, err := nicknameScalar(nickname)
	if err != ErrNicknameTooLong {
		t.Errorf("expected ErrNicknameTooLong, got %v", err)
	}
}

func TestDiscriminatorValidTwoDigit(t *testing.T) {
	d, err := validateDiscriminator("42")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d != 42 {
		t.Errorf("got %d, want 42", d)
	}
}

func TestDiscriminatorValidThreeDigitNoLeadingZero(t *testing.T) {
	d, err := validateDiscriminator("123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d != 123 {
		t.Errorf("got %d, want 123", d)
	}
}

func TestDiscriminatorMiddleNonDigit(t *testing.T) {
	_, err := validateDiscriminator("1a2")
	if err != ErrBadDiscriminatorCharacter {
		t.Errorf("expected ErrBadDiscriminatorCharacter, got %v", err)
	}
}
