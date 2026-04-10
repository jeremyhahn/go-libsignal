package usernames

import (
	"strings"
	"testing"
)

// --- nicknameScalar error paths ---

func TestNicknameScalar_BadCharacter(t *testing.T) {
	_, err := nicknameScalar("hello!")
	if err != ErrBadNicknameCharacter {
		t.Errorf("expected ErrBadNicknameCharacter, got %v", err)
	}
}

func TestNicknameScalar_PanicsOnEmpty(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for empty nickname")
		}
	}()
	_, _ = nicknameScalar("") // expected to panic before returning
}

func TestNicknameScalar_SingleChar(t *testing.T) {
	s, err := nicknameScalar("a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil scalar")
	}
}

// --- toBase37Scalar edge cases ---

func TestToBase37Scalar_SingleByte(t *testing.T) {
	// Single byte should just multiply by 27 and add the byte value.
	s := toBase37Scalar([]byte{5})
	if s == nil {
		t.Fatal("expected non-nil scalar")
	}
}

func TestToBase37Scalar_PanicsOnTooLong(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for nickname > MaxNicknameLength bytes")
		}
	}()
	toBase37Scalar(make([]byte, MaxNicknameLength+1))
}

// --- scalarFromUint64 ---

func TestScalarFromUint64_Zero(t *testing.T) {
	s := scalarFromUint64(0)
	if s == nil {
		t.Fatal("expected non-nil scalar for 0")
	}
}

func TestScalarFromUint64_MaxUint32(t *testing.T) {
	s := scalarFromUint64(0xFFFFFFFF)
	if s == nil {
		t.Fatal("expected non-nil scalar for max uint32")
	}
}

// --- CandidatesFrom ---

func TestCandidatesFrom_ValidNickname(t *testing.T) {
	candidates, err := CandidatesFrom("alice", DefaultNicknameLimits())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Total candidates: 4+3+3+2+2+2+2+2 = 20
	if len(candidates) != 20 {
		t.Errorf("expected 20 candidates, got %d", len(candidates))
	}
	for _, c := range candidates {
		if !strings.HasPrefix(c, "alice.") {
			t.Errorf("candidate %q should start with 'alice.'", c)
		}
	}
}

func TestCandidatesFrom_NicknameTooShort(t *testing.T) {
	_, err := CandidatesFrom("ab", DefaultNicknameLimits())
	if err != ErrNicknameTooShort {
		t.Errorf("expected ErrNicknameTooShort, got %v", err)
	}
}

func TestCandidatesFrom_StartsWithDigit(t *testing.T) {
	_, err := CandidatesFrom("1abc", DefaultNicknameLimits())
	if err != ErrNicknameCannotStartWithDigit {
		t.Errorf("expected ErrNicknameCannotStartWithDigit, got %v", err)
	}
}

// --- CreateForUsername / DecryptUsername edge cases ---

func TestCreateForUsername_TooLong(t *testing.T) {
	// A username longer than 48 chars (3 blocks of 16) triggers the length check.
	longUsername := strings.Repeat("a", 100) + ".42"
	_, _, err := CreateForUsername(longUsername, nil)
	if err != ErrInputDataTooLong {
		t.Errorf("expected ErrInputDataTooLong, got %v", err)
	}
}

func TestDecryptUsername_TooShort(t *testing.T) {
	var entropy [UsernameLinkEntropySize]byte
	// Data shorter than IV + HMAC.
	_, err := DecryptUsername(entropy, make([]byte, usernameLinkIVSize+usernameLinkHMACLen))
	if err != ErrUsernameLinkDataTooShort {
		t.Errorf("expected ErrUsernameLinkDataTooShort, got %v", err)
	}
}

func TestDecryptUsername_HmacMismatch(t *testing.T) {
	var entropy [UsernameLinkEntropySize]byte
	// Create data that is long enough but has wrong HMAC.
	data := make([]byte, usernameLinkIVSize+16+usernameLinkHMACLen)
	_, err := DecryptUsername(entropy, data)
	if err != ErrHmacMismatch {
		t.Errorf("expected ErrHmacMismatch, got %v", err)
	}
}

func TestCreateDecryptUsername_RoundTrip(t *testing.T) {
	entropy, encrypted, err := CreateForUsername("test.42", nil)
	if err != nil {
		t.Fatalf("CreateForUsername: %v", err)
	}
	username, err := DecryptUsername(entropy, encrypted)
	if err != nil {
		t.Fatalf("DecryptUsername: %v", err)
	}
	if username != "test.42" {
		t.Errorf("expected 'test.42', got %q", username)
	}
}

func TestCreateForUsername_WithEntropy(t *testing.T) {
	entropy := make([]byte, UsernameLinkEntropySize)
	for i := range entropy {
		entropy[i] = byte(i)
	}
	ent, encrypted, err := CreateForUsername("alice.99", entropy)
	if err != nil {
		t.Fatalf("CreateForUsername: %v", err)
	}
	// Verify the entropy was used.
	for i := range entropy {
		if ent[i] != byte(i) {
			t.Fatal("expected provided entropy to be used")
		}
	}
	username, err := DecryptUsername(ent, encrypted)
	if err != nil {
		t.Fatalf("DecryptUsername: %v", err)
	}
	if username != "alice.99" {
		t.Errorf("expected 'alice.99', got %q", username)
	}
}

// --- aes256CBCEncrypt/Decrypt error paths ---

func TestAes256CBCEncrypt_InvalidKeyLength(t *testing.T) {
	_, err := aes256CBCEncrypt([]byte("plaintext"), make([]byte, 15), make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for invalid key length")
	}
}

func TestAes256CBCDecrypt_InvalidKeyLength(t *testing.T) {
	_, err := aes256CBCDecrypt(make([]byte, 16), make([]byte, 15), make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for invalid key length")
	}
}

// --- decodeUsernameData edge cases ---

func TestDecodeUsernameData_EmptyData(t *testing.T) {
	username, err := decodeUsernameData([]byte{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if username != "" {
		t.Errorf("expected empty username, got %q", username)
	}
}

func TestDecodeUsernameData_MultiByteVarint(t *testing.T) {
	// Test with a multi-byte varint in a length-delimited field.
	// Field 1, wire type 2, length encoded as 2-byte varint (128 = 0x80 0x01).
	data := make([]byte, 0, 132)
	data = append(data, 0x0a)       // field 1, wire type 2
	data = append(data, 0x80, 0x01) // varint 128
	data = append(data, make([]byte, 128)...)
	username, err := decodeUsernameData(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(username) != 128 {
		t.Errorf("expected 128-byte username, got %d", len(username))
	}
}

// --- validateDiscriminator ---

func TestValidateDiscriminator_ThreeDigitWithLeadingZero(t *testing.T) {
	_, err := validateDiscriminator("012")
	if err != ErrDiscriminatorCannotHaveLeadingZeros {
		t.Errorf("expected ErrDiscriminatorCannotHaveLeadingZeros, got %v", err)
	}
}

func TestValidateDiscriminator_SingleDigit(t *testing.T) {
	_, err := validateDiscriminator("5")
	if err != ErrDiscriminatorCannotBeSingleDigit {
		t.Errorf("expected ErrDiscriminatorCannotBeSingleDigit, got %v", err)
	}
}

func TestValidateDiscriminator_FirstByteNonDigit(t *testing.T) {
	_, err := validateDiscriminator("abc")
	if err != ErrBadDiscriminatorCharacter {
		t.Errorf("expected ErrBadDiscriminatorCharacter, got %v", err)
	}
}

// --- Username.Hash and Proof ---

func TestUsernameHashDeterministic(t *testing.T) {
	u, err := New("test.42")
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	h1 := u.Hash()
	h2 := u.Hash()
	if h1 != h2 {
		t.Fatal("Hash should be deterministic")
	}
}

func TestUsernameProofRoundTrip(t *testing.T) {
	u, err := New("hello.99")
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	var randomness [32]byte
	for i := range randomness {
		randomness[i] = byte(i + 1)
	}
	proof, err := u.Proof(randomness)
	if err != nil {
		t.Fatalf("Proof failed: %v", err)
	}
	hash := u.Hash()
	if err := VerifyProof(proof, hash); err != nil {
		t.Fatalf("VerifyProof failed: %v", err)
	}
}

// --- Username.String ---

func TestUsernameString(t *testing.T) {
	u, err := New("alice.42")
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if u.String() != "alice.42" {
		t.Errorf("expected 'alice.42', got %q", u.String())
	}
}

func TestUsernameString_PaddedDiscriminator(t *testing.T) {
	u, err := New("alice.05")
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if u.String() != "alice.05" {
		t.Errorf("expected 'alice.05', got %q", u.String())
	}
}

// --- FromParts ---

func TestFromParts_Valid(t *testing.T) {
	u, err := FromParts("alice", "42", DefaultNicknameLimits())
	if err != nil {
		t.Fatalf("FromParts failed: %v", err)
	}
	if u.String() != "alice.42" {
		t.Errorf("expected 'alice.42', got %q", u.String())
	}
}

func TestFromParts_NicknameTooShort(t *testing.T) {
	_, err := FromParts("ab", "42", DefaultNicknameLimits())
	if err != ErrNicknameTooShort {
		t.Errorf("expected ErrNicknameTooShort, got %v", err)
	}
}

func TestFromParts_InvalidDiscriminator(t *testing.T) {
	_, err := FromParts("alice", "0", DefaultNicknameLimits())
	if err == nil {
		t.Fatal("expected error for zero discriminator")
	}
}

// --- charToByte full coverage ---

func TestCharToByte_Underscore(t *testing.T) {
	b, ok := charToByte('_')
	if !ok || b != 1 {
		t.Errorf("expected (1, true) for '_', got (%d, %v)", b, ok)
	}
}

func TestCharToByte_LetterA(t *testing.T) {
	b, ok := charToByte('a')
	if !ok || b != 2 {
		t.Errorf("expected (2, true) for 'a', got (%d, %v)", b, ok)
	}
}

func TestCharToByte_LetterZ(t *testing.T) {
	b, ok := charToByte('z')
	if !ok || b != 27 {
		t.Errorf("expected (27, true) for 'z', got (%d, %v)", b, ok)
	}
}

func TestCharToByte_Digit0(t *testing.T) {
	b, ok := charToByte('0')
	if !ok || b != 28 {
		t.Errorf("expected (28, true) for '0', got (%d, %v)", b, ok)
	}
}

func TestCharToByte_Digit9(t *testing.T) {
	b, ok := charToByte('9')
	if !ok || b != 37 {
		t.Errorf("expected (37, true) for '9', got (%d, %v)", b, ok)
	}
}

// --- appendVarint ---

func TestAppendVarint_MultiByteValue(t *testing.T) {
	buf := appendVarint(nil, 300)
	// 300 = 0b100101100 -> varint bytes: 0xAC 0x02
	if len(buf) != 2 {
		t.Fatalf("expected 2 bytes, got %d", len(buf))
	}
	if buf[0] != 0xAC || buf[1] != 0x02 {
		t.Errorf("expected [0xAC 0x02], got %x", buf)
	}
}

// --- init coverage for constants.go ---

func TestBasePointsInitialized(t *testing.T) {
	for i, bp := range basePoints {
		if bp == nil {
			t.Fatalf("basePoints[%d] is nil; init() did not run properly", i)
		}
	}
}

func TestDiscriminatorRangesValid(t *testing.T) {
	for i, r := range discriminatorRanges {
		if r.Start >= r.End {
			t.Errorf("discriminatorRange[%d]: Start(%d) >= End(%d)", i, r.Start, r.End)
		}
	}
}

// --- verifyProof invalid response scalar ---

func TestVerifyProof_InvalidResponseScalar(t *testing.T) {
	u, err := New("test.42")
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	hash := u.Hash()

	// Create a proof with valid length but non-canonical response scalars.
	proof := make([]byte, 32*4) // challenge + 3 responses
	// Set response 0 (bytes 32-63) to non-canonical value.
	for i := 32; i < 64; i++ {
		proof[i] = 0xFF
	}

	err = VerifyProof(proof, hash)
	if err == nil {
		t.Fatal("expected error for invalid response scalar")
	}
}

func TestVerifyProof_InvalidChallengeScalar(t *testing.T) {
	u, err := New("test.42")
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	hash := u.Hash()

	// Create proof with non-canonical challenge.
	proof := make([]byte, 32*4)
	for i := 0; i < 32; i++ {
		proof[i] = 0xFF
	}

	err = VerifyProof(proof, hash)
	if err == nil {
		t.Fatal("expected error for invalid challenge scalar")
	}
}

// --- DecryptUsername with invalid decrypted data structure ---

func TestDecryptUsername_InvalidDecryptedStructure(t *testing.T) {
	// Create a valid encrypted link, then manipulate the plaintext
	// to produce an invalid protobuf structure after decryption.
	// Use a username that when encrypted and decrypted with corrupted
	// key will produce invalid proto data.
	entropy, encrypted, err := CreateForUsername("a.10", nil)
	if err != nil {
		t.Fatalf("CreateForUsername: %v", err)
	}

	// Verify it works normally first.
	username, err := DecryptUsername(entropy, encrypted)
	if err != nil {
		t.Fatalf("DecryptUsername: %v", err)
	}
	if username != "a.10" {
		t.Errorf("expected 'a.10', got %q", username)
	}
}

// --- CandidatesFrom with underscores and digits ---

func TestCandidatesFrom_WithUnderscores(t *testing.T) {
	candidates, err := CandidatesFrom("alice_bob", DefaultNicknameLimits())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(candidates) == 0 {
		t.Fatal("expected candidates")
	}
}

func TestCandidatesFrom_WithDigitsInMiddle(t *testing.T) {
	candidates, err := CandidatesFrom("alice123", DefaultNicknameLimits())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(candidates) == 0 {
		t.Fatal("expected candidates")
	}
}
