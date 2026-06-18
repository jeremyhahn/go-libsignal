// Frame-layer crypto unit tests ported from the Rust message-backup crate.
//
// Rust libsignal ref: rust/message-backup/src/frame/ @ 98915c44
//   - unpad.rs tests (empty, single, multiple, last_is_all_padding, empty_without_padding)
//   - block_stream.rs tests (empty, multiple_blocks, exact_block_stream_valid,
//     exact_block_stream_ragged_block)
//   - cbc.rs tests (stream_empty, stream_decrypts, stream_passes_errors — adapted)
//   - forward_secrecy.rs ValidateMetadata (valid, invalid variants)
//
// The hex / byte inputs mirror the exact constants used in the Rust tests.
// The unpadding and block-stream logic is exercised directly on Go's
// pkcs7Unpad and on the FrameDecryptor internals respectively.
package backup

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"testing"
)

// ---------------------------------------------------------------------------
// PKCS#7 unpadding tests (Rust: frame/unpad.rs)
// ---------------------------------------------------------------------------

// LAST and LAST_PADDING match the Rust constants in unpad.rs:115.
//
//	const LAST: [u8; 10] = [0xab; 10];
//	const LAST_PADDING: [u8; 6] = [6; 6];
var (
	unpadLAST        = bytes.Repeat([]byte{0xab}, 10)
	unpadLASTPADDING = bytes.Repeat([]byte{6}, 6)
	unpadALLPADDING  = bytes.Repeat([]byte{16}, 16) // [16; 16]
)

// TestPkcs7Unpad_Empty mirrors Rust unpad::test::empty.
// An empty stream (no blocks) produces no output.
// Here Go's pkcs7Unpad on empty input must return ErrEmptyUnpadData.
func TestPkcs7Unpad_Empty(t *testing.T) {
	_, err := pkcs7Unpad(nil, 16)
	if err == nil {
		t.Fatal("pkcs7Unpad(nil): expected error, got nil")
	}
	var emptyErr *ErrEmptyUnpadData
	if !errors.As(err, &emptyErr) {
		t.Fatalf("expected *ErrEmptyUnpadData, got %T: %v", err, err)
	}
}

// TestPkcs7Unpad_Single mirrors Rust unpad::test::single.
// A 16-byte block consisting of 10 data bytes [0xab] followed by 6 padding
// bytes [0x06] is unpadded to the 10 data bytes.
func TestPkcs7Unpad_Single(t *testing.T) {
	padded := make([]byte, 16)
	copy(padded[:10], unpadLAST)
	copy(padded[10:], unpadLASTPADDING)

	got, err := pkcs7Unpad(padded, 16)
	if err != nil {
		t.Fatalf("pkcs7Unpad single: %v", err)
	}
	if !bytes.Equal(got, unpadLAST) {
		t.Errorf("pkcs7Unpad single: got %x, want %x", got, unpadLAST)
	}
}

// TestPkcs7Unpad_Multiple mirrors Rust unpad::test::multiple.
// Three 16-byte blocks: two full blocks [0x11] and [0x22], then the padded block.
// The first two blocks are returned as-is; the last is unpadded.
func TestPkcs7Unpad_Multiple(t *testing.T) {
	block1 := bytes.Repeat([]byte{0x11}, 16)
	block2 := bytes.Repeat([]byte{0x22}, 16)
	lastBlock := make([]byte, 16)
	copy(lastBlock[:10], unpadLAST)
	copy(lastBlock[10:], unpadLASTPADDING)

	// Concatenate all three blocks: total 48 bytes with PKCS#7 padding in last block.
	data := append(append(block1, block2...), lastBlock...)

	// pkcs7Unpad operates on the entire slice. After unpadding a 48-byte input
	// with 6 bytes of padding, the result is 42 bytes.
	got, err := pkcs7Unpad(data, 16)
	if err != nil {
		t.Fatalf("pkcs7Unpad multiple: %v", err)
	}
	want := append(append(block1, block2...), unpadLAST...)
	if !bytes.Equal(got, want) {
		t.Errorf("pkcs7Unpad multiple: got %d bytes, want %d bytes", len(got), len(want))
	}
}

// TestPkcs7Unpad_LastIsAllPadding mirrors Rust unpad::test::last_is_all_padding.
// Three 16-byte blocks where the final block is all-padding [16; 16], so the
// final output should be the first two blocks and no trailing bytes.
func TestPkcs7Unpad_LastIsAllPadding(t *testing.T) {
	block1 := bytes.Repeat([]byte{0x11}, 16)
	block2 := bytes.Repeat([]byte{0x22}, 16)
	data := append(append(block1, block2...), unpadALLPADDING...)

	got, err := pkcs7Unpad(data, 16)
	if err != nil {
		t.Fatalf("pkcs7Unpad all-padding last block: %v", err)
	}
	want := append(block1, block2...)
	if !bytes.Equal(got, want) {
		t.Errorf("pkcs7Unpad all-padding: got %d bytes %x, want %d bytes %x",
			len(got), got, len(want), want)
	}
}

// TestPkcs7Unpad_EmptyWithoutPadding mirrors Rust unpad::test::empty_without_padding.
// A single 16-byte block consisting solely of all-padding [16; 16] results
// in an empty output (the data region is entirely consumed by padding).
func TestPkcs7Unpad_EmptyWithoutPadding(t *testing.T) {
	got, err := pkcs7Unpad(unpadALLPADDING, 16)
	if err != nil {
		t.Fatalf("pkcs7Unpad empty-without-padding: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("pkcs7Unpad empty-without-padding: got %d bytes, want 0", len(got))
	}
}

// TestPkcs7Unpad_InvalidPadding verifies that a block with an inconsistent
// padding byte is rejected. This exercises the constant-time guard in pkcs7Unpad.
func TestPkcs7Unpad_InvalidPadding(t *testing.T) {
	// Claim padding of 5 but only the last 4 bytes are 0x05.
	bad := make([]byte, 16)
	for i := 11; i < 16; i++ {
		bad[i] = 0x05 // 5 bytes of 0x05 is valid padding
	}
	bad[11] = 0x99 // corrupt the first pad byte

	_, err := pkcs7Unpad(bad, 16)
	if err == nil {
		t.Fatal("pkcs7Unpad invalid padding: expected error, got nil")
	}
	var padErr *ErrInvalidPadding
	if !errors.As(err, &padErr) {
		t.Fatalf("pkcs7Unpad invalid padding: expected *ErrInvalidPadding, got %T: %v", err, err)
	}
}

// TestPkcs7Unpad_NotAligned verifies that non-block-aligned input is rejected.
// Rust's UnpadLast only ever receives full blocks; misalignment is a logic error.
func TestPkcs7Unpad_NotAligned(t *testing.T) {
	// 17 bytes: not a multiple of 16.
	_, err := pkcs7Unpad(make([]byte, 17), 16)
	if err == nil {
		t.Fatal("pkcs7Unpad not-aligned: expected error, got nil")
	}
	var alignErr *ErrUnpadNotAligned
	if !errors.As(err, &alignErr) {
		t.Fatalf("pkcs7Unpad not-aligned: expected *ErrUnpadNotAligned, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// AES-256-CBC block decryption tests (Rust: frame/cbc.rs)
// ---------------------------------------------------------------------------

// These constants match the Rust test constants in cbc.rs:71.
//
//	const FAKE_AES_KEY: [u8; 32] = [0; 32];
//	const FAKE_AES_ID: [u8; 16] = [0; 16];
var (
	cbcFakeKey = make([]byte, 32) // all zeros
	cbcFakeIV  = make([]byte, 16) // all zeros
)

// TestCBCDecrypt_SingleBlock mirrors Rust cbc::test::stream_decrypts.
// Encrypts two 16-byte blocks with CBC and verifies decryption round-trips.
// Input blocks: [0xaa; 16] and [0xbb; 16].
func TestCBCDecrypt_SingleBlock(t *testing.T) {
	plaintext1 := bytes.Repeat([]byte{0xaa}, 16)
	plaintext2 := bytes.Repeat([]byte{0xbb}, 16)
	plaintext := append(plaintext1, plaintext2...)

	block, err := aes.NewCipher(cbcFakeKey)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}

	// Encrypt.
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, cbcFakeIV).CryptBlocks(ciphertext, plaintext)

	// Decrypt.
	block2, _ := aes.NewCipher(cbcFakeKey)
	decrypted := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block2, cbcFakeIV).CryptBlocks(decrypted, ciphertext)

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("CBC round-trip failed: got %x, want %x", decrypted, plaintext)
	}
}

// TestCBCDecrypt_EmptyInput mirrors Rust cbc::test::stream_empty.
// An empty input slice produces an empty output — no panic.
func TestCBCDecrypt_EmptyInput(t *testing.T) {
	block, err := aes.NewCipher(cbcFakeKey)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	dec := cipher.NewCBCDecrypter(block, cbcFakeIV)
	out := make([]byte, 0)
	dec.CryptBlocks(out, nil) // must not panic
}

// TestCBCDecrypt_IVChainsBlocks verifies that the IV chains correctly between
// blocks (each block's decryption XORs with the previous ciphertext block).
// This ensures the CBC mode is not operating as ECB.
func TestCBCDecrypt_IVChainsBlocks(t *testing.T) {
	// Two identical plaintext blocks should produce different ciphertext blocks
	// in CBC mode due to IV chaining.
	pt := bytes.Repeat([]byte{0xcc}, 32) // two identical 16-byte blocks

	block, _ := aes.NewCipher(cbcFakeKey)
	ct := make([]byte, 32)
	cipher.NewCBCEncrypter(block, cbcFakeIV).CryptBlocks(ct, pt)

	// The two ciphertext blocks must differ.
	if bytes.Equal(ct[:16], ct[16:]) {
		t.Error("CBC: identical plaintext blocks produced identical ciphertext blocks (ECB behavior)")
	}

	// Round-trip back.
	block2, _ := aes.NewCipher(cbcFakeKey)
	got := make([]byte, 32)
	cipher.NewCBCDecrypter(block2, cbcFakeIV).CryptBlocks(got, ct)
	if !bytes.Equal(got, pt) {
		t.Errorf("CBC IV-chaining round-trip failed: got %x, want %x", got, pt)
	}
}

// ---------------------------------------------------------------------------
// Block-stream boundary tests (Rust: frame/block_stream.rs)
// ---------------------------------------------------------------------------

// TestBlockStream_Empty mirrors Rust block_stream::test::empty.
// An empty byte source produces no blocks.
func TestBlockStream_Empty(t *testing.T) {
	// Exercise via FrameDecryptor with empty input — expects ErrDataTooShort.
	key := testMessageBackupKey(t)
	defer key.Zeroize()

	dec := NewFrameDecryptor(key)
	_, err := dec.DecryptFrames(bytes.NewReader(nil))
	if err == nil {
		t.Fatal("DecryptFrames(empty): expected error, got nil")
	}
	var shortErr *ErrDataTooShort
	if !errors.As(err, &shortErr) {
		t.Fatalf("expected *ErrDataTooShort, got %T: %v", err, err)
	}
}

// TestBlockStream_MinimumLengthRejected mirrors the block_stream "too short" scenario.
// Input shorter than IV+HMAC (48 bytes) is rejected before any block processing.
func TestBlockStream_MinimumLengthRejected(t *testing.T) {
	key := testMessageBackupKey(t)
	defer key.Zeroize()

	// 40 bytes: less than AESIVSize(16) + HMACLen(32) = 48.
	input := make([]byte, 40)

	dec := NewFrameDecryptor(key)
	_, err := dec.DecryptFrames(bytes.NewReader(input))
	if err == nil {
		t.Fatal("DecryptFrames(40 bytes): expected error, got nil")
	}
	var shortErr *ErrDataTooShort
	if !errors.As(err, &shortErr) {
		t.Fatalf("expected *ErrDataTooShort, got %T: %v", err, err)
	}
}

// TestBlockStream_CiphertextMustBeAligned verifies that ciphertext whose length
// is not a multiple of AES block size is rejected with ErrCiphertextNotAligned.
// This mirrors the ExactBlockStream ragged-block check in block_stream.rs.
func TestBlockStream_CiphertextMustBeAligned(t *testing.T) {
	// Build a valid HMAC over a deliberately non-aligned ciphertext payload
	// by using decryptPayload directly (skips HMAC check).
	key := testMessageBackupKey(t)
	defer key.Zeroize()

	fd := &FrameDecryptor{key: key}

	// content = 16-byte IV + 17-byte ciphertext (not aligned to 16)
	content := make([]byte, 33)

	_, err := fd.decryptPayload(content)
	if err == nil {
		t.Fatal("decryptPayload(non-aligned): expected error, got nil")
	}
	var alignErr *ErrCiphertextNotAligned
	if !errors.As(err, &alignErr) {
		t.Fatalf("expected *ErrCiphertextNotAligned, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// ForwardSecrecy / Metadata validation tests (Rust: frame/forward_secrecy.rs)
// ---------------------------------------------------------------------------

// TestValidateMetadata_Valid mirrors the Rust forward_secrecy::test::valid test.
// The test metadata from TestMetadata() (12-byte IV, 2 pairs with 48+32 byte fields)
// must pass validation without error.
func TestValidateMetadata_Valid(t *testing.T) {
	meta := TestMetadata()
	if err := ValidateMetadata(meta); err != nil {
		t.Fatalf("ValidateMetadata(valid): unexpected error: %v", err)
	}
}

// TestValidateMetadata_MissingPair mirrors Rust forward_secrecy::test::invalid(MetadataPb::new()).
// Empty pair list must be rejected with ForwardSecrecyErrorMissingField.
func TestValidateMetadata_MissingPair(t *testing.T) {
	meta := &BackupMetadata{
		IV:    make([]byte, 12),
		Pairs: nil,
	}
	err := ValidateMetadata(meta)
	if err == nil {
		t.Fatal("ValidateMetadata(no pairs): expected error, got nil")
	}
	var fsErr *ForwardSecrecyError
	if !errors.As(err, &fsErr) {
		t.Fatalf("expected *ForwardSecrecyError, got %T: %v", err, err)
	}
	if fsErr.Kind != ForwardSecrecyErrorMissingField {
		t.Errorf("error kind = %v, want ForwardSecrecyErrorMissingField", fsErr.Kind)
	}
}

// TestValidateMetadata_MissingCT mirrors Rust: pair with ct=empty, pw_salt set.
func TestValidateMetadata_MissingCT(t *testing.T) {
	meta := &BackupMetadata{
		IV: make([]byte, 12),
		Pairs: []ForwardSecrecyPair{
			{CT: nil, PWSalt: bytes.Repeat([]byte{1}, 32)},
		},
	}
	err := ValidateMetadata(meta)
	if err == nil {
		t.Fatal("ValidateMetadata(empty CT): expected error, got nil")
	}
	var fsErr *ForwardSecrecyError
	if !errors.As(err, &fsErr) {
		t.Fatalf("expected *ForwardSecrecyError, got %T: %v", err, err)
	}
	if fsErr.Kind != ForwardSecrecyErrorMissingField {
		t.Errorf("error kind = %v, want ForwardSecrecyErrorMissingField", fsErr.Kind)
	}
}

// TestValidateMetadata_MissingPWSalt mirrors Rust: pair with pw_salt=empty, ct set.
func TestValidateMetadata_MissingPWSalt(t *testing.T) {
	meta := &BackupMetadata{
		IV: make([]byte, 12),
		Pairs: []ForwardSecrecyPair{
			{CT: bytes.Repeat([]byte{1}, 48), PWSalt: nil},
		},
	}
	err := ValidateMetadata(meta)
	if err == nil {
		t.Fatal("ValidateMetadata(empty PWSalt): expected error, got nil")
	}
	var fsErr *ForwardSecrecyError
	if !errors.As(err, &fsErr) {
		t.Fatalf("expected *ForwardSecrecyError, got %T: %v", err, err)
	}
	if fsErr.Kind != ForwardSecrecyErrorMissingField {
		t.Errorf("error kind = %v, want ForwardSecrecyErrorMissingField", fsErr.Kind)
	}
}

// TestValidateMetadata_TooManyPairs mirrors Rust test_case with 3 default pairs.
func TestValidateMetadata_TooManyPairs(t *testing.T) {
	pair := ForwardSecrecyPair{
		CT:     bytes.Repeat([]byte{1}, 48),
		PWSalt: bytes.Repeat([]byte{2}, 32),
	}
	meta := &BackupMetadata{
		IV:    make([]byte, 12),
		Pairs: []ForwardSecrecyPair{pair, pair, pair},
	}
	err := ValidateMetadata(meta)
	if err == nil {
		t.Fatal("ValidateMetadata(3 pairs): expected error, got nil")
	}
	var fsErr *ForwardSecrecyError
	if !errors.As(err, &fsErr) {
		t.Fatalf("expected *ForwardSecrecyError, got %T: %v", err, err)
	}
	if fsErr.Kind != ForwardSecrecyErrorTooManyPairs {
		t.Errorf("error kind = %v, want ForwardSecrecyErrorTooManyPairs", fsErr.Kind)
	}
}

// TestValidateMetadata_InvalidIVLength verifies that an IV of the wrong length
// is rejected. The Rust test covers this via the iv field length check.
func TestValidateMetadata_InvalidIVLength(t *testing.T) {
	pair := ForwardSecrecyPair{
		CT:     bytes.Repeat([]byte{1}, 48),
		PWSalt: bytes.Repeat([]byte{2}, 32),
	}
	meta := &BackupMetadata{
		IV:    make([]byte, 8), // wrong: should be 12
		Pairs: []ForwardSecrecyPair{pair},
	}
	err := ValidateMetadata(meta)
	if err == nil {
		t.Fatal("ValidateMetadata(wrong IV length): expected error, got nil")
	}
	var fsErr *ForwardSecrecyError
	if !errors.As(err, &fsErr) {
		t.Fatalf("expected *ForwardSecrecyError, got %T: %v", err, err)
	}
	if fsErr.Kind != ForwardSecrecyErrorInvalidLength {
		t.Errorf("error kind = %v, want ForwardSecrecyErrorInvalidLength", fsErr.Kind)
	}
}

// ---------------------------------------------------------------------------
// Encrypt→Decrypt round-trip with plaintext comparison
// ---------------------------------------------------------------------------

// TestFrameEncryptDecryptRoundTrip verifies that Go-encrypted frames can be
// decrypted back to the original bytes. This exercises both the FrameEncryptor
// and FrameDecryptor code paths end-to-end with a plaintext comparison.
//
// This extends the coverage of messagebackup_cases_valid_test.go, which only
// verifies HMAC on Rust-generated data; here we verify Go-generated data.
func TestFrameEncryptDecryptRoundTrip(t *testing.T) {
	key := testMessageBackupKey(t)
	defer key.Zeroize()

	frames := [][]byte{
		{0x01, 0x02, 0x03, 0x04}, // simulated BackupInfo proto bytes
		{0x0a, 0x0b, 0x0c},       // simulated Frame proto bytes
		bytes.Repeat([]byte{0xff}, 128),
	}

	var buf bytes.Buffer
	enc := NewFrameEncryptor(key)
	if err := enc.EncryptFrames(&buf, frames); err != nil {
		t.Fatalf("EncryptFrames: %v", err)
	}

	dec := NewFrameDecryptor(key)
	got, err := dec.DecryptFrames(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("DecryptFrames: %v", err)
	}

	if len(got) != len(frames) {
		t.Fatalf("frame count: got %d, want %d", len(got), len(frames))
	}
	for i, f := range frames {
		if !bytes.Equal(got[i], f) {
			t.Errorf("frame %d mismatch: got %x, want %x", i, got[i], f)
		}
	}
}

// TestModernFrameEncryptDecryptRoundTrip verifies the modern SBACKUP\x01 format
// round-trips correctly, including metadata encode/decode and HMAC verification.
func TestModernFrameEncryptDecryptRoundTrip(t *testing.T) {
	key := testMessageBackupKey(t)
	defer key.Zeroize()

	meta := TestMetadata()
	frames := [][]byte{
		{0x01, 0x00},
		{0x0a, 0x02, 0xAB, 0xCD},
	}

	var buf bytes.Buffer
	enc := NewFrameEncryptor(key)
	if err := enc.EncryptFramesModern(&buf, frames, meta); err != nil {
		t.Fatalf("EncryptFramesModern: %v", err)
	}

	data := buf.Bytes()
	if !IsMagicNumber(data) {
		t.Fatalf("modern format missing SBACKUP\\x01 magic: %x", data[:8])
	}

	dec := NewFrameDecryptor(key)
	got, err := dec.DecryptFrames(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("DecryptFrames(modern): %v", err)
	}
	if len(got) != len(frames) {
		t.Fatalf("frame count: got %d, want %d", len(got), len(frames))
	}
	for i, f := range frames {
		if !bytes.Equal(got[i], f) {
			t.Errorf("frame %d mismatch: got %x, want %x", i, got[i], f)
		}
	}
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

// testMessageBackupKey creates a MessageBackupKey with deterministic all-zero
// and all-one byte patterns, suitable for unit tests.
func testMessageBackupKey(t *testing.T) *MessageBackupKey {
	t.Helper()
	key, err := NewMessageBackupKey(
		bytes.Repeat([]byte{0x00}, 32), // HMAC key
		bytes.Repeat([]byte{0x01}, 32), // AES key
	)
	if err != nil {
		t.Fatalf("NewMessageBackupKey: %v", err)
	}
	return key
}
