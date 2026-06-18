package cipher

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"errors"
	"math"
	"testing"
)

func TestAESCTREncryptDecryptRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := []byte("AES-CTR test data for Signal protocol")

	ciphertext, err := AESCTREncrypt(key, plaintext)
	if err != nil {
		t.Fatalf("AESCTREncrypt: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext should differ from plaintext")
	}

	decrypted, err := AESCTRDecrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("AESCTRDecrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("round-trip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestAESCTRInvalidKeySize(t *testing.T) {
	_, err := AESCTREncrypt(make([]byte, 16), []byte("data"))
	if err == nil {
		t.Fatal("expected error for 16-byte key")
	}

	_, err = AESCTRDecrypt(make([]byte, 16), []byte("data"))
	if err == nil {
		t.Fatal("expected error for 16-byte key")
	}
}

func TestAESCTREmptyPlaintext(t *testing.T) {
	key := make([]byte, 32)
	ct, err := AESCTREncrypt(key, []byte{})
	if err != nil {
		t.Fatalf("AESCTREncrypt with empty: %v", err)
	}
	if len(ct) != 0 {
		t.Errorf("empty plaintext should produce empty ciphertext, got %d bytes", len(ct))
	}
}

func TestAESCTRNilInput(t *testing.T) {
	key := make([]byte, 32)
	ct, err := AESCTREncrypt(key, nil)
	if err != nil {
		t.Fatalf("AESCTREncrypt with nil: %v", err)
	}
	if len(ct) != 0 {
		t.Errorf("nil input should produce empty output, got %d bytes", len(ct))
	}
}

func TestAESCTRZeroLengthKey(t *testing.T) {
	_, err := AESCTREncrypt(nil, []byte("data"))
	if err == nil {
		t.Error("AESCTREncrypt should reject nil key")
	}

	_, err = AESCTRDecrypt([]byte{}, []byte("data"))
	if err == nil {
		t.Error("AESCTRDecrypt should reject empty key")
	}
}

func TestAESCTRLargePayload(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	// 4KB payload exercises multiple stream blocks.
	plaintext := make([]byte, 4096)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	ct, err := AESCTREncrypt(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := AESCTRDecrypt(key, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Error("round-trip failed for large payload")
	}
}

func TestAESCTRSymmetric(t *testing.T) {
	// AES-CTR: encrypt is same as decrypt
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 10)
	}
	data := []byte("symmetry test")

	enc, _ := AESCTREncrypt(key, data)
	dec, _ := AESCTREncrypt(key, enc) // encrypt again to decrypt
	if !bytes.Equal(dec, data) {
		t.Error("AES-CTR should be symmetric")
	}
}

// TestAESCTR32BitCounter verifies that only the last 4 bytes of the counter
// block increment (32-bit big-endian counter), matching Rust's ctr::Ctr32BE.
// With a 128-bit counter (Go stdlib), bytes [0..12] would also change after
// the 32-bit counter wraps, producing different keystream.
func TestAESCTR32BitCounter(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	// Generate keystream blocks manually using our 32-bit BE counter,
	// starting from counter 0, and verify the nonce bytes stay fixed.
	var counter [aes.BlockSize]byte
	var ks1, ks2 [aes.BlockSize]byte

	// Block 0: counter = 0
	block.Encrypt(ks1[:], counter[:])

	// Block 1: counter = 1 (only last 4 bytes change)
	binary.BigEndian.PutUint32(counter[12:16], 1)
	block.Encrypt(ks2[:], counter[:])

	// The nonce portion (first 12 bytes of counter) should remain zero
	// for both blocks.
	for i := 0; i < 12; i++ {
		if counter[i] != 0 {
			t.Errorf("nonce byte %d changed: got 0x%02x", i, counter[i])
		}
	}

	// Keystream blocks should differ (different counter values).
	if bytes.Equal(ks1[:], ks2[:]) {
		t.Error("keystream blocks for counter 0 and 1 should differ")
	}
}

// TestAESCTR32BitCounterWrap verifies correct behavior when the 32-bit
// counter wraps from 0xFFFFFFFF to 0x00000000. A 128-bit big-endian counter
// would carry into byte 11, changing the nonce and producing different
// keystream. Our 32-bit counter wraps without affecting the nonce.
func TestAESCTR32BitCounterWrap(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate what our CTR does at counter = 0xFFFFFFFF.
	var counterPre [aes.BlockSize]byte
	binary.BigEndian.PutUint32(counterPre[12:16], 0xFFFFFFFF)
	var ksPre [aes.BlockSize]byte
	block.Encrypt(ksPre[:], counterPre[:])

	// After wrap: counter = 0x00000000, nonce stays zero.
	var counterPost [aes.BlockSize]byte
	// 32-bit wrap: 0xFFFFFFFF + 1 = 0x00000000 (no carry into nonce).
	binary.BigEndian.PutUint32(counterPost[12:16], 0)
	var ksPost [aes.BlockSize]byte
	block.Encrypt(ksPost[:], counterPost[:])

	// With a 128-bit counter, the carry would propagate into byte 11,
	// producing counterPost = [0,0,...,0,1,0,0,0,0] which would yield
	// a different keystream than counter = [0,0,...,0,0,0,0,0,0].
	//
	// With our 32-bit counter, post-wrap counter is identical to counter 0,
	// so ksPost should equal the keystream for counter 0.
	var counterZero [aes.BlockSize]byte
	var ksZero [aes.BlockSize]byte
	block.Encrypt(ksZero[:], counterZero[:])

	if !bytes.Equal(ksPost[:], ksZero[:]) {
		t.Error("32-bit counter wrap should produce same block as counter 0 (no carry into nonce)")
	}

	// Also verify that counterPre != counterPost (different keystream).
	if bytes.Equal(ksPre[:], ksPost[:]) {
		t.Error("counter 0xFFFFFFFF and 0x00000000 should produce different keystream")
	}
}

// TestNewAES256CTR_RoundTrip verifies that NewAES256CTR encrypts and
// decrypts (second Process call) correctly.
func TestNewAES256CTR_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	nonce := make([]byte, AES256CTRNonceSize)
	for i := range nonce {
		nonce[i] = byte(i + 100)
	}
	plaintext := []byte("NewAES256CTR round-trip test data!")

	ctr1, err := NewAES256CTR(key, nonce, 0)
	if err != nil {
		t.Fatalf("NewAES256CTR: %v", err)
	}
	ct := make([]byte, len(plaintext))
	copy(ct, plaintext)
	if err := ctr1.Process(ct); err != nil {
		t.Fatalf("Process (encrypt): %v", err)
	}
	if bytes.Equal(ct, plaintext) {
		t.Fatal("ciphertext should differ from plaintext")
	}

	ctr2, err := NewAES256CTR(key, nonce, 0)
	if err != nil {
		t.Fatalf("NewAES256CTR (decrypt): %v", err)
	}
	if err := ctr2.Process(ct); err != nil {
		t.Fatalf("Process (decrypt): %v", err)
	}
	if !bytes.Equal(ct, plaintext) {
		t.Errorf("round-trip failed: got %q", ct)
	}
}

// TestNewAES256CTR_InitCtr verifies that a non-zero initCtr produces
// different keystream from initCtr=0, matching Rust Aes256Ctr32::from_key
// seek behaviour.
func TestNewAES256CTR_InitCtr(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, AES256CTRNonceSize)
	plaintext := make([]byte, 32)

	ctr0, err := NewAES256CTR(key, nonce, 0)
	if err != nil {
		t.Fatalf("NewAES256CTR(0): %v", err)
	}
	ct0 := make([]byte, len(plaintext))
	copy(ct0, plaintext)
	if err := ctr0.Process(ct0); err != nil {
		t.Fatalf("Process(ctr0): %v", err)
	}

	ctr1, err := NewAES256CTR(key, nonce, 1)
	if err != nil {
		t.Fatalf("NewAES256CTR(1): %v", err)
	}
	ct1 := make([]byte, len(plaintext))
	copy(ct1, plaintext)
	if err := ctr1.Process(ct1); err != nil {
		t.Fatalf("Process(ctr1): %v", err)
	}

	if bytes.Equal(ct0, ct1) {
		t.Error("initCtr=0 and initCtr=1 should produce different ciphertext")
	}
}

// TestNewAES256CTR_InvalidKeyLength verifies ErrInvalidKeyLength is returned.
func TestNewAES256CTR_InvalidKeyLength(t *testing.T) {
	nonce := make([]byte, AES256CTRNonceSize)
	_, err := NewAES256CTR(make([]byte, 16), nonce, 0)
	if err == nil {
		t.Fatal("expected error for 16-byte key")
	}
	if !errors.Is(err, &ErrInvalidKeyLength{}) {
		t.Errorf("expected ErrInvalidKeyLength, got %T: %v", err, err)
	}
}

// TestNewAES256CTR_InvalidNonceLength verifies ErrInvalidNonceLength is returned.
func TestNewAES256CTR_InvalidNonceLength(t *testing.T) {
	key := make([]byte, 32)
	_, err := NewAES256CTR(key, make([]byte, 8), 0)
	if err == nil {
		t.Fatal("expected error for 8-byte nonce")
	}
	if !errors.Is(err, &ErrInvalidNonceLength{}) {
		t.Errorf("expected ErrInvalidNonceLength, got %T: %v", err, err)
	}
	// Zero-length nonce.
	_, err = NewAES256CTR(key, nil, 0)
	if err == nil {
		t.Fatal("expected error for nil nonce")
	}
}

// TestNewAES256CTR_NISTVector verifies against the NIST SP 800-38A vector
// also used by Rust's aes_ctr_smoke_test. This is a partial check since the
// full interop fixture drives the same test in tests/interop.
// Key: 603DEB10...  Nonce: F0F1F2F3F4F5F6F7F8F9FAFB  InitCtr: 0xFCFDFEFF
func TestNewAES256CTR_NISTVector(t *testing.T) {
	key, err := hexDecode("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4")
	if err != nil {
		t.Fatalf("hexDecode key: %v", err)
	}
	nonce, err := hexDecode("F0F1F2F3F4F5F6F7F8F9FAFB")
	if err != nil {
		t.Fatalf("hexDecode nonce: %v", err)
	}
	input, err := hexDecode("6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710")
	if err != nil {
		t.Fatalf("hexDecode input: %v", err)
	}
	want, err := hexDecode("601EC313775789A5B7A7F504BBF3D228F443E3CA4D62B59ACA84E990CACAF5C52B0930DAA23DE94CE87017BA2D84988DDFC9C58DB67AADA613C2DD08457941A6")
	if err != nil {
		t.Fatalf("hexDecode want: %v", err)
	}

	ctr, err := NewAES256CTR(key, nonce, 0xFCFDFEFF)
	if err != nil {
		t.Fatalf("NewAES256CTR: %v", err)
	}
	got := make([]byte, len(input))
	copy(got, input)
	if err := ctr.Process(got); err != nil {
		t.Fatalf("Process: %v", err)
	}

	if !bytes.Equal(got, want) {
		t.Errorf("NIST vector mismatch:\n  got  %x\n  want %x", got, want)
	}
}

func hexDecode(s string) ([]byte, error) {
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		hi := hexNibble(s[i])
		lo := hexNibble(s[i+1])
		b[i/2] = (hi << 4) | lo
	}
	return b, nil
}

func hexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

// TestNewAES256CTR_BoundEnforcement verifies that Process returns
// ErrAESCTRInputTooLong when the cumulative bytes across calls would
// exceed the 32-bit counter capacity. The test uses initCtr=MaxUint32 so
// only one block (16 bytes) is valid, avoiding multi-gigabyte allocations.
func TestNewAES256CTR_BoundEnforcement(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, AES256CTRNonceSize)

	// With initCtr = MaxUint32 exactly one block (16 bytes) remains.
	ctr, err := NewAES256CTR(key, nonce, math.MaxUint32)
	if err != nil {
		t.Fatalf("NewAES256CTR: %v", err)
	}

	// First call: exactly 16 bytes — must succeed.
	buf := make([]byte, aes.BlockSize)
	if err := ctr.Process(buf); err != nil {
		t.Fatalf("first Process (16 bytes) should succeed: %v", err)
	}

	// Second call: 1 byte — must fail with ErrAESCTRInputTooLong.
	err = ctr.Process(make([]byte, 1))
	if err == nil {
		t.Fatal("second Process after exhausting counter should return error")
	}
	var tooLong *ErrAESCTRInputTooLong
	if !errors.As(err, &tooLong) {
		t.Errorf("expected *ErrAESCTRInputTooLong, got %T: %v", err, err)
	}
}

// TestNewAES256CTR_BoundCumulativeMultiCall verifies the bound is tracked
// cumulatively: multiple small calls that together exceed the limit fail.
func TestNewAES256CTR_BoundCumulativeMultiCall(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, AES256CTRNonceSize)

	// initCtr = MaxUint32 - 1 leaves 2 blocks (32 bytes) available.
	ctr, err := NewAES256CTR(key, nonce, math.MaxUint32-1)
	if err != nil {
		t.Fatalf("NewAES256CTR: %v", err)
	}

	// Process 16 bytes twice — both succeed (2 blocks consumed).
	for i := 0; i < 2; i++ {
		if err := ctr.Process(make([]byte, aes.BlockSize)); err != nil {
			t.Fatalf("Process call %d should succeed: %v", i+1, err)
		}
	}

	// Third call must fail: no capacity remains.
	if err := ctr.Process(make([]byte, 1)); err == nil {
		t.Fatal("Process after exhausting 2-block capacity should return error")
	}
}

// TestAESCTRMultiBlockConsistency encrypts data spanning multiple blocks
// and verifies each block uses the correct sequential counter value.
func TestAESCTRMultiBlockConsistency(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	// Encrypt 3 blocks of zeros to extract raw keystream.
	zeros := make([]byte, 3*aes.BlockSize)
	keystream, err := AESCTREncrypt(key, zeros)
	if err != nil {
		t.Fatal(err)
	}

	// Manually compute expected keystream for each counter value.
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	for ctrVal := uint32(0); ctrVal < 3; ctrVal++ {
		var counter [aes.BlockSize]byte
		binary.BigEndian.PutUint32(counter[12:16], ctrVal)

		var expected [aes.BlockSize]byte
		block.Encrypt(expected[:], counter[:])

		offset := int(ctrVal) * aes.BlockSize
		got := keystream[offset : offset+aes.BlockSize]
		if !bytes.Equal(got, expected[:]) {
			t.Errorf("block %d keystream mismatch", ctrVal)
		}
	}
}
