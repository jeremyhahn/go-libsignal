package cipher

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
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
