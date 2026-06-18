// Package cipher is a package for common encrypt/decrypt of symmetric key messages.
package cipher

import (
	"bytes"
	"crypto/aes"
	"crypto/subtle"
)

// Decrypt decrypts AES-256-CBC ciphertext using the given iv and key, removing
// PKCS7 padding. The key must be exactly 32 bytes (AES-256). The ciphertext is
// not mutated.
//
// This function is used by the Signal session and group ciphers. The argument
// order (iv, key) differs from AESCBCDecrypt (key, iv); both delegate to the
// same underlying implementation.
//
// IMPORTANT: Callers MUST collapse all decrypt errors into a single opaque
// "decryption failed" result before returning to network peers. Returning
// distinct errors (e.g. bad padding vs. wrong key) creates an oracle that can
// be exploited for chosen-ciphertext attacks. This matches the Rust reference
// which maps all failures to DecryptionError::BadCiphertext("failed to decrypt").
// Rust source: rust/crypto/src/aes_cbc.rs:52
func Decrypt(iv, key, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, &ErrCipherInvalidKeySize{Got: len(key)}
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, ErrCiphertextTooShort
	}
	return AESCBCDecrypt(key, iv, ciphertext)
}

// Encrypt encrypts plaintext using AES-256-CBC with the given iv and key,
// appending PKCS7 padding. The key must be exactly 32 bytes (AES-256).
//
// The argument order (iv, key) differs from AESCBCEncrypt (key, iv); both
// delegate to the same underlying implementation.
func Encrypt(iv, key, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, &ErrCipherInvalidKeySize{Got: len(key)}
	}
	return AESCBCEncrypt(key, iv, plaintext)
}

// pkcs7Pad right-pads the given byte slice with 1 to n bytes, where
// n is the block size. The size of the result is x times n, where x
// is at least 1. Empty input is valid per PKCS#7: it produces a full
// block of padding bytes (e.g., 16 bytes of 0x10 for a 16-byte block).
func pkcs7Pad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, &ErrCipherInvalidBlockSize{Got: blocksize}
	}
	n := blocksize - (len(b) % blocksize)
	pb := make([]byte, len(b)+n)
	copy(pb, b)
	copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
	return pb, nil
}

// pkcs7Unpad validates and removes PKCS#7 padding from the given byte slice.
// The validation is constant-time: all padding bytes are checked without
// early return to prevent timing side-channels. The returned value will be
// 1 to n bytes smaller depending on the amount of padding, where n is the
// block size.
func pkcs7Unpad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, &ErrCipherInvalidBlockSize{Got: blocksize}
	}
	if len(b) == 0 {
		return nil, ErrInvalidPKCS7Data
	}
	if len(b)%blocksize != 0 {
		return nil, ErrInvalidPKCS7Padding
	}

	padByte := b[len(b)-1]
	padLen := int(padByte)

	// Constant-time check: padLen must be in [1, blocksize].
	good := subtle.ConstantTimeLessOrEq(1, padLen) &
		subtle.ConstantTimeLessOrEq(padLen, blocksize)

	// Check all padding bytes match padByte in constant time.
	// We always iterate over the last blocksize bytes to avoid
	// leaking padLen through loop count. For each position, we
	// conditionally include its comparison based on whether it
	// falls within the padding region.
	for i := 0; i < blocksize; i++ {
		// isPad is 1 if position (len(b)-1-i) is in the padding region.
		isPad := subtle.ConstantTimeLessOrEq(i+1, padLen)
		// match is 1 if b[len(b)-1-i] == padByte.
		match := subtle.ConstantTimeByteEq(b[len(b)-1-i], padByte)
		// If isPad is 1 and match is 0, this is bad padding.
		// good &= (isPad & match) | (1 - isPad)
		good &= (isPad & match) | (1 - isPad)
	}

	if good != 1 {
		return nil, ErrInvalidPKCS7Padding
	}
	return b[:len(b)-padLen], nil
}
