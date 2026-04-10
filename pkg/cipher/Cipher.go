// Package cipher is a package for common encrypt/decrypt of symmetric key messages.
package cipher

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
)

// Decrypt will use the given key, iv, and ciphertext and return
// the plaintext bytes. The key must be exactly 32 bytes (AES-256).
// Unlike AESCBCDecrypt, this function is used by the Signal group cipher
// and always requires AES-256. The ciphertext is not mutated.
func Decrypt(iv, key, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, &ErrCipherInvalidKeySize{Got: len(key)}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, ErrCiphertextTooShort
	}

	// Decrypt into a new buffer to avoid mutating the input.
	plaintext := make([]byte, len(ciphertext))
	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(plaintext, ciphertext)

	return pkcs7Unpad(plaintext, aes.BlockSize)
}

// Encrypt will use the given iv, key, and plaintext bytes
// and return ciphertext bytes. The key must be exactly 32 bytes (AES-256).
func Encrypt(iv, key, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, &ErrCipherInvalidKeySize{Got: len(key)}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	paddedText, err := pkcs7Pad(plaintext, block.BlockSize())
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(paddedText))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedText)

	return ciphertext, nil
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
