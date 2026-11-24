// Package cipher is a package for common encrypt/decrypt of symmetric key messages.
package cipher

import (
	"bytes"
	"crypto/aes"
	"crypto/subtle"
)

// Decrypt removes PKCS7 padding from AES-256-CBC ciphertext; callers must collapse all decrypt errors into one opaque failure to avoid a padding oracle.
func Decrypt(iv, key, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, &ErrCipherInvalidKeySize{Got: len(key)}
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, ErrCiphertextTooShort
	}
	return AESCBCDecrypt(key, iv, ciphertext)
}

// Encrypt encrypts with AES-256-CBC and PKCS7 padding; note the (iv, key) argument order.
func Encrypt(iv, key, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, &ErrCipherInvalidKeySize{Got: len(key)}
	}
	return AESCBCEncrypt(key, iv, plaintext)
}

// pkcs7Pad appends 1 to n bytes of padding; empty input yields a full block.
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

// pkcs7Unpad validates and removes PKCS#7 padding in constant time.
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

	// Check the last blocksize bytes in constant time, masking positions outside the padding.
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
