// Package cipher provides symmetric encryption primitives used by the Signal
// protocol. This file implements AES-CBC encrypt/decrypt with PKCS7 padding,
// matching the Rust libsignal cbc module used for message backup frame
// encryption.
package cipher

import (
	"crypto/aes"
	"crypto/cipher"
)

// AESCBCEncrypt encrypts plaintext using AES-256-CBC with PKCS7 padding.
//
// The key must be exactly 32 bytes (AES-256), matching the Rust libsignal
// reference which only supports AES-256 for this operation.
// The iv must be exactly 16 bytes. Empty plaintext is valid and produces a
// full block of PKCS#7 padding per the spec.
//
// Returns the encrypted ciphertext whose length is a multiple of the AES
// block size (16 bytes).
func AESCBCEncrypt(key, iv, plaintext []byte) ([]byte, error) {
	if err := validateAESCBCParams(key, iv); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	padded, err := pkcs7Pad(plaintext, block.BlockSize())
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	return ciphertext, nil
}

// AESCBCDecrypt decrypts ciphertext encrypted with AES-256-CBC and removes
// PKCS7 padding.
//
// The key must be exactly 32 bytes (AES-256), matching the Rust libsignal
// reference which only supports AES-256 for this operation.
// The iv must be exactly 16 bytes. The ciphertext length must be a non-zero
// multiple of the AES block size (16 bytes).
//
// Returns the decrypted plaintext with PKCS7 padding removed.
func AESCBCDecrypt(key, iv, ciphertext []byte) ([]byte, error) {
	if err := validateAESCBCParams(key, iv); err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 {
		return nil, &ErrAESCBCCiphertextEmpty{}
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, &ErrAESCBCCiphertextNotAligned{Length: len(ciphertext), BlockSize: aes.BlockSize}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Decrypt into a new buffer to avoid mutating the input.
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	return pkcs7Unpad(plaintext, block.BlockSize())
}

// validateAESCBCParams checks that the key is exactly 32 bytes (AES-256) and
// the IV is 16 bytes. Only AES-256 is supported to match the Rust libsignal
// reference implementation.
func validateAESCBCParams(key, iv []byte) error {
	if len(key) != 32 {
		return &ErrAESCBCInvalidKey{Got: len(key)}
	}
	if len(iv) != aes.BlockSize {
		return &ErrAESCBCInvalidIVSize{Got: len(iv)}
	}
	return nil
}
