// Package cipher provides symmetric encryption primitives used by the Signal
// protocol. This file implements AES-256-GCM-SIV (RFC 8452), a nonce-misuse-
// resistant AEAD cipher used by Sealed Sender v2 and SVR.
//
// AES-GCM-SIV provides nonce-misuse resistance: if the same nonce is
// accidentally reused, the only information leaked is whether the same
// plaintext was encrypted twice with the same nonce and key. The plaintext
// itself remains confidential.
//
// This is a pure Go implementation. For production deployments handling high
// throughput, consider replacing the POLYVAL carry-less multiplication with
// architecture-specific assembly (PCLMULQDQ on x86, PMULL on ARM).
package cipher

import (
	"crypto/aes"
	gocipher "crypto/cipher"
	"crypto/subtle"
	"encoding/binary"

	crypto "github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

const (
	// aesGCMSIVNonceSize is the nonce size for AES-GCM-SIV (96 bits).
	aesGCMSIVNonceSize = 12

	// aesGCMSIVTagSize is the authentication tag size (128 bits).
	aesGCMSIVTagSize = 16

	// aesGCMSIVKeySize is the key size for AES-256-GCM-SIV.
	aesGCMSIVKeySize = 32
)

// aesGCMSIV implements the crypto/cipher.AEAD interface for AES-256-GCM-SIV.
// The key is stored in memguard-protected memory and must be destroyed via
// Zeroize() when the cipher is no longer needed.
type aesGCMSIV struct {
	key *secret.Secret
}

// NewAESGCMSIV creates an AES-256-GCM-SIV AEAD cipher from a 32-byte key.
// The returned value implements crypto/cipher.AEAD.
//
// AES-GCM-SIV provides nonce-misuse resistance, meaning accidental nonce
// reuse only leaks whether the same plaintext was encrypted twice with the
// same nonce and key, not the plaintext itself.
func NewAESGCMSIV(key []byte) (gocipher.AEAD, error) {
	if len(key) != aesGCMSIVKeySize {
		return nil, &ErrAESGCMSIVKeySize{Expected: aesGCMSIVKeySize, Got: len(key)}
	}

	k := make([]byte, aesGCMSIVKeySize)
	copy(k, key)

	s, err := secret.New(k)
	if err != nil {
		return nil, &ErrAESGCMSIVProtectKey{Err: err}
	}

	return &aesGCMSIV{key: s}, nil
}

// NonceSize returns the required nonce size (12 bytes).
func (a *aesGCMSIV) NonceSize() int {
	return aesGCMSIVNonceSize
}

// Overhead returns the maximum difference between plaintext and ciphertext
// lengths (16 bytes for the authentication tag).
func (a *aesGCMSIV) Overhead() int {
	return aesGCMSIVTagSize
}

// Zeroize destroys the key material held in guarded memory. After calling
// Zeroize, any subsequent Seal or Open calls will panic. This method is
// idempotent and safe to call multiple times.
func (a *aesGCMSIV) Zeroize() {
	if a.key != nil {
		a.key.Destroy()
	}
}

// Seal encrypts and authenticates plaintext, authenticates the additional
// data, and appends the result to dst, returning the updated slice. The
// nonce must be NonceSize() bytes long and should be unique for each
// key/plaintext pair for best security (though AES-GCM-SIV tolerates reuse).
func (a *aesGCMSIV) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != aesGCMSIVNonceSize {
		// panic: cryptographic invariant violation — caller violated the AEAD
		// interface contract; nonce must be exactly NonceSize() bytes.
		panic("aesgcmsiv: incorrect nonce length")
	}

	ct, err := aesGCMSIVEncryptInternal(a.key.Bytes(), nonce, plaintext, additionalData)
	if err != nil {
		// panic: cryptographic invariant violation — the key was validated in
		// NewAESGCMSIV; internal encryption with a valid key cannot fail.
		panic("aesgcmsiv: encryption failed: " + err.Error())
	}

	return append(dst, ct...)
}

// Open decrypts and authenticates ciphertext, authenticates the additional
// data, and if successful appends the resulting plaintext to dst, returning
// the updated slice. The nonce must be NonceSize() bytes long. If the
// ciphertext or additional data have been tampered with, Open returns an error.
func (a *aesGCMSIV) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != aesGCMSIVNonceSize {
		return nil, &ErrAESGCMSIVIncorrectNonce{}
	}
	if len(ciphertext) < aesGCMSIVTagSize {
		return nil, &ErrAESGCMSIVCiphertextTooShort{}
	}

	pt, err := aesGCMSIVDecryptInternal(a.key.Bytes(), nonce, ciphertext, additionalData)
	if err != nil {
		return nil, err
	}

	return append(dst, pt...), nil
}

// AESGCMSIVEncrypt encrypts plaintext with the given key, nonce, and
// additional authenticated data using AES-256-GCM-SIV.
//
// The key must be 32 bytes, the nonce must be 12 bytes. Returns the
// ciphertext with the 16-byte authentication tag appended.
func AESGCMSIVEncrypt(key, nonce, plaintext, aad []byte) ([]byte, error) {
	if len(key) != aesGCMSIVKeySize {
		return nil, &ErrAESGCMSIVKeySize{Expected: aesGCMSIVKeySize, Got: len(key)}
	}
	if len(nonce) != aesGCMSIVNonceSize {
		return nil, &ErrAESGCMSIVNonceSize{Expected: aesGCMSIVNonceSize, Got: len(nonce)}
	}

	return aesGCMSIVEncryptInternal(key, nonce, plaintext, aad)
}

// AESGCMSIVDecrypt decrypts ciphertext with the given key, nonce, and
// additional authenticated data using AES-256-GCM-SIV.
//
// The key must be 32 bytes, the nonce must be 12 bytes. The ciphertext
// must include the 16-byte authentication tag (appended during encryption).
func AESGCMSIVDecrypt(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != aesGCMSIVKeySize {
		return nil, &ErrAESGCMSIVKeySize{Expected: aesGCMSIVKeySize, Got: len(key)}
	}
	if len(nonce) != aesGCMSIVNonceSize {
		return nil, &ErrAESGCMSIVNonceSize{Expected: aesGCMSIVNonceSize, Got: len(nonce)}
	}
	if len(ciphertext) < aesGCMSIVTagSize {
		return nil, &ErrAESGCMSIVCiphertextTooShort{}
	}

	return aesGCMSIVDecryptInternal(key, nonce, ciphertext, aad)
}

// aesGCMSIVEncryptInternal implements AES-256-GCM-SIV encryption per RFC 8452.
func aesGCMSIVEncryptInternal(key, nonce, plaintext, aad []byte) ([]byte, error) {
	// Step 1: Derive per-message keys from the master key and nonce.
	hashKey, encKey, err := derivePolyvalKey(key, nonce)
	if err != nil {
		return nil, &ErrAESGCMSIVKeyDerivation{Err: err}
	}
	defer crypto.Zeroize(hashKey)
	defer crypto.Zeroize(encKey)

	// Step 2: Compute the authentication tag (synthetic IV).
	tag, err := computeTag(hashKey, encKey, nonce, plaintext, aad)
	if err != nil {
		return nil, &ErrAESGCMSIVTagComputation{Err: err}
	}

	// Step 3: Encrypt the plaintext using AES-CTR with the tag as the IV.
	ciphertext := make([]byte, len(plaintext)+aesGCMSIVTagSize)
	aesGCMSIVCTR(encKey, tag, plaintext, ciphertext[:len(plaintext)])

	// Step 4: Append the tag.
	copy(ciphertext[len(plaintext):], tag)

	return ciphertext, nil
}

// aesGCMSIVDecryptInternal implements AES-256-GCM-SIV decryption per RFC 8452.
func aesGCMSIVDecryptInternal(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	// Split ciphertext into encrypted data and tag.
	ctLen := len(ciphertext) - aesGCMSIVTagSize
	ct := ciphertext[:ctLen]
	tag := ciphertext[ctLen:]

	// Step 1: Derive per-message keys.
	hashKey, encKey, err := derivePolyvalKey(key, nonce)
	if err != nil {
		return nil, &ErrAESGCMSIVKeyDerivation{Err: err}
	}
	defer crypto.Zeroize(hashKey)
	defer crypto.Zeroize(encKey)

	// Step 2: Decrypt the ciphertext using AES-CTR with the tag as IV.
	plaintext := make([]byte, ctLen)
	aesGCMSIVCTR(encKey, tag, ct, plaintext)

	// Step 3: Recompute the tag from the decrypted plaintext and verify.
	expectedTag, err := computeTag(hashKey, encKey, nonce, plaintext, aad)
	if err != nil {
		return nil, &ErrAESGCMSIVTagComputation{Err: err}
	}

	if subtle.ConstantTimeCompare(tag, expectedTag) != 1 {
		// Zero out plaintext on authentication failure to prevent misuse.
		for i := range plaintext {
			plaintext[i] = 0
		}
		return nil, &ErrAESGCMSIVAuthFailed{}
	}

	return plaintext, nil
}

// computeTag computes the AES-GCM-SIV authentication tag (synthetic IV)
// per RFC 8452 Section 4.
//
// The tag is computed as:
//  1. Build the POLYVAL input: pad(AAD) || pad(plaintext) || len(AAD) || len(plaintext)
//  2. Compute POLYVAL over this input using the hash key.
//  3. XOR the nonce into the result.
//  4. Clear the most significant bit of the last byte.
//  5. Encrypt the result with AES using the encryption key.
func computeTag(hashKey, encKey, nonce, plaintext, aad []byte) ([]byte, error) {
	// Build POLYVAL input: padded AAD || padded plaintext || length block.
	input := buildPolyvalInput(aad, plaintext)

	// Compute POLYVAL.
	s := polyval(hashKey, input)

	// XOR the nonce into the first 12 bytes of the POLYVAL result.
	for i := 0; i < aesGCMSIVNonceSize; i++ {
		s[i] ^= nonce[i]
	}

	// Clear the most significant bit of the last byte (bit 127).
	s[15] &= 0x7f

	// Encrypt with AES to produce the tag.
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}

	tag := make([]byte, aesGCMSIVTagSize)
	block.Encrypt(tag, s)

	return tag, nil
}

// buildPolyvalInput constructs the input to POLYVAL per RFC 8452:
//
//	pad(AAD, 16) || pad(plaintext, 16) || le64(len(AAD)*8) || le64(len(plaintext)*8)
func buildPolyvalInput(aad, plaintext []byte) []byte {
	paddedAAD := padToBlockSize(aad)
	paddedPT := padToBlockSize(plaintext)

	// Length block: 8 bytes for AAD bit length + 8 bytes for plaintext bit length.
	lengthBlock := make([]byte, polyvalBlockSize)
	binary.LittleEndian.PutUint64(lengthBlock[0:8], uint64(len(aad))*8)
	binary.LittleEndian.PutUint64(lengthBlock[8:16], uint64(len(plaintext))*8)

	input := make([]byte, 0, len(paddedAAD)+len(paddedPT)+polyvalBlockSize)
	input = append(input, paddedAAD...)
	input = append(input, paddedPT...)
	input = append(input, lengthBlock...)

	return input
}

// padToBlockSize pads data with zeros to a multiple of polyvalBlockSize.
// If the data is empty, returns an empty slice (no padding needed since
// there are no blocks to process).
func padToBlockSize(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	padLen := (polyvalBlockSize - (len(data) % polyvalBlockSize)) % polyvalBlockSize
	result := make([]byte, len(data)+padLen)
	copy(result, data)
	return result
}

// aesGCMSIVCTR encrypts or decrypts data using AES-CTR mode with the
// authentication tag as the initial counter value, per RFC 8452 Section 4.
//
// The counter is formed from the tag with the most significant bit of the
// last byte set to 1, and only the first 32 bits are incremented.
func aesGCMSIVCTR(encKey, tag, input, output []byte) {
	// RFC 8452: plaintext is limited to 2^36 bytes to prevent counter wrap.
	// Use >= to reject inputs of exactly maxPlaintextLen, which would cause
	// the 32-bit CTR counter to wrap back to its initial value on the last block.
	const maxPlaintextLen = 1 << 36
	if len(input) >= maxPlaintextLen {
		panic("aesgcmsiv: plaintext exceeds RFC 8452 maximum length")
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		// panic: cryptographic invariant violation — encKey is always derived
		// internally from a validated 32-byte key via derivePolyvalKey.
		panic("aesgcmsiv: invalid encryption key: " + err.Error())
	}

	// Form the initial counter from the tag with bit 127 set.
	counter := make([]byte, aes.BlockSize)
	copy(counter, tag)
	counter[15] |= 0x80
	defer crypto.Zeroize(counter)

	keystreamBlock := make([]byte, aes.BlockSize)
	defer crypto.Zeroize(keystreamBlock)

	for i := 0; i < len(input); i += aes.BlockSize {
		block.Encrypt(keystreamBlock, counter)

		end := i + aes.BlockSize
		if end > len(input) {
			end = len(input)
		}

		subtle.XORBytes(output[i:end], input[i:end], keystreamBlock[:end-i])

		// Increment the 32-bit little-endian counter (first 4 bytes).
		ctr := binary.LittleEndian.Uint32(counter[0:4])
		ctr++
		binary.LittleEndian.PutUint32(counter[0:4], ctr)
	}
}
