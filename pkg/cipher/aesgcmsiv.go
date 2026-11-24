// AES-256-GCM-SIV (RFC 8452), the nonce-misuse-resistant AEAD used by Sealed Sender v2 and SVR.
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

	// AESGCMSIVNonceSize is the nonce size for AES-256-GCM-SIV (96 bits).
	// Mirrors Rust aes_gcm_siv nonce size per RFC 8452 §4.
	AESGCMSIVNonceSize = aesGCMSIVNonceSize

	// AESGCMSIVTagSize is the authentication tag size for AES-256-GCM-SIV (128 bits).
	// Mirrors Rust aes_gcm_siv tag size per RFC 8452 §4.
	AESGCMSIVTagSize = aesGCMSIVTagSize

	// AESGCMSIVKeySize is the key size for AES-256-GCM-SIV (256 bits = 32 bytes).
	// Mirrors Rust aes_gcm_siv key size per RFC 8452 §4.
	AESGCMSIVKeySize = aesGCMSIVKeySize
)

// aesGCMSIV implements cipher.AEAD for AES-256-GCM-SIV; its key is in locked memory until Zeroize.
type aesGCMSIV struct {
	key *secret.Secret
}

// NewAESGCMSIV returns an AES-256-GCM-SIV cipher.AEAD for a 32-byte key.
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

// Seal encrypts and authenticates plaintext and additional data and appends the result to dst.
func (a *aesGCMSIV) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != aesGCMSIVNonceSize {
		// panic: cryptographic invariant violation — caller violated the AEAD
		// interface contract; nonce must be exactly NonceSize() bytes.
		panic("aesgcmsiv: incorrect nonce length")
	}
	if int64(len(plaintext)) > aesGCMSIVMaxPlaintextLen {
		// panic: plaintext exceeds the RFC 8452 §6 maximum (2^36 - 32).
		panic("aesgcmsiv: plaintext exceeds RFC 8452 §6 maximum length")
	}

	var ct []byte
	err := a.key.WithBytes(func(key []byte) error {
		var encErr error
		ct, encErr = aesGCMSIVEncryptInternal(key, nonce, plaintext, additionalData)
		return encErr
	})
	if err != nil {
		// panic: cryptographic invariant violation — the key was validated in
		// NewAESGCMSIV; internal encryption with a valid key cannot fail.
		panic("aesgcmsiv: encryption failed: " + err.Error())
	}

	return append(dst, ct...)
}

// Open authenticates and decrypts ciphertext and appends the plaintext to dst.
func (a *aesGCMSIV) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != aesGCMSIVNonceSize {
		return nil, &ErrAESGCMSIVIncorrectNonce{}
	}
	if len(ciphertext) < aesGCMSIVTagSize {
		return nil, &ErrAESGCMSIVCiphertextTooShort{}
	}

	var pt []byte
	err := a.key.WithBytes(func(key []byte) error {
		var decErr error
		pt, decErr = aesGCMSIVDecryptInternal(key, nonce, ciphertext, additionalData)
		return decErr
	})
	if err != nil {
		return nil, err
	}

	return append(dst, pt...), nil
}

// AESGCMSIVEncrypt encrypts with AES-256-GCM-SIV (32-byte key, 12-byte nonce) and appends the 16-byte tag.
func AESGCMSIVEncrypt(key, nonce, plaintext, aad []byte) ([]byte, error) {
	if len(key) != aesGCMSIVKeySize {
		return nil, &ErrAESGCMSIVKeySize{Expected: aesGCMSIVKeySize, Got: len(key)}
	}
	if len(nonce) != aesGCMSIVNonceSize {
		return nil, &ErrAESGCMSIVNonceSize{Expected: aesGCMSIVNonceSize, Got: len(nonce)}
	}
	// RFC 8452 §6: plaintext length MUST NOT exceed aesGCMSIVMaxPlaintextLen
	// (2^36 - 32). Inputs equal to the limit are permitted; only strictly
	// greater inputs are rejected.
	if int64(len(plaintext)) > aesGCMSIVMaxPlaintextLen {
		return nil, &ErrAESGCMSIVPlaintextTooLong{Length: len(plaintext)}
	}

	return aesGCMSIVEncryptInternal(key, nonce, plaintext, aad)
}

// AESGCMSIVDecrypt decrypts AES-256-GCM-SIV ciphertext with its 16-byte tag (32-byte key, 12-byte nonce).
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

// computeTag computes the synthetic IV tag per RFC 8452 §4.
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

// aesGCMSIVMaxPlaintextLen is the maximum plaintext length for AES-GCM-SIV per
// RFC 8452 §6: 2^36 - 32 bytes. The -32 ensures the last counter block cannot
// wrap back to the initial value, which would allow the 32-bit counter to alias.
const aesGCMSIVMaxPlaintextLen = (1 << 36) - 32

// aesGCMSIVCTR runs AES-CTR from the tag with its top bit set, per RFC 8452 §4; the caller enforces the length limit.
func aesGCMSIVCTR(encKey, tag, input, output []byte) {

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
