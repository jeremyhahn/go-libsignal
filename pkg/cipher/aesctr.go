// Package cipher provides the symmetric primitives of the Signal protocol: AES-CBC, AES-CTR with a 32-bit big-endian counter, AES-GCM and AES-GCM-SIV.
package cipher

import (
	"crypto/aes"
	goCipher "crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"math"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
)

// AES256CTRNonceSize is the nonce size for AES-256-CTR-32-BE.
// Mirrors Rust signal_crypto::Aes256Ctr32::NONCE_SIZE = 12.
// Rust source: rust/crypto/src/aes_ctr.rs:16
const AES256CTRNonceSize = 12

// AES256CTR is a streaming AES-256-CTR with a 12-byte nonce and 32-bit big-endian counter (Rust Aes256Ctr32); Process refuses input that would wrap the counter.
type AES256CTR struct {
	stream    goCipher.Stream
	remaining int64 // bytes remaining before the 32-bit counter wraps
}

// NewAES256CTR builds the cipher from a 32-byte key, a 12-byte nonce and a starting counter, like Rust Aes256Ctr32::from_key.
func NewAES256CTR(key, nonce []byte, initCtr uint32) (*AES256CTR, error) {
	if len(key) != 32 {
		return nil, &ErrInvalidKeyLength{Got: len(key), Expected: 32}
	}
	if len(nonce) != AES256CTRNonceSize {
		return nil, &ErrInvalidNonceLength{Got: len(nonce), Expected: AES256CTRNonceSize}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Build 16-byte IV: nonce(12) || be32(initCtr).
	var iv [aes.BlockSize]byte
	copy(iv[:AES256CTRNonceSize], nonce)
	binary.BigEndian.PutUint32(iv[AES256CTRNonceSize:], initCtr)

	// Compute remaining byte capacity: (MaxUint32 - initCtr + 1) blocks.
	remaining := (int64(math.MaxUint32) - int64(initCtr) + 1) * aes.BlockSize

	return &AES256CTR{stream: goCipher.NewCTR(block, iv[:]), remaining: remaining}, nil
}

// Process applies the keystream to buf in place; ErrAESCTRInputTooLong if the 32-bit counter would wrap.
func (c *AES256CTR) Process(buf []byte) error {
	if int64(len(buf)) > c.remaining {
		return &ErrAESCTRInputTooLong{Length: int64(len(buf)), Max: c.remaining}
	}
	c.remaining -= int64(len(buf))
	c.stream.XORKeyStream(buf, buf)
	return nil
}

// aesCTR32BEMaxLength is 2^32 blocks of 16 bytes; unlike Rust, longer input is rejected to prevent keystream reuse.
const aesCTR32BEMaxLength = (int64(math.MaxUint32) + 1) * aes.BlockSize

// AESCTREncrypt encrypts or decrypts with AES-256-CTR, a zero IV and a 32-bit big-endian counter.
func AESCTREncrypt(key, plaintext []byte) ([]byte, error) {
	return aesCTR32BE(key, plaintext)
}

// AESCTRDecrypt decrypts ciphertext using AES-256-CTR with a zero IV
// and a 32-bit big-endian counter (matching Rust ctr::Ctr32BE).
// In CTR mode, decryption is the same operation as encryption.
func AESCTRDecrypt(key, ciphertext []byte) ([]byte, error) {
	return aesCTR32BE(key, ciphertext)
}

// aesCTR32BE runs AES-CTR with a zero IV, incrementing only bytes 12..16 as a big-endian uint32, like Rust ctr::Ctr32BE.
func aesCTR32BE(key, input []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, &ErrAESCTRKeySize{}
	}

	if int64(len(input)) > aesCTR32BEMaxLength {
		return nil, &ErrAESCTRInputTooLong{Length: int64(len(input)), Max: aesCTR32BEMaxLength}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(input) == 0 {
		return make([]byte, 0), nil
	}

	output := make([]byte, len(input))

	// Counter block: 12-byte nonce (zeros) || 4-byte big-endian counter.
	// Initial counter value is 0.
	var counter [aes.BlockSize]byte
	defer crypto.Zeroize(counter[:])
	var keystreamBlock [aes.BlockSize]byte
	defer crypto.Zeroize(keystreamBlock[:])

	for i := 0; i < len(input); i += aes.BlockSize {
		block.Encrypt(keystreamBlock[:], counter[:])

		end := i + aes.BlockSize
		if end > len(input) {
			end = len(input)
		}

		subtle.XORBytes(output[i:end], input[i:end], keystreamBlock[:end-i])

		// Increment only the last 4 bytes as a big-endian 32-bit counter.
		ctr := binary.BigEndian.Uint32(counter[12:16])
		ctr++
		binary.BigEndian.PutUint32(counter[12:16], ctr)
	}

	return output, nil
}
