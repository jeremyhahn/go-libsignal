// Package cipher provides symmetric encryption primitives used by
// the Signal protocol, including AES-CBC (existing) and AES-CTR
// (used by sealed sender v1).
//
// The AES-CTR implementation uses a 32-bit big-endian counter matching
// Rust's ctr::Ctr32BE<Aes256>. The first 12 bytes of the 16-byte IV
// are a fixed nonce, and only the last 4 bytes are incremented as a
// big-endian 32-bit counter.
package cipher

import (
	"crypto/aes"
	"crypto/subtle"
	"encoding/binary"
	"math"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
)

// aesCTR32BEMaxLength is the maximum input length for AES-CTR with a 32-bit
// counter. The counter can produce at most 2^32 keystream blocks of 16 bytes
// each. Using math.MaxUint32 (not 1<<32) because the counter starts at 0 and
// the last usable counter value is 0xFFFFFFFF.
const aesCTR32BEMaxLength = int64(math.MaxUint32) * aes.BlockSize

// AESCTREncrypt encrypts plaintext using AES-256-CTR with a zero IV
// and a 32-bit big-endian counter (matching Rust ctr::Ctr32BE).
// In CTR mode, encryption and decryption are identical XOR operations,
// so this function can also be used for decryption.
func AESCTREncrypt(key, plaintext []byte) ([]byte, error) {
	return aesCTR32BE(key, plaintext)
}

// AESCTRDecrypt decrypts ciphertext using AES-256-CTR with a zero IV
// and a 32-bit big-endian counter (matching Rust ctr::Ctr32BE).
// In CTR mode, decryption is the same operation as encryption.
func AESCTRDecrypt(key, ciphertext []byte) ([]byte, error) {
	return aesCTR32BE(key, ciphertext)
}

// aesCTR32BE performs AES-CTR encryption or decryption with a zero IV,
// using a 32-bit big-endian counter in the last 4 bytes of the 16-byte
// counter block. The first 12 bytes remain fixed (all zeros for the
// sealed sender protocol).
//
// This matches Rust's ctr::Ctr32BE<Aes256>, where only bytes [12..16]
// of the counter block are incremented as a big-endian uint32.
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
