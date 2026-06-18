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

// AES256CTR is a streaming AES-256-CTR cipher with a 12-byte nonce and
// 32-bit big-endian counter, mirroring Rust's signal_crypto::Aes256Ctr32.
// Rust source: rust/crypto/src/aes_ctr.rs:13-46
//
// The 32-bit counter limits the total keystream to
// (2^32 - initCtr) * 16 bytes from the starting counter position.
// Process returns ErrAESCTRInputTooLong if cumulative bytes across all
// calls would exceed this bound, preventing keystream reuse from counter
// wrap that would diverge from Rust's ctr::Ctr32BE semantics.
//
// Use NewAES256CTR to construct; call Process to encrypt or decrypt in-place.
type AES256CTR struct {
	stream    goCipher.Stream
	remaining int64 // bytes remaining before the 32-bit counter wraps
}

// NewAES256CTR constructs an AES-256-CTR-32-BE stream cipher matching
// Rust's Aes256Ctr32::from_key(key, nonce, init_ctr).
// Rust source: rust/crypto/src/aes_ctr.rs:35-45
//
// key must be exactly 32 bytes (AES-256).
// nonce must be exactly AES256CTRNonceSize (12) bytes.
// initCtr is the starting 32-bit big-endian counter value; seek is applied
// by constructing the IV as nonce(12 bytes) || be32(initCtr). The maximum
// total bytes processable is (math.MaxUint32 - initCtr + 1) * 16.
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

// Process applies the AES-CTR keystream to buf in-place.
// Mirrors Rust Aes256Ctr32::process(&mut buf).
// Rust source: rust/crypto/src/aes_ctr.rs:43-45
//
// Returns ErrAESCTRInputTooLong if processing buf would cause the cumulative
// bytes across all Process calls to exceed (math.MaxUint32 - initCtr + 1) * 16,
// the point at which Go's underlying 128-bit counter would diverge from Rust's
// 32-bit ctr::Ctr32BE counter due to carry propagation.
func (c *AES256CTR) Process(buf []byte) error {
	if int64(len(buf)) > c.remaining {
		return &ErrAESCTRInputTooLong{Length: int64(len(buf)), Max: c.remaining}
	}
	c.remaining -= int64(len(buf))
	c.stream.XORKeyStream(buf, buf)
	return nil
}

// aesCTR32BEMaxLength is the maximum input length for AES-CTR with a 32-bit
// counter. The counter starts at 0 and can produce 2^32 distinct keystream
// blocks (counter values 0x00000000 through 0xFFFFFFFF, inclusive) of 16
// bytes each, giving 2^32 * 16 bytes total before the counter wraps.
//
// Note: The Rust reference implementation does not enforce an explicit length
// cap and allows the ctr crate to silently wrap the 32-bit counter. Go
// intentionally rejects inputs that would wrap in order to prevent keystream
// reuse. This is a deliberate hardening measure beyond the Rust reference.
const aesCTR32BEMaxLength = (int64(math.MaxUint32) + 1) * aes.BlockSize

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
