// Package cipher provides symmetric encryption primitives used by the Signal
// protocol. This file implements POLYVAL, the universal hash function used by
// AES-GCM-SIV (RFC 8452, Section 3).
//
// POLYVAL is defined in terms of GHASH with byte-order conversions. From
// RFC 8452 Section 3:
//
//	POLYVAL(H, X_1, ..., X_s) =
//	  ByteReverse(GHASH(mulX_GHASH(ByteReverse(H)),
//	                     ByteReverse(X_1), ..., ByteReverse(X_s)))
//
// The GHASH field uses the polynomial x^128 + x^7 + x^2 + x + 1 with
// big-endian bit ordering.
//
// For production use at scale, the carry-less multiplication should be
// replaced with architecture-specific assembly (PCLMULQDQ on x86-64,
// PMULL on ARM64).
package cipher

import (
	"crypto/aes"
	"encoding/binary"

	crypto "github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
)

// polyvalBlockSize is the size of a POLYVAL block in bytes (128 bits).
const polyvalBlockSize = 16

// polyval computes POLYVAL over the given input blocks using the provided
// hash key H. The input length must be a multiple of 16 bytes.
//
// POLYVAL is defined as:
//
//	POLYVAL(H, X_1, X_2, ..., X_s) iteratively computes:
//	  S_0 = 0
//	  S_i = dot(S_{i-1} XOR X_i, H)
//	  result = S_s
//
// This is implemented via the GHASH relationship from RFC 8452 Section 3.
func polyval(h, input []byte) []byte {
	if len(input)%polyvalBlockSize != 0 {
		// panic: cryptographic invariant violation — all callers pass input
		// through buildPolyvalInput which guarantees 16-byte alignment.
		panic("polyval: input length must be a multiple of 16")
	}

	// Convert POLYVAL key H to GHASH key: mulX_GHASH(ByteReverse(H)).
	ghashKey := toGHASHKey(h)

	// Process blocks through GHASH with byte-reversed inputs.
	var s [4]uint32 // GHASH state (big-endian 32-bit words)

	for i := 0; i < len(input); i += polyvalBlockSize {
		// ByteReverse the input block and XOR into state.
		// ByteReverse reverses the order of bytes in the 16-byte block.
		for j := 0; j < 4; j++ {
			// Read as little-endian uint32 from input (which effectively
			// byte-reverses when we treat it as big-endian GHASH state).
			w := binary.LittleEndian.Uint32(input[i+12-j*4 : i+16-j*4])
			s[j] ^= w
		}

		// Multiply state by GHASH key.
		ghashMul(&s, &ghashKey)
	}

	// ByteReverse the output.
	result := make([]byte, polyvalBlockSize)
	for j := 0; j < 4; j++ {
		binary.LittleEndian.PutUint32(result[12-j*4:16-j*4], s[j])
	}

	return result
}

// toGHASHKey converts a POLYVAL key to a GHASH key by computing
// mulX_GHASH(ByteReverse(H)).
//
// mulX_GHASH multiplies by x in the GHASH field, which is a right shift
// of the 128-bit value with conditional XOR of the reduction constant
// (0xe1 << 120) if the lowest bit was set.
func toGHASHKey(h []byte) [4]uint32 {
	// ByteReverse: reverse byte order of the 16-byte key.
	var rev [16]byte
	for i := 0; i < 16; i++ {
		rev[i] = h[15-i]
	}

	// mulX_GHASH: right-shift by 1 bit with polynomial reduction.
	// Check if the LSB (bit 127 in GHASH convention) is set.
	hiBit := rev[15] & 1

	// Right-shift the entire 128-bit value by 1.
	var carry byte
	for i := 0; i < 16; i++ {
		t := rev[i]
		rev[i] = (t >> 1) | carry
		carry = (t & 1) << 7
	}

	// Constant-time conditional XOR with the reduction constant.
	// In GHASH, the reduction polynomial (excluding x^128) is
	// x^7 + x^2 + x + 1 = 0xe1 at byte 0.
	// mask is 0xFF when hiBit==1, 0x00 when hiBit==0.
	mask := -hiBit // 0xFF when hiBit=1, 0x00 when hiBit=0
	rev[0] ^= 0xe1 & mask

	// Convert to uint32 array for efficient multiplication.
	var key [4]uint32
	key[0] = binary.BigEndian.Uint32(rev[0:4])
	key[1] = binary.BigEndian.Uint32(rev[4:8])
	key[2] = binary.BigEndian.Uint32(rev[8:12])
	key[3] = binary.BigEndian.Uint32(rev[12:16])

	return key
}

// ghashMul multiplies the GHASH state s by key h in-place.
//
// The multiplication is performed in GF(2^128) with the polynomial
// x^128 + x^7 + x^2 + x + 1, using big-endian bit ordering.
//
// This uses a bit-by-bit multiply-and-reduce approach. For each bit of
// the state, if set, XOR the key (shifted appropriately) into the result,
// then double the key (multiply by x) with polynomial reduction.
func ghashMul(s *[4]uint32, h *[4]uint32) {
	// We'll iterate over each bit of s (128 bits total), and for each
	// set bit, XOR the current value of v (which represents h * x^i)
	// into the result z.
	var z [4]uint32 // accumulator (result)

	// v starts as a copy of h, and is doubled (mulX) at each step.
	v := *h

	// Process each bit of s, from the MSB of s[0] down to LSB of s[3].
	// All operations are constant-time: no data-dependent branches.
	for i := 0; i < 4; i++ {
		word := s[i]
		for j := 31; j >= 0; j-- {
			// Constant-time conditional XOR: mask is all-ones when bit is set,
			// all-zeros when bit is clear. This avoids branching on secret data.
			bit := (word >> uint(j)) & 1
			mask := uint32(-int32(bit)) // 0xFFFFFFFF when bit=1, 0x00000000 when bit=0
			z[0] ^= v[0] & mask
			z[1] ^= v[1] & mask
			z[2] ^= v[2] & mask
			z[3] ^= v[3] & mask

			// Double v: v = v * x in the GHASH field.
			// This is a right-shift with constant-time reduction.
			lsb := v[3] & 1
			v[3] = (v[3] >> 1) | (v[2] << 31)
			v[2] = (v[2] >> 1) | (v[1] << 31)
			v[1] = (v[1] >> 1) | (v[0] << 31)
			v[0] = v[0] >> 1
			// Constant-time: XOR with reduction constant when lsb=1.
			reduceMask := uint32(-int32(lsb)) // 0xFFFFFFFF when lsb=1, 0x00000000 when lsb=0
			v[0] ^= 0xe1000000 & reduceMask   // 0xe1 << 24, big-endian uint32
		}
	}

	*s = z
}

// derivePolyvalKey derives the POLYVAL hash key and AES encryption key from
// a master AES key and nonce, as specified in RFC 8452 Section 4.
//
// For AES-256-GCM-SIV, six key-derivation blocks are computed:
//
//	Blocks 0-1: message_authentication_key (POLYVAL hash key, 16 bytes)
//	Blocks 2-5: message_encryption_key (AES-256 key, 32 bytes)
//
// Each block is formed by encrypting le32(counter) || nonce with the
// master key and taking only the first 8 bytes.
func derivePolyvalKey(aesKey, nonce []byte) (hashKey, encKey []byte, err error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, nil, err
	}

	derive := func(counter byte) []byte {
		input := make([]byte, aes.BlockSize)
		input[0] = counter // le32(counter), only low byte needed for 0..5
		copy(input[4:], nonce)
		output := make([]byte, aes.BlockSize)
		block.Encrypt(output, input)
		return output
	}

	b0 := derive(0)
	b1 := derive(1)
	b2 := derive(2)
	b3 := derive(3)
	b4 := derive(4)
	b5 := derive(5)
	defer crypto.Zeroize(b0)
	defer crypto.Zeroize(b1)
	defer crypto.Zeroize(b2)
	defer crypto.Zeroize(b3)
	defer crypto.Zeroize(b4)
	defer crypto.Zeroize(b5)

	// Hash key: first 8 bytes of block 0 || first 8 bytes of block 1
	hashKey = make([]byte, 16)
	copy(hashKey[0:8], b0[0:8])
	copy(hashKey[8:16], b1[0:8])

	// Encryption key: first 8 bytes of blocks 2-5 concatenated
	encKey = make([]byte, 32)
	copy(encKey[0:8], b2[0:8])
	copy(encKey[8:16], b3[0:8])
	copy(encKey[16:24], b4[0:8])
	copy(encKey[24:32], b5[0:8])

	return hashKey, encKey, nil
}
