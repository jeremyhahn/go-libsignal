// POLYVAL for AES-GCM-SIV (RFC 8452 §3), computed through GHASH with byte reversal.
package cipher

import (
	"crypto/aes"
	"encoding/binary"

	crypto "github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
)

// polyvalBlockSize is the size of a POLYVAL block in bytes (128 bits).
const polyvalBlockSize = 16

// polyval computes POLYVAL over 16-byte blocks with hash key H through the GHASH relationship of RFC 8452 §3.
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
			// Little-endian reads byte-reverse the input for the big-endian GHASH state.
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

// toGHASHKey computes mulX_GHASH(ByteReverse(H)): a right shift with conditional reduction by 0xe1 << 120.
func toGHASHKey(h []byte) [4]uint32 {
	// ByteReverse: reverse byte order of the 16-byte key.
	var rev [16]byte
	for i := 0; i < 16; i++ {
		rev[i] = h[15-i]
	}

	// mulX_GHASH: right shift by one bit with reduction when the low bit is set.
	hiBit := rev[15] & 1

	// Right-shift the entire 128-bit value by 1.
	var carry byte
	for i := 0; i < 16; i++ {
		t := rev[i]
		rev[i] = (t >> 1) | carry
		carry = (t & 1) << 7
	}

	// Constant-time XOR of the reduction constant 0xe1; mask is 0xFF when hiBit is 1.
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

// ghashMul multiplies s by h in place in GF(2^128) modulo x^128 + x^7 + x^2 + x + 1, bit by bit.
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

			// v = v * x with constant-time reduction.
			lsb := v[3] & 1
			v[3] = (v[3] >> 1) | (v[2] << 31)
			v[2] = (v[2] >> 1) | (v[1] << 31)
			v[1] = (v[1] >> 1) | (v[0] << 31)
			v[0] >>= 1
			// Constant-time: XOR with reduction constant when lsb=1.
			reduceMask := uint32(-int32(lsb)) // 0xFFFFFFFF when lsb=1, 0x00000000 when lsb=0
			v[0] ^= 0xe1000000 & reduceMask   // 0xe1 << 24, big-endian uint32
		}
	}

	*s = z
}

// derivePolyvalKey derives the POLYVAL key (blocks 0-1) and AES-256 key (blocks 2-5) from AES(le32(i) || nonce), RFC 8452 §4.
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
