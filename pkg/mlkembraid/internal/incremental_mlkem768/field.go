// Package incremental_mlkem768 implements the libcrux ML-KEM-768 incremental
// encapsulation API in pure Go.
//
// This is a port of the libcrux-ml-kem crate's `incremental` feature
// (libcrux-ml-kem v0.0.8, src/ind_cca/incremental.rs) targeting the
// sparsepostquantumratchet v1.5.1 crate's incremental_mlkem768.rs API.
//
// Rust upstream paths:
//   - libcrux-ml-kem/src/ind_cca/incremental.rs
//   - libcrux-ml-kem/src/ind_cca/incremental/types.rs
//   - libcrux-ml-kem/src/mlkem768.rs (impl_incr_key_size macro instantiations)
//   - sparsepostquantumratchet/src/incremental_mlkem768.rs
//
// The Go stdlib crypto/mlkem does not expose a split encaps1/encaps2 API.
// This package re-implements the ML-KEM-768 K-PKE layer in pure Go following
// NIST FIPS 203, which is required to produce a wire-compatible 2080-byte
// EncapsulationState that Rust's spqr crate can deserialize.
//
// KeyGen, Encaps1, Encaps2, and Decaps (in mlkem768.go) are fully implemented,
// along with the underlying field arithmetic, NTT, sampling, and encoding.
package incremental_mlkem768

import (
	"crypto/sha3"
	"encoding/binary"
	"errors"
)

// ML-KEM-768 global constants (FIPS 203, Table 2).
const (
	n = 256  // polynomial degree
	q = 3329 // modulus

	k = 3 // module dimension for ML-KEM-768

	// encodingSize12 is the byte size of ByteEncode12 output per polynomial.
	encodingSize12 = n * 12 / 8 // 384

	// encodingSize10 is the byte size of ByteEncode10 output per polynomial.
	encodingSize10 = n * 10 / 8 // 320

	// encodingSize4 is the byte size of ByteEncode4 output per polynomial.
	encodingSize4 = n * 4 / 8 // 128

	// encodingSize1 is the byte size of ByteEncode1 output per polynomial.
	encodingSize1 = n * 1 / 8 // 32

	// PublicKey1Size is the size of pk1 = seed_for_A(32) || H(ek)(32).
	// Rust: incremental::pk1_len() == 64.
	PublicKey1Size = 64

	// PublicKey2Size is the size of pk2 = ByteEncode12(t) = k * encodingSize12.
	// Rust: incremental::pk2_len() == 1152.
	PublicKey2Size = k * encodingSize12 // 1152

	// Ciphertext1Size is the size of ct1 = k * ByteEncode10(Compress10(u)).
	// Rust: incremental::Ciphertext1::len() == 960.
	Ciphertext1Size = k * encodingSize10 // 960

	// Ciphertext2Size is the size of ct2 = ByteEncode4(Compress4(v)).
	// Rust: incremental::Ciphertext2::len() == 128.
	Ciphertext2Size = encodingSize4 // 128

	// SharedSecretSize is the size of the shared secret.
	SharedSecretSize = 32

	// EncapsStateSize is the serialized size of EncapsState:
	//   r_as_ntt: k polynomials × encodingSize12 = 1152 bytes
	//   error2:   1 polynomial  × encodingSize12 = 384 bytes (stored as i16 LE)
	//   randomness: 32 bytes
	// Total: 1152 + 384 + 32 = 1568... wait, libcrux uses LE i16 for NTT elements.
	//
	// Per libcrux types.rs EncapsState::num_bytes():
	//   vec_len_bytes::<K, Vector>() = K * BITS_PER_RING_ELEMENT / 8 = 3 * 256 * 2 = 1536
	//   PolynomialRingElement::num_bytes()                             = 256 * 2     = 512
	//   randomness: 32
	// Total: 1536 + 512 + 32 = 2080.
	//
	// NB: libcrux stores NTT coefficients as raw i16 little-endian (not ByteEncode12).
	EncapsStateSize = k*n*2 + n*2 + 32 // 2080
)

// fieldElement is an integer modulo q = 3329.
// Follows FIPS 203, Section 2.4.
type fieldElement uint16

// fieldReduceOnce reduces a value a < 2q to [0, q).
func fieldReduceOnce(a uint16) fieldElement {
	x := a - q
	x += (x >> 15) * q
	return fieldElement(x)
}

func fieldAdd(a, b fieldElement) fieldElement {
	return fieldReduceOnce(uint16(a + b))
}

func fieldSub(a, b fieldElement) fieldElement {
	return fieldReduceOnce(uint16(a - b + q))
}

const (
	barrettMultiplier = 5039 // ⌊2²⁴ / q⌋
	barrettShift      = 24
)

// fieldReduce reduces a < 2q² using Barrett reduction.
func fieldReduce(a uint32) fieldElement {
	quotient := uint32((uint64(a) * barrettMultiplier) >> barrettShift)
	return fieldReduceOnce(uint16(a - quotient*q))
}

func fieldMul(a, b fieldElement) fieldElement {
	return fieldReduce(uint32(a) * uint32(b))
}

func fieldMulSub(a, b, c fieldElement) fieldElement {
	return fieldReduce(uint32(a) * uint32(b-c+q))
}

func fieldAddMul(a, b, c, d fieldElement) fieldElement {
	x := uint32(a)*uint32(b) + uint32(c)*uint32(d)
	return fieldReduce(x)
}

// compress maps a field element to [0, 2^d) per FIPS 203 Definition 4.7.
func compress(x fieldElement, d uint8) uint16 {
	dividend := uint32(x) << d
	quotient := uint32(uint64(dividend) * barrettMultiplier >> barrettShift)
	remainder := dividend - quotient*q
	quotient += (q/2 - remainder) >> 31 & 1
	quotient += (q + q/2 - remainder) >> 31 & 1
	var mask uint32 = (1 << d) - 1
	return uint16(quotient & mask)
}

// decompress maps [0, 2^d) to a field element per FIPS 203 Definition 4.8.
func decompress(y uint16, d uint8) fieldElement {
	dividend := uint32(y) * q
	quotient := dividend >> d
	quotient += dividend >> (d - 1) & 1
	return fieldElement(quotient)
}

// ringElement is a polynomial in R_q = Z_q[X]/(X^256 + 1).
type ringElement [n]fieldElement

// nttElement is the NTT representation of a ringElement.
type nttElement [n]fieldElement

func polyAdd[T ~[n]fieldElement](a, b T) (s T) {
	for i := range s {
		s[i] = fieldAdd(a[i], b[i])
	}
	return s
}

func polySub[T ~[n]fieldElement](a, b T) (s T) {
	for i := range s {
		s[i] = fieldSub(a[i], b[i])
	}
	return s
}

// zetas are ζ^BitRev7(k) mod q for k = 0..127. FIPS 203 Appendix A.
var zetas = [128]fieldElement{
	1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746,
	296, 2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
	289, 331, 3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915,
	2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
	17, 2761, 583, 2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
	1703, 1651, 2789, 1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641,
	1584, 2298, 2037, 3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594,
	2804, 1092, 403, 1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
}

// gammas are ζ^(2*BitRev7(i)+1) mod q for i = 0..127. FIPS 203 Appendix A.
var gammas = [128]fieldElement{
	17, 3312, 2761, 568, 583, 2746, 2649, 680, 1637, 1692, 723, 2606, 2288, 1041, 1100, 2229,
	1409, 1920, 2662, 667, 3281, 48, 233, 3096, 756, 2573, 2156, 1173, 3015, 314, 3050, 279,
	1703, 1626, 1651, 1678, 2789, 540, 1789, 1540, 1847, 1482, 952, 2377, 1461, 1868, 2687, 642,
	939, 2390, 2308, 1021, 2437, 892, 2388, 941, 733, 2596, 2337, 992, 268, 3061, 641, 2688,
	1584, 1745, 2298, 1031, 2037, 1292, 3220, 109, 375, 2954, 2549, 780, 2090, 1239, 1645, 1684,
	1063, 2266, 319, 3010, 2773, 556, 757, 2572, 2099, 1230, 561, 2768, 2466, 863, 2594, 735,
	2804, 525, 1092, 2237, 403, 2926, 1026, 2303, 1143, 2186, 2150, 1179, 2775, 554, 886, 2443,
	1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300, 2110, 1219, 2935, 394, 885, 2444, 2154, 1175,
}

// nttForward implements NTT (FIPS 203 Algorithm 9).
func nttForward(f ringElement) nttElement {
	kk := 1
	for length := 128; length >= 2; length /= 2 {
		for start := 0; start < n; start += 2 * length {
			zeta := zetas[kk]
			kk++
			for j := 0; j < length; j++ {
				t := fieldMul(zeta, f[start+length+j])
				f[start+length+j] = fieldSub(f[start+j], t)
				f[start+j] = fieldAdd(f[start+j], t)
			}
		}
	}
	return nttElement(f)
}

// nttInverse implements NTT⁻¹ (FIPS 203 Algorithm 10).
func nttInverse(f nttElement) ringElement {
	kk := 127
	for length := 2; length <= 128; length *= 2 {
		for start := 0; start < n; start += 2 * length {
			zeta := zetas[kk]
			kk--
			for j := 0; j < length; j++ {
				t := f[start+j]
				f[start+j] = fieldAdd(t, f[start+length+j])
				f[start+length+j] = fieldMulSub(zeta, f[start+length+j], t)
			}
		}
	}
	for i := range f {
		f[i] = fieldMul(f[i], 3303) // 3303 = 128⁻¹ mod q
	}
	return ringElement(f)
}

// nttMul implements MultiplyNTTs (FIPS 203 Algorithm 11).
func nttMul(f, g nttElement) nttElement {
	var h nttElement
	for i := 0; i < n; i += 2 {
		a0, a1 := f[i], f[i+1]
		b0, b1 := g[i], g[i+1]
		h[i] = fieldAddMul(a0, b0, fieldMul(a1, b1), gammas[i/2])
		h[i+1] = fieldAddMul(a0, b1, a1, b0)
	}
	return h
}

// sampleNTT implements SampleNTT (FIPS 203 Algorithm 7).
// Draws a uniformly random nttElement from XOF(rho || ii || jj).
func sampleNTT(rho []byte, ii, jj byte) nttElement {
	xof := sha3.NewSHAKE128()
	mustWrite(xof, rho)
	mustWrite(xof, []byte{ii, jj})

	var a nttElement
	j := 0
	var buf [24]byte
	off := len(buf)
	for {
		if off >= len(buf) {
			mustRead(xof, buf[:])
			off = 0
		}
		d1 := (uint16(buf[off]) | uint16(buf[off+1])<<8) & 0x0FFF
		d2 := (uint16(buf[off+1]) | uint16(buf[off+2])<<8) >> 4
		off += 3
		if d1 < q {
			a[j] = fieldElement(d1)
			j++
		}
		if j >= n {
			break
		}
		if d2 < q {
			a[j] = fieldElement(d2)
			j++
		}
		if j >= n {
			break
		}
	}
	return a
}

// samplePolyCBD implements SamplePolyCBD_η (FIPS 203 Algorithm 8) with η=2.
// Generates a polynomial from PRF(s, b) using SHAKE256.
func samplePolyCBD(s []byte, b byte) ringElement {
	prf := sha3.NewSHAKE256()
	mustWrite(prf, s)
	mustWrite(prf, []byte{b})
	// η=2: each coefficient needs 2η=4 bits; 256 coefficients × 4 bits = 128 bytes.
	B := make([]byte, 128)
	mustRead(prf, B)

	// Each byte B[j] encodes two coefficients: coeff[2j] and coeff[2j+1].
	// For coeff[2j]:   b0=B[j][0], b1=B[j][1], b2=B[j][2], b3=B[j][3]
	//                  coeff = (b0+b1) - (b2+b3)
	// For coeff[2j+1]: b4=B[j][4], b5=B[j][5], b6=B[j][6], b7=B[j][7]
	//                  coeff = (b4+b5) - (b6+b7)
	var f ringElement
	for j := 0; j < n/2; j++ {
		bb := B[j]
		b0 := fieldElement(bb & 1)
		b1 := fieldElement((bb >> 1) & 1)
		b2 := fieldElement((bb >> 2) & 1)
		b3 := fieldElement((bb >> 3) & 1)
		b4 := fieldElement((bb >> 4) & 1)
		b5 := fieldElement((bb >> 5) & 1)
		b6 := fieldElement((bb >> 6) & 1)
		b7 := fieldElement((bb >> 7) & 1)
		f[2*j] = fieldSub(b0+b1, b2+b3)
		f[2*j+1] = fieldSub(b4+b5, b6+b7)
	}
	return f
}

// byteEncode12 encodes a polynomial f using ByteEncode12 (FIPS 203 Algorithm 5).
// Output is 384 bytes appended to dst.
func byteEncode12(dst []byte, f nttElement) []byte {
	out := append(dst, make([]byte, encodingSize12)...)
	b := out[len(dst):]
	for i := 0; i < n; i += 2 {
		x := uint32(f[i]) | uint32(f[i+1])<<12
		b[0] = uint8(x)
		b[1] = uint8(x >> 8)
		b[2] = uint8(x >> 16)
		b = b[3:]
	}
	return out
}

// byteDecode12 decodes 384 bytes into an nttElement using ByteDecode12 (FIPS 203 Algorithm 6).
func byteDecode12(b []byte) (nttElement, error) {
	if len(b) < encodingSize12 {
		return nttElement{}, errors.New("incremental_mlkem768: byteDecode12: insufficient input")
	}
	var f nttElement
	for i := 0; i < n; i += 2 {
		d := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16
		a0 := uint16(d & 0x0FFF)
		a1 := uint16(d >> 12)
		if a0 >= q || a1 >= q {
			return nttElement{}, errors.New("incremental_mlkem768: byteDecode12: unreduced coefficient")
		}
		f[i] = fieldElement(a0)
		f[i+1] = fieldElement(a1)
		b = b[3:]
	}
	return f, nil
}

// ringCompressEncode10 appends Compress10(u) to dst (320 bytes per polynomial).
func ringCompressEncode10(dst []byte, f ringElement) []byte {
	out := append(dst, make([]byte, encodingSize10)...)
	b := out[len(dst):]
	for i := 0; i < n; i += 4 {
		var x uint64
		x |= uint64(compress(f[i], 10))
		x |= uint64(compress(f[i+1], 10)) << 10
		x |= uint64(compress(f[i+2], 10)) << 20
		x |= uint64(compress(f[i+3], 10)) << 30
		b[0] = uint8(x)
		b[1] = uint8(x >> 8)
		b[2] = uint8(x >> 16)
		b[3] = uint8(x >> 24)
		b[4] = uint8(x >> 32)
		b = b[5:]
	}
	return out
}

// ringCompressEncode4 appends Compress4(v) to dst (128 bytes).
func ringCompressEncode4(dst []byte, f ringElement) []byte {
	out := append(dst, make([]byte, encodingSize4)...)
	b := out[len(dst):]
	for i := 0; i < n; i += 2 {
		b[i/2] = uint8(compress(f[i], 4) | compress(f[i+1], 4)<<4)
	}
	return out
}

// ringCompressEncode1 appends Compress1(msg) to dst (32 bytes).
func ringCompressEncode1(dst []byte, f ringElement) []byte {
	out := append(dst, make([]byte, encodingSize1)...)
	b := out[len(dst):]
	for i := range f {
		b[i/8] |= uint8(compress(f[i], 1)) << (i % 8)
	}
	return out
}

// ringDecodeDecompress1 maps 32 bytes to a ring element (message decoding).
func ringDecodeDecompress1(b []byte) ringElement {
	const halfQ = (q + 1) / 2
	var f ringElement
	for i := range f {
		bit := (b[i/8] >> (i % 8)) & 1
		f[i] = fieldElement(bit) * halfQ
	}
	return f
}

// byteEncode12Into encodes a polynomial f directly into a fixed-length output buffer.
// The buffer must be exactly encodingSize12 bytes.
func byteEncode12Into(dst []byte, f nttElement) {
	for i := 0; i < n; i += 2 {
		x := uint32(f[i]) | uint32(f[i+1])<<12
		dst[0] = uint8(x)
		dst[1] = uint8(x >> 8)
		dst[2] = uint8(x >> 16)
		dst = dst[3:]
	}
}

// ringDecodeDecompress10 decodes a 320-byte buffer into a ring element.
// Each coefficient is encoded with 10 bits and decompressed from [0, 2^10) to [0, q).
// Matches FIPS 203 Algorithm 6 (ByteDecode10) followed by Decompress10.
func ringDecodeDecompress10(b []byte) ringElement {
	var f ringElement
	for i := 0; i < n; i += 4 {
		x := uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 | uint64(b[4])<<32
		f[i] = decompress(uint16(x&0x3FF), 10)
		f[i+1] = decompress(uint16((x>>10)&0x3FF), 10)
		f[i+2] = decompress(uint16((x>>20)&0x3FF), 10)
		f[i+3] = decompress(uint16((x>>30)&0x3FF), 10)
		b = b[5:]
	}
	return f
}

// ringDecodeDecompress4 decodes a 128-byte buffer into a ring element.
// Each coefficient is encoded with 4 bits and decompressed from [0, 16) to [0, q).
// Matches FIPS 203 Algorithm 6 (ByteDecode4) followed by Decompress4.
func ringDecodeDecompress4(b []byte) ringElement {
	var f ringElement
	for i := 0; i < n; i += 2 {
		f[i] = decompress(uint16(b[i/2]&0x0F), 4)
		f[i+1] = decompress(uint16(b[i/2]>>4), 4)
	}
	return f
}

// pkeEncrypt implements K-PKE.Encrypt (FIPS 203 Algorithm 14) returning the
// two ciphertext parts separately. Used by Decaps for re-encryption in the
// implicit rejection check.
//
// Inputs:
//   - A:          k×k matrix of NTT elements (precomputed from rho)
//   - t:          k NTT elements (public key polynomial)
//   - m:          32-byte plaintext message (ByteEncode1 format)
//   - rnd:        pseudorandomness for r, e1, e2 sampling
//
// Returns ct1 (960B) and ct2 (128B).
func pkeEncrypt(A [k * k]nttElement, t [k]nttElement, m [encodingSize1]byte, rnd []byte) ([Ciphertext1Size]byte, [Ciphertext2Size]byte) {
	var N byte
	var r [k]nttElement
	for i := range r {
		r[i] = nttForward(samplePolyCBD(rnd, N))
		N++
	}
	var e1 [k]ringElement
	for i := range e1 {
		e1[i] = samplePolyCBD(rnd, N)
		N++
	}
	e2 := samplePolyCBD(rnd, N)

	// u = NTT⁻¹(A^T · r) + e1
	var u [k]ringElement
	for i := range u {
		var uHat nttElement
		for j := 0; j < k; j++ {
			uHat = polyAdd(uHat, nttMul(A[j*k+i], r[j]))
		}
		u[i] = polyAdd(e1[i], nttInverse(uHat))
	}

	// μ = Decompress1(m)
	mu := ringDecodeDecompress1(m[:])

	// v = NTT⁻¹(t^T · r) + e2 + μ
	var vHat nttElement
	for i := range t {
		vHat = polyAdd(vHat, nttMul(t[i], r[i]))
	}
	v := polyAdd(polyAdd(nttInverse(vHat), e2), mu)

	var ct1 [Ciphertext1Size]byte
	var ct2 [Ciphertext2Size]byte
	var buf []byte
	for i := range u {
		buf = ringCompressEncode10(buf, u[i])
	}
	copy(ct1[:], buf)
	buf = ringCompressEncode4(nil, v)
	copy(ct2[:], buf)
	return ct1, ct2
}

// encapsStateToBytes serializes an EncapsState to 2080 bytes in libcrux wire format.
//
// libcrux encoding (types.rs EncapsState::to_bytes):
//
//	r_as_ntt:   k polynomials, each 256 i16 in little-endian = 1536 bytes
//	error2:     1 polynomial,  256 i16 in little-endian       = 512 bytes
//	randomness: 32 bytes (raw)
//
// This matches Rust's vec_to_bytes / PolynomialRingElement::to_bytes, which write
// each coefficient as a raw i16 (little-endian), NOT as ByteEncode12.
func encapsStateToBytes(rAsNTT [k]nttElement, error2 ringElement, randomness [32]byte) [EncapsStateSize]byte {
	var out [EncapsStateSize]byte
	off := 0
	for i := range rAsNTT {
		for _, coeff := range rAsNTT[i] {
			binary.LittleEndian.PutUint16(out[off:], uint16(coeff))
			off += 2
		}
	}
	for _, coeff := range error2 {
		binary.LittleEndian.PutUint16(out[off:], uint16(coeff))
		off += 2
	}
	copy(out[off:], randomness[:])
	return out
}

// encapsStateFromBytes deserializes a 2080-byte blob into EncapsState components.
func encapsStateFromBytes(b []byte) ([k]nttElement, ringElement, [32]byte, error) {
	if len(b) < EncapsStateSize {
		return [k]nttElement{}, ringElement{}, [32]byte{},
			errors.New("incremental_mlkem768: encapsStateFromBytes: buffer too short")
	}
	var rAsNTT [k]nttElement
	off := 0
	for i := range rAsNTT {
		for j := range rAsNTT[i] {
			rAsNTT[i][j] = fieldElement(binary.LittleEndian.Uint16(b[off:]))
			off += 2
		}
	}
	var error2 ringElement
	for j := range error2 {
		error2[j] = fieldElement(binary.LittleEndian.Uint16(b[off:]))
		off += 2
	}
	var randomness [32]byte
	copy(randomness[:], b[off:])
	return rAsNTT, error2, randomness, nil
}
