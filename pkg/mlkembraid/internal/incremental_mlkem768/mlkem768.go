package incremental_mlkem768

// This file implements the public incremental ML-KEM-768 API matching the
// libcrux-ml-kem incremental feature and the sparsepostquantumratchet crate's
// incremental_mlkem768.rs wrapper.
//
// Rust upstream:
//   - sparsepostquantumratchet/src/incremental_mlkem768.rs
//   - libcrux-ml-kem v0.0.8 src/ind_cca/incremental.rs
//   - libcrux-ml-kem v0.0.8 src/ind_cca/incremental/types.rs
//
// Public key layout (matches libcrux KeyPairCompressedBytes::pk1 / pk2):
//   pk1 (64 bytes)  = seed_for_A(32) || H(ek)(32)
//   pk2 (1152 bytes) = ByteEncode12(t_as_ntt[0]) || ... || ByteEncode12(t_as_ntt[k-1])
//
// Decapsulation key layout (KeyPairCompressedBytes, 2400 bytes):
//   libcrux src/ind_cca/incremental/types.rs to_bytes_compressed lines 417-433:
//   ByteEncode12(s_as_ntt[0..k]) || ByteEncode12(t[0..k]) || seed_for_A(32) || H(ek)(32) || z(32)
//   = k*384 + k*384 + 32 + 32 + 32 = 1152 + 1152 + 96 = 2400 bytes
//
//   This matches the NIST FIPS 203 standard decapsulation key format:
//   dk_pke(1152) || ek(1184) || H(ek)(32) || z(32) = 2400 bytes
//   where ek = ByteEncode12(t) || rho = 1152 + 32 = 1184 bytes.
//
// Wire sizes:
//   ct1: k * encodingSize10 = 960 bytes
//   ct2: encodingSize4      = 128 bytes
//   es:  EncapsStateSize    = 2080 bytes
//   ss:  SharedSecretSize   = 32 bytes

import (
	"crypto/rand"
	"crypto/sha3"
	"crypto/subtle"
	"errors"
)

// DecapsKeySize is the size of the compressed decapsulation key (dk).
// Layout: s_ntt(1152) || t_ntt(1152) || seed_for_A(32) || H(ek)(32) || z(32) = 2400.
const DecapsKeySize = k*encodingSize12 + k*encodingSize12 + 32 + 32 + 32

// GenerateKey generates a new ML-KEM-768 key pair for incremental encapsulation.
//
// Returns:
//   - pk1:  64-byte first public key part = seed_for_A(32) || H(ek)(32)
//   - pk2:  1152-byte second public key part = ByteEncode12(t_as_ntt)
//   - dk:   2400-byte compressed decapsulation key in libcrux KeyPairCompressedBytes layout:
//     ByteEncode12(s)(1152) || ByteEncode12(t)(1152) || rho(32) || H(ek)(32) || z(32)
//
// Rust: sparsepostquantumratchet::incremental_mlkem768::generate
// Libcrux: ind_cca/incremental/types.rs KeyPair::to_bytes_compressed (lines 417-433)
func GenerateKey() (pk1 [PublicKey1Size]byte, pk2 [PublicKey2Size]byte, dk [DecapsKeySize]byte, err error) {
	// Draw 64 random bytes: d (32B CPA seed) || z (32B implicit-rejection seed).
	var seed [64]byte
	if _, err = rand.Read(seed[:]); err != nil {
		return pk1, pk2, dk, err
	}
	d := seed[:32]
	z := seed[32:]
	return kemKeyGen(d, z)
}

// kemKeyGen implements ML-KEM.KeyGen_internal (FIPS 203 Algorithm 16) merged
// with K-PKE.KeyGen (FIPS 203 Algorithm 13).
//
// Inputs d (32B CPA seed) and z (32B implicit-rejection seed).
// Matches the Go stdlib's internal kemKeyGen in crypto/internal/fips140/mlkem/mlkem768.go.
func kemKeyGen(d, z []byte) (pk1 [PublicKey1Size]byte, pk2 [PublicKey2Size]byte, dk [DecapsKeySize]byte, err error) {
	// Step 1: G(d || k) → (rho, sigma). The domain separator byte k=3 is
	// appended per FIPS 203 Algorithm 16 and the Go stdlib implementation.
	g := sha3.New512()
	mustWrite(g, d)
	mustWrite(g, []byte{k}) // module dimension as domain separator
	G := g.Sum(nil)
	rho := G[:32]   // seed for matrix A
	sigma := G[32:] // seed for secret/error sampling

	// Step 2: Build matrix A from rho.
	var A [k * k]nttElement
	for i := byte(0); i < k; i++ {
		for j := byte(0); j < k; j++ {
			A[i*k+j] = sampleNTT(rho, j, i)
		}
	}

	// Step 3: Sample secret s and error e via CBD (eta1 = 2 for ML-KEM-768).
	var N byte
	var s [k]nttElement
	for i := range s {
		s[i] = nttForward(samplePolyCBD(sigma, N))
		N++
	}
	var e [k]nttElement
	for i := range e {
		e[i] = nttForward(samplePolyCBD(sigma, N))
		N++
	}

	// Step 4: Compute t = A·s + e in NTT domain.
	var t [k]nttElement
	for i := range t {
		t[i] = e[i]
		for j := range s {
			t[i] = polyAdd(t[i], nttMul(A[i*k+j], s[j]))
		}
	}

	// Step 5: Serialize pk2 = ByteEncode12(t).
	var pk2Buf []byte
	for i := range t {
		pk2Buf = byteEncode12(pk2Buf, t[i])
	}
	copy(pk2[:], pk2Buf)

	// Step 6: Serialize ek = ByteEncode12(t) || rho (FIPS 203 §5.1 encapsulation key).
	ek := make([]byte, PublicKey2Size+32)
	copy(ek, pk2[:])
	copy(ek[PublicKey2Size:], rho)

	// Step 7: Compute H(ek) = SHA3-256(ek).
	h := sha3.New256()
	mustWrite(h, ek)
	var hek [32]byte
	h.Sum(hek[:0])

	// Step 8: pk1 = rho || H(ek).
	copy(pk1[:32], rho)
	copy(pk1[32:], hek[:])

	// Step 9: Serialize dk in libcrux KeyPairCompressedBytes format:
	//   ByteEncode12(s)(1152) || ByteEncode12(t)(1152) || rho(32) || H(ek)(32) || z(32)
	// This matches FIPS 203 expanded dk: dk_pke(1152) || ek(1184) || H(ek)(32) || z(32).
	off := 0
	for i := range s {
		byteEncode12Into(dk[off:off+encodingSize12], s[i])
		off += encodingSize12
	}
	copy(dk[off:], pk2[:]) // ByteEncode12(t), 1152 bytes
	off += PublicKey2Size
	copy(dk[off:], rho) // seed_for_A / rho, 32 bytes
	off += 32
	copy(dk[off:], hek[:]) // H(ek), 32 bytes
	off += 32
	copy(dk[off:], z) // implicit rejection seed, 32 bytes

	return pk1, pk2, dk, nil
}

// Encaps1 performs the first phase of incremental ML-KEM-768 encapsulation.
//
// Input:
//   - pk1:       64-byte first public key (seed_for_A || H(ek))
//   - randomness: 32-byte randomness (must be uniformly random)
//
// Output:
//   - ct1:  960-byte first ciphertext (Compress10(A^T·r + e1))
//   - es:   2080-byte encapsulation state for Encaps2
//   - ss:   32-byte shared secret (KDF output, immediately available)
//
// This is the central missing primitive relative to the Go stdlib. The stdlib
// crypto/mlkem.Encapsulate is monolithic (requires the full ek = pk2 || pk1).
// Here we use only pk1 to produce ct1 and ss, deferring the pk2-dependent
// computation (ct2) to Encaps2.
//
// Algorithm (FIPS 203 §5.1, K-PKE.Encrypt split):
//
//	hashed  = G(randomness || H(ek))   where H(ek) = pk1[32:64]
//	K, r    = hashed[:32], hashed[32:]
//	sample r_i via PRF(r, i), e1_i via PRF(r, k+i), e2 via PRF(r, 2k)
//	rebuild A from ρ = pk1[:32] via sampleNTT
//	u_i = NTT⁻¹(A^T[i]·r_ntt) + e1_i   (c1 component)
//	ct1 = Compress10(u[0]) || ... || Compress10(u[k-1])
//	es  = encode(r_as_ntt, e2, randomness)   (for Encaps2)
//	ss  = K
//
// Rust: sparsepostquantumratchet::incremental_mlkem768::encaps1
func Encaps1(pk1 []byte, randomness [SharedSecretSize]byte) (ct1 [Ciphertext1Size]byte, es [EncapsStateSize]byte, ss [SharedSecretSize]byte, err error) {
	if len(pk1) != PublicKey1Size {
		return ct1, es, ss, errors.New("incremental_mlkem768: Encaps1: pk1 must be 64 bytes")
	}

	var seed [32]byte
	copy(seed[:], pk1[:32])
	var hek [32]byte
	copy(hek[:], pk1[32:64])

	// hashed = G(randomness || H(ek))  (FIPS 203 Algorithm 17 step 1)
	g := sha3.New512()
	mustWrite(g, randomness[:])
	mustWrite(g, hek[:])
	hashed := g.Sum(nil)
	copy(ss[:], hashed[:SharedSecretSize])
	rPseudo := hashed[SharedSecretSize:]

	// Rebuild matrix A from seed_for_A (ρ = pk1[:32]).
	var A [k * k]nttElement
	for i := byte(0); i < k; i++ {
		for j := byte(0); j < k; j++ {
			A[i*k+j] = sampleNTT(seed[:], j, i)
		}
	}

	// Sample r, e1, e2 via CBD using pseudorandomness r.
	var rPoly [k]nttElement
	var N byte
	for i := range rPoly {
		rPoly[i] = nttForward(samplePolyCBD(rPseudo, N))
		N++
	}
	var e1 [k]ringElement
	for i := range e1 {
		e1[i] = samplePolyCBD(rPseudo, N)
		N++
	}
	e2 := samplePolyCBD(rPseudo, N)

	// Compute u = NTT⁻¹(A^T · r) + e1.  (A^T means A[j*k+i] for column i)
	var u [k]ringElement
	for i := range u {
		var uHat nttElement
		for j := 0; j < k; j++ {
			uHat = polyAdd(uHat, nttMul(A[j*k+i], rPoly[j]))
		}
		u[i] = polyAdd(e1[i], nttInverse(uHat))
	}

	// ct1 = Compress10(u[0]) || ... || Compress10(u[k-1])
	var ct1Buf []byte
	for i := range u {
		ct1Buf = ringCompressEncode10(ct1Buf, u[i])
	}
	copy(ct1[:], ct1Buf)

	// Serialize encapsulation state: r_as_ntt, e2, randomness.
	es = encapsStateToBytes(rPoly, e2, randomness)
	return ct1, es, ss, nil
}

// Encaps2 performs the second phase of incremental ML-KEM-768 encapsulation.
//
// Input:
//   - es:  2080-byte encapsulation state from Encaps1
//   - pk2: 1152-byte second public key (ByteEncode12(t))
//
// Output:
//   - ct2: 128-byte second ciphertext (Compress4(t^T·r + e2 + msg))
//
// Algorithm:
//
//	deserialize r_as_ntt, e2, randomness from es
//	deserialize t from pk2 via ByteDecode12
//	msg = Compress1-inverse(SHAKE256(randomness) ... )
//	Note: in the incremental split, msg is derived from randomness (same as in full encaps).
//	v = NTT⁻¹(t^T · r_ntt) + e2 + Decompress1(encode1(mu))
//	ct2 = Compress4(v)
//
// Rust: sparsepostquantumratchet::incremental_mlkem768::encaps2
func Encaps2(es []byte, pk2 []byte) (ct2 [Ciphertext2Size]byte, err error) {
	if len(es) < EncapsStateSize {
		return ct2, errors.New("incremental_mlkem768: Encaps2: es too short")
	}
	if len(pk2) < PublicKey2Size {
		return ct2, errors.New("incremental_mlkem768: Encaps2: pk2 too short")
	}

	rAsNTT, e2, randomness, err := encapsStateFromBytes(es)
	if err != nil {
		return ct2, err
	}

	// Deserialize t from pk2.
	var t [k]nttElement
	for i := range t {
		t[i], err = byteDecode12(pk2[i*encodingSize12:])
		if err != nil {
			return ct2, err
		}
	}

	// The message mu in full K-PKE.Encrypt is Compress1^{-1}(encode(m)).
	// In the incremental split, m was derived from randomness via G in Encaps1
	// and encoded into 32 bytes. We re-derive it from the stored randomness.
	//
	// Per FIPS 203 Algorithm 17: the K-PKE.Encrypt call uses m (a 32-byte
	// message from the hash) and r (pseudorandomness). In the split:
	//   - Encaps1 used r to produce r_poly, e1, e2 and the A^T·r part of u
	//   - Encaps2 uses t^T·r + e2 + Decompress1(m) for v
	//
	// We need to recover m. In the full encapsulation:
	//   G(randomness || H(ek)) → (K, r)
	// But m = randomness itself (the input to G before hashing), encoded as a
	// 32-byte ring element message via Compress1.
	//
	// FIPS 203 Algorithm 14 K-PKE.Encrypt line 1: the message m is the 32-byte
	// argument. In ML-KEM.Encaps_internal, m is the random seed passed into G.
	// So mu = Decompress1(m) where m = randomness.
	var msgArr [encodingSize1]byte
	copy(msgArr[:], randomness[:])
	mu := ringDecodeDecompress1(msgArr[:])

	// v = NTT⁻¹(t^T · r_ntt) + e2 + mu
	var vHat nttElement
	for i := 0; i < k; i++ {
		vHat = polyAdd(vHat, nttMul(t[i], rAsNTT[i]))
	}
	v := polyAdd(polyAdd(nttInverse(vHat), e2), mu)

	// ct2 = Compress4(v)
	var ct2Buf []byte
	ct2Buf = ringCompressEncode4(ct2Buf, v)
	copy(ct2[:], ct2Buf)
	return ct2, nil
}

// Decaps decapsulates using the 2400-byte compressed decapsulation key dk.
//
// Input:
//   - dk:  2400-byte compressed decapsulation key from GenerateKey
//   - ct1: 960-byte first ciphertext
//   - ct2: 128-byte second ciphertext
//
// Output:
//   - ss: 32-byte shared secret
//
// Algorithm: ML-KEM.Decaps_internal (FIPS 203 Algorithm 18) with implicit rejection.
// All secret-dependent branches are avoided; ciphertext comparison is constant-time.
//
// Rust: sparsepostquantumratchet::incremental_mlkem768::decaps
func Decaps(dk []byte, ct1 []byte, ct2 []byte) (ss [SharedSecretSize]byte, err error) {
	if len(dk) != DecapsKeySize {
		return ss, &ErrInvalidInputLength{Name: "Decaps/dk", Expected: DecapsKeySize, Got: len(dk)}
	}
	if len(ct1) != Ciphertext1Size {
		return ss, &ErrInvalidInputLength{Name: "Decaps/ct1", Expected: Ciphertext1Size, Got: len(ct1)}
	}
	if len(ct2) != Ciphertext2Size {
		return ss, &ErrInvalidInputLength{Name: "Decaps/ct2", Expected: Ciphertext2Size, Got: len(ct2)}
	}

	// Parse the 2400-byte compressed dk:
	//   [0..1152]    ByteEncode12(s_ntt) — CPA secret key
	//   [1152..2304] ByteEncode12(t_ntt) — encapsulation key part 1
	//   [2304..2336] rho                 — encapsulation key part 2
	//   [2336..2368] H(ek)
	//   [2368..2400] z                  — implicit rejection seed
	off := 0
	var s [k]nttElement
	for i := range s {
		s[i], err = byteDecode12(dk[off:])
		if err != nil {
			return ss, err
		}
		off += encodingSize12
	}
	var t [k]nttElement
	for i := range t {
		t[i], err = byteDecode12(dk[off:])
		if err != nil {
			return ss, err
		}
		off += encodingSize12
	}
	rho := dk[off : off+32]
	off += 32
	hek := dk[off : off+32]
	off += 32
	z := dk[off : off+32]

	// K-PKE.Decrypt (FIPS 203 Algorithm 15):
	// Decode u from ct1 (960 bytes = k × encodingSize10).
	var u [k]ringElement
	for i := range u {
		b := ct1[i*encodingSize10 : (i+1)*encodingSize10]
		u[i] = ringDecodeDecompress10(b)
	}
	// Decode v from ct2 (128 bytes = encodingSize4).
	v := ringDecodeDecompress4(ct2[:encodingSize4])

	// w = v - NTT⁻¹(s^T · NTT(u)) — recover plaintext message bits.
	var mask nttElement
	for i := range s {
		mask = polyAdd(mask, nttMul(s[i], nttForward(u[i])))
	}
	w := polySub(v, nttInverse(mask))

	// m' = ByteEncode1(Compress1(w)) — 32-byte recovered message.
	mPrime := ringCompressEncode1(nil, w)

	// ML-KEM.Decaps_internal step 2: G(m' || H(ek)) → (K_bar, r_bar).
	g := sha3.New512()
	mustWrite(g, mPrime)
	mustWrite(g, hek)
	G := g.Sum(nil)
	kBar := G[:SharedSecretSize]
	rBar := G[SharedSecretSize:]

	// Compute implicit-rejection shared secret: J(z || c) where J = SHAKE-256.
	// c = ct1 || ct2 (full combined ciphertext).
	jShake := sha3.NewSHAKE256()
	mustWrite(jShake, z)
	mustWrite(jShake, ct1)
	mustWrite(jShake, ct2)
	var kImplicit [SharedSecretSize]byte
	mustRead(jShake, kImplicit[:])

	// Re-encrypt with recovered m' to check ciphertext validity.
	// Rebuild A from rho (we need A for re-encryption).
	var A [k * k]nttElement
	for i := byte(0); i < k; i++ {
		for j := byte(0); j < k; j++ {
			A[i*k+j] = sampleNTT(rho, j, i)
		}
	}

	// K-PKE.Encrypt(ek, m', r_bar) — produce expected ciphertext.
	var mPrimeArr [encodingSize1]byte
	copy(mPrimeArr[:], mPrime)
	ct1Prime, ct2Prime := pkeEncrypt(A, t, mPrimeArr, rBar)

	// Constant-time ciphertext comparison.
	ct1Match := subtle.ConstantTimeCompare(ct1, ct1Prime[:])
	ct2Match := subtle.ConstantTimeCompare(ct2, ct2Prime[:])
	match := subtle.ConstantTimeCompare([]byte{byte(ct1Match)}, []byte{byte(ct2Match)})
	allMatch := ct1Match & ct2Match & match

	// Select K_bar if ciphertexts match, kImplicit otherwise.
	subtle.ConstantTimeCopy(allMatch, kImplicit[:], kBar)
	copy(ss[:], kImplicit[:])
	return ss, nil
}

// ValidatePKBytes checks that pk1 and pk2 are consistent.
//
// Checks performed (matching libcrux incremental.rs validate_pk_bytes):
//  1. Length check: pk1 must be 64 bytes, pk2 must be 1152 bytes.
//  2. Hash check: SHA3-256(pk2 || pk1[:32]) must equal pk1[32:64].
//  3. Modulus check: each polynomial in pk2 must have all coefficients < q.
//
// Rust: libcrux_ml_kem::mlkem768::incremental::validate_pk_bytes
// Libcrux: ind_cca/incremental.rs validate_pk_bytes / validate_pk_parts (lines 303-338)
func ValidatePKBytes(pk1 []byte, pk2 []byte) error {
	if len(pk1) != PublicKey1Size {
		return &ErrInvalidInputLength{Name: "ValidatePKBytes/pk1", Expected: PublicKey1Size, Got: len(pk1)}
	}
	if len(pk2) != PublicKey2Size {
		return &ErrInvalidInputLength{Name: "ValidatePKBytes/pk2", Expected: PublicKey2Size, Got: len(pk2)}
	}

	// Reconstruct ek = ByteEncode12(t) || rho = pk2 || pk1[:32].
	ek := make([]byte, PublicKey2Size+32)
	copy(ek, pk2)
	copy(ek[PublicKey2Size:], pk1[:32])

	// Hash check: SHA3-256(ek) must match pk1[32:64].
	h := sha3.New256()
	mustWrite(h, ek)
	var computed [32]byte
	h.Sum(computed[:0])
	if subtle.ConstantTimeCompare(computed[:], pk1[32:64]) != 1 {
		return ErrInvalidPublicKey{Detail: "H(ek) mismatch"}
	}

	// Modulus check: round-trip ByteDecode12 → ByteEncode12 on each polynomial.
	for i := 0; i < k; i++ {
		segment := pk2[i*encodingSize12 : (i+1)*encodingSize12]
		poly, err := byteDecode12(segment)
		if err != nil {
			return ErrInvalidPublicKey{Detail: "coefficient out of range in pk2"}
		}
		var reencoded [encodingSize12]byte
		byteEncode12Into(reencoded[:], poly)
		if subtle.ConstantTimeCompare(reencoded[:], segment) != 1 {
			return ErrInvalidPublicKey{Detail: "pk2 polynomial not in reduced form"}
		}
	}

	return nil
}

// GenerateRandom fills b with cryptographically random bytes.
func GenerateRandom(b []byte) error {
	_, err := rand.Read(b)
	return err
}
