package kem

// Cross-implementation compatibility tests for the Kyber KEM wrappers.
//
// These tests use the circl scheme's deterministic APIs (DeriveKeyPair and
// EncapsulateDeterministically) to produce fixed, reproducible outputs and
// verify that:
//
//  1. Key sizes match the Kyber specification (round 3).
//  2. The same seed always produces the same key material (determinism).
//  3. Encapsulate/Decapsulate round-trips succeed with deterministic seeds.
//  4. The go-libsignal wrappers produce results that are byte-identical to
//     direct circl calls for the same inputs.
//
// Algorithm parameter sizes (Kyber round 3):
//
//	Kyber-768:  pk=1184, sk=2400, ct=1088, ss=32, keySeed=64, encapSeed=32
//	Kyber-1024: pk=1568, sk=3168, ct=1568, ss=32, keySeed=64, encapSeed=32

import (
	"bytes"
	"testing"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

// kyber768KeySeedSize is the seed length required by DeriveKeyPair for Kyber-768.
// cpapke.KeySeedSize = 32; the CCA wrapper appends another 32 bytes → total 64.
const kyber768KeySeedSize = 64

// kyberEncapSeedSize is the seed length required by EncapsulateDeterministically.
const kyberEncapSeedSize = 32

// fixedKeySeed is a stable 64-byte seed used across all determinism tests.
var fixedKeySeed = [kyber768KeySeedSize]byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
	0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
	0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
}

// fixedEncapSeed is a stable 32-byte seed used for deterministic encapsulation.
var fixedEncapSeed = [kyberEncapSeedSize]byte{
	0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
	0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
	0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
	0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0,
}

// TestKyber768KeySizes verifies that the Kyber-768 wrapper produces keys of the
// sizes mandated by the round-3 specification.
func TestKyber768KeySizes(t *testing.T) {
	k := NewMLKEM768KEM()
	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	const (
		wantPKSize = 1184
		wantSKSize = 2400
		wantCTSize = 1088
		wantSSSize = 32
	)

	if got := len(kp.Public.Data()); got != wantPKSize {
		t.Errorf("public key size = %d, want %d", got, wantPKSize)
	}
	if got := len(kp.Secret.Data()); got != wantSKSize {
		t.Errorf("secret key size = %d, want %d", got, wantSKSize)
	}

	_, ct768, err := k.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	if got := len(ct768.Data()); got != wantCTSize {
		t.Errorf("ciphertext size = %d, want %d", got, wantCTSize)
	}
}

// TestKyber1024KeySizes verifies that the Kyber-1024 wrapper produces keys of
// the sizes mandated by the specification.
func TestKyber1024KeySizes(t *testing.T) {
	k := NewKyber1024KEM()
	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	const (
		wantPKSize = 1568
		wantSKSize = 3168
		wantCTSize = 1568
		wantSSSize = 32
	)

	if got := len(kp.Public.Data()); got != wantPKSize {
		t.Errorf("public key size = %d, want %d", got, wantPKSize)
	}
	if got := len(kp.Secret.Data()); got != wantSKSize {
		t.Errorf("secret key size = %d, want %d", got, wantSKSize)
	}

	_, ct1024, err := k.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	if got := len(ct1024.Data()); got != wantCTSize {
		t.Errorf("ciphertext size = %d, want %d", got, wantCTSize)
	}
}

// TestKyber768DeterministicKeyDerivation verifies that DeriveKeyPair is
// deterministic: the same seed always yields the same public and secret keys.
func TestKyber768DeterministicKeyDerivation(t *testing.T) {
	scheme := kyber768.Scheme()

	pk1, sk1 := scheme.DeriveKeyPair(fixedKeySeed[:])
	pk2, sk2 := scheme.DeriveKeyPair(fixedKeySeed[:])

	pk1Bytes, err := pk1.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary pk1: %v", err)
	}
	pk2Bytes, err := pk2.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary pk2: %v", err)
	}
	if !bytes.Equal(pk1Bytes, pk2Bytes) {
		t.Error("kyber768: same seed produced different public keys")
	}

	sk1Bytes, err := sk1.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary sk1: %v", err)
	}
	sk2Bytes, err := sk2.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary sk2: %v", err)
	}
	if !bytes.Equal(sk1Bytes, sk2Bytes) {
		t.Error("kyber768: same seed produced different secret keys")
	}
}

// TestKyber1024DeterministicKeyDerivation verifies DeriveKeyPair determinism
// for Kyber-1024.
func TestKyber1024DeterministicKeyDerivation(t *testing.T) {
	scheme := kyber1024.Scheme()

	pk1, sk1 := scheme.DeriveKeyPair(fixedKeySeed[:])
	pk2, sk2 := scheme.DeriveKeyPair(fixedKeySeed[:])

	pk1Bytes, err := pk1.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary pk1: %v", err)
	}
	pk2Bytes, err := pk2.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary pk2: %v", err)
	}
	if !bytes.Equal(pk1Bytes, pk2Bytes) {
		t.Error("kyber1024: same seed produced different public keys")
	}

	sk1Bytes, err := sk1.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary sk1: %v", err)
	}
	sk2Bytes, err := sk2.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary sk2: %v", err)
	}
	if !bytes.Equal(sk1Bytes, sk2Bytes) {
		t.Error("kyber1024: same seed produced different secret keys")
	}
}

// TestKyber768DeterministicEncapsulation verifies that
// EncapsulateDeterministically is stable: the same (pk, seed) always yields
// the same ciphertext and shared secret.
func TestKyber768DeterministicEncapsulation(t *testing.T) {
	scheme := kyber768.Scheme()
	pk, _ := scheme.DeriveKeyPair(fixedKeySeed[:])

	ct1, ss1, err := scheme.EncapsulateDeterministically(pk, fixedEncapSeed[:])
	if err != nil {
		t.Fatalf("EncapsulateDeterministically (1): %v", err)
	}
	ct2, ss2, err := scheme.EncapsulateDeterministically(pk, fixedEncapSeed[:])
	if err != nil {
		t.Fatalf("EncapsulateDeterministically (2): %v", err)
	}

	if !bytes.Equal(ct1, ct2) {
		t.Error("kyber768: same encap seed produced different ciphertexts")
	}
	if !bytes.Equal(ss1, ss2) {
		t.Error("kyber768: same encap seed produced different shared secrets")
	}
}

// TestKyber1024DeterministicEncapsulation verifies EncapsulateDeterministically
// stability for Kyber-1024.
func TestKyber1024DeterministicEncapsulation(t *testing.T) {
	scheme := kyber1024.Scheme()
	pk, _ := scheme.DeriveKeyPair(fixedKeySeed[:])

	ct1, ss1, err := scheme.EncapsulateDeterministically(pk, fixedEncapSeed[:])
	if err != nil {
		t.Fatalf("EncapsulateDeterministically (1): %v", err)
	}
	ct2, ss2, err := scheme.EncapsulateDeterministically(pk, fixedEncapSeed[:])
	if err != nil {
		t.Fatalf("EncapsulateDeterministically (2): %v", err)
	}

	if !bytes.Equal(ct1, ct2) {
		t.Error("kyber1024: same encap seed produced different ciphertexts")
	}
	if !bytes.Equal(ss1, ss2) {
		t.Error("kyber1024: same encap seed produced different shared secrets")
	}
}

// TestKyber768WrapperMatchesCirclDirect verifies that the go-libsignal
// MLKEM768KEM wrapper produces byte-identical results to direct circl calls
// when using the same key material.  The wrapper operates on serialized keys,
// so we derive a key via circl, feed the serialized bytes into the wrapper,
// and confirm the shared secret from Decapsulate matches the circl reference.
func TestKyber768WrapperMatchesCirclDirect(t *testing.T) {
	scheme := kyber768.Scheme()

	// Derive a deterministic key pair via circl.
	circlPK, circlSK := scheme.DeriveKeyPair(fixedKeySeed[:])

	pkBytes, err := circlPK.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary pk: %v", err)
	}
	skBytes, err := circlSK.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary sk: %v", err)
	}

	// Deterministic encapsulation via circl.
	ctBytes, ssRef, err := scheme.EncapsulateDeterministically(circlPK, fixedEncapSeed[:])
	if err != nil {
		t.Fatalf("EncapsulateDeterministically: %v", err)
	}

	// Feed the serialized keys into the wrapper.
	wrapperPK := NewPublicKey(KeyTypeKyber768, pkBytes)
	wrapperSK, err := NewSecretKey(KeyTypeKyber768, skBytes)
	if err != nil {
		t.Fatalf("NewSecretKey: %v", err)
	}
	wrapperCT := NewCiphertext(KeyTypeKyber768, ctBytes)

	// Decapsulate through the wrapper and compare to the circl reference.
	k := NewMLKEM768KEM()
	ss, err := k.Decapsulate(wrapperSK, wrapperCT)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}

	if !bytes.Equal(ss[:], ssRef) {
		t.Errorf("wrapper shared secret does not match circl reference\n  got:  %x\n  want: %x", ss[:], ssRef)
	}

	// Also verify the wrapper can encapsulate and decapsulate its own output.
	ss2, ct2, err := k.Encapsulate(wrapperPK)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	ss3, err := k.Decapsulate(wrapperSK, ct2)
	if err != nil {
		t.Fatalf("Decapsulate (round-trip): %v", err)
	}
	if *ss2 != *ss3 {
		t.Error("wrapper round-trip shared secrets do not match")
	}
}

// TestKyber1024WrapperMatchesCirclDirect is the Kyber-1024 equivalent of
// TestKyber768WrapperMatchesCirclDirect.
func TestKyber1024WrapperMatchesCirclDirect(t *testing.T) {
	scheme := kyber1024.Scheme()

	circlPK, circlSK := scheme.DeriveKeyPair(fixedKeySeed[:])

	pkBytes, err := circlPK.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary pk: %v", err)
	}
	skBytes, err := circlSK.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary sk: %v", err)
	}

	ctBytes, ssRef, err := scheme.EncapsulateDeterministically(circlPK, fixedEncapSeed[:])
	if err != nil {
		t.Fatalf("EncapsulateDeterministically: %v", err)
	}

	wrapperPK := NewPublicKey(KeyTypeKyber1024, pkBytes)
	wrapperSK, err := NewSecretKey(KeyTypeKyber1024, skBytes)
	if err != nil {
		t.Fatalf("NewSecretKey: %v", err)
	}
	wrapperCT := NewCiphertext(KeyTypeKyber1024, ctBytes)

	k := NewKyber1024KEM()
	ss, err := k.Decapsulate(wrapperSK, wrapperCT)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}

	if !bytes.Equal(ss[:], ssRef) {
		t.Errorf("wrapper shared secret does not match circl reference\n  got:  %x\n  want: %x", ss[:], ssRef)
	}

	ss2, ct2, err := k.Encapsulate(wrapperPK)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	ss3, err := k.Decapsulate(wrapperSK, ct2)
	if err != nil {
		t.Fatalf("Decapsulate (round-trip): %v", err)
	}
	if *ss2 != *ss3 {
		t.Error("wrapper round-trip shared secrets do not match")
	}
}

// TestKyber768WrapperDeterministicRoundTrip uses serialization/deserialization
// to verify that the public-key-serialize → deserialize → encapsulate →
// decapsulate chain remains consistent for a fixed seed.
func TestKyber768WrapperDeterministicRoundTrip(t *testing.T) {
	scheme := kyber768.Scheme()
	circlPK, circlSK := scheme.DeriveKeyPair(fixedKeySeed[:])

	pkBytes, err := circlPK.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary pk: %v", err)
	}
	skBytes, err := circlSK.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary sk: %v", err)
	}

	// Round-trip through the wrapper's Serialize/DeserializePublicKey path.
	wrapperPK := NewPublicKey(KeyTypeKyber768, pkBytes)
	serialized := wrapperPK.Serialize()

	deserializedPK, err := DeserializePublicKey(serialized)
	if err != nil {
		t.Fatalf("DeserializePublicKey: %v", err)
	}
	if !bytes.Equal(wrapperPK.Data(), deserializedPK.Data()) {
		t.Error("public key data changed across Serialize/Deserialize")
	}

	wrapperSK, err := NewSecretKey(KeyTypeKyber768, skBytes)
	if err != nil {
		t.Fatalf("NewSecretKey: %v", err)
	}

	k := NewMLKEM768KEM()
	ss1, ct, err := k.Encapsulate(deserializedPK)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}

	// Round-trip ciphertext through Serialize/DeserializeCiphertext.
	ctSerialized := ct.Serialize()
	deserializedCT, err := DeserializeCiphertext(ctSerialized)
	if err != nil {
		t.Fatalf("DeserializeCiphertext: %v", err)
	}

	ss2, err := k.Decapsulate(wrapperSK, deserializedCT)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}

	if *ss1 != *ss2 {
		t.Error("shared secrets differ after Serialize/Deserialize round-trip")
	}
}

// TestKyber1024WrapperDeterministicRoundTrip is the Kyber-1024 equivalent of
// TestKyber768WrapperDeterministicRoundTrip.
func TestKyber1024WrapperDeterministicRoundTrip(t *testing.T) {
	scheme := kyber1024.Scheme()
	circlPK, circlSK := scheme.DeriveKeyPair(fixedKeySeed[:])

	pkBytes, err := circlPK.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary pk: %v", err)
	}
	skBytes, err := circlSK.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary sk: %v", err)
	}

	wrapperPK := NewPublicKey(KeyTypeKyber1024, pkBytes)
	serialized := wrapperPK.Serialize()

	deserializedPK, err := DeserializePublicKey(serialized)
	if err != nil {
		t.Fatalf("DeserializePublicKey: %v", err)
	}
	if !bytes.Equal(wrapperPK.Data(), deserializedPK.Data()) {
		t.Error("public key data changed across Serialize/Deserialize")
	}

	wrapperSK, err := NewSecretKey(KeyTypeKyber1024, skBytes)
	if err != nil {
		t.Fatalf("NewSecretKey: %v", err)
	}

	k := NewKyber1024KEM()
	ss1, ct, err := k.Encapsulate(deserializedPK)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}

	ctSerialized := ct.Serialize()
	deserializedCT, err := DeserializeCiphertext(ctSerialized)
	if err != nil {
		t.Fatalf("DeserializeCiphertext: %v", err)
	}

	ss2, err := k.Decapsulate(wrapperSK, deserializedCT)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}

	if *ss1 != *ss2 {
		t.Error("shared secrets differ after Serialize/Deserialize round-trip")
	}
}

// TestKyber768DistinctSeedsProduceDifferentKeys verifies that two different
// seeds yield genuinely different key material.
func TestKyber768DistinctSeedsProduceDifferentKeys(t *testing.T) {
	scheme := kyber768.Scheme()

	seed2 := fixedKeySeed
	seed2[0] ^= 0xff // flip one bit to get a different seed

	pk1, _ := scheme.DeriveKeyPair(fixedKeySeed[:])
	pk2, _ := scheme.DeriveKeyPair(seed2[:])

	pk1Bytes, _ := pk1.MarshalBinary()
	pk2Bytes, _ := pk2.MarshalBinary()

	if bytes.Equal(pk1Bytes, pk2Bytes) {
		t.Error("different seeds should produce different public keys")
	}
}

// TestKyber1024DistinctSeedsProduceDifferentKeys is the Kyber-1024 equivalent.
func TestKyber1024DistinctSeedsProduceDifferentKeys(t *testing.T) {
	scheme := kyber1024.Scheme()

	seed2 := fixedKeySeed
	seed2[0] ^= 0xff

	pk1, _ := scheme.DeriveKeyPair(fixedKeySeed[:])
	pk2, _ := scheme.DeriveKeyPair(seed2[:])

	pk1Bytes, _ := pk1.MarshalBinary()
	pk2Bytes, _ := pk2.MarshalBinary()

	if bytes.Equal(pk1Bytes, pk2Bytes) {
		t.Error("different seeds should produce different public keys")
	}
}
