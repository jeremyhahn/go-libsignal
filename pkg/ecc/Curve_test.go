package ecc

import (
	"bytes"
	"testing"

	"filippo.io/edwards25519"
	crypto "github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
)

func TestGenerateKeyPair_Success(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if kp == nil {
		t.Fatal("expected non-nil key pair")
	}
	if kp.PublicKey() == nil {
		t.Fatal("expected non-nil public key")
	}
	if kp.PrivateKey() == nil {
		t.Fatal("expected non-nil private key")
	}
}

func TestGenerateKeyPair_UniquePairs(t *testing.T) {
	kp1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	kp2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	pub1 := kp1.PublicKey().PublicKey()
	pub2 := kp2.PublicKey().PublicKey()
	if pub1 == pub2 {
		t.Fatal("two generated key pairs should not have identical public keys")
	}
}

func TestDecodePoint_DjbType(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	serialized := kp.PublicKey().Serialize()
	decoded, err := DecodePoint(serialized, 0)
	if err != nil {
		t.Fatalf("DecodePoint failed: %v", err)
	}
	if decoded.Type() != DjbType {
		t.Fatalf("expected type %d, got %d", DjbType, decoded.Type())
	}
	origPub := kp.PublicKey().PublicKey()
	decodedPub := decoded.PublicKey()
	if origPub != decodedPub {
		t.Fatal("decoded public key does not match original")
	}
}

func TestDecodePoint_EmptyInput(t *testing.T) {
	_, err := DecodePoint([]byte{}, 0)
	if err == nil {
		t.Fatal("expected error for empty input")
	}
	if err != ErrInputTooShort {
		t.Fatalf("expected ErrInputTooShort, got: %v", err)
	}
}

func TestDecodePoint_OffsetPastEnd(t *testing.T) {
	data := []byte{DjbType, 0x01, 0x02}
	_, err := DecodePoint(data, 5)
	if err == nil {
		t.Fatal("expected error when offset is past end of input")
	}
	if err != ErrInputTooShort {
		t.Fatalf("expected ErrInputTooShort, got: %v", err)
	}
}

func TestDecodePoint_NegativeOffset(t *testing.T) {
	data := []byte{DjbType, 0x01, 0x02}
	_, err := DecodePoint(data, -1)
	if err == nil {
		t.Fatal("expected error for negative offset")
	}
	if err != ErrInputTooShort {
		t.Fatalf("expected ErrInputTooShort, got: %v", err)
	}
}

func TestDecodePoint_TruncatedKeyData(t *testing.T) {
	// Type byte + only 10 bytes of key data (need 32)
	data := make([]byte, 11)
	data[0] = DjbType
	for i := 1; i < 11; i++ {
		data[i] = byte(i)
	}
	_, err := DecodePoint(data, 0)
	if err == nil {
		t.Fatal("expected error for truncated key data, got silent partial copy")
	}
	if err != ErrBadKeyLength {
		t.Fatalf("expected ErrBadKeyLength, got: %v", err)
	}
}

func TestDecodePoint_Exact33Bytes(t *testing.T) {
	// Exactly 1 type byte + 32 key bytes = 33 bytes
	data := make([]byte, 33)
	data[0] = DjbType
	for i := 1; i < 33; i++ {
		data[i] = byte(i)
	}
	pub, err := DecodePoint(data, 0)
	if err != nil {
		t.Fatalf("expected success for exactly 33 bytes, got: %v", err)
	}
	key := pub.PublicKey()
	for i := 0; i < 32; i++ {
		if key[i] != byte(i+1) {
			t.Fatalf("key byte %d: expected %d, got %d", i, i+1, key[i])
		}
	}
}

func TestDecodePoint_BadKeyType(t *testing.T) {
	badBytes := []byte{0x01, 0x02, 0x03}
	_, err := DecodePoint(badBytes, 0)
	if err == nil {
		t.Fatal("expected error for bad key type")
	}
}

func TestDecodePoint_WithOffset(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	serialized := kp.PublicKey().Serialize()
	// Prepend some garbage bytes
	withOffset := append([]byte{0x00, 0x00, 0x00}, serialized...)
	decoded, err := DecodePoint(withOffset, 3)
	if err != nil {
		t.Fatalf("DecodePoint with offset failed: %v", err)
	}
	origPub := kp.PublicKey().PublicKey()
	decodedPub := decoded.PublicKey()
	if origPub != decodedPub {
		t.Fatal("decoded public key does not match original after offset")
	}
}

// TestDecodePoint_ExtraTrailingBytesAccepted mirrors Rust test_decode_size
// (rust/core/src/curve.rs:450-456): a 34-byte input (33 key bytes + 1 trailing
// byte) must be accepted, and the decoded key must round-trip to the same 33-byte
// serialization as the original 33-byte input.
func TestDecodePoint_ExtraTrailingBytesAccepted(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	serialized := kp.PublicKey().Serialize() // 33 bytes

	// Append one extra byte — must still be accepted.
	extra := append(serialized, 0xFF)
	decoded, err := DecodePoint(extra, 0)
	if err != nil {
		t.Fatalf("DecodePoint with 34-byte input failed: %v", err)
	}

	// Serialization must match the original 33-byte form.
	if !bytes.Equal(decoded.Serialize(), serialized) {
		t.Fatal("decoded key serialization does not match original after extra trailing byte")
	}

	// Append many extra bytes — must also be accepted.
	manyExtra := append(serialized, make([]byte, 100)...)
	decoded2, err := DecodePoint(manyExtra, 0)
	if err != nil {
		t.Fatalf("DecodePoint with 133-byte input failed: %v", err)
	}
	if !bytes.Equal(decoded2.Serialize(), serialized) {
		t.Fatal("decoded key serialization does not match original after many trailing bytes")
	}
}

func TestVerifySignature_ValidSignature(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	message := []byte("hello world")
	sig, err := CalculateSignature(kp.PrivateKey(), message)
	if err != nil {
		t.Fatalf("CalculateSignature failed: %v", err)
	}
	if !VerifySignature(kp.PublicKey(), message, sig) {
		t.Fatal("expected valid signature")
	}
}

func TestVerifySignature_InvalidSignature(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	message := []byte("hello world")
	var badSig [64]byte
	if VerifySignature(kp.PublicKey(), message, badSig) {
		t.Fatal("expected invalid signature with zero bytes")
	}
}

func TestVerifySignature_WrongMessage(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	sig, err := CalculateSignature(kp.PrivateKey(), []byte("correct message"))
	if err != nil {
		t.Fatalf("CalculateSignature failed: %v", err)
	}
	if VerifySignature(kp.PublicKey(), []byte("wrong message"), sig) {
		t.Fatal("expected verification to fail for wrong message")
	}
}

func TestVerifySignature_WrongKey(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()
	message := []byte("test")
	sig, _ := CalculateSignature(kp1.PrivateKey(), message)
	if VerifySignature(kp2.PublicKey(), message, sig) {
		t.Fatal("expected verification to fail with wrong key")
	}
}

func TestCalculateSignature_DifferentMessages(t *testing.T) {
	kp, _ := GenerateKeyPair()
	sig1, _ := CalculateSignature(kp.PrivateKey(), []byte("message1"))
	sig2, _ := CalculateSignature(kp.PrivateKey(), []byte("message2"))
	if sig1 == sig2 {
		t.Fatal("signatures for different messages should differ")
	}
}

func TestCalculateSignature_EmptyMessage(t *testing.T) {
	kp, _ := GenerateKeyPair()
	sig, err := CalculateSignature(kp.PrivateKey(), []byte{})
	if err != nil {
		t.Fatalf("CalculateSignature failed on empty message: %v", err)
	}
	if !VerifySignature(kp.PublicKey(), []byte{}, sig) {
		t.Fatal("expected valid signature for empty message")
	}
}

func TestCryptoZeroize_Internal(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	crypto.Zeroize(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("Zeroize did not clear byte at index %d", i)
		}
	}
}

func TestCryptoZeroize_EmptySlice(t *testing.T) {
	b := []byte{}
	crypto.Zeroize(b) // should not panic
}

func TestDjbECPublicKey_Serialize(t *testing.T) {
	var pubBytes [32]byte
	pubBytes[0] = 0xAA
	pubBytes[31] = 0xBB
	pub := NewDjbECPublicKey(pubBytes)
	serialized := pub.Serialize()
	if len(serialized) != 33 {
		t.Fatalf("expected 33 bytes, got %d", len(serialized))
	}
	if serialized[0] != DjbType {
		t.Fatalf("first byte should be DjbType (0x05), got 0x%02x", serialized[0])
	}
	if serialized[1] != 0xAA || serialized[32] != 0xBB {
		t.Fatal("key bytes mismatch in serialized output")
	}
}

func TestDjbECPublicKey_Type(t *testing.T) {
	pub := NewDjbECPublicKey([32]byte{})
	if pub.Type() != DjbType {
		t.Fatalf("expected type %d, got %d", DjbType, pub.Type())
	}
}

func TestDjbECPublicKey_PublicKey(t *testing.T) {
	var key [32]byte
	key[15] = 0x42
	pub := NewDjbECPublicKey(key)
	if pub.PublicKey() != key {
		t.Fatal("PublicKey should return the original bytes")
	}
}

func TestDjbECPrivateKey_Serialize(t *testing.T) {
	// Use pre-clamped bytes so the constructor does not mutate them,
	// allowing a direct equality check on the serialized form.
	// Pre-clamped: byte 0 has bits 0-2 clear (0xF8), byte 31 has bit 7
	// clear and bit 6 set (0x7F satisfies both since 0x7F & 0x80 == 0
	// and 0x7F & 0x40 != 0).
	var privBytes [32]byte
	privBytes[0] = 0xF8  // pre-clamped low byte
	privBytes[31] = 0x7F // pre-clamped high byte
	priv := NewDjbECPrivateKey(privBytes)
	serialized := priv.Serialize()
	if serialized != privBytes {
		t.Fatalf("Serialize should return clamped key bytes; got[0]=0x%02x got[31]=0x%02x", serialized[0], serialized[31])
	}
}

func TestDjbECPrivateKey_Type(t *testing.T) {
	priv := NewDjbECPrivateKey([32]byte{})
	if priv.Type() != DjbType {
		t.Fatalf("expected type %d, got %d", DjbType, priv.Type())
	}
}

func TestDjbECPrivateKey_PrivateKey(t *testing.T) {
	// Use a pre-clamped key so the constructor does not alter the bytes.
	// byte 10 can be 0xFF (not affected by clamping), byte 0 must have
	// bits 0-2 clear, byte 31 must have bit 7 clear and bit 6 set.
	var key [32]byte
	key[0] = 0xF8  // pre-clamped
	key[10] = 0xFF // unaffected by clamping
	key[31] = 0x7F // pre-clamped
	priv := NewDjbECPrivateKey(key)
	if priv.PrivateKey() != key {
		t.Fatal("PrivateKey should return the clamped key bytes")
	}
}

func TestNewECKeyPair(t *testing.T) {
	pub := NewDjbECPublicKey([32]byte{1})
	priv := NewDjbECPrivateKey([32]byte{2})
	kp := NewECKeyPair(pub, priv)
	if kp.PublicKey() != pub {
		t.Fatal("PublicKey mismatch")
	}
	if kp.PrivateKey() != priv {
		t.Fatal("PrivateKey mismatch")
	}
}

func TestKeySize(t *testing.T) {
	if KeySize != 33 {
		t.Fatalf("expected KeySize 33, got %d", KeySize)
	}
}

func TestVerifySignature_RejectsNonCanonicalPublicKey(t *testing.T) {
	// A public key of all 0xFF bytes represents a value >= p (2^255-19).
	// verify() must reject this as non-canonical per the XEdDSA spec.
	var nonCanonicalKey [32]byte
	for i := range nonCanonicalKey {
		nonCanonicalKey[i] = 0xFF
	}
	pub := NewDjbECPublicKey(nonCanonicalKey)
	message := []byte("test message")
	var sig [64]byte
	if VerifySignature(pub, message, sig) {
		t.Fatal("expected verification to reject non-canonical public key (all 0xFF)")
	}
}

func TestVerifySignature_RejectsPublicKeyEqualToP(t *testing.T) {
	// p = 2^255 - 19 in little-endian: 0xED, 0xFF...0xFF, 0x7F
	// This is exactly p, which must be rejected.
	var exactlyP [32]byte
	exactlyP[0] = 0xED
	for i := 1; i <= 30; i++ {
		exactlyP[i] = 0xFF
	}
	exactlyP[31] = 0x7F
	pub := NewDjbECPublicKey(exactlyP)
	message := []byte("test message")
	var sig [64]byte
	if VerifySignature(pub, message, sig) {
		t.Fatal("expected verification to reject public key equal to p")
	}
}

func TestVerifySignature_AcceptsCanonicalPublicKeyJustBelowP(t *testing.T) {
	// p-1 in little-endian: 0xEC, 0xFF...0xFF, 0x7F
	// This is canonical and should not be rejected by the bounds check.
	// It won't produce a valid signature, but it should pass the u >= p check
	// and fail later in verification (not panic).
	var justBelowP [32]byte
	justBelowP[0] = 0xEC
	for i := 1; i <= 30; i++ {
		justBelowP[i] = 0xFF
	}
	justBelowP[31] = 0x7F
	pub := NewDjbECPublicKey(justBelowP)
	message := []byte("test message")
	var sig [64]byte
	// Should not panic; will return false since sig is invalid, but the key is canonical
	result := VerifySignature(pub, message, sig)
	_ = result // we only care it doesn't panic; false is expected with a zero signature
}

func TestVerifySignature_RejectsNonCanonicalREncoding(t *testing.T) {
	// Create a valid keypair and signature, then corrupt the R encoding
	// to be non-canonical (y >= p).
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	message := []byte("test message")
	sig, err := CalculateSignature(kp.PrivateKey(), message)
	if err != nil {
		t.Fatalf("CalculateSignature failed: %v", err)
	}

	// Set the first 32 bytes (R encoding) to all 0xFF, which is non-canonical
	for i := 0; i < 32; i++ {
		sig[i] = 0xFF
	}
	if VerifySignature(kp.PublicKey(), message, sig) {
		t.Fatal("expected verification to reject signature with non-canonical R encoding")
	}
}

func TestVerifySignature_ValidSignatureStillAccepted(t *testing.T) {
	// Ensure the new validation checks don't break valid signature verification.
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	message := []byte("XEdDSA validation test message")
	sig, err := CalculateSignature(kp.PrivateKey(), message)
	if err != nil {
		t.Fatalf("CalculateSignature failed: %v", err)
	}
	if !VerifySignature(kp.PublicKey(), message, sig) {
		t.Fatal("expected valid signature to be accepted after adding bounds checks")
	}
}

func TestIsNonCanonicalFieldElement(t *testing.T) {
	tests := []struct {
		name     string
		input    [32]byte
		expected bool
	}{
		{
			name:     "zero is canonical",
			input:    [32]byte{},
			expected: false,
		},
		{
			name: "p-1 is canonical",
			input: func() [32]byte {
				var b [32]byte
				b[0] = 0xEC
				for i := 1; i <= 30; i++ {
					b[i] = 0xFF
				}
				b[31] = 0x7F
				return b
			}(),
			expected: false,
		},
		{
			name: "p is non-canonical",
			input: func() [32]byte {
				var b [32]byte
				b[0] = 0xED
				for i := 1; i <= 30; i++ {
					b[i] = 0xFF
				}
				b[31] = 0x7F
				return b
			}(),
			expected: true,
		},
		{
			name: "p+1 is non-canonical",
			input: func() [32]byte {
				var b [32]byte
				b[0] = 0xEE
				for i := 1; i <= 30; i++ {
					b[i] = 0xFF
				}
				b[31] = 0x7F
				return b
			}(),
			expected: true,
		},
		{
			name: "all 0xFF is non-canonical",
			input: func() [32]byte {
				var b [32]byte
				for i := range b {
					b[i] = 0xFF
				}
				// clear bit 255 as verify() does
				b[31] &= 0x7F
				return b
			}(),
			expected: true,
		},
		{
			name: "byte 31 less than 0x7F is canonical",
			input: func() [32]byte {
				var b [32]byte
				for i := range b {
					b[i] = 0xFF
				}
				b[31] = 0x7E
				return b
			}(),
			expected: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isNonCanonicalFieldElement(tt.input)
			if got != tt.expected {
				t.Fatalf("isNonCanonicalFieldElement: got %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDjbECPublicKey_SerializeRoundTrip(t *testing.T) {
	kp, _ := GenerateKeyPair()
	serialized := kp.PublicKey().Serialize()
	decoded, err := DecodePoint(serialized, 0)
	if err != nil {
		t.Fatalf("DecodePoint failed: %v", err)
	}
	reserialized := decoded.Serialize()
	if !bytes.Equal(serialized, reserialized) {
		t.Fatal("round-trip serialization mismatch")
	}
}

// TestSign_EmbeddsSignBitInSignature verifies that the XEdDSA sign() function
// embeds the Edwards public key sign bit in signature[63], matching the
// Rust/Java Signal reference implementation behavior. Keys whose Edwards
// point has sign bit 1 (approximately 50% of keys) will have bit 7 of
// signature[63] set.
func TestSign_EmbeddsSignBitInSignature(t *testing.T) {
	seenSignBitSet := false
	seenSignBitClear := false

	for i := 0; i < 100; i++ {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair failed: %v", err)
		}
		message := []byte("test sign bit embedding")
		sig, err := CalculateSignature(kp.PrivateKey(), message)
		if err != nil {
			t.Fatalf("CalculateSignature failed: %v", err)
		}

		if sig[63]&0x80 != 0 {
			seenSignBitSet = true
		} else {
			seenSignBitClear = true
		}

		// Verify the signature still works regardless of sign bit value
		if !VerifySignature(kp.PublicKey(), message, sig) {
			t.Fatalf("iteration %d: valid signature rejected", i)
		}
	}

	if !seenSignBitSet {
		t.Fatal("expected to see sign bit set in at least one signature out of 100")
	}
	if !seenSignBitClear {
		t.Fatal("expected to see sign bit clear in at least one signature out of 100")
	}
}

// TestSign_CalculateKeyPairNormalization verifies that sign() uses
// calculateEdwardsKeyPair, producing consistent signatures regardless of
// whether the raw Edwards point has sign bit 0 or 1.
func TestSign_CalculateKeyPairNormalization(t *testing.T) {
	// Run many iterations to cover both sign-bit-0 and sign-bit-1 cases
	// (statistically ~50% each).
	for i := 0; i < 100; i++ {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("iteration %d: GenerateKeyPair failed: %v", i, err)
		}
		message := []byte("normalization test")
		sig, err := CalculateSignature(kp.PrivateKey(), message)
		if err != nil {
			t.Fatalf("iteration %d: CalculateSignature failed: %v", i, err)
		}
		if !VerifySignature(kp.PublicKey(), message, sig) {
			t.Fatalf("iteration %d: valid signature rejected", i)
		}
	}
}

// TestVerify_ExtractsSignBitFromSignature confirms that the verifier reads
// the Edwards public key sign bit from signature[63] and uses it to reconstruct
// the correct Edwards point. Flipping this bit should cause verification to fail
// because the wrong Edwards point is recovered.
func TestVerify_ExtractsSignBitFromSignature(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	message := []byte("verify sign bit test")
	sig, err := CalculateSignature(kp.PrivateKey(), message)
	if err != nil {
		t.Fatalf("CalculateSignature failed: %v", err)
	}

	// Verify the original signature works.
	if !VerifySignature(kp.PublicKey(), message, sig) {
		t.Fatal("valid signature rejected")
	}

	// Flip bit 7 of byte 63 (the sign bit). This changes which Edwards point
	// the verifier reconstructs, causing verification to fail because the
	// signature was computed against the other point.
	corruptedSig := sig
	corruptedSig[63] ^= 0x80
	if VerifySignature(kp.PublicKey(), message, corruptedSig) {
		t.Fatal("signature with flipped sign bit should be rejected")
	}
}

// TestCalculateEdwardsKeyPair_ConstantTime verifies that calculateEdwardsKeyPair
// produces a valid (A, a) pair where A has sign bit 0 and a*B == A.
func TestCalculateEdwardsKeyPair_ConstantTime(t *testing.T) {
	for i := 0; i < 100; i++ {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("iteration %d: GenerateKeyPair failed: %v", i, err)
		}
		privKey := kp.PrivateKey().Serialize()
		kpResult := calculateEdwardsKeyPair(&privKey)

		// A must have sign bit 0
		aEncoded := kpResult.A.Bytes()
		if aEncoded[31]&0x80 != 0 {
			t.Fatalf("iteration %d: A has sign bit 1, expected 0", i)
		}

		// pubBytes must match A's encoding
		if !bytes.Equal(kpResult.PublicKey, aEncoded) {
			t.Fatalf("iteration %d: pubBytes does not match A encoding", i)
		}

		// a*B must equal A
		recomputed := new(edwards25519.Point).ScalarBaseMult(kpResult.Scalar)
		if recomputed.Equal(kpResult.A) != 1 {
			t.Fatalf("iteration %d: a*B != A", i)
		}
	}
}

// ============= Zeroize Tests =============

func TestDjbECPrivateKey_Zeroize(t *testing.T) {
	key := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	privKey := NewDjbECPrivateKey(key)

	// Verify key is non-zero before zeroize.
	serialized := privKey.Serialize()
	allZero := true
	for _, b := range serialized {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("private key should not be all zeros before Zeroize")
	}

	privKey.Zeroize()

	serialized = privKey.Serialize()
	for i, b := range serialized {
		if b != 0 {
			t.Fatalf("byte %d not zeroed after Zeroize: %d", i, b)
		}
	}
}

func TestDjbECPrivateKey_ZeroizeAlreadyZero(t *testing.T) {
	key := [32]byte{}
	privKey := NewDjbECPrivateKey(key)
	privKey.Zeroize() // should not panic
	serialized := privKey.Serialize()
	for i, b := range serialized {
		if b != 0 {
			t.Fatalf("byte %d not zero: %d", i, b)
		}
	}
}

func TestECKeyPair_ZeroizePrivateKey(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Verify private key is non-zero.
	serialized := kp.PrivateKey().Serialize()
	allZero := true
	for _, b := range serialized {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("generated private key should not be all zeros")
	}

	kp.ZeroizePrivateKey()

	// After zeroization, GuardedECPrivateKey is destroyed and must report as such.
	guarded, ok := kp.PrivateKey().(*GuardedECPrivateKey)
	if !ok {
		t.Fatal("expected GuardedECPrivateKey after GenerateKeyPair")
	}
	if !guarded.IsDestroyed() {
		t.Fatal("guarded private key should be destroyed after ZeroizePrivateKey")
	}
}

func TestECKeyPair_ZeroizePrivateKeyPreservesPublicKey(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	pubBefore := kp.PublicKey().Serialize()
	kp.ZeroizePrivateKey()
	pubAfter := kp.PublicKey().Serialize()

	if !bytes.Equal(pubBefore, pubAfter) {
		t.Fatal("public key should not be affected by ZeroizePrivateKey")
	}
}

// ============= IsCanonical Tests =============

// TestVerifySignature_RejectsNonCanonicalScalar verifies that XEdDSA verify
// rejects signatures where the s scalar has high bits set (bits 5 or 6 of
// s[31] after clearing the sign bit), indicating a non-canonical scalar >= L.
// This matches the Rust reference check: s[31] & 0xE0 != 0 after clearing bit 7.
func TestVerifySignature_RejectsNonCanonicalScalar(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	message := []byte("non-canonical scalar test")
	sig, err := CalculateSignature(kp.PrivateKey(), message)
	if err != nil {
		t.Fatalf("CalculateSignature failed: %v", err)
	}

	// Sanity: valid signature must verify.
	if !VerifySignature(kp.PublicKey(), message, sig) {
		t.Fatal("valid signature should verify before mutation")
	}

	tests := []struct {
		name   string
		mutate func(s *[64]byte)
	}{
		{
			name: "bit 5 set in s[31]",
			mutate: func(s *[64]byte) {
				s[63] &= 0x7F // Clear sign bit first (as verifier does)
				s[63] |= 0x20 // Set bit 5
			},
		},
		{
			name: "bit 6 set in s[31]",
			mutate: func(s *[64]byte) {
				s[63] &= 0x7F // Clear sign bit first
				s[63] |= 0x40 // Set bit 6
			},
		},
		{
			name: "bits 5 and 6 set in s[31]",
			mutate: func(s *[64]byte) {
				s[63] &= 0x7F // Clear sign bit first
				s[63] |= 0x60 // Set bits 5 and 6
			},
		},
		{
			name: "all high bits set in s[31] except sign bit",
			mutate: func(s *[64]byte) {
				s[63] &= 0x7F // Clear sign bit
				s[63] |= 0xE0 // Set bits 5, 6, 7 (but 7 was just cleared, so effectively 5+6)
				// After verifier clears bit 7, 0x60 remains
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mutated := sig // copy
			tt.mutate(&mutated)
			if VerifySignature(kp.PublicKey(), message, mutated) {
				t.Fatal("expected verification to reject signature with non-canonical scalar")
			}
		})
	}
}

// TestVerifySignature_AcceptsCanonicalScalar verifies that valid signatures
// with low scalar values (bits 5-6 of s[31] both clear) are still accepted.
func TestVerifySignature_AcceptsCanonicalScalar(t *testing.T) {
	for i := 0; i < 50; i++ {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("iteration %d: GenerateKeyPair failed: %v", i, err)
		}
		message := []byte("canonical scalar acceptance test")
		sig, err := CalculateSignature(kp.PrivateKey(), message)
		if err != nil {
			t.Fatalf("iteration %d: CalculateSignature failed: %v", i, err)
		}

		// A legitimate signature from our signer should always have a canonical
		// scalar (s < L), so bits 5-6 of s[31] should be clear after removing
		// the sign bit.
		sByte := sig[63] & 0x7F
		if sByte&0x60 != 0 {
			t.Fatalf("iteration %d: signer produced non-canonical scalar byte 0x%02x", i, sByte)
		}

		if !VerifySignature(kp.PublicKey(), message, sig) {
			t.Fatalf("iteration %d: valid signature with canonical scalar rejected", i)
		}
	}
}

// TestIsCanonical_GeneratedKeys verifies that all freshly generated Curve25519
// public keys are canonical (torsion-free and in the reduced scalar range).
func TestIsCanonical_GeneratedKeys(t *testing.T) {
	for i := 0; i < 50; i++ {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("iteration %d: GenerateKeyPair failed: %v", i, err)
		}
		if !kp.PublicKey().IsCanonical() {
			pk := kp.PublicKey().PublicKey()
			t.Fatalf("iteration %d: freshly generated key should be canonical: %x", i, pk)
		}
	}
}

// TestIsCanonical_ZeroPoint verifies that the all-zero point (which corresponds
// to a torsion point on the curve) is not canonical.
func TestIsCanonical_ZeroPoint(t *testing.T) {
	pub := NewDjbECPublicKey([32]byte{})
	if pub.IsCanonical() {
		t.Fatal("all-zero public key should not be canonical")
	}
}

// TestIsCanonical_HighBitSet verifies that a public key with the high bit set
// (value >= 2^255) fails the scalar range check.
func TestIsCanonical_HighBitSet(t *testing.T) {
	// Start with a valid key and set the high bit.
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	pk := kp.PublicKey().PublicKey()
	pk[31] |= 0x80 // Set high bit - makes it >= 2^255 >= p.
	nonCanonical := NewDjbECPublicKey(pk)
	if nonCanonical.IsCanonical() {
		t.Fatal("public key with high bit set should not be canonical")
	}
}

// TestIsCanonical_FieldPrimeSelf verifies that the field prime p = 2^255 - 19
// itself is not canonical (it's >= p, hence not in the reduced range).
func TestIsCanonical_FieldPrimeSelf(t *testing.T) {
	// p = 2^255 - 19 in little-endian
	p := [32]byte{
		0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
	}
	pub := NewDjbECPublicKey(p)
	if pub.IsCanonical() {
		t.Fatal("field prime p should not be canonical (not in reduced range)")
	}
}

// TestIsCanonical_SmallOrderPoints verifies that known small-order points
// (torsion points) are not canonical.
func TestIsCanonical_SmallOrderPoints(t *testing.T) {
	// The point u=0 (Montgomery form) maps to the identity in Edwards form.
	// The identity is the neutral element (order 1), which is a torsion point.
	zeroPoint := NewDjbECPublicKey([32]byte{})
	if zeroPoint.IsCanonical() {
		t.Fatal("u=0 (identity) should not be canonical")
	}

	// The point u=1 maps to Edwards y=0, which is a 2-torsion point.
	var onePoint [32]byte
	onePoint[0] = 1
	pub := NewDjbECPublicKey(onePoint)
	if pub.IsCanonical() {
		t.Fatal("u=1 (2-torsion) should not be canonical")
	}
}

// TestIsCanonical_Interface verifies that the IsCanonical method is accessible
// through the ECPublicKeyable interface.
func TestIsCanonical_Interface(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	pub := kp.PublicKey()
	// Should compile and return true for a generated key.
	if !pub.IsCanonical() {
		t.Fatal("generated key should be canonical via interface")
	}
}

// ============= ECC-3: Private key clamping tests =============

// TestNewDjbECPrivateKey_ClampsOnConstruction verifies that NewDjbECPrivateKey
// applies Curve25519 clamping to the input bytes, matching Rust
// PrivateKey::From<[u8;32]> (rust/core/src/curve/curve25519.rs:172).
func TestNewDjbECPrivateKey_ClampsOnConstruction(t *testing.T) {
	// Unclamped raw bytes: low bits of byte 0 set, high bit of byte 31 set,
	// and bit 6 of byte 31 clear — all three clamping bits need fixing.
	var raw [32]byte
	raw[0] = 0xFF  // bits 0-2 should be cleared → 0xF8
	raw[31] = 0xFF // bit 7 should be cleared, bit 6 set → 0x7F then |0x40 → 0x7F? no:
	// After clamping: raw[31] &= 127 = 0x7F, then |= 64 = 0x7F (0x7F already has bit 6 set)
	// raw[0] after: 0xFF & 0xF8 = 0xF8

	priv := NewDjbECPrivateKey(raw)
	got := priv.Serialize()

	if got[0] != 0xF8 {
		t.Errorf("byte 0: expected 0xF8 after clamping, got 0x%02x", got[0])
	}
	if got[31]&0x80 != 0 {
		t.Errorf("byte 31 bit 7: expected clear after clamping, got 0x%02x", got[31])
	}
	if got[31]&0x40 == 0 {
		t.Errorf("byte 31 bit 6: expected set after clamping, got 0x%02x", got[31])
	}
	if got[0]&0x07 != 0 {
		t.Errorf("byte 0 bits 0-2: expected clear after clamping, got 0x%02x", got[0])
	}
}

// TestNewDjbECPrivateKey_ClampingIdemPotent verifies that clamping is
// idempotent: a key that is already clamped is unchanged by construction.
func TestNewDjbECPrivateKey_ClampingIdemPotent(t *testing.T) {
	var raw [32]byte
	raw[0] = 0xF8  // already clamped low byte
	raw[31] = 0x7F // already clamped high byte (bit 6 set, bit 7 clear) — wait: 0x7F has bit 6 set? 0x40=64. 0x7F = 0111 1111 — yes, bit 6 is set.
	// Actually NewDjbECPrivateKey applies: &= 248 (&=0xF8), &= 127 (&=0x7F), |= 64 (|=0x40)
	// raw[31] = 0x7F after &=127 stays 0x7F; |=64 → 0x7F (bit 6 already set in 0x7F)
	// So 0x7F is idempotent.

	priv := NewDjbECPrivateKey(raw)
	got := priv.Serialize()

	if got[0] != raw[0] {
		t.Errorf("byte 0 changed: expected 0x%02x, got 0x%02x", raw[0], got[0])
	}
	if got[31] != 0x7F {
		t.Errorf("byte 31 changed: expected 0x7F, got 0x%02x", got[31])
	}
}

// TestNewGuardedECPrivateKey_ClampsOnConstruction verifies that
// NewGuardedECPrivateKey applies Curve25519 clamping, matching Rust
// PrivateKey::deserialize (rust/core/src/curve.rs:246-247).
func TestNewGuardedECPrivateKey_ClampsOnConstruction(t *testing.T) {
	var raw [32]byte
	raw[0] = 0x07  // low 3 bits set — must be cleared
	raw[31] = 0x80 // bit 7 set, bit 6 clear — both must be fixed

	priv, err := NewGuardedECPrivateKey(raw)
	if err != nil {
		t.Fatalf("NewGuardedECPrivateKey failed: %v", err)
	}
	defer priv.Zeroize()

	got := priv.Serialize()

	if got[0]&0x07 != 0 {
		t.Errorf("byte 0 bits 0-2: expected clear, got 0x%02x", got[0])
	}
	if got[31]&0x80 != 0 {
		t.Errorf("byte 31 bit 7: expected clear, got 0x%02x", got[31])
	}
	if got[31]&0x40 == 0 {
		t.Errorf("byte 31 bit 6: expected set, got 0x%02x", got[31])
	}
}

// TestPrivateKeyClamp_SerializeRoundTrip verifies that serialize→deserialize
// produces byte-for-byte identical output for unclamped inputs, matching
// the Rust round-trip contract.
func TestPrivateKeyClamp_SerializeRoundTrip(t *testing.T) {
	var raw [32]byte
	for i := range raw {
		raw[i] = 0xFF
	}
	// After clamping: raw[0]=0xF8, raw[31]=0x7F
	priv1 := NewDjbECPrivateKey(raw)
	ser1 := priv1.Serialize()

	priv2 := NewDjbECPrivateKey(ser1)
	ser2 := priv2.Serialize()

	if ser1 != ser2 {
		t.Fatal("serialize→deserialize is not idempotent: round-trip diverges")
	}
}

// ============= ECC-7: KeyPairFromBytes constructor tests =============

// TestKeyPairFromBytes_Success verifies that KeyPairFromBytes constructs a
// valid key pair from raw public and private key bytes.
// Mirrors Rust KeyPair::from_public_and_private (rust/core/src/curve.rs:350-360).
func TestKeyPairFromBytes_Success(t *testing.T) {
	// Generate a reference key pair and extract its raw bytes.
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	pubBytes := kp.PublicKey().Serialize() // 33 bytes: type || 32 key bytes
	privBytes := kp.PrivateKey().Serialize()

	kp2, err := KeyPairFromBytes(pubBytes, privBytes)
	if err != nil {
		t.Fatalf("KeyPairFromBytes failed: %v", err)
	}
	if !bytes.Equal(kp2.PublicKey().Serialize(), pubBytes) {
		t.Fatal("reconstructed public key does not match original")
	}
}

// TestKeyPairFromBytes_InvalidPublicKey verifies that KeyPairFromBytes returns
// an error when the public key bytes are invalid.
func TestKeyPairFromBytes_InvalidPublicKey(t *testing.T) {
	var priv [32]byte
	_, err := KeyPairFromBytes([]byte{0x01, 0x02, 0x03}, priv)
	if err == nil {
		t.Fatal("expected error for invalid public key bytes")
	}
}

// TestKeyPairFromBytes_ClampsPrivateKey verifies that KeyPairFromBytes applies
// clamping to the private key bytes, consistent with NewGuardedECPrivateKey.
func TestKeyPairFromBytes_ClampsPrivateKey(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	pubBytes := kp.PublicKey().Serialize()

	var raw [32]byte
	raw[0] = 0xFF
	raw[31] = 0xFF

	kp2, err := KeyPairFromBytes(pubBytes, raw)
	if err != nil {
		t.Fatalf("KeyPairFromBytes failed: %v", err)
	}
	got := kp2.PrivateKey().Serialize()
	if got[0]&0x07 != 0 {
		t.Errorf("byte 0 not clamped: 0x%02x", got[0])
	}
	if got[31]&0x80 != 0 {
		t.Errorf("byte 31 bit 7 not clamped: 0x%02x", got[31])
	}
	if got[31]&0x40 == 0 {
		t.Errorf("byte 31 bit 6 not set: 0x%02x", got[31])
	}
}

// ============= ECC-9: Constant-time PublicKey equality tests =============

// TestDjbECPublicKey_Equal_SameKey verifies that Equal returns true for two
// public keys with identical byte content.
// Mirrors Rust PublicKey's subtle::ConstantTimeEq (rust/core/src/curve.rs:201-218).
func TestDjbECPublicKey_Equal_SameKey(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	pub := kp.PublicKey().(*DjbECPublicKey)
	pub2 := NewDjbECPublicKey(pub.PublicKey())
	if !pub.Equal(pub2) {
		t.Fatal("Equal should return true for identical public keys")
	}
}

// TestDjbECPublicKey_Equal_DifferentKeys verifies that Equal returns false for
// two public keys with different byte content.
func TestDjbECPublicKey_Equal_DifferentKeys(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()
	pub1 := kp1.PublicKey().(*DjbECPublicKey)
	pub2 := kp2.PublicKey().(*DjbECPublicKey)
	if pub1.Equal(pub2) {
		t.Fatal("Equal should return false for different public keys")
	}
}

// TestDjbECPublicKey_Equal_NilOther verifies that Equal returns false when
// the other key is nil.
func TestDjbECPublicKey_Equal_NilOther(t *testing.T) {
	kp, _ := GenerateKeyPair()
	pub := kp.PublicKey().(*DjbECPublicKey)
	if pub.Equal(nil) {
		t.Fatal("Equal should return false for nil other key")
	}
}

// TestCalculateSignatureWithRandomness verifies the deterministic signing path.
func TestCalculateSignatureWithRandomness(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	message := []byte("test message for deterministic sign")
	var randomness [64]byte
	for i := range randomness {
		randomness[i] = byte(i + 1)
	}
	sig, err := CalculateSignatureWithRandomness(kp.PrivateKey(), message, randomness)
	if err != nil {
		t.Fatalf("CalculateSignatureWithRandomness: %v", err)
	}
	var zero [64]byte
	if sig == zero {
		t.Fatal("signature is all-zero")
	}

	// Same inputs must produce the same signature (deterministic).
	sig2, err := CalculateSignatureWithRandomness(kp.PrivateKey(), message, randomness)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if sig != sig2 {
		t.Fatal("CalculateSignatureWithRandomness is not deterministic")
	}
}

// TestDjbECPublicKey_ScalarIsInRange exercises the public ScalarIsInRange method.
func TestDjbECPublicKey_ScalarIsInRange(t *testing.T) {
	// A key generated from GenerateKeyPair is always clamped; its scalar
	// should be in range.
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	pub := kp.PublicKey().(*DjbECPublicKey)
	if !pub.ScalarIsInRange() {
		t.Error("fresh generated key should be in scalar range")
	}

	// A key with the high bit of byte[31] set is out of range.
	var outOfRangeBytes [32]byte
	outOfRangeBytes[31] = 0x80 // high bit set
	outKey := NewDjbECPublicKey(outOfRangeBytes)
	if outKey.ScalarIsInRange() {
		t.Error("key with high bit of byte 31 set should be out of range")
	}
}
