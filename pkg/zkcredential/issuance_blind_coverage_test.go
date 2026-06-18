package zkcredential

import (
	"testing"
)

// TestBlindedIssuanceSerializationRoundTrip exercises the
// encode/decode serialization paths for BlindedIssuanceProof that
// are not covered by the existing test suite.
func TestBlindedIssuanceSerializationRoundTrip(t *testing.T) {
	var serverRandomness [RandomnessLen]byte
	for i := range serverRandomness {
		serverRandomness[i] = 0x60
	}
	var clientRandomness [RandomnessLen]byte
	for i := range clientRandomness {
		clientRandomness[i] = 0x61
	}
	var issueRandomness [RandomnessLen]byte
	for i := range issueRandomness {
		issueRandomness[i] = 0x62
	}

	label := []byte("TestBlindedIssuanceSerial_20231011")
	credKeyPair := GenerateCredentialKeyPair(serverRandomness)

	blindingSHO := NewShoHmacSha256Ext("TestBlindedIssuanceSerial_Blinding")
	blindingSHO.AbsorbAndRatchet(clientRandomness[:])
	blindingKP, err := GenerateBlindingKeyPair(blindingSHO)
	if err != nil {
		t.Fatalf("GenerateBlindingKeyPair: %v", err)
	}

	// Use AddBlindedAttribute (two-point attribute) to exercise that code path.
	nonceSHO := NewShoHmacSha256Ext("TestBlindedIssuanceSerial_Nonce")
	nonceSHO.AbsorbAndRatchet(clientRandomness[:])

	point := NewShoSha256Ext("test_serial_room").MustGetPoint()
	bp0, err := blindingKP.Blind(&PointAttribute{Point: point}, nonceSHO)
	if err != nil {
		t.Fatalf("Blind[0]: %v", err)
	}
	bp1, err := blindingKP.Blind(&PointAttribute{Point: point}, nonceSHO)
	if err != nil {
		t.Fatalf("Blind[1]: %v", err)
	}

	blindedAttr := &BlindedAttribute{BlindedPoints: [2]*BlindedPoint{bp0, bp1}}
	blindedAttrNoNonce := blindedAttr.StripNonce()

	issuanceBuilder := NewIssuanceProofBuilder(label)
	blindedBuilder := NewBlindedIssuanceProofBuilder(issuanceBuilder)
	if err := blindedBuilder.AddBlindedAttribute(blindedAttrNoNonce); err != nil {
		t.Fatalf("AddBlindedAttribute: %v", err)
	}
	blindedProof, err := blindedBuilder.Issue(credKeyPair, blindingKP.PubKey, issueRandomness)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	t.Run("simple_encode_decode_round_trip", func(t *testing.T) {
		encoded := EncodeBlindedIssuanceProof(blindedProof)
		if len(encoded) == 0 {
			t.Fatal("EncodeBlindedIssuanceProof returned empty bytes")
		}
		decoded, err := DecodeBlindedIssuanceProof(encoded)
		if err != nil {
			t.Fatalf("DecodeBlindedIssuanceProof: %v", err)
		}
		if decoded.Credential.T.Equal(blindedProof.Credential.T) != 1 {
			t.Fatal("T mismatch after round-trip")
		}
	})

	t.Run("bincode_encode_decode_round_trip", func(t *testing.T) {
		bincoded := EncodeBlindedIssuanceProofBincode(blindedProof)
		if len(bincoded) == 0 {
			t.Fatal("EncodeBlindedIssuanceProofBincode returned empty bytes")
		}
		decodedBincode, off, err := DecodeBlindedIssuanceProofBincode(bincoded)
		if err != nil {
			t.Fatalf("DecodeBlindedIssuanceProofBincode: %v", err)
		}
		if off != len(bincoded) {
			t.Fatalf("consumed %d bytes, want %d", off, len(bincoded))
		}
		if decodedBincode.Credential.T.Equal(blindedProof.Credential.T) != 1 {
			t.Fatal("T mismatch after bincode round-trip")
		}
	})

	t.Run("simple_decode_too_short", func(t *testing.T) {
		if _, err := DecodeBlindedIssuanceProof([]byte{0x01, 0x02}); err == nil {
			t.Fatal("expected error for too-short input")
		}
	})

	t.Run("bincode_decode_too_short", func(t *testing.T) {
		if _, _, err := DecodeBlindedIssuanceProofBincode([]byte{0x01}); err == nil {
			t.Fatal("expected error for too-short bincode input")
		}
	})
}

// TestBlindedIssuanceVerify_InvalidProof exercises the Verify error path.
func TestBlindedIssuanceVerify_InvalidProof(t *testing.T) {
	var serverRandomness [RandomnessLen]byte
	for i := range serverRandomness {
		serverRandomness[i] = 0x70
	}
	var clientRandomness [RandomnessLen]byte
	for i := range clientRandomness {
		clientRandomness[i] = 0x71
	}
	var issueRandomness [RandomnessLen]byte
	for i := range issueRandomness {
		issueRandomness[i] = 0x72
	}

	label := []byte("TestBlindedIssuanceVerifyInvalid_20231011")
	credKeyPair := GenerateCredentialKeyPair(serverRandomness)

	blindingSHO := NewShoHmacSha256Ext("TestBlindedIssuanceVerifyInvalid_Blinding")
	blindingSHO.AbsorbAndRatchet(clientRandomness[:])
	blindingKP, err := GenerateBlindingKeyPair(blindingSHO)
	if err != nil {
		t.Fatalf("GenerateBlindingKeyPair: %v", err)
	}

	nonceSHO := NewShoHmacSha256Ext("TestBlindedIssuanceVerifyInvalid_Nonce")
	nonceSHO.AbsorbAndRatchet(clientRandomness[:])
	point := NewShoSha256Ext("room_invalid").MustGetPoint()
	blindedPoint, err := blindingKP.Blind(&PointAttribute{Point: point}, nonceSHO)
	if err != nil {
		t.Fatalf("Blind: %v", err)
	}
	blindedPointNoNonce := blindedPoint.StripNonce()

	issuanceBuilder := NewIssuanceProofBuilder(label)
	blindedBuilder := NewBlindedIssuanceProofBuilder(issuanceBuilder)
	if err := blindedBuilder.AddBlindedRevealedAttribute(blindedPointNoNonce); err != nil {
		t.Fatalf("AddBlindedRevealedAttribute: %v", err)
	}
	blindedProof, err := blindedBuilder.Issue(credKeyPair, blindingKP.PubKey, issueRandomness)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Corrupt the proof to trigger verification failure.
	if len(blindedProof.PokshoProof) > 0 {
		blindedProof.PokshoProof[0] ^= 0xFF
	}

	verifyBuilder := NewIssuanceProofBuilder(label)
	verifyBlindedBuilder := NewBlindedIssuanceProofBuilder(verifyBuilder)
	if err := verifyBlindedBuilder.AddBlindedRevealedAttribute(blindedPointNoNonce); err != nil {
		t.Fatalf("AddBlindedRevealedAttribute (verify): %v", err)
	}
	_, err = verifyBlindedBuilder.Verify(credKeyPair.PublicKey(), blindingKP, blindedProof)
	if err == nil {
		t.Fatal("expected verification failure for corrupted proof")
	}
}
