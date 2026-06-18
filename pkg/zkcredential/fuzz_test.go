package zkcredential

import (
	"testing"
)

// FuzzDecodePresentationProofBincode verifies that DecodePresentationProofBincode
// never panics on arbitrary input. Seed corpus is a valid round-tripped encoding
// derived from the same deterministic inputs used in existing coverage tests.
//
// Matches the u64-LE length prefix protection added to address integer-overflow
// / unbounded-alloc on attacker-controlled wire lengths (Rust bincode
// reject_trailing_bytes + bounded-alloc invariant).
func FuzzDecodePresentationProofBincode(f *testing.F) {
	// Seed: generate a real PresentationProof and encode it.
	var keyRand [RandomnessLen]byte
	var issueRand [RandomnessLen]byte
	var presentRand [RandomnessLen]byte
	for i := range keyRand {
		keyRand[i] = 0x80
		issueRand[i] = 0x81
		presentRand[i] = 0x82
	}

	label := []byte("FuzzDecodePresentationProof_20240101")
	credKP := GenerateCredentialKeyPair(keyRand)

	attrSHO := NewShoSha256Ext("Fuzz_Attr")
	attr := PointPairAttribute{attrSHO.MustGetPoint(), attrSHO.MustGetPoint()}

	domain := newTestDomain("Fuzz_Domain")
	keySHO := NewShoHmacSha256Ext("Fuzz_Key")
	kp, err := DeriveKeyPair(keySHO, domain)
	if err != nil {
		f.Fatalf("DeriveKeyPair: %v", err)
	}

	issuanceBuilder := NewIssuanceProofBuilder(label)
	if err := issuanceBuilder.AddAttribute(attr); err != nil {
		f.Fatalf("AddAttribute: %v", err)
	}
	proof, err := issuanceBuilder.Issue(credKP, issueRand)
	if err != nil {
		f.Fatalf("Issue: %v", err)
	}
	verifyBuilder := NewIssuanceProofBuilder(label)
	if err := verifyBuilder.AddAttribute(attr); err != nil {
		f.Fatalf("AddAttribute(verify): %v", err)
	}
	cred, err := verifyBuilder.Verify(credKP.PublicKey(), proof)
	if err != nil {
		f.Fatalf("Verify: %v", err)
	}

	ct := kp.Encrypt(attr)
	presentBuilder := NewPresentationProofBuilder(label)
	presentBuilder.AddAttribute(ct, kp)
	presentProof, err := presentBuilder.Present(credKP.PublicKey(), cred, presentRand)
	if err != nil {
		f.Fatalf("Present: %v", err)
	}

	validSeed := EncodePresentationProofBincode(presentProof)
	f.Add(validSeed)

	// Additional seeds: empty, minimal, large-length-prefix attack vectors.
	f.Add([]byte{})
	f.Add([]byte{0x01, 0x02, 0x03})
	// Large u64 length (potential overflow attack): 0xFF bytes in length field.
	largeLen := make([]byte, 96+8)
	for i := 96; i < 104; i++ {
		largeLen[i] = 0xFF
	}
	f.Add(largeLen)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic; error return is fine.
		_, _, _ = DecodePresentationProofBincode(data)
	})
}

// FuzzDecodeBlindedIssuanceProofBincode verifies that
// DecodeBlindedIssuanceProofBincode never panics on arbitrary input.
func FuzzDecodeBlindedIssuanceProofBincode(f *testing.F) {
	// Seed: generate a valid BlindedIssuanceProof and encode it.
	var serverRand [RandomnessLen]byte
	var clientRand [RandomnessLen]byte
	var issueRand [RandomnessLen]byte
	for i := range serverRand {
		serverRand[i] = 0x60
		clientRand[i] = 0x61
		issueRand[i] = 0x62
	}

	label := []byte("FuzzBlindedIssuance_20240101")
	credKP := GenerateCredentialKeyPair(serverRand)

	blindingSHO := NewShoHmacSha256Ext("Fuzz_BlindingKey")
	blindingSHO.AbsorbAndRatchet(clientRand[:])
	blindingKP, err := GenerateBlindingKeyPair(blindingSHO)
	if err != nil {
		f.Fatalf("GenerateBlindingKeyPair: %v", err)
	}

	nonceSHO := NewShoHmacSha256Ext("Fuzz_Nonce")
	nonceSHO.AbsorbAndRatchet(clientRand[:])
	point := NewShoSha256Ext("fuzz_room").MustGetPoint()
	bp0, err := blindingKP.Blind(&PointAttribute{Point: point}, nonceSHO)
	if err != nil {
		f.Fatalf("Blind[0]: %v", err)
	}
	bp1, err := blindingKP.Blind(&PointAttribute{Point: point}, nonceSHO)
	if err != nil {
		f.Fatalf("Blind[1]: %v", err)
	}

	blindedAttr := &BlindedAttribute{BlindedPoints: [2]*BlindedPoint{bp0, bp1}}
	issuanceBuilder := NewIssuanceProofBuilder(label)
	blindedBuilder := NewBlindedIssuanceProofBuilder(issuanceBuilder)
	if err := blindedBuilder.AddBlindedAttribute(blindedAttr.StripNonce()); err != nil {
		f.Fatalf("AddBlindedAttribute: %v", err)
	}
	blindedProof, err := blindedBuilder.Issue(credKP, blindingKP.PubKey, issueRand)
	if err != nil {
		f.Fatalf("Issue: %v", err)
	}

	f.Add(EncodeBlindedIssuanceProofBincode(blindedProof))
	f.Add([]byte{})
	f.Add([]byte{0x01, 0x02})
	// Large u64 attack vector after 128-byte credential.
	largeLen := make([]byte, 136)
	for i := 128; i < 136; i++ {
		largeLen[i] = 0xFF
	}
	f.Add(largeLen)

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = DecodeBlindedIssuanceProofBincode(data)
	})
}
