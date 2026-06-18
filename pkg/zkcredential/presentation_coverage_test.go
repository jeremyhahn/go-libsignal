package zkcredential

import (
	"strings"
	"testing"
)

// TestEncodePresentationProofBincode_RoundTrip exercises the bincode
// serialization path for PresentationProof.
func TestEncodePresentationProofBincode_RoundTrip(t *testing.T) {
	var keyRandomness [RandomnessLen]byte
	for i := range keyRandomness {
		keyRandomness[i] = 0x80
	}
	var issueRandomness [RandomnessLen]byte
	for i := range issueRandomness {
		issueRandomness[i] = 0x81
	}
	var presentRandomness [RandomnessLen]byte
	for i := range presentRandomness {
		presentRandomness[i] = 0x82
	}

	label := []byte("TestPresentationBincode_20231011")
	credKeyPair := GenerateCredentialKeyPair(keyRandomness)

	attrSHO := NewShoSha256Ext("TestPresentationBincode_Attr")
	attr := PointPairAttribute{attrSHO.MustGetPoint(), attrSHO.MustGetPoint()}

	domain := newTestDomain("TestPresentationBincode_Domain")
	keySHO := NewShoHmacSha256Ext("TestPresentationBincode_Key")
	kp, err := DeriveKeyPair(keySHO, domain)
	if err != nil {
		t.Fatalf("DeriveKeyPair: %v", err)
	}

	// Issue a credential.
	issuanceBuilder := NewIssuanceProofBuilder(label)
	if err := issuanceBuilder.AddAttribute(attr); err != nil {
		t.Fatalf("AddAttribute: %v", err)
	}
	proof, err := issuanceBuilder.Issue(credKeyPair, issueRandomness)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	verifyBuilder := NewIssuanceProofBuilder(label)
	if err := verifyBuilder.AddAttribute(attr); err != nil {
		t.Fatalf("AddAttribute: %v", err)
	}
	cred, err := verifyBuilder.Verify(credKeyPair.PublicKey(), proof)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Build presentation proof.
	ct := kp.Encrypt(attr)
	presentBuilder := NewPresentationProofBuilder(label)
	presentBuilder.AddAttribute(ct, kp)
	presentProof, err := presentBuilder.Present(credKeyPair.PublicKey(), cred, presentRandomness)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}

	t.Run("bincode_round_trip", func(t *testing.T) {
		encoded := EncodePresentationProofBincode(presentProof)
		if len(encoded) == 0 {
			t.Fatal("EncodePresentationProofBincode returned empty bytes")
		}
		decoded, off, err := DecodePresentationProofBincode(encoded)
		if err != nil {
			t.Fatalf("DecodePresentationProofBincode: %v", err)
		}
		if off != len(encoded) {
			t.Fatalf("consumed %d bytes, want %d", off, len(encoded))
		}
		if decoded.Commitments.Cx0.Equal(presentProof.Commitments.Cx0) != 1 {
			t.Fatal("Cx0 mismatch after bincode round-trip")
		}
	})

	t.Run("bincode_decode_too_short", func(t *testing.T) {
		if _, _, err := DecodePresentationProofBincode([]byte{0x01}); err == nil {
			t.Fatal("expected error for too-short bincode input")
		}
	})

	t.Run("bincode_decode_truncated_cy", func(t *testing.T) {
		// Build a header with valid Cx0/Cx1/CV but a large Cy count
		// that exceeds the remaining data.
		buf := make([]byte, 96+8) // 3 points + 8-byte count
		buf[96] = 255             // Cy vec length = very large
		if _, _, err := DecodePresentationProofBincode(buf); err == nil {
			t.Fatal("expected error for truncated Cy data")
		}
	})
}

// TestErrKeyPairTypeAssertion_Error verifies the error message format.
func TestErrKeyPairTypeAssertion_Error(t *testing.T) {
	err := &ErrKeyPairTypeAssertion{Got: "unexpected"}
	msg := err.Error()
	if !strings.Contains(msg, "anyKeyPair") {
		t.Fatalf("error message %q does not mention anyKeyPair", msg)
	}
}

// TestErrVerificationType_Error verifies the ErrVerificationType error message.
func TestErrVerificationType_Error(t *testing.T) {
	err := &ErrVerificationType{}
	msg := err.Error()
	if !strings.Contains(msg, "verification failed") {
		t.Fatalf("error message %q does not mention verification failed", msg)
	}
}
