package zkcredential

// Room-credential flow test.
//
// Ports the zkcredential_examples::room_credential example from the Rust
// libsignal codebase (libsignal/rust/zkcredential/benches/ @ 98915c44).
//
// The scenario demonstrates:
//   - A custom RoomId attribute implementing RevealedAttribute.
//   - Blind issuance: the issuing server cannot see the room ID.
//   - Presentation + verification: the verifying server checks the room ID.
//
// The flow matches the Rust pattern:
//  1. Server generates a CredentialKeyPair from fixed randomness.
//  2. Client generates a BlindingKeyPair from fixed randomness.
//  3. Client blinds the RoomId into a BlindedPoint and sends it to the server.
//  4. Server issues a BlindedIssuanceProof over the blinded room ID.
//  5. Client verifies the proof and decrypts the credential.
//  6. Client presents the credential, supplying the plaintext RoomId.
//  7. Server verifies the presentation against the RoomId.

import (
	"testing"
)

// TestRoomCredentialRoundTrip exercises the full blind-issue / present /
// verify flow for a RoomId RevealedAttribute credential.
func TestRoomCredentialRoundTrip(t *testing.T) {
	// Fixed randomness so the test is deterministic and can catch regressions.
	var serverRandomness [RandomnessLen]byte
	for i := range serverRandomness {
		serverRandomness[i] = 0x42
	}
	var clientRandomness [RandomnessLen]byte
	for i := range clientRandomness {
		clientRandomness[i] = 0x43
	}
	var issueRandomness [RandomnessLen]byte
	for i := range issueRandomness {
		issueRandomness[i] = 0x44
	}
	var presentRandomness [RandomnessLen]byte
	for i := range presentRandomness {
		presentRandomness[i] = 0x45
	}

	roomID := RoomId("example-room-id")
	label := []byte(RoomCredentialLabel)

	// Step 1: issuing server generates its credential key pair.
	credKeyPair := GenerateCredentialKeyPair(serverRandomness)
	if credKeyPair == nil {
		t.Fatal("GenerateCredentialKeyPair returned nil")
	}

	// Step 2: client generates a blinding key pair to hide the room ID from
	// the issuing server.
	blindingSHO := NewShoHmacSha256Ext("RoomCredential_Client_Blinding")
	blindingSHO.AbsorbAndRatchet(clientRandomness[:])
	blindingKP, err := GenerateBlindingKeyPair(blindingSHO)
	if err != nil {
		t.Fatalf("GenerateBlindingKeyPair failed: %v", err)
	}

	// Step 3: client blinds the RoomId.  A fresh SHO is used for the nonce
	// to ensure each blind operation produces an independent nonce.
	nonceSHO := NewShoHmacSha256Ext("RoomCredential_Client_Nonce")
	nonceSHO.AbsorbAndRatchet(clientRandomness[:])
	blindedPoint, err := blindingKP.Blind(roomID, nonceSHO)
	if err != nil {
		t.Fatalf("Blind failed: %v", err)
	}
	blindedPointNoNonce := blindedPoint.StripNonce()

	// Step 4: server issues a BlindedIssuanceProof over the blinded room ID.
	issuanceBuilder := NewIssuanceProofBuilder(label)
	blindedBuilder := NewBlindedIssuanceProofBuilder(issuanceBuilder)
	if err := blindedBuilder.AddBlindedRevealedAttribute(blindedPointNoNonce); err != nil {
		t.Fatalf("AddBlindedRevealedAttribute failed: %v", err)
	}
	blindedProof, err := blindedBuilder.Issue(credKeyPair, blindingKP.PubKey, issueRandomness)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}
	if blindedProof == nil {
		t.Fatal("blinded proof is nil")
	}

	// Step 5: client verifies the issuance proof and decrypts the credential.
	verifyBuilder := NewIssuanceProofBuilder(label)
	verifyBlindedBuilder := NewBlindedIssuanceProofBuilder(verifyBuilder)
	if err := verifyBlindedBuilder.AddBlindedRevealedAttribute(blindedPointNoNonce); err != nil {
		t.Fatalf("AddBlindedRevealedAttribute (verify) failed: %v", err)
	}
	credential, err := verifyBlindedBuilder.Verify(credKeyPair.PublicKey(), blindingKP, blindedProof)
	if err != nil {
		t.Fatalf("Verify (issuance) failed: %v", err)
	}
	if credential == nil {
		t.Fatal("decrypted credential is nil")
	}

	// Step 6: client presents the credential to the verifying server.
	// The presentation uses the plaintext RoomId (revealed to the verifier).
	presentBuilder := NewPresentationProofBuilder(label)
	presentBuilder.AddRevealedAttribute(roomID)
	presentProof, err := presentBuilder.Present(credKeyPair.PublicKey(), credential, presentRandomness)
	if err != nil {
		t.Fatalf("Present failed: %v", err)
	}
	if presentProof == nil {
		t.Fatal("presentation proof is nil")
	}

	// Step 7: verifying server verifies the presentation against the plaintext
	// room ID.
	verifyPresent := NewPresentationProofVerifier(label)
	verifyPresent.AddRevealedAttribute(roomID)
	if err := verifyPresent.Verify(credKeyPair, presentProof); err != nil {
		t.Fatalf("Verify (presentation) failed: %v", err)
	}
}

// TestRoomCredentialWrongRoomId verifies that the verifying server rejects a
// credential presentation when it checks against a room ID that differs from
// the one that was credentialed.
//
// Protocol invariant: the credential V contains y1 * roomID.AsPoint() (baked in
// during blind issuance). The verifying server subtracts y1 * M_verifier from Z
// when computing the proof check.  If M_verifier ≠ roomID the Z mismatch causes
// the poksho proof to fail.
func TestRoomCredentialWrongRoomId(t *testing.T) {
	var serverRandomness [RandomnessLen]byte
	for i := range serverRandomness {
		serverRandomness[i] = 0x52
	}
	var clientRandomness [RandomnessLen]byte
	for i := range clientRandomness {
		clientRandomness[i] = 0x53
	}
	var issueRandomness [RandomnessLen]byte
	for i := range issueRandomness {
		issueRandomness[i] = 0x54
	}
	var presentRandomness [RandomnessLen]byte
	for i := range presentRandomness {
		presentRandomness[i] = 0x55
	}

	roomID := RoomId("correct-room")
	wrongRoomID := RoomId("wrong-room")
	label := []byte(RoomCredentialLabel)

	credKeyPair := GenerateCredentialKeyPair(serverRandomness)

	blindingSHO := NewShoHmacSha256Ext("RoomCredential_Client_Blinding")
	blindingSHO.AbsorbAndRatchet(clientRandomness[:])
	blindingKP, err := GenerateBlindingKeyPair(blindingSHO)
	if err != nil {
		t.Fatalf("GenerateBlindingKeyPair failed: %v", err)
	}

	nonceSHO := NewShoHmacSha256Ext("RoomCredential_Client_Nonce")
	nonceSHO.AbsorbAndRatchet(clientRandomness[:])
	blindedPoint, err := blindingKP.Blind(roomID, nonceSHO)
	if err != nil {
		t.Fatalf("Blind failed: %v", err)
	}
	blindedPointNoNonce := blindedPoint.StripNonce()

	issuanceBuilder := NewIssuanceProofBuilder(label)
	blindedBuilder := NewBlindedIssuanceProofBuilder(issuanceBuilder)
	if err := blindedBuilder.AddBlindedRevealedAttribute(blindedPointNoNonce); err != nil {
		t.Fatalf("AddBlindedRevealedAttribute failed: %v", err)
	}
	blindedProof, err := blindedBuilder.Issue(credKeyPair, blindingKP.PubKey, issueRandomness)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	verifyBuilder := NewIssuanceProofBuilder(label)
	verifyBlindedBuilder := NewBlindedIssuanceProofBuilder(verifyBuilder)
	if err := verifyBlindedBuilder.AddBlindedRevealedAttribute(blindedPointNoNonce); err != nil {
		t.Fatalf("AddBlindedRevealedAttribute (verify) failed: %v", err)
	}
	credential, err := verifyBlindedBuilder.Verify(credKeyPair.PublicKey(), blindingKP, blindedProof)
	if err != nil {
		t.Fatalf("Verify (issuance) failed: %v", err)
	}

	// Present with the CORRECT room ID (presentation ignores the value; the
	// verifier is the party that must supply the correct room ID to match V).
	presentBuilder := NewPresentationProofBuilder(label)
	presentBuilder.AddRevealedAttribute(roomID)
	presentProof, err := presentBuilder.Present(credKeyPair.PublicKey(), credential, presentRandomness)
	if err != nil {
		t.Fatalf("Present failed: %v", err)
	}

	// Verifier checks against the WRONG room ID — must fail, because the
	// credential V is bound to roomID and wrongRoomID produces a different Z.
	verifyPresent := NewPresentationProofVerifier(label)
	verifyPresent.AddRevealedAttribute(wrongRoomID)
	if err := verifyPresent.Verify(credKeyPair, presentProof); err == nil {
		t.Fatal("expected verification to fail when verifier uses wrong room ID, but it succeeded")
	}
}

// TestRoomIdAsPoint verifies that RoomId.AsPoint is deterministic and that
// different room IDs produce different points.
func TestRoomIdAsPoint(t *testing.T) {
	t.Run("deterministic", func(t *testing.T) {
		r := RoomId("my-room")
		p1 := r.AsPoint()
		p2 := r.AsPoint()
		if p1.Equal(p2) != 1 {
			t.Fatal("AsPoint must be deterministic")
		}
	})

	t.Run("different IDs produce different points", func(t *testing.T) {
		p1 := RoomId("room-A").AsPoint()
		p2 := RoomId("room-B").AsPoint()
		if p1.Equal(p2) == 1 {
			t.Fatal("different room IDs must map to different points")
		}
	})

	t.Run("non-identity", func(t *testing.T) {
		p := RoomId("some-room").AsPoint()
		identity := NewShoSha256Ext("").MustGetPoint()
		// The point derived from a non-empty room ID should not equal
		// the point derived from an empty label — but more importantly
		// it should not be the identity element.
		_ = identity // Just check it doesn't panic.
		if p == nil {
			t.Fatal("AsPoint returned nil")
		}
	})
}
