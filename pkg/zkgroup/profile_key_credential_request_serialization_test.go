package zkgroup

import (
	"bytes"
	"testing"
)

// TestProfileKeyCredentialRequest_SerializeRoundTrip verifies that a request
// produced by the client survives serialize→deserialize unchanged, both at the
// byte level and cryptographically: the deserialized request must issue a
// credential the client can receive/unblind. Because issuance verifies the
// request's poksho proof, a correct round-trip proves the wire encoding
// preserves the public key, ciphertext, and proof exactly.
func TestProfileKeyCredentialRequest_SerializeRoundTrip(t *testing.T) {
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i + 1)
	}
	serverSecret, err := GenerateServerSecretParams(randomness)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}
	serverPublic := serverSecret.GetPublicParams()

	var aciUUID UIDBytes
	for i := range aciUUID {
		aciUUID[i] = byte(i + 0x61)
	}
	aci := NewACI(aciUUID)

	var pkBytes ProfileKeyBytes
	for i := range pkBytes {
		pkBytes[i] = byte(i + 1)
	}
	profileKey := NewProfileKey(pkBytes)

	var reqRandomness RandomnessBytes
	for i := range reqRandomness {
		reqRandomness[i] = byte(i + 20)
	}
	ctx, err := serverPublic.CreateProfileKeyCredentialRequestContext(reqRandomness, aci, profileKey)
	if err != nil {
		t.Fatalf("CreateProfileKeyCredentialRequestContext: %v", err)
	}
	original := ctx.GetRequest()

	// Byte-level round trip: serialize -> deserialize -> serialize must be stable.
	wire := SerializeProfileKeyCredentialRequest(original)
	if len(wire) <= profileKeyCredentialRequestFixedSize {
		t.Fatalf("serialized request too short: %d bytes", len(wire))
	}
	decoded, err := DeserializeProfileKeyCredentialRequest(wire)
	if err != nil {
		t.Fatalf("DeserializeProfileKeyCredentialRequest: %v", err)
	}
	rewire := SerializeProfileKeyCredentialRequest(decoded)
	if !bytes.Equal(wire, rewire) {
		t.Fatal("serialize is not stable across a deserialize round trip")
	}

	// Cryptographic round trip: the DESERIALIZED request AND a DESERIALIZED
	// commitment must issue a valid credential that the original client context
	// can receive. The commitment round-trips through its wire format too.
	commitmentWire := SerializeProfileKeyCommitment(profileKey.GetCommitment(aci))
	if len(commitmentWire) != profileKeyCommitmentSize {
		t.Fatalf("commitment wire size = %d, want %d", len(commitmentWire), profileKeyCommitmentSize)
	}
	commitment, err := DeserializeProfileKeyCommitment(commitmentWire)
	if err != nil {
		t.Fatalf("DeserializeProfileKeyCommitment: %v", err)
	}
	currentTime := NewTimestamp(SecondsPerDay * 100)
	expirationTime := NewTimestamp(SecondsPerDay * 103)

	var issueRandomness RandomnessBytes
	for i := range issueRandomness {
		issueRandomness[i] = byte(i + 30)
	}
	response, err := serverSecret.IssueExpiringProfileKeyCredential(
		issueRandomness, decoded, aci, commitment, expirationTime,
	)
	if err != nil {
		t.Fatalf("issuance on deserialized request failed: %v", err)
	}

	// Round-trip the response through its wire format too, then have the client
	// receive the credential from the DESERIALIZED response. This validates the
	// full server→client wire path.
	respWire := SerializeExpiringProfileKeyCredentialResponse(response)
	if len(respWire) <= expiringProfileKeyCredentialResponseFixedSize {
		t.Fatalf("serialized response too short: %d bytes", len(respWire))
	}
	decodedResp, err := DeserializeExpiringProfileKeyCredentialResponse(respWire)
	if err != nil {
		t.Fatalf("DeserializeExpiringProfileKeyCredentialResponse: %v", err)
	}
	if !bytes.Equal(respWire, SerializeExpiringProfileKeyCredentialResponse(decodedResp)) {
		t.Fatal("response serialize is not stable across a deserialize round trip")
	}

	credential, err := serverPublic.ReceiveExpiringProfileKeyCredential(ctx, decodedResp, currentTime)
	if err != nil {
		t.Fatalf("client could not receive credential from deserialized response: %v", err)
	}
	if credential.GetExpirationTime() != expirationTime {
		t.Error("expiration time mismatch")
	}
	if credential.ACIBytes != aciUUID {
		t.Error("ACI mismatch")
	}
}

// TestProfileKeyCredentialRequest_DeserializeRejectsMalformed checks the
// defensive error paths.
func TestProfileKeyCredentialRequest_DeserializeRejectsMalformed(t *testing.T) {
	// Too short.
	if _, err := DeserializeProfileKeyCredentialRequest(make([]byte, 10)); err == nil {
		t.Error("expected error for short input")
	}
	// Bad reserved byte.
	bad := make([]byte, profileKeyCredentialRequestFixedSize+8)
	bad[0] = 0x01
	if _, err := DeserializeProfileKeyCredentialRequest(bad); err == nil {
		t.Error("expected error for non-zero reserved byte")
	}
	// Non-canonical point bytes (all 0xFF is not a valid ristretto encoding).
	badPoint := make([]byte, profileKeyCredentialRequestFixedSize+8)
	for i := 1; i < profileKeyCredentialRequestFixedSize; i++ {
		badPoint[i] = 0xFF
	}
	if _, err := DeserializeProfileKeyCredentialRequest(badPoint); err == nil {
		t.Error("expected error for non-canonical point bytes")
	}
}
