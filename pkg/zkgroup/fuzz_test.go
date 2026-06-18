package zkgroup

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
)

// FuzzDeserializeReceiptCredentialPresentation verifies that
// DeserializeReceiptCredentialPresentation never panics on arbitrary input.
// Seeds are derived from the deterministic inputs used in existing round-trip tests.
//
// Hardening target: u64-LE poksho_proof length prefix in the ReceiptCredentialPresentation
// wire format (rust/zkgroup/src/api/receipts/receipt_credential_presentation.rs).
func FuzzDeserializeReceiptCredentialPresentation(f *testing.F) {
	// Seed: produce a valid presentation using the same randomness as the
	// existing round-trip test.
	var r0, r1, r2, r3 RandomnessBytes
	for i := range r0 {
		r0[i] = 0x42
		r1[i] = 0x43
		r2[i] = 0x44
		r3[i] = 0x45
	}
	var serial ReceiptSerialBytes
	for i := range serial {
		serial[i] = 0x84
	}

	serverParams, err := GenerateServerSecretParams(r0)
	if err != nil {
		f.Fatalf("GenerateServerSecretParams: %v", err)
	}
	serverPub := serverParams.GetPublicParams()
	ctx := serverPub.CreateReceiptCredentialRequestContext(r1, serial)
	req := ctx.GetRequest()
	receiptExpiration := NewTimestamp(31337 * SecondsPerDay)
	resp, err := serverParams.IssueReceiptCredential(r2, req, receiptExpiration, 3)
	if err != nil {
		f.Fatalf("IssueReceiptCredential: %v", err)
	}
	cred, err := serverPub.ReceiveReceiptCredential(ctx, resp)
	if err != nil {
		f.Fatalf("ReceiveReceiptCredential: %v", err)
	}
	presentation, err := serverPub.CreateReceiptCredentialPresentation(r3, cred)
	if err != nil {
		f.Fatalf("CreateReceiptCredentialPresentation: %v", err)
	}

	f.Add(SerializeReceiptCredentialPresentation(presentation))
	f.Add([]byte{})
	f.Add([]byte{0x00})
	// Large u64 in the poksho_proof length field (overflow attack vector).
	// 1 (reserved) + 5*32 (points) = 161 bytes before the length field.
	largeLen := make([]byte, 169)
	for i := 161; i < 169; i++ {
		largeLen[i] = 0xFF
	}
	f.Add(largeLen)

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DeserializeReceiptCredentialPresentation(data)
	})
}

// FuzzDeserializeAnyProfileKeyCredentialPresentation verifies that
// DeserializeAnyProfileKeyCredentialPresentation never panics on arbitrary input.
// Covers V1–V4 dispatch and the u64-LE proof length in V1/V2/V3/V4 proofs.
func FuzzDeserializeAnyProfileKeyCredentialPresentation(f *testing.F) {
	// Build a valid V1 presentation as a seed using the test helpers from the
	// same package (buildLegacyPresentationBytes / makeTestPoints / makeTestCiphertext).
	pts := makeTestPoints()
	proof := bytes.Repeat([]byte{0xAB}, 320)
	uidCT := makeTestCiphertext(10)
	pkCT := makeTestCiphertext(20)

	v1Seed := buildLegacyPresentationBytes(PresentationVersion1, pts, proof, uidCT, pkCT)
	v2Seed := buildLegacyPresentationBytes(PresentationVersion2, pts, proof, uidCT, pkCT)
	f.Add(v1Seed)
	f.Add(v2Seed)

	// Synthesize a minimal V3/V4 seed: version + 8 points + 8-byte proof len + proof + 64 + 64 + 8.
	var v3Buf bytes.Buffer
	v3Buf.WriteByte(PresentationVersion3)
	for _, pt := range pts {
		v3Buf.Write(pt.Bytes())
	}
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], uint64(len(proof)))
	v3Buf.Write(lenBuf[:])
	v3Buf.Write(proof)
	v3Buf.Write(zkcredential.EncodeCiphertext(uidCT))
	v3Buf.Write(zkcredential.EncodeCiphertext(pkCT))
	binary.LittleEndian.PutUint64(lenBuf[:], 1681344000)
	v3Buf.Write(lenBuf[:])
	f.Add(v3Buf.Bytes())

	f.Add([]byte{})
	f.Add([]byte{0x00}) // V1 version byte, too short
	f.Add([]byte{0x01}) // V2 version byte, too short
	f.Add([]byte{0xFF}) // unknown version

	// Large u64 in proof length field (after version + 8 points = 257 bytes).
	largeLen := make([]byte, 265)
	largeLen[0] = PresentationVersion3
	for i := 257; i < 265; i++ {
		largeLen[i] = 0xFF
	}
	f.Add(largeLen)

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DeserializeAnyProfileKeyCredentialPresentation(data)
	})
}

// FuzzDeserializeCallLinkAuthCredentialPresentation verifies that
// DeserializeCallLinkAuthCredentialPresentation never panics on arbitrary input.
func FuzzDeserializeCallLinkAuthCredentialPresentation(f *testing.F) {
	var r1, r2, r4 RandomnessBytes
	for i := range r1 {
		r1[i] = 0x43
		r2[i] = 0x44
		r4[i] = 0x46
	}

	uuid := [UUIDLen]byte{0x04}
	userID := NewACI(uuid)
	ts := NewTimestamp(1681344000)

	serverParams := GenerateGenericServerSecretParams(r1)
	serverPub := serverParams.GetPublicParams()

	response, err := IssueCallLinkAuthCredential(userID, ts, serverParams, r2)
	if err != nil {
		f.Fatalf("IssueCallLinkAuthCredential: %v", err)
	}
	cred, err := ReceiveCallLinkAuthCredential(response, userID, ts, serverPub)
	if err != nil {
		f.Fatalf("ReceiveCallLinkAuthCredential: %v", err)
	}
	rootKey := make([]byte, 32)
	for i := range rootKey {
		rootKey[i] = byte(i + 1)
	}
	callLinkParams, err := DeriveCallLinkSecretParams(rootKey)
	if err != nil {
		f.Fatalf("DeriveCallLinkSecretParams: %v", err)
	}
	presentation, err := cred.Present(userID, ts, serverPub, callLinkParams, r4)
	if err != nil {
		f.Fatalf("Present: %v", err)
	}

	f.Add(SerializeCallLinkAuthCredentialPresentation(presentation))
	f.Add([]byte{})
	f.Add([]byte{0x00})
	// Large u64 in embedded PresentationProof Cy length (at byte 1+96+8=105).
	largeLen := make([]byte, 113)
	largeLen[0] = 0x00
	for i := 105; i < 113; i++ {
		largeLen[i] = 0xFF
	}
	f.Add(largeLen)

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DeserializeCallLinkAuthCredentialPresentation(data)
	})
}

// FuzzDeserializeGroupSendEndorsementsResponse verifies that
// DeserializeGroupSendEndorsementsResponse never panics on arbitrary input.
// Focuses on the u64-LE length prefix for the R point vector (endorsement response).
func FuzzDeserializeGroupSendEndorsementsResponse(f *testing.F) {
	// Seed using the same construction as makeTestGroupSendEndorsementsResponse
	// from the existing serialization test.
	var rootRandomness [zkcredential.RandomnessLen]byte
	for i := range rootRandomness {
		rootRandomness[i] = byte(i + 1)
	}
	rootKP, err := zkcredential.GenerateServerRootKeyPair(rootRandomness)
	if err != nil {
		f.Fatalf("GenerateServerRootKeyPair: %v", err)
	}
	expiration := NewTimestamp(2 * SecondsPerDay)
	keyPair, err := ForExpiration(expiration, rootKP)
	if err != nil {
		f.Fatalf("ForExpiration: %v", err)
	}
	var groupRandomness RandomnessBytes
	for i := range groupRandomness {
		groupRandomness[i] = byte(i + 11)
	}
	groupParams, err := GenerateGroupSecretParams(groupRandomness)
	if err != nil {
		f.Fatalf("GenerateGroupSecretParams: %v", err)
	}
	uuid1 := [UUIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	uuid2 := [UUIDLen]byte{17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	ct1 := groupParams.EncryptServiceID(NewACI(uuid1))
	ct2 := groupParams.EncryptServiceID(NewACI(uuid2))
	var issueRandomness RandomnessBytes
	for i := range issueRandomness {
		issueRandomness[i] = byte(i + 55)
	}
	resp, err := IssueGroupSendEndorsements([]*UUIDCiphertext{ct1, ct2}, keyPair, issueRandomness)
	if err != nil {
		f.Fatalf("IssueGroupSendEndorsements: %v", err)
	}

	f.Add(SerializeGroupSendEndorsementsResponse(resp))
	f.Add([]byte{})
	f.Add([]byte{0x00})
	// Large u64 in R vec length field (byte 1 is after reserved byte 0x00).
	largeLen := make([]byte, 9)
	largeLen[0] = 0x00
	for i := 1; i < 9; i++ {
		largeLen[i] = 0xFF
	}
	f.Add(largeLen)

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DeserializeGroupSendEndorsementsResponse(data)
	})
}
