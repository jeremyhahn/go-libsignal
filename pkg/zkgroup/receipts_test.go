package zkgroup

import (
	"testing"

	"github.com/gtank/ristretto255"
	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
)

func TestReceiptCredential(t *testing.T) {
	ts := NewTimestamp(86400)
	rc := &ReceiptCredential{
		ReceiptExpirationTime: ts,
		ReceiptLvl:            42,
	}
	if rc.GetReceiptExpirationTime() != ts {
		t.Error("expiration time mismatch")
	}
	if rc.GetReceiptLevel() != 42 {
		t.Errorf("level = %d, want 42", rc.GetReceiptLevel())
	}
}

func TestReceiptCredentialRequestContext(t *testing.T) {
	var serial ReceiptSerialBytes
	for i := range serial {
		serial[i] = byte(i)
	}
	Y := new(ristretto255.Element).ScalarBaseMult(ristretto255.NewScalar())
	D1 := new(ristretto255.Element).ScalarBaseMult(ristretto255.NewScalar())
	D2 := new(ristretto255.Element).ScalarBaseMult(ristretto255.NewScalar())

	ctx := &ReceiptCredentialRequestContext{
		ReceiptSerialBuf: serial,
		KeyPair: &receiptCredentialRequestKeyPair{
			y: ristretto255.NewScalar(),
			Y: Y,
		},
		CiphertextWithSecretNonce: &receiptCredentialRequestCiphertextWithSecretNonce{
			r1: ristretto255.NewScalar(),
			D1: D1,
			D2: D2,
		},
	}
	req := ctx.GetRequest()
	if req == nil {
		t.Fatal("GetRequest returned nil")
	}
	if req.PublicKey == nil {
		t.Error("PublicKey is nil")
	}
	if req.Ciphertext == nil {
		t.Error("Ciphertext is nil")
	}
}

func TestReceiptCredentialPresentation(t *testing.T) {
	var serial ReceiptSerialBytes
	for i := range serial {
		serial[i] = byte(i)
	}
	ts := NewTimestamp(172800)

	pres := &ReceiptCredentialPresentation{
		ReceiptExpirationTime: ts,
		ReceiptLvl:            10,
		ReceiptSerialBuf:      serial,
	}

	if pres.GetReceiptExpirationTime() != ts {
		t.Error("expiration time mismatch")
	}
	if pres.GetReceiptLevel() != 10 {
		t.Errorf("level = %d, want 10", pres.GetReceiptLevel())
	}
	if pres.GetReceiptSerialBytes() != serial {
		t.Error("serial mismatch")
	}

	rs := pres.GetReceiptStruct()
	if rs == nil {
		t.Fatal("GetReceiptStruct returned nil")
	}
	if rs.ReceiptSerialBytes != serial {
		t.Error("receipt struct serial mismatch")
	}
	if rs.ReceiptExpirationTime != ts {
		t.Error("receipt struct expiration mismatch")
	}
	if rs.ReceiptLevel != 10 {
		t.Error("receipt struct level mismatch")
	}
}

func TestReceiptCredentialFullFlow(t *testing.T) {
	// Generate server params.
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i + 1)
	}
	serverSecret, err := GenerateServerSecretParams(randomness)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}
	serverPublic := serverSecret.GetPublicParams()

	// Client creates request.
	var serial ReceiptSerialBytes
	for i := range serial {
		serial[i] = byte(i + 10)
	}
	var reqRandomness RandomnessBytes
	for i := range reqRandomness {
		reqRandomness[i] = byte(i + 20)
	}
	ctx := serverPublic.CreateReceiptCredentialRequestContext(reqRandomness, serial)
	if ctx == nil {
		t.Fatal("CreateReceiptCredentialRequestContext returned nil")
	}

	request := ctx.GetRequest()
	if request == nil {
		t.Fatal("GetRequest returned nil")
	}

	// Server issues credential.
	expirationTime := NewTimestamp(SecondsPerDay * 30)
	var issueRandomness RandomnessBytes
	for i := range issueRandomness {
		issueRandomness[i] = byte(i + 30)
	}
	response, err := serverSecret.IssueReceiptCredential(
		issueRandomness, request, expirationTime, 5,
	)
	if err != nil {
		t.Fatalf("IssueReceiptCredential: %v", err)
	}
	if response == nil {
		t.Fatal("IssueReceiptCredential returned nil response")
	}

	// Client receives credential.
	credential, err := serverPublic.ReceiveReceiptCredential(ctx, response)
	if err != nil {
		t.Fatalf("ReceiveReceiptCredential: %v", err)
	}
	if credential == nil {
		t.Fatal("ReceiveReceiptCredential returned nil credential")
	}
	if credential.GetReceiptExpirationTime() != expirationTime {
		t.Error("expiration time mismatch")
	}
	if credential.GetReceiptLevel() != 5 {
		t.Errorf("level = %d, want 5", credential.GetReceiptLevel())
	}
	if credential.ReceiptSerialBuf != serial {
		t.Error("serial bytes mismatch")
	}

	// Client creates presentation.
	var presRandomness RandomnessBytes
	for i := range presRandomness {
		presRandomness[i] = byte(i + 40)
	}
	presentation, err := serverPublic.CreateReceiptCredentialPresentation(presRandomness, credential)
	if err != nil {
		t.Fatalf("CreateReceiptCredentialPresentation: %v", err)
	}
	if presentation == nil {
		t.Fatal("CreateReceiptCredentialPresentation returned nil")
	}
	if presentation.GetReceiptExpirationTime() != expirationTime {
		t.Error("presentation expiration time mismatch")
	}
	if presentation.GetReceiptLevel() != 5 {
		t.Errorf("presentation level = %d, want 5", presentation.GetReceiptLevel())
	}
	if presentation.GetReceiptSerialBytes() != serial {
		t.Error("presentation serial bytes mismatch")
	}

	// Server verifies presentation.
	err = serverSecret.VerifyReceiptCredentialPresentation(presentation)
	if err != nil {
		t.Fatalf("VerifyReceiptCredentialPresentation: %v", err)
	}
}

func TestReceiptCredentialVerificationFailure(t *testing.T) {
	// Generate two different server params.
	var randomness1 RandomnessBytes
	for i := range randomness1 {
		randomness1[i] = byte(i + 1)
	}
	serverSecret1, err := GenerateServerSecretParams(randomness1)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}
	serverPublic1 := serverSecret1.GetPublicParams()

	var randomness2 RandomnessBytes
	for i := range randomness2 {
		randomness2[i] = byte(i + 100)
	}
	serverSecret2, err := GenerateServerSecretParams(randomness2)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}

	// Create credential with server 1.
	var serial ReceiptSerialBytes
	for i := range serial {
		serial[i] = byte(i + 10)
	}
	var reqRandomness RandomnessBytes
	for i := range reqRandomness {
		reqRandomness[i] = byte(i + 20)
	}
	ctx := serverPublic1.CreateReceiptCredentialRequestContext(reqRandomness, serial)
	request := ctx.GetRequest()

	expirationTime := NewTimestamp(SecondsPerDay * 30)
	var issueRandomness RandomnessBytes
	for i := range issueRandomness {
		issueRandomness[i] = byte(i + 30)
	}
	response, err := serverSecret1.IssueReceiptCredential(
		issueRandomness, request, expirationTime, 5,
	)
	if err != nil {
		t.Fatalf("IssueReceiptCredential: %v", err)
	}

	credential, err := serverPublic1.ReceiveReceiptCredential(ctx, response)
	if err != nil {
		t.Fatalf("ReceiveReceiptCredential: %v", err)
	}

	// Create presentation.
	var presRandomness RandomnessBytes
	for i := range presRandomness {
		presRandomness[i] = byte(i + 40)
	}
	presentation, err := serverPublic1.CreateReceiptCredentialPresentation(presRandomness, credential)
	if err != nil {
		t.Fatalf("CreateReceiptCredentialPresentation: %v", err)
	}

	// Verify with server 2 -- should fail.
	err = serverSecret2.VerifyReceiptCredentialPresentation(presentation)
	if err == nil {
		t.Fatal("expected verification failure with wrong server")
	}
}

func TestReceiptCredentialIssuanceProofVerify_InvalidProof(t *testing.T) {
	// Generate server params.
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i + 1)
	}
	serverSecret, err := GenerateServerSecretParams(randomness)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}
	serverPublic := serverSecret.GetPublicParams()

	// Create request.
	var serial ReceiptSerialBytes
	for i := range serial {
		serial[i] = byte(i + 10)
	}
	var reqRandomness RandomnessBytes
	for i := range reqRandomness {
		reqRandomness[i] = byte(i + 20)
	}
	ctx := serverPublic.CreateReceiptCredentialRequestContext(reqRandomness, serial)

	// Create a valid response but tamper with the proof.
	var issueRandomness RandomnessBytes
	for i := range issueRandomness {
		issueRandomness[i] = byte(i + 30)
	}
	response, err := serverSecret.IssueReceiptCredential(
		issueRandomness, ctx.GetRequest(), NewTimestamp(SecondsPerDay*30), 5,
	)
	if err != nil {
		t.Fatalf("IssueReceiptCredential: %v", err)
	}

	// Tamper with the proof.
	if len(response.Proof) > 0 {
		response.Proof[0] ^= 0xFF
	}

	_, err = serverPublic.ReceiveReceiptCredential(ctx, response)
	if err == nil {
		t.Fatal("expected error with tampered proof")
	}
}

func TestReceiveWithServiceIDs(t *testing.T) {
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i + 1)
	}

	rootKP, err := zkcredential.GenerateServerRootKeyPair(randomness)
	if err != nil {
		t.Fatalf("GenerateServerRootKeyPair: %v", err)
	}

	expiration := NewTimestamp(2 * SecondsPerDay)
	derived, err := ForExpiration(expiration, rootKP)
	if err != nil {
		t.Fatalf("ForExpiration: %v", err)
	}

	groupParams, err := GenerateGroupSecretParams(randomness)
	if err != nil {
		t.Fatalf("GenerateGroupSecretParams: %v", err)
	}

	uuid1 := [UUIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	uuid2 := [UUIDLen]byte{17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	sid1 := NewACI(uuid1)
	sid2 := NewACI(uuid2)

	// Encrypt service IDs to ciphertexts for issuance.
	ct1 := groupParams.EncryptServiceID(sid1)
	ct2 := groupParams.EncryptServiceID(sid2)
	memberCTs := []*UUIDCiphertext{ct1, ct2}

	resp, err := IssueGroupSendEndorsements(memberCTs, derived, randomness)
	if err != nil {
		t.Fatalf("IssueGroupSendEndorsements: %v", err)
	}

	pubKey := rootKP.PublicKey()
	now := NewTimestamp(SecondsPerDay)

	// Receive with service IDs.
	serviceIDs := []ServiceID{sid1, sid2}
	received, err := resp.ReceiveWithServiceIDs(serviceIDs, now, pubKey, groupParams)
	if err != nil {
		t.Fatalf("ReceiveWithServiceIDs: %v", err)
	}
	if len(received) != 2 {
		t.Fatalf("expected 2 endorsements, got %d", len(received))
	}
	for i, r := range received {
		if r.Compressed == nil {
			t.Fatalf("endorsement %d: Compressed is nil", i)
		}
		if r.Decompressed == nil {
			t.Fatalf("endorsement %d: Decompressed is nil", i)
		}
	}
}

func TestReceiveWithServiceIDs_InvalidKey(t *testing.T) {
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i + 1)
	}

	rootKP, err := zkcredential.GenerateServerRootKeyPair(randomness)
	if err != nil {
		t.Fatal(err)
	}

	expiration := NewTimestamp(2 * SecondsPerDay)
	derived, err := ForExpiration(expiration, rootKP)
	if err != nil {
		t.Fatal(err)
	}

	groupParams, err := GenerateGroupSecretParams(randomness)
	if err != nil {
		t.Fatal(err)
	}

	uuid1 := [UUIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	sid1 := NewACI(uuid1)
	ct1 := groupParams.EncryptServiceID(sid1)
	memberCTs := []*UUIDCiphertext{ct1}

	resp, err := IssueGroupSendEndorsements(memberCTs, derived, randomness)
	if err != nil {
		t.Fatal(err)
	}

	// Use wrong key.
	var randomness2 RandomnessBytes
	for i := range randomness2 {
		randomness2[i] = byte(i + 99)
	}
	wrongRootKP, _ := zkcredential.GenerateServerRootKeyPair(randomness2)
	wrongPubKey := wrongRootKP.PublicKey()

	now := NewTimestamp(SecondsPerDay)
	serviceIDs := []ServiceID{sid1}
	_, err = resp.ReceiveWithServiceIDs(serviceIDs, now, wrongPubKey, groupParams)
	if err == nil {
		t.Fatal("expected verification failure with wrong public key")
	}
}

func TestBlobEncryptDecrypt(t *testing.T) {
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i + 1)
	}
	params, err := GenerateGroupSecretParams(randomness)
	if err != nil {
		t.Fatalf("GenerateGroupSecretParams: %v", err)
	}

	plaintext := []byte("hello world group metadata")

	ct, err := params.EncryptBlob(randomness, plaintext)
	if err != nil {
		t.Fatalf("EncryptBlob: %v", err)
	}

	decrypted, err := params.DecryptBlob(ct)
	if err != nil {
		t.Fatalf("DecryptBlob: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("DecryptBlob = %q, want %q", string(decrypted), string(plaintext))
	}
}

func TestBlobEncryptDecrypt_InvalidCiphertext(t *testing.T) {
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i + 1)
	}
	params, err := GenerateGroupSecretParams(randomness)
	if err != nil {
		t.Fatalf("GenerateGroupSecretParams: %v", err)
	}

	// Too short.
	_, err = params.DecryptBlob([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for short ciphertext")
	}

	// Valid length but tampered.
	ct, err := params.EncryptBlob(randomness, []byte("test"))
	if err != nil {
		t.Fatalf("EncryptBlob: %v", err)
	}
	ct[0] ^= 0xFF
	_, err = params.DecryptBlob(ct)
	if err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
}

func TestBlobEncryptDecryptWithPadding(t *testing.T) {
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i + 1)
	}
	params, err := GenerateGroupSecretParams(randomness)
	if err != nil {
		t.Fatalf("GenerateGroupSecretParams: %v", err)
	}

	plaintext := []byte("Signal group title")
	paddingLen := 32

	ct, err := params.EncryptBlobWithPadding(randomness, plaintext, paddingLen)
	if err != nil {
		t.Fatalf("EncryptBlobWithPadding: %v", err)
	}

	decrypted, err := params.DecryptBlobWithPadding(ct)
	if err != nil {
		t.Fatalf("DecryptBlobWithPadding: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("DecryptBlobWithPadding = %q, want %q", string(decrypted), string(plaintext))
	}
}

func TestBlobEncryptDecryptWithPadding_InvalidInput(t *testing.T) {
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i + 1)
	}
	params, err := GenerateGroupSecretParams(randomness)
	if err != nil {
		t.Fatalf("GenerateGroupSecretParams: %v", err)
	}

	// Negative padding should fail.
	_, err = params.EncryptBlobWithPadding(randomness, []byte("test"), -1)
	if err == nil {
		t.Fatal("expected error for negative padding length")
	}

	// Tampered ciphertext.
	ct, err := params.EncryptBlobWithPadding(randomness, []byte("test"), 16)
	if err != nil {
		t.Fatalf("EncryptBlobWithPadding: %v", err)
	}
	ct[0] ^= 0xFF
	_, err = params.DecryptBlobWithPadding(ct)
	if err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
}

func TestBlobEncryptDecrypt_EmptyPlaintext(t *testing.T) {
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i + 1)
	}
	params, err := GenerateGroupSecretParams(randomness)
	if err != nil {
		t.Fatalf("GenerateGroupSecretParams: %v", err)
	}

	// Empty plaintext.
	ct, err := params.EncryptBlob(randomness, []byte{})
	if err != nil {
		t.Fatalf("EncryptBlob: %v", err)
	}

	decrypted, err := params.DecryptBlob(ct)
	if err != nil {
		t.Fatalf("DecryptBlob: %v", err)
	}
	if len(decrypted) != 0 {
		t.Errorf("expected empty plaintext, got %d bytes", len(decrypted))
	}
}

func TestBlobEncryptDecryptWithPadding_ZeroPadding(t *testing.T) {
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i + 1)
	}
	params, err := GenerateGroupSecretParams(randomness)
	if err != nil {
		t.Fatalf("GenerateGroupSecretParams: %v", err)
	}

	plaintext := []byte("no padding")
	ct, err := params.EncryptBlobWithPadding(randomness, plaintext, 0)
	if err != nil {
		t.Fatalf("EncryptBlobWithPadding: %v", err)
	}

	decrypted, err := params.DecryptBlobWithPadding(ct)
	if err != nil {
		t.Fatalf("DecryptBlobWithPadding: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("got %q, want %q", string(decrypted), string(plaintext))
	}
}
