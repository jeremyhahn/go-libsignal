package zkgroup

import (
	"testing"

	"github.com/gtank/ristretto255"
	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
)

func TestProfileKeyCredentialRequestContext(t *testing.T) {
	var aciBytes UIDBytes
	var pkBytes ProfileKeyBytes
	for i := range aciBytes {
		aciBytes[i] = byte(i)
	}
	for i := range pkBytes {
		pkBytes[i] = byte(i + 100)
	}

	Y := new(ristretto255.Element).ScalarBaseMult(ristretto255.NewScalar())
	D1 := new(ristretto255.Element).ScalarBaseMult(ristretto255.NewScalar())
	D2 := new(ristretto255.Element).ScalarBaseMult(ristretto255.NewScalar())
	E1 := new(ristretto255.Element).ScalarBaseMult(ristretto255.NewScalar())
	E2 := new(ristretto255.Element).ScalarBaseMult(ristretto255.NewScalar())

	ctx := &ProfileKeyCredentialRequestContext{
		ACIBytes:        aciBytes,
		ProfileKeyBytes: pkBytes,
		KeyPair: &profileKeyCredentialRequestKeyPair{
			y: ristretto255.NewScalar(),
			Y: Y,
		},
		CiphertextWithSecretNonce: &profileKeyCredentialRequestCiphertextWithSecretNonce{
			r1: ristretto255.NewScalar(),
			r2: ristretto255.NewScalar(),
			D1: D1,
			D2: D2,
			E1: E1,
			E2: E2,
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

func TestExpiringProfileKeyCredential(t *testing.T) {
	var aciBytes UIDBytes
	for i := range aciBytes {
		aciBytes[i] = byte(i)
	}
	ts := NewTimestamp(86400)

	cred := &ExpiringProfileKeyCredential{
		ACIBytes:                 aciBytes,
		CredentialExpirationTime: ts,
	}

	if cred.GetExpirationTime() != ts {
		t.Error("expiration mismatch")
	}

	aci := cred.ACI()
	if aci.Type != ServiceIDTypeACI {
		t.Error("should be ACI type")
	}
	if aci.RawUUID != aciBytes {
		t.Error("UUID mismatch")
	}
}

func TestExpiringProfileKeyCredentialPresentation(t *testing.T) {
	ts := NewTimestamp(86400)
	domain := UIDEncryptionDomain{}
	sho := zkcredential.NewShoHmacSha256Ext("test_key_epkcp")
	kp, err := zkcredential.DeriveKeyPair(sho, domain)
	if err != nil {
		t.Fatalf("DeriveKeyPair: %v", err)
	}

	uuid := [UUIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	uid := NewUIDStructFromServiceID(NewACI(uuid))
	uidCT := &UUIDCiphertext{Ciphertext: kp.Encrypt(uid)}

	pkDomain := ProfileKeyEncryptionDomain{}
	pkSho := zkcredential.NewShoHmacSha256Ext("test_pk_key")
	pkKP, _ := zkcredential.DeriveKeyPair(pkSho, pkDomain)

	var pkBytes ProfileKeyBytes
	for i := range pkBytes {
		pkBytes[i] = byte(i)
	}
	pks := NewProfileKeyStruct(pkBytes, uuid)
	pkCT := &ProfileKeyCiphertext{Ciphertext: pkKP.Encrypt(pks)}

	pres := &ExpiringProfileKeyCredentialPresentation{
		UIDEncCiphertext:         uidCT,
		ProfileKeyEncCiphertext:  pkCT,
		CredentialExpirationTime: ts,
	}

	if pres.GetUUIDCiphertext() != uidCT {
		t.Error("GetUUIDCiphertext mismatch")
	}
	if pres.GetProfileKeyCiphertext() != pkCT {
		t.Error("GetProfileKeyCiphertext mismatch")
	}
	if pres.GetExpirationTime() != ts {
		t.Error("GetExpirationTime mismatch")
	}
}

func TestAnyProfileKeyCredentialPresentation(t *testing.T) {
	t.Run("nil v3 variant returns nil ciphertexts", func(t *testing.T) {
		// An AnyProfileKeyCredentialPresentation with Version=3 but nil V3
		// must return nil from both accessors without panicking.
		any := &AnyProfileKeyCredentialPresentation{
			Version: PresentationVersion3,
			V3:      nil,
		}
		if any.GetUUIDCiphertext() != nil {
			t.Error("expected nil UUID ciphertext for nil V3")
		}
		if any.GetProfileKeyCiphertext() != nil {
			t.Error("expected nil profile key ciphertext for nil V3")
		}
		if _, ok := any.GetExpirationTime(); ok {
			t.Error("expected no expiration for nil V3")
		}
	})

	t.Run("v3 with presentation returns correct ciphertexts", func(t *testing.T) {
		uidCT := &UUIDCiphertext{}
		pkCT := &ProfileKeyCiphertext{}
		ts := NewTimestamp(SecondsPerDay * 5)
		pres := &ExpiringProfileKeyCredentialPresentation{
			UIDEncCiphertext:         uidCT,
			ProfileKeyEncCiphertext:  pkCT,
			CredentialExpirationTime: ts,
		}
		any := &AnyProfileKeyCredentialPresentation{
			Version: PresentationVersion3,
			V3:      pres,
		}
		if any.GetUUIDCiphertext() != uidCT {
			t.Error("GetUUIDCiphertext mismatch")
		}
		if any.GetProfileKeyCiphertext() != pkCT {
			t.Error("GetProfileKeyCiphertext mismatch")
		}
		expTime, ok := any.GetExpirationTime()
		if !ok {
			t.Error("expected expiration time for V3")
		}
		if expTime != ts {
			t.Error("expiration time mismatch")
		}
	})

	t.Run("v1 and v2 report no expiration", func(t *testing.T) {
		// V1 with no variant set
		anyV1 := &AnyProfileKeyCredentialPresentation{Version: PresentationVersion1}
		if _, ok := anyV1.GetExpirationTime(); ok {
			t.Error("V1 should not have expiration")
		}
		// V2 with no variant set
		anyV2 := &AnyProfileKeyCredentialPresentation{Version: PresentationVersion2}
		if _, ok := anyV2.GetExpirationTime(); ok {
			t.Error("V2 should not have expiration")
		}
	})
}

func TestExpiringProfileKeyCredentialFullFlow(t *testing.T) {
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

	// Client creates request context.
	var aciUUID UIDBytes
	for i := range aciUUID {
		aciUUID[i] = byte(i + 0x61) // 'a'
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
	if ctx == nil {
		t.Fatal("CreateProfileKeyCredentialRequestContext returned nil")
	}

	request := ctx.GetRequest()
	if request == nil {
		t.Fatal("GetRequest returned nil")
	}

	// Server issues credential.
	commitment := profileKey.GetCommitment(aci)
	// Set expiration to 3 days from now (day-aligned).
	currentTime := NewTimestamp(SecondsPerDay * 100)
	expirationTime := NewTimestamp(SecondsPerDay * 103)

	var issueRandomness RandomnessBytes
	for i := range issueRandomness {
		issueRandomness[i] = byte(i + 30)
	}
	response, err := serverSecret.IssueExpiringProfileKeyCredential(
		issueRandomness, request, aci, commitment, expirationTime,
	)
	if err != nil {
		t.Fatalf("IssueExpiringProfileKeyCredential: %v", err)
	}
	if response == nil {
		t.Fatal("IssueExpiringProfileKeyCredential returned nil response")
	}

	// Client receives credential.
	credential, err := serverPublic.ReceiveExpiringProfileKeyCredential(ctx, response, currentTime)
	if err != nil {
		t.Fatalf("ReceiveExpiringProfileKeyCredential: %v", err)
	}
	if credential == nil {
		t.Fatal("ReceiveExpiringProfileKeyCredential returned nil credential")
	}
	if credential.GetExpirationTime() != expirationTime {
		t.Error("expiration time mismatch")
	}
	if credential.ACIBytes != aciUUID {
		t.Error("ACI bytes mismatch")
	}

	// Client creates presentation.
	groupParams, err := GenerateGroupSecretParams(randomness)
	if err != nil {
		t.Fatalf("GenerateGroupSecretParams: %v", err)
	}

	var presRandomness RandomnessBytes
	for i := range presRandomness {
		presRandomness[i] = byte(i + 40)
	}
	presentation, err := serverPublic.CreateExpiringProfileKeyCredentialPresentation(
		presRandomness, groupParams, credential, PresentationVersion3,
	)
	if err != nil {
		t.Fatalf("CreateExpiringProfileKeyCredentialPresentation: %v", err)
	}
	if presentation == nil {
		t.Fatal("CreateExpiringProfileKeyCredentialPresentation returned nil")
	}
	if presentation.GetExpirationTime() != expirationTime {
		t.Error("presentation expiration time mismatch")
	}
	if presentation.GetUUIDCiphertext() == nil {
		t.Error("UUID ciphertext is nil")
	}
	if presentation.GetProfileKeyCiphertext() == nil {
		t.Error("profile key ciphertext is nil")
	}

	// Server verifies presentation.
	groupPublicParams := groupParams.GetPublicParams()
	err = serverSecret.VerifyExpiringProfileKeyCredentialPresentation(
		groupPublicParams, presentation, currentTime, PresentationVersion3,
	)
	if err != nil {
		t.Fatalf("VerifyExpiringProfileKeyCredentialPresentation: %v", err)
	}
}

func TestExpiringProfileKeyCredentialVerificationFailure(t *testing.T) {
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

	// Client creates request context.
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
	ctx, err := serverPublic1.CreateProfileKeyCredentialRequestContext(reqRandomness, aci, profileKey)
	if err != nil {
		t.Fatalf("CreateProfileKeyCredentialRequestContext: %v", err)
	}

	commitment := profileKey.GetCommitment(aci)
	currentTime := NewTimestamp(SecondsPerDay * 100)
	expirationTime := NewTimestamp(SecondsPerDay * 103)

	var issueRandomness RandomnessBytes
	for i := range issueRandomness {
		issueRandomness[i] = byte(i + 30)
	}
	response, err := serverSecret1.IssueExpiringProfileKeyCredential(
		issueRandomness, ctx.GetRequest(), aci, commitment, expirationTime,
	)
	if err != nil {
		t.Fatalf("IssueExpiringProfileKeyCredential: %v", err)
	}

	credential, err := serverPublic1.ReceiveExpiringProfileKeyCredential(ctx, response, currentTime)
	if err != nil {
		t.Fatalf("ReceiveExpiringProfileKeyCredential: %v", err)
	}

	// Create presentation.
	groupParams, err := GenerateGroupSecretParams(randomness1)
	if err != nil {
		t.Fatalf("GenerateGroupSecretParams: %v", err)
	}

	var presRandomness RandomnessBytes
	for i := range presRandomness {
		presRandomness[i] = byte(i + 40)
	}
	presentation, err := serverPublic1.CreateExpiringProfileKeyCredentialPresentation(
		presRandomness, groupParams, credential, PresentationVersion3,
	)
	if err != nil {
		t.Fatalf("CreateExpiringProfileKeyCredentialPresentation: %v", err)
	}

	// Verify with server 2 -- should fail.
	groupPublicParams := groupParams.GetPublicParams()
	err = serverSecret2.VerifyExpiringProfileKeyCredentialPresentation(
		groupPublicParams, presentation, currentTime, PresentationVersion3,
	)
	if err == nil {
		t.Fatal("expected verification failure with wrong server")
	}
}

func TestExpiringProfileKeyCredentialExpiredCredential(t *testing.T) {
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

	commitment := profileKey.GetCommitment(aci)
	currentTime := NewTimestamp(SecondsPerDay * 100)
	expirationTime := NewTimestamp(SecondsPerDay * 103)

	var issueRandomness RandomnessBytes
	for i := range issueRandomness {
		issueRandomness[i] = byte(i + 30)
	}
	response, err := serverSecret.IssueExpiringProfileKeyCredential(
		issueRandomness, ctx.GetRequest(), aci, commitment, expirationTime,
	)
	if err != nil {
		t.Fatalf("IssueExpiringProfileKeyCredential: %v", err)
	}

	credential, err := serverPublic.ReceiveExpiringProfileKeyCredential(ctx, response, currentTime)
	if err != nil {
		t.Fatalf("ReceiveExpiringProfileKeyCredential: %v", err)
	}

	// Create presentation.
	groupParams, err := GenerateGroupSecretParams(randomness)
	if err != nil {
		t.Fatalf("GenerateGroupSecretParams: %v", err)
	}

	var presRandomness RandomnessBytes
	for i := range presRandomness {
		presRandomness[i] = byte(i + 40)
	}
	presentation, err := serverPublic.CreateExpiringProfileKeyCredentialPresentation(
		presRandomness, groupParams, credential, PresentationVersion3,
	)
	if err != nil {
		t.Fatalf("CreateExpiringProfileKeyCredentialPresentation: %v", err)
	}

	// Verify with time past expiration -- should fail.
	expiredTime := NewTimestamp(SecondsPerDay * 200)
	groupPublicParams := groupParams.GetPublicParams()
	err = serverSecret.VerifyExpiringProfileKeyCredentialPresentation(
		groupPublicParams, presentation, expiredTime, PresentationVersion3,
	)
	if err == nil {
		t.Fatal("expected verification failure with expired credential")
	}
}

func TestReceiveExpiringProfileKeyCredential_NotDayAligned(t *testing.T) {
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

	commitment := profileKey.GetCommitment(aci)
	// Not day-aligned expiration.
	expirationTime := NewTimestamp(SecondsPerDay*103 + 1)

	var issueRandomness RandomnessBytes
	for i := range issueRandomness {
		issueRandomness[i] = byte(i + 30)
	}
	response, err := serverSecret.IssueExpiringProfileKeyCredential(
		issueRandomness, ctx.GetRequest(), aci, commitment, expirationTime,
	)
	if err != nil {
		t.Fatalf("IssueExpiringProfileKeyCredential: %v", err)
	}

	currentTime := NewTimestamp(SecondsPerDay * 100)
	_, err = serverPublic.ReceiveExpiringProfileKeyCredential(ctx, response, currentTime)
	if err == nil {
		t.Fatal("expected error for non-day-aligned expiration time")
	}
}
