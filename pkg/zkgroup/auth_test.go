package zkgroup

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
)

func TestAuthCredentialWithPniZkcPresentation(t *testing.T) {
	ts := NewTimestamp(86400)
	domain := UIDEncryptionDomain{}
	sho := zkcredential.NewShoHmacSha256Ext("test_key")
	kp, err := zkcredential.DeriveKeyPair(sho, domain)
	if err != nil {
		t.Fatalf("DeriveKeyPair failed: %v", err)
	}

	uuid1 := [UUIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	uuid2 := [UUIDLen]byte{17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	aci := NewACI(uuid1)
	pni := NewPNI(uuid2)

	aciUID := NewUIDStructFromServiceID(aci)
	pniUID := NewUIDStructFromServiceID(pni)

	aciCT := &UUIDCiphertext{Ciphertext: kp.Encrypt(aciUID)}
	pniCT := &UUIDCiphertext{Ciphertext: kp.Encrypt(pniUID)}

	pres := &AuthCredentialWithPniZkcPresentation{
		ACICiphertext:      aciCT,
		PNICiphertext:      pniCT,
		RedemptionTimeSecs: ts,
	}

	if pres.ACICiphertextValue() != aciCT {
		t.Error("ACICiphertextValue mismatch")
	}
	if pres.PNICiphertextValue() != pniCT {
		t.Error("PNICiphertextValue mismatch")
	}
	if pres.RedemptionTime() != ts {
		t.Error("RedemptionTime mismatch")
	}
}

func TestAuthCredentialWithPniVersions(t *testing.T) {
	cred := &AuthCredentialWithPni{
		Version: AuthCredentialWithPniVersionZkc,
	}
	if cred.Version != AuthCredentialWithPniVersionZkc {
		t.Errorf("Version = %d, want %d", cred.Version, AuthCredentialWithPniVersionZkc)
	}
}

func TestAuthCredentialWithPniZkcFullFlow(t *testing.T) {
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

	// Set up identities.
	var aciUUID UIDBytes
	for i := range aciUUID {
		aciUUID[i] = byte(i + 0x61)
	}
	var pniUUID UIDBytes
	for i := range pniUUID {
		pniUUID[i] = byte(i + 0x81)
	}
	aci := NewACI(aciUUID)
	pni := NewPNI(pniUUID)

	// Day-aligned redemption time.
	redemptionTime := NewTimestamp(SecondsPerDay * 100)

	// Server issues credential.
	var issueRandomness RandomnessBytes
	for i := range issueRandomness {
		issueRandomness[i] = byte(i + 10)
	}
	response, err := serverSecret.IssueAuthCredentialWithPniZkc(
		aci, pni, redemptionTime, issueRandomness,
	)
	if err != nil {
		t.Fatalf("IssueAuthCredentialWithPniZkc: %v", err)
	}
	if response == nil {
		t.Fatal("IssueAuthCredentialWithPniZkc returned nil")
	}
	if response.RedemptionTime != redemptionTime {
		t.Error("response redemption time mismatch")
	}

	// Client receives credential.
	credential, err := serverPublic.ReceiveAuthCredentialWithPniZkc(
		aci, pni, redemptionTime, response,
	)
	if err != nil {
		t.Fatalf("ReceiveAuthCredentialWithPniZkc: %v", err)
	}
	if credential == nil {
		t.Fatal("ReceiveAuthCredentialWithPniZkc returned nil")
	}
	if credential.RedemptionTime != redemptionTime {
		t.Error("credential redemption time mismatch")
	}
	if credential.ACI == nil {
		t.Error("credential ACI is nil")
	}
	if credential.PNI == nil {
		t.Error("credential PNI is nil")
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
	presentation, err := serverPublic.CreateAuthCredentialWithPniZkcPresentation(
		credential, groupParams, presRandomness,
	)
	if err != nil {
		t.Fatalf("CreateAuthCredentialWithPniZkcPresentation: %v", err)
	}
	if presentation == nil {
		t.Fatal("CreateAuthCredentialWithPniZkcPresentation returned nil")
	}
	if presentation.RedemptionTimeSecs != redemptionTime {
		t.Error("presentation redemption time mismatch")
	}
	if presentation.ACICiphertext == nil {
		t.Error("presentation ACI ciphertext is nil")
	}
	if presentation.PNICiphertext == nil {
		t.Error("presentation PNI ciphertext is nil")
	}

	// Server verifies presentation.
	groupPublicParams := groupParams.GetPublicParams()
	err = serverSecret.VerifyAuthCredentialWithPniZkcPresentation(
		groupPublicParams, presentation, redemptionTime,
	)
	if err != nil {
		t.Fatalf("VerifyAuthCredentialWithPniZkcPresentation: %v", err)
	}
}

func TestAuthCredentialWithPniZkcVerificationFailure(t *testing.T) {
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

	var aciUUID, pniUUID UIDBytes
	for i := range aciUUID {
		aciUUID[i] = byte(i + 0x61)
	}
	for i := range pniUUID {
		pniUUID[i] = byte(i + 0x81)
	}
	aci := NewACI(aciUUID)
	pni := NewPNI(pniUUID)
	redemptionTime := NewTimestamp(SecondsPerDay * 100)

	var issueRandomness RandomnessBytes
	for i := range issueRandomness {
		issueRandomness[i] = byte(i + 10)
	}
	response, err := serverSecret1.IssueAuthCredentialWithPniZkc(
		aci, pni, redemptionTime, issueRandomness,
	)
	if err != nil {
		t.Fatalf("IssueAuthCredentialWithPniZkc: %v", err)
	}

	credential, err := serverPublic1.ReceiveAuthCredentialWithPniZkc(
		aci, pni, redemptionTime, response,
	)
	if err != nil {
		t.Fatalf("ReceiveAuthCredentialWithPniZkc: %v", err)
	}

	groupParams, err := GenerateGroupSecretParams(randomness1)
	if err != nil {
		t.Fatalf("GenerateGroupSecretParams: %v", err)
	}

	var presRandomness RandomnessBytes
	for i := range presRandomness {
		presRandomness[i] = byte(i + 40)
	}
	presentation, err := serverPublic1.CreateAuthCredentialWithPniZkcPresentation(
		credential, groupParams, presRandomness,
	)
	if err != nil {
		t.Fatalf("CreateAuthCredentialWithPniZkcPresentation: %v", err)
	}

	// Verify with wrong server -- should fail.
	groupPublicParams := groupParams.GetPublicParams()
	err = serverSecret2.VerifyAuthCredentialWithPniZkcPresentation(
		groupPublicParams, presentation, redemptionTime,
	)
	if err == nil {
		t.Fatal("expected verification failure with wrong server")
	}
}

func TestAuthCredentialWithPniZkcWrongRedemptionTime(t *testing.T) {
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i + 1)
	}
	serverSecret, err := GenerateServerSecretParams(randomness)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}
	serverPublic := serverSecret.GetPublicParams()

	var aciUUID, pniUUID UIDBytes
	for i := range aciUUID {
		aciUUID[i] = byte(i + 0x61)
	}
	for i := range pniUUID {
		pniUUID[i] = byte(i + 0x81)
	}
	aci := NewACI(aciUUID)
	pni := NewPNI(pniUUID)
	redemptionTime := NewTimestamp(SecondsPerDay * 100)

	var issueRandomness RandomnessBytes
	for i := range issueRandomness {
		issueRandomness[i] = byte(i + 10)
	}
	response, err := serverSecret.IssueAuthCredentialWithPniZkc(
		aci, pni, redemptionTime, issueRandomness,
	)
	if err != nil {
		t.Fatalf("IssueAuthCredentialWithPniZkc: %v", err)
	}

	credential, err := serverPublic.ReceiveAuthCredentialWithPniZkc(
		aci, pni, redemptionTime, response,
	)
	if err != nil {
		t.Fatalf("ReceiveAuthCredentialWithPniZkc: %v", err)
	}

	groupParams, err := GenerateGroupSecretParams(randomness)
	if err != nil {
		t.Fatalf("GenerateGroupSecretParams: %v", err)
	}

	var presRandomness RandomnessBytes
	for i := range presRandomness {
		presRandomness[i] = byte(i + 40)
	}
	presentation, err := serverPublic.CreateAuthCredentialWithPniZkcPresentation(
		credential, groupParams, presRandomness,
	)
	if err != nil {
		t.Fatalf("CreateAuthCredentialWithPniZkcPresentation: %v", err)
	}

	// Verify with different redemption time -- should fail.
	wrongTime := NewTimestamp(SecondsPerDay * 200)
	groupPublicParams := groupParams.GetPublicParams()
	err = serverSecret.VerifyAuthCredentialWithPniZkcPresentation(
		groupPublicParams, presentation, wrongTime,
	)
	if err == nil {
		t.Fatal("expected verification failure with wrong redemption time")
	}
}

func TestReceiveAuthCredentialWithPniZkc_NotDayAligned(t *testing.T) {
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i + 1)
	}
	serverSecret, err := GenerateServerSecretParams(randomness)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}
	serverPublic := serverSecret.GetPublicParams()

	var aciUUID, pniUUID UIDBytes
	for i := range aciUUID {
		aciUUID[i] = byte(i + 0x61)
	}
	for i := range pniUUID {
		pniUUID[i] = byte(i + 0x81)
	}
	aci := NewACI(aciUUID)
	pni := NewPNI(pniUUID)
	// Not day-aligned.
	redemptionTime := NewTimestamp(SecondsPerDay*100 + 1)

	var issueRandomness RandomnessBytes
	for i := range issueRandomness {
		issueRandomness[i] = byte(i + 10)
	}
	response, err := serverSecret.IssueAuthCredentialWithPniZkc(
		aci, pni, redemptionTime, issueRandomness,
	)
	if err != nil {
		t.Fatalf("IssueAuthCredentialWithPniZkc: %v", err)
	}

	_, err = serverPublic.ReceiveAuthCredentialWithPniZkc(
		aci, pni, redemptionTime, response,
	)
	if err == nil {
		t.Fatal("expected error for non-day-aligned redemption time")
	}
}

func TestAnyAuthCredentialPresentation(t *testing.T) {
	ts := NewTimestamp(86400)
	domain := UIDEncryptionDomain{}
	sho := zkcredential.NewShoHmacSha256Ext("test_key_any")
	kp, err := zkcredential.DeriveKeyPair(sho, domain)
	if err != nil {
		t.Fatalf("DeriveKeyPair failed: %v", err)
	}

	uuid1 := [UUIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	uuid2 := [UUIDLen]byte{17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	aci := NewACI(uuid1)
	pni := NewPNI(uuid2)
	aciUID := NewUIDStructFromServiceID(aci)
	pniUID := NewUIDStructFromServiceID(pni)

	aciCT := &UUIDCiphertext{Ciphertext: kp.Encrypt(aciUID)}
	pniCT := &UUIDCiphertext{Ciphertext: kp.Encrypt(pniUID)}

	inner := &AuthCredentialWithPniZkcPresentation{
		ACICiphertext:      aciCT,
		PNICiphertext:      pniCT,
		RedemptionTimeSecs: ts,
	}

	any := &AnyAuthCredentialPresentation{
		Version:      PresentationVersion4,
		Presentation: inner,
	}

	if any.GetACICiphertext() != aciCT {
		t.Error("GetACICiphertext mismatch")
	}
	if any.GetPNICiphertext() != pniCT {
		t.Error("GetPNICiphertext mismatch")
	}
	if any.GetRedemptionTime() != ts {
		t.Error("GetRedemptionTime mismatch")
	}
}
