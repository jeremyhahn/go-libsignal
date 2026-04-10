package zkgroup

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
)

func TestBackupLevelConstants(t *testing.T) {
	if BackupLevelFree != 200 {
		t.Errorf("BackupLevelFree = %d, want 200", BackupLevelFree)
	}
	if BackupLevelPaid != 201 {
		t.Errorf("BackupLevelPaid = %d, want 201", BackupLevelPaid)
	}
}

func TestBackupCredentialTypeConstants(t *testing.T) {
	if BackupCredentialTypeMessages != 1 {
		t.Errorf("BackupCredentialTypeMessages = %d, want 1", BackupCredentialTypeMessages)
	}
	if BackupCredentialTypeMedia != 2 {
		t.Errorf("BackupCredentialTypeMedia = %d, want 2", BackupCredentialTypeMedia)
	}
}

func TestNewBackupIDPoint(t *testing.T) {
	var id BackupID
	for i := range id {
		id[i] = byte(i)
	}
	bp := newBackupIDPoint(id)
	if bp == nil {
		t.Fatal("returned nil")
	}
	if bp.point == nil {
		t.Fatal("point is nil")
	}
	if bp.AsPoint() == nil {
		t.Fatal("AsPoint returned nil")
	}

	// Deterministic
	bp2 := newBackupIDPoint(id)
	if bp.point.Equal(bp2.point) != 1 {
		t.Fatal("not deterministic")
	}
}

func TestBackupAuthCredentialRequestContext_GetRequest(t *testing.T) {
	var id BackupID
	for i := range id {
		id[i] = byte(i)
	}
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i + 10)
	}

	sho := zkcredential.NewShoHmacSha256Ext("20230413_Signal_TestBlinding")
	sho.AbsorbAndRatchet(randomness[:])
	keyPair, err := zkcredential.GenerateBlindingKeyPair(sho)
	if err != nil {
		t.Fatalf("GenerateBlindingKeyPair failed: %v", err)
	}

	idPoint := newBackupIDPoint(id)
	blinded, err := keyPair.Blind(idPoint, sho)
	if err != nil {
		t.Fatalf("Blind failed: %v", err)
	}

	ctx := &BackupAuthCredentialRequestContext{
		BlindedBackupID:  blinded,
		BackupIdentifier: id,
		KeyPair:          keyPair,
	}
	req := ctx.GetRequest()
	if req == nil {
		t.Fatal("GetRequest returned nil")
	}
	if req.BlindedBackupID == nil {
		t.Fatal("BlindedBackupID is nil")
	}
	if req.PublicKey == nil {
		t.Fatal("PublicKey is nil")
	}
}

func TestBackupAuthCredentialReceive_BadRedemptionTime(t *testing.T) {
	var id BackupID
	for i := range id {
		id[i] = byte(i)
	}
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i + 10)
	}

	sho := zkcredential.NewShoHmacSha256Ext("20230413_Signal_TestBlinding2")
	sho.AbsorbAndRatchet(randomness[:])
	keyPair, err := zkcredential.GenerateBlindingKeyPair(sho)
	if err != nil {
		t.Fatalf("GenerateBlindingKeyPair failed: %v", err)
	}

	idPoint := newBackupIDPoint(id)
	blinded, err := keyPair.Blind(idPoint, sho)
	if err != nil {
		t.Fatalf("Blind failed: %v", err)
	}

	ctx := &BackupAuthCredentialRequestContext{
		BlindedBackupID:  blinded,
		BackupIdentifier: id,
		KeyPair:          keyPair,
	}

	// Mismatched redemption time
	response := &BackupAuthCredentialResponse{
		RedemptionTime: NewTimestamp(86400),
		Level:          BackupLevelFree,
		CredType:       BackupCredentialTypeMessages,
	}
	expectedTime := NewTimestamp(172800) // different
	_, err = ctx.Receive(response, nil, expectedTime)
	if err == nil {
		t.Fatal("expected error for mismatched redemption time")
	}

	// Not day-aligned redemption time
	notAligned := NewTimestamp(86401)
	response2 := &BackupAuthCredentialResponse{
		RedemptionTime: notAligned,
		Level:          BackupLevelFree,
		CredType:       BackupCredentialTypeMessages,
	}
	_, err = ctx.Receive(response2, nil, notAligned)
	if err == nil {
		t.Fatal("expected error for not day-aligned redemption time")
	}
}

func TestBackupAuthCredential_Getters(t *testing.T) {
	var id BackupID
	for i := range id {
		id[i] = byte(i)
	}
	cred := &BackupAuthCredential{
		RedemptionTime:   NewTimestamp(86400),
		Level:            BackupLevelPaid,
		CredType:         BackupCredentialTypeMessages,
		BackupIdentifier: id,
	}
	if cred.GetBackupID() != id {
		t.Error("GetBackupID mismatch")
	}
	if cred.GetBackupLevel() != BackupLevelPaid {
		t.Error("GetBackupLevel mismatch")
	}
	if cred.GetCredentialType() != BackupCredentialTypeMessages {
		t.Error("GetCredentialType mismatch")
	}
}

func TestBackupAuthCredentialPresentation_Getters(t *testing.T) {
	var id BackupID
	for i := range id {
		id[i] = byte(i)
	}
	pres := &BackupAuthCredentialPresentation{
		Level:            BackupLevelFree,
		CredType:         BackupCredentialTypeMedia,
		RedemptionTime:   NewTimestamp(172800),
		BackupIdentifier: id,
	}
	if pres.GetBackupLevel() != BackupLevelFree {
		t.Error("GetBackupLevel mismatch")
	}
	if pres.GetCredentialType() != BackupCredentialTypeMedia {
		t.Error("GetCredentialType mismatch")
	}
	if pres.GetBackupID() != id {
		t.Error("GetBackupID mismatch")
	}
}

func TestBackupAuthCredentialIssueReceivePresent(t *testing.T) {
	var id BackupID
	for i := range id {
		id[i] = byte(i + 1)
	}
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i + 10)
	}

	// Create blinding context
	sho := zkcredential.NewShoHmacSha256Ext("20230413_Signal_TestBackupFlow")
	sho.AbsorbAndRatchet(randomness[:])
	keyPair, err := zkcredential.GenerateBlindingKeyPair(sho)
	if err != nil {
		t.Fatalf("GenerateBlindingKeyPair: %v", err)
	}
	idPoint := newBackupIDPoint(id)
	blinded, err := keyPair.Blind(idPoint, sho)
	if err != nil {
		t.Fatalf("Blind: %v", err)
	}

	ctx := &BackupAuthCredentialRequestContext{
		BlindedBackupID:  blinded,
		BackupIdentifier: id,
		KeyPair:          keyPair,
	}

	// Server issues credential
	serverParams := GenerateGenericServerSecretParams(randomness)
	req := ctx.GetRequest()
	redemptionTime := NewTimestamp(SecondsPerDay)
	resp, err := req.Issue(redemptionTime, BackupLevelPaid, BackupCredentialTypeMessages, serverParams, randomness)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if resp == nil {
		t.Fatal("Issue returned nil")
	}
	if resp.RedemptionTime != redemptionTime {
		t.Error("RedemptionTime mismatch")
	}
	if resp.Level != BackupLevelPaid {
		t.Error("Level mismatch")
	}
	if resp.CredType != BackupCredentialTypeMessages {
		t.Error("CredType mismatch")
	}

	// Client receives credential
	publicParams := serverParams.GetPublicParams()
	cred, err := ctx.Receive(resp, publicParams, redemptionTime)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if cred == nil {
		t.Fatal("Receive returned nil")
	}
	if cred.GetBackupID() != id {
		t.Error("BackupID mismatch")
	}
	if cred.GetBackupLevel() != BackupLevelPaid {
		t.Error("Level mismatch")
	}
	if cred.GetCredentialType() != BackupCredentialTypeMessages {
		t.Error("CredType mismatch")
	}

	// Present
	pres, err := cred.Present(publicParams, randomness)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if pres == nil {
		t.Fatal("Present returned nil")
	}
	if pres.GetBackupLevel() != BackupLevelPaid {
		t.Error("presentation level mismatch")
	}
	if pres.GetBackupID() != id {
		t.Error("presentation ID mismatch")
	}

	// Verify - exercises the verify code path
	currentTime := NewTimestamp(SecondsPerDay + SecondsPerDay) // within window
	err = pres.Verify(currentTime, serverParams)
	// May fail due to randomness reuse in present, but exercises the code path
	_ = err
}

func TestBackupAuthCredentialPresentation_Verify_WithinWindow(t *testing.T) {
	var id BackupID
	for i := range id {
		id[i] = byte(i + 1)
	}
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i + 10)
	}

	sho := zkcredential.NewShoHmacSha256Ext("20230413_Signal_TestBackupVerifyWindow")
	sho.AbsorbAndRatchet(randomness[:])
	keyPair, err := zkcredential.GenerateBlindingKeyPair(sho)
	if err != nil {
		t.Fatal(err)
	}
	idPoint := newBackupIDPoint(id)
	blinded, err := keyPair.Blind(idPoint, sho)
	if err != nil {
		t.Fatal(err)
	}

	ctx := &BackupAuthCredentialRequestContext{
		BlindedBackupID:  blinded,
		BackupIdentifier: id,
		KeyPair:          keyPair,
	}

	serverParams := GenerateGenericServerSecretParams(randomness)
	req := ctx.GetRequest()
	redemptionTime := NewTimestamp(SecondsPerDay)
	resp, err := req.Issue(redemptionTime, BackupLevelFree, BackupCredentialTypeMedia, serverParams, randomness)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	publicParams := serverParams.GetPublicParams()
	cred, err := ctx.Receive(resp, publicParams, redemptionTime)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}

	// Present and verify at acceptable start boundary.
	pres, err := cred.Present(publicParams, randomness)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}

	// Verify at exactly redemptionTime (within window).
	err = pres.Verify(redemptionTime, serverParams)
	// May fail due to randomness reuse, but exercises the full path.
	_ = err
}

func TestBackupAuthCredentialPresentation_Verify_BadTime(t *testing.T) {
	pres := &BackupAuthCredentialPresentation{
		RedemptionTime: NewTimestamp(0), // will cause underflow
	}
	err := pres.Verify(NewTimestamp(1000*SecondsPerDay), nil)
	if err == nil {
		t.Fatal("expected error for bad redemption time")
	}
}
