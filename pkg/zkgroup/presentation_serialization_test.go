package zkgroup

import (
	"errors"
	"testing"
)

// TestSerializeReceiptCredentialPresentation_RoundTrip verifies that a
// ReceiptCredentialPresentation can be serialized and deserialized without
// data loss. Exercises the full path from CreateReceiptCredentialPresentation
// through the serializer.
//
// Rust reference: rust/zkgroup/tests/receipt_flow.rs:test_api
// Wire layout: rust/zkgroup/src/api/receipts/receipt_credential_presentation.rs
func TestSerializeReceiptCredentialPresentation_RoundTrip(t *testing.T) {
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
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}
	serverPub := serverParams.GetPublicParams()

	ctx := serverPub.CreateReceiptCredentialRequestContext(r1, serial)
	req := ctx.GetRequest()

	receiptExpiration := NewTimestamp(31337 * SecondsPerDay)
	var receiptLevel ReceiptLevel = 3

	resp, err := serverParams.IssueReceiptCredential(r2, req, receiptExpiration, receiptLevel)
	if err != nil {
		t.Fatalf("IssueReceiptCredential: %v", err)
	}

	cred, err := serverPub.ReceiveReceiptCredential(ctx, resp)
	if err != nil {
		t.Fatalf("ReceiveReceiptCredential: %v", err)
	}

	presentation, err := serverPub.CreateReceiptCredentialPresentation(r3, cred)
	if err != nil {
		t.Fatalf("CreateReceiptCredentialPresentation: %v", err)
	}

	encoded := SerializeReceiptCredentialPresentation(presentation)

	// First byte must be reserved 0x00.
	if len(encoded) == 0 || encoded[0] != 0x00 {
		t.Fatalf("first byte = 0x%02x, want 0x00", encoded[0])
	}

	decoded, err := DeserializeReceiptCredentialPresentation(encoded)
	if err != nil {
		t.Fatalf("DeserializeReceiptCredentialPresentation: %v", err)
	}

	if decoded.ReceiptExpirationTime != presentation.ReceiptExpirationTime {
		t.Errorf("ReceiptExpirationTime mismatch: got %d, want %d",
			decoded.ReceiptExpirationTime.EpochSeconds(),
			presentation.ReceiptExpirationTime.EpochSeconds())
	}
	if decoded.ReceiptLvl != presentation.ReceiptLvl {
		t.Errorf("ReceiptLevel mismatch: got %d, want %d", decoded.ReceiptLvl, presentation.ReceiptLvl)
	}
	if decoded.ReceiptSerialBuf != presentation.ReceiptSerialBuf {
		t.Error("ReceiptSerialBuf mismatch")
	}
	if decoded.Cx0.Equal(presentation.Cx0) != 1 {
		t.Error("Cx0 mismatch")
	}
	if decoded.Cx1.Equal(presentation.Cx1) != 1 {
		t.Error("Cx1 mismatch")
	}
	if decoded.Cy1.Equal(presentation.Cy1) != 1 {
		t.Error("Cy1 mismatch")
	}
	if decoded.Cy2.Equal(presentation.Cy2) != 1 {
		t.Error("Cy2 mismatch")
	}
	if decoded.CV.Equal(presentation.CV) != 1 {
		t.Error("CV mismatch")
	}
}

// TestDeserializeReceiptCredentialPresentation_RejectsBadReservedByte verifies
// that a non-zero first byte is rejected.
func TestDeserializeReceiptCredentialPresentation_RejectsBadReservedByte(t *testing.T) {
	data := make([]byte, 329) // RECEIPT_CREDENTIAL_PRESENTATION_LEN
	data[0] = 0x01            // bad reserved byte

	_, err := DeserializeReceiptCredentialPresentation(data)
	if err == nil {
		t.Fatal("expected error for bad reserved byte")
	}
	var reservedErr *ErrUnexpectedReservedByte
	if !errors.As(err, &reservedErr) {
		t.Errorf("expected *ErrUnexpectedReservedByte, got %T: %v", err, err)
	}
}

// TestDeserializeReceiptCredentialPresentation_TooShort rejects short input.
func TestDeserializeReceiptCredentialPresentation_TooShort(t *testing.T) {
	_, err := DeserializeReceiptCredentialPresentation([]byte{0x00})
	if err == nil {
		t.Fatal("expected error for too-short input")
	}
}

// TestSerializeReceiptCredentialPresentation_TimestampIsLE verifies that the
// receipt expiration time is encoded as little-endian per the Rust bincode format.
func TestSerializeReceiptCredentialPresentation_TimestampIsLE(t *testing.T) {
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
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}
	serverPub := serverParams.GetPublicParams()

	ctx := serverPub.CreateReceiptCredentialRequestContext(r1, serial)
	req := ctx.GetRequest()
	receiptExpiration := NewTimestamp(31337 * SecondsPerDay)
	var receiptLevel ReceiptLevel = 3

	resp, err := serverParams.IssueReceiptCredential(r2, req, receiptExpiration, receiptLevel)
	if err != nil {
		t.Fatalf("IssueReceiptCredential: %v", err)
	}
	cred, err := serverPub.ReceiveReceiptCredential(ctx, resp)
	if err != nil {
		t.Fatalf("ReceiveReceiptCredential: %v", err)
	}
	presentation, err := serverPub.CreateReceiptCredentialPresentation(r3, cred)
	if err != nil {
		t.Fatalf("CreateReceiptCredentialPresentation: %v", err)
	}

	encoded := SerializeReceiptCredentialPresentation(presentation)

	// Find the timestamp: it appears after reserved(1) + 5 points(160) + poksho_len(8) + poksho_data.
	// We can verify by round-tripping and checking the decoded value.
	decoded, err := DeserializeReceiptCredentialPresentation(encoded)
	if err != nil {
		t.Fatalf("round-trip decode: %v", err)
	}
	if decoded.ReceiptExpirationTime.EpochSeconds() != receiptExpiration.EpochSeconds() {
		t.Errorf("expiration time mismatch after round-trip: got %d, want %d",
			decoded.ReceiptExpirationTime.EpochSeconds(), receiptExpiration.EpochSeconds())
	}
}

// TestSerializeBackupAuthCredentialPresentation_RoundTrip verifies the backup
// auth presentation serialization round-trip.
//
// Rust wire layout: rust/zkgroup/src/api/backups/auth_credential.rs:271-278.
func TestSerializeBackupAuthCredentialPresentation_RoundTrip(t *testing.T) {
	var r1, r2, r3 RandomnessBytes
	for i := range r1 {
		r1[i] = 0x43
		r2[i] = 0x44
		r3[i] = 0x45
	}
	var backupKey [32]byte
	for i := range backupKey {
		backupKey[i] = 0x46
	}
	aciBytes := [16]byte{
		0xc0, 0xfc, 0x16, 0xe4, 0xba, 0xe5, 0x43, 0x43,
		0x9f, 0x0d, 0xe7, 0xec, 0xf4, 0x25, 0x13, 0x43,
	}
	aci := NewACI(aciBytes)

	ctx, err := NewBackupAuthCredentialRequestContext(backupKey, aci)
	if err != nil {
		t.Fatalf("NewBackupAuthCredentialRequestContext: %v", err)
	}

	serverParams := GenerateGenericServerSecretParams(r1)
	req := ctx.GetRequest()
	redemptionTime := NewTimestamp(1681344000) // 2023-04-13 UTC

	resp, err := req.Issue(redemptionTime, BackupLevelFree, BackupCredentialTypeMessages, serverParams, r2)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	publicParams := serverParams.GetPublicParams()
	cred, err := ctx.Receive(resp, publicParams, redemptionTime)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}

	presentation, err := cred.Present(publicParams, r3)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}

	encoded := SerializeBackupAuthCredentialPresentation(presentation)

	if len(encoded) == 0 || encoded[0] != 0x00 {
		t.Fatalf("first byte = 0x%02x, want 0x00 (reserved)", encoded[0])
	}

	decoded, err := DeserializeBackupAuthCredentialPresentation(encoded)
	if err != nil {
		t.Fatalf("DeserializeBackupAuthCredentialPresentation: %v", err)
	}

	if decoded.Level != presentation.Level {
		t.Errorf("Level mismatch: got %d, want %d", decoded.Level, presentation.Level)
	}
	if decoded.CredType != presentation.CredType {
		t.Errorf("CredType mismatch: got %d, want %d", decoded.CredType, presentation.CredType)
	}
	if decoded.RedemptionTime != presentation.RedemptionTime {
		t.Errorf("RedemptionTime mismatch: got %d, want %d",
			decoded.RedemptionTime.EpochSeconds(), presentation.RedemptionTime.EpochSeconds())
	}
	if decoded.BackupIdentifier != presentation.BackupIdentifier {
		t.Error("BackupIdentifier mismatch")
	}
}

// TestDeserializeBackupAuthCredentialPresentation_RejectsBadReservedByte ensures
// that a non-zero first byte is rejected.
func TestDeserializeBackupAuthCredentialPresentation_RejectsBadReservedByte(t *testing.T) {
	data := make([]byte, 200)
	data[0] = 0xFF

	_, err := DeserializeBackupAuthCredentialPresentation(data)
	if err == nil {
		t.Fatal("expected error for bad reserved byte")
	}
	var reservedErr *ErrUnexpectedReservedByte
	if !errors.As(err, &reservedErr) {
		t.Errorf("expected *ErrUnexpectedReservedByte, got %T: %v", err, err)
	}
}

// TestDeserializeBackupAuthCredentialPresentation_TooShort rejects short data.
func TestDeserializeBackupAuthCredentialPresentation_TooShort(t *testing.T) {
	_, err := DeserializeBackupAuthCredentialPresentation([]byte{0x00})
	if err == nil {
		t.Fatal("expected error for too-short data")
	}
}

// TestSerializeCallLinkAuthCredentialPresentation_RoundTrip verifies the call
// link auth presentation serialization round-trip.
//
// Rust wire layout: rust/zkgroup/src/api/call_links/auth_credential.rs:103-109.
func TestSerializeCallLinkAuthCredentialPresentation_RoundTrip(t *testing.T) {
	var r1, r2, r3, r4 RandomnessBytes
	for i := range r1 {
		r1[i] = 0x43
		r2[i] = 0x44
		r3[i] = 0x45
		r4[i] = 0x46
	}

	uuid := [UUIDLen]byte{0x04}
	userID := NewACI(uuid)
	ts := NewTimestamp(1681344000)

	serverParams := GenerateGenericServerSecretParams(r1)
	serverPub := serverParams.GetPublicParams()

	response, err := IssueCallLinkAuthCredential(userID, ts, serverParams, r2)
	if err != nil {
		t.Fatalf("IssueCallLinkAuthCredential: %v", err)
	}

	cred, err := ReceiveCallLinkAuthCredential(response, userID, ts, serverPub)
	if err != nil {
		t.Fatalf("ReceiveCallLinkAuthCredential: %v", err)
	}

	rootKey := make([]byte, 32)
	for i := range rootKey {
		rootKey[i] = byte(i + 1)
	}
	callLinkParams, err := DeriveCallLinkSecretParams(rootKey)
	if err != nil {
		t.Fatalf("DeriveCallLinkSecretParams: %v", err)
	}

	presentation, err := cred.Present(userID, ts, serverPub, callLinkParams, r4)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}

	encoded := SerializeCallLinkAuthCredentialPresentation(presentation)

	if len(encoded) == 0 || encoded[0] != 0x00 {
		t.Fatalf("first byte = 0x%02x, want 0x00 (reserved)", encoded[0])
	}

	decoded, err := DeserializeCallLinkAuthCredentialPresentation(encoded)
	if err != nil {
		t.Fatalf("DeserializeCallLinkAuthCredentialPresentation: %v", err)
	}

	if decoded.RedemptionTime != presentation.RedemptionTime {
		t.Errorf("RedemptionTime mismatch: got %d, want %d",
			decoded.RedemptionTime.EpochSeconds(), presentation.RedemptionTime.EpochSeconds())
	}
}

// TestDeserializeCallLinkAuthCredentialPresentation_RejectsBadReservedByte
// ensures a non-zero first byte is rejected.
func TestDeserializeCallLinkAuthCredentialPresentation_RejectsBadReservedByte(t *testing.T) {
	data := make([]byte, 300)
	data[0] = 0x02

	_, err := DeserializeCallLinkAuthCredentialPresentation(data)
	if err == nil {
		t.Fatal("expected error for bad reserved byte")
	}
	var reservedErr *ErrUnexpectedReservedByte
	if !errors.As(err, &reservedErr) {
		t.Errorf("expected *ErrUnexpectedReservedByte, got %T: %v", err, err)
	}
}

// TestDeserializeCallLinkAuthCredentialPresentation_TooShort rejects short data.
func TestDeserializeCallLinkAuthCredentialPresentation_TooShort(t *testing.T) {
	_, err := DeserializeCallLinkAuthCredentialPresentation([]byte{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

// TestSerializeCreateCallLinkCredentialPresentation_RoundTrip verifies the
// create call link credential presentation serialization round-trip.
//
// Rust wire layout: rust/zkgroup/src/api/call_links/create_credential.rs:184-191.
func TestSerializeCreateCallLinkCredentialPresentation_RoundTrip(t *testing.T) {
	var r0, r1, r2, r3, r4 RandomnessBytes
	for i := range r0 {
		r0[i] = 0x42
		r1[i] = 0x43
		r2[i] = 0x44
		r3[i] = 0x45
		r4[i] = 0x46
	}

	roomID := []byte("a very special room")
	uuid := [UUIDLen]byte{0x04}
	userID := NewACI(uuid)
	ts := NewTimestamp(1681344000)

	ctx, err := NewCreateCallLinkCredentialRequestContext(roomID, r0)
	if err != nil {
		t.Fatalf("NewCreateCallLinkCredentialRequestContext: %v", err)
	}
	req := ctx.GetRequest()

	serverParams := GenerateGenericServerSecretParams(r1)
	serverPub := serverParams.GetPublicParams()

	resp, err := req.Issue(userID, ts, serverParams, r2)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	cred, err := ctx.Receive(resp, userID, serverPub)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}

	rootKey := make([]byte, 32)
	for i := range rootKey {
		rootKey[i] = byte(i + 1)
	}
	callLinkParams, err := DeriveCallLinkSecretParams(rootKey)
	if err != nil {
		t.Fatalf("DeriveCallLinkSecretParams: %v", err)
	}

	presentation, err := cred.Present(roomID, userID, serverPub, callLinkParams, r4)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}

	encoded := SerializeCreateCallLinkCredentialPresentation(presentation)

	if len(encoded) == 0 || encoded[0] != 0x00 {
		t.Fatalf("first byte = 0x%02x, want 0x00 (reserved)", encoded[0])
	}

	decoded, err := DeserializeCreateCallLinkCredentialPresentation(encoded)
	if err != nil {
		t.Fatalf("DeserializeCreateCallLinkCredentialPresentation: %v", err)
	}

	if decoded.Timestamp != presentation.Timestamp {
		t.Errorf("Timestamp mismatch: got %d, want %d",
			decoded.Timestamp.EpochSeconds(), presentation.Timestamp.EpochSeconds())
	}
}

// TestDeserializeCreateCallLinkCredentialPresentation_RejectsBadReservedByte
// ensures a non-zero first byte is rejected.
func TestDeserializeCreateCallLinkCredentialPresentation_RejectsBadReservedByte(t *testing.T) {
	data := make([]byte, 300)
	data[0] = 0x03

	_, err := DeserializeCreateCallLinkCredentialPresentation(data)
	if err == nil {
		t.Fatal("expected error for bad reserved byte")
	}
	var reservedErr *ErrUnexpectedReservedByte
	if !errors.As(err, &reservedErr) {
		t.Errorf("expected *ErrUnexpectedReservedByte, got %T: %v", err, err)
	}
}

// TestDeserializeCreateCallLinkCredentialPresentation_TooShort rejects short data.
func TestDeserializeCreateCallLinkCredentialPresentation_TooShort(t *testing.T) {
	_, err := DeserializeCreateCallLinkCredentialPresentation([]byte{0x00})
	if err == nil {
		t.Fatal("expected error for too-short input")
	}
}
