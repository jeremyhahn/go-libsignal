package zkgroup

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// TestSerializeBackupAuthCredentialRequest_RoundTrip verifies the request
// serializer survives a full issue→receive→present cycle: the deserialized
// request must still be functionally equivalent to the original (i.e. server
// can issue a credential from it that the client can receive).
func TestSerializeBackupAuthCredentialRequest_RoundTrip(t *testing.T) {
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

	req := ctx.GetRequest()
	encoded := SerializeBackupAuthCredentialRequest(req)
	if got, want := len(encoded), backupAuthCredentialRequestSize; got != want {
		t.Fatalf("encoded length = %d, want %d", got, want)
	}
	if encoded[0] != 0x00 {
		t.Fatalf("first byte = 0x%02x, want 0x00 (reserved)", encoded[0])
	}

	decoded, err := DeserializeBackupAuthCredentialRequest(encoded)
	if err != nil {
		t.Fatalf("DeserializeBackupAuthCredentialRequest: %v", err)
	}

	// The decoded request must round-trip byte-for-byte.
	reencoded := SerializeBackupAuthCredentialRequest(decoded)
	if !bytes.Equal(encoded, reencoded) {
		t.Errorf("re-encoded bytes differ from original")
	}

	// Functional: issue + receive must succeed with the decoded request.
	var r1, r2 RandomnessBytes
	for i := range r1 {
		r1[i] = 0x43
		r2[i] = 0x44
	}
	serverParams := GenerateGenericServerSecretParams(r1)
	redemption := NewTimestamp(1681344000) // 2023-04-13 UTC, day-aligned
	resp, err := decoded.Issue(redemption, BackupLevelFree, BackupCredentialTypeMessages, serverParams, r2)
	if err != nil {
		t.Fatalf("Issue via decoded request: %v", err)
	}
	publicParams := serverParams.GetPublicParams()
	if _, err := ctx.Receive(resp, publicParams, redemption); err != nil {
		t.Fatalf("Receive: %v", err)
	}
}

// TestSerializeBackupAuthCredentialResponse_RoundTrip verifies the response
// serializer round-trips a real Issue-produced response and that the
// deserialized response is still consumable by Receive.
func TestSerializeBackupAuthCredentialResponse_RoundTrip(t *testing.T) {
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

	var r1, r2 RandomnessBytes
	for i := range r1 {
		r1[i] = 0x43
		r2[i] = 0x44
	}
	serverParams := GenerateGenericServerSecretParams(r1)
	redemption := NewTimestamp(1681344000)
	resp, err := ctx.GetRequest().Issue(redemption, BackupLevelPaid, BackupCredentialTypeMedia, serverParams, r2)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	encoded := SerializeBackupAuthCredentialResponse(resp)
	if encoded[0] != 0x00 {
		t.Fatalf("first byte = 0x%02x, want 0x00 (reserved)", encoded[0])
	}

	decoded, err := DeserializeBackupAuthCredentialResponse(encoded)
	if err != nil {
		t.Fatalf("DeserializeBackupAuthCredentialResponse: %v", err)
	}

	if decoded.RedemptionTime != redemption {
		t.Errorf("RedemptionTime: got %d, want %d", decoded.RedemptionTime.EpochSeconds(), redemption.EpochSeconds())
	}
	if decoded.Level != BackupLevelPaid {
		t.Errorf("Level: got %d, want %d", decoded.Level, BackupLevelPaid)
	}
	if decoded.CredType != BackupCredentialTypeMedia {
		t.Errorf("CredType: got %d, want %d", decoded.CredType, BackupCredentialTypeMedia)
	}

	// Round-trip byte-for-byte.
	reencoded := SerializeBackupAuthCredentialResponse(decoded)
	if !bytes.Equal(encoded, reencoded) {
		t.Errorf("re-encoded bytes differ from original (len got %d, want %d)", len(reencoded), len(encoded))
	}

	// Functional: the decoded response must still drive Receive successfully.
	publicParams := serverParams.GetPublicParams()
	if _, err := ctx.Receive(decoded, publicParams, redemption); err != nil {
		t.Fatalf("Receive of decoded response: %v", err)
	}
}

// TestDeserializeBackupAuthCredentialRequest_RejectsBadReservedByte ensures
// that a non-zero first byte is rejected.
func TestDeserializeBackupAuthCredentialRequest_RejectsBadReservedByte(t *testing.T) {
	data := make([]byte, backupAuthCredentialRequestSize)
	data[0] = 0xFF

	_, err := DeserializeBackupAuthCredentialRequest(data)
	if err == nil {
		t.Fatal("expected error for bad reserved byte")
	}
	var reservedErr *ErrUnexpectedReservedByte
	if !errors.As(err, &reservedErr) {
		t.Errorf("expected *ErrUnexpectedReservedByte, got %T: %v", err, err)
	}
}

// TestDeserializeBackupAuthCredentialRequest_WrongLength rejects inputs that
// do not match the fixed wire size.
func TestDeserializeBackupAuthCredentialRequest_WrongLength(t *testing.T) {
	for _, n := range []int{0, 1, backupAuthCredentialRequestSize - 1, backupAuthCredentialRequestSize + 1} {
		_, err := DeserializeBackupAuthCredentialRequest(make([]byte, n))
		if err == nil {
			t.Errorf("length %d: expected error, got nil", n)
		}
	}
}

// TestDeserializeBackupAuthCredentialResponse_RejectsBadReservedByte ensures
// that a non-zero first byte is rejected.
func TestDeserializeBackupAuthCredentialResponse_RejectsBadReservedByte(t *testing.T) {
	data := make([]byte, 200)
	data[0] = 0xFF

	_, err := DeserializeBackupAuthCredentialResponse(data)
	if err == nil {
		t.Fatal("expected error for bad reserved byte")
	}
	var reservedErr *ErrUnexpectedReservedByte
	if !errors.As(err, &reservedErr) {
		t.Errorf("expected *ErrUnexpectedReservedByte, got %T: %v", err, err)
	}
}

// TestDeserializeBackupAuthCredentialResponse_TooShort rejects truncated
// inputs (less than the fixed-length header).
func TestDeserializeBackupAuthCredentialResponse_TooShort(t *testing.T) {
	_, err := DeserializeBackupAuthCredentialResponse([]byte{0x00})
	if err == nil {
		t.Fatal("expected error for too-short input")
	}
}

// buildValidResponseBlob returns a complete, byte-valid wire blob for a
// BackupAuthCredentialResponse so regression tests can mutate a single field.
func buildValidResponseBlob(t *testing.T) []byte {
	t.Helper()
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
		t.Fatalf("buildValidResponseBlob: NewBackupAuthCredentialRequestContext: %v", err)
	}
	var r1, r2 RandomnessBytes
	for i := range r1 {
		r1[i] = 0x43
		r2[i] = 0x44
	}
	serverParams := GenerateGenericServerSecretParams(r1)
	redemptionTime := NewTimestamp(1681344000)
	resp, err := ctx.GetRequest().Issue(redemptionTime, BackupLevelFree, BackupCredentialTypeMessages, serverParams, r2)
	if err != nil {
		t.Fatalf("buildValidResponseBlob: Issue: %v", err)
	}
	return SerializeBackupAuthCredentialResponse(resp)
}

// TestDeserializeBackupAuthCredentialResponse_InvalidLevel_Regression is a
// regression test for the bug where BackupLevel was read as u64 but cast to
// byte without range or enum validation.
//
// Wire layout for response: reserved(1) + redemption_time(8) + backup_level(8) + …
// Level occupies bytes [9:17].
//
// Before the fix: 256 was truncated to BackupLevel(0), no error.
// After the fix: rejected with a deserialization error.
//
// Rust reference: TryFrom<u64> for BackupLevel at
// rust/zkgroup/src/api/backups/auth_credential.rs:68-78.
func TestDeserializeBackupAuthCredentialResponse_InvalidLevel_Regression(t *testing.T) {
	validBlob := buildValidResponseBlob(t)

	tests := []struct {
		name     string
		levelU64 uint64
	}{
		{"gt_255_truncates_to_0", 256},
		{"gt_255_large", 0xFFFF},
		{"max_uint64", ^uint64(0)},
		{"byte_range_invalid_0", 0},
		{"byte_range_invalid_42", 42},
		{"byte_range_invalid_199", 199},
		{"byte_range_invalid_202", 202},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blob := make([]byte, len(validBlob))
			copy(blob, validBlob)
			// reserved(1) + redemption_time(8) = 9 bytes before level.
			binary.LittleEndian.PutUint64(blob[9:17], tt.levelU64)
			_, err := DeserializeBackupAuthCredentialResponse(blob)
			if err == nil {
				t.Fatalf("level=%d: expected deserialization error, got nil", tt.levelU64)
			}
		})
	}
}

// TestDeserializeBackupAuthCredentialResponse_InvalidCredentialType_Regression
// mirrors the level regression for BackupCredentialType (bytes [17:25]).
//
// Rust reference: TryFrom<u64> for BackupCredentialType at
// rust/zkgroup/src/api/backups/auth_credential.rs:98-108.
func TestDeserializeBackupAuthCredentialResponse_InvalidCredentialType_Regression(t *testing.T) {
	validBlob := buildValidResponseBlob(t)

	tests := []struct {
		name        string
		credTypeU64 uint64
	}{
		{"gt_255", 256},
		{"max_uint64", ^uint64(0)},
		{"byte_range_invalid_0", 0},
		{"byte_range_invalid_3", 3},
		{"byte_range_invalid_99", 99},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blob := make([]byte, len(validBlob))
			copy(blob, validBlob)
			// Set a valid level (200 = BackupLevelFree) so only the credType check fires.
			binary.LittleEndian.PutUint64(blob[9:17], 200)
			// reserved(1) + redemption_time(8) + level(8) = 17 bytes before credType.
			binary.LittleEndian.PutUint64(blob[17:25], tt.credTypeU64)
			_, err := DeserializeBackupAuthCredentialResponse(blob)
			if err == nil {
				t.Fatalf("credType=%d: expected deserialization error, got nil", tt.credTypeU64)
			}
		})
	}
}
