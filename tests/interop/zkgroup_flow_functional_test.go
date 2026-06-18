// Functional round-trip conformance tests for zkgroup credential flows that
// have no static hex vectors in the Rust test suite.
//
// Each test mirrors the corresponding Rust test file exactly — same canonical
// randomness seeds, same ServiceID byte values, same room IDs, same timestamps,
// same flow order — so that any algorithmic divergence from the Rust reference
// implementation will cause the round-trip to fail rather than pass silently.
//
// Sources:
//   - rust/zkgroup/tests/backup_auth_flow.rs   → TestZkgroupFlow_BackupAuth
//   - rust/zkgroup/tests/call_link_flow.rs      → TestZkgroupFlow_CallLinkCreateCredential
//                                                  TestZkgroupFlow_CallLinkCreateEnforcesTimestamp
//                                                  TestZkgroupFlow_CallLinkAuthCredential
//                                                  TestZkgroupFlow_CallLinkAuthEnforcesTimestamp
//   - rust/zkgroup/tests/group_send_endorsements.rs → TestZkgroupFlow_GroupSendEndorsement
//                                                       TestZkgroupFlow_GroupSendSingleMember
//                                                       TestZkgroupFlow_GroupSendRejectsExpiration
//   - rust/zkgroup/tests/receipt_flow.rs        → TestZkgroupFlow_ReceiptApi
//                                                  TestZkgroupFlow_ReceiptRejectsNonDayAligned

package interop

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"
)

// dayAlignedTimestamp mirrors DAY_ALIGNED_TIMESTAMP in the Rust tests:
// 1681344000 = 2023-04-13 00:00:00 UTC.
const dayAlignedTimestamp uint64 = 1681344000

// ---- Backup auth flow -------------------------------------------------------

// TestZkgroupFlow_BackupAuth mirrors backup_auth_flow.rs::test_backup_auth_request_response.
// Uses canonical seeds: randomness1=[0x43;32], randomness2=[0x44;32], randomness3=[0x45;32],
// backup_key=[0x46;32], ACI=c0fc16e4-bae5-4343-9f0d-e7ecf4251343.
func TestZkgroupFlow_BackupAuth(t *testing.T) {
	var r1, r2, r3 [32]byte
	fill32(&r1, 0x43)
	fill32(&r2, 0x44)
	fill32(&r3, 0x45)

	var backupKey [32]byte
	fill32(&backupKey, 0x46)

	aciBytes := [16]byte{
		0xc0, 0xfc, 0x16, 0xe4, 0xba, 0xe5, 0x43, 0x43,
		0x9f, 0x0d, 0xe7, 0xec, 0xf4, 0x25, 0x13, 0x43,
	}
	aci := zkgroup.NewACI(aciBytes)

	redemptionTime := zkgroup.NewTimestamp(dayAlignedTimestamp)
	backupLevel := zkgroup.BackupLevelFree
	credType := zkgroup.BackupCredentialTypeMessages

	// client: derive request context (deterministic from backup_key + aci).
	ctx, err := zkgroup.NewBackupAuthCredentialRequestContext(backupKey, aci)
	if err != nil {
		t.Fatalf("NewBackupAuthCredentialRequestContext: %v", err)
	}
	req := ctx.GetRequest()

	// server: issue.
	serverParams := zkgroup.GenerateGenericServerSecretParams(r1)
	resp, err := req.Issue(redemptionTime, backupLevel, credType, serverParams, r2)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// client: receive.
	serverPublic := serverParams.GetPublicParams()
	cred, err := ctx.Receive(resp, serverPublic, redemptionTime)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if cred.GetBackupLevel() != backupLevel {
		t.Errorf("backup level: got %v, want %v", cred.GetBackupLevel(), backupLevel)
	}
	if cred.GetCredentialType() != credType {
		t.Errorf("credential type: got %v, want %v", cred.GetCredentialType(), credType)
	}

	// client: present.
	presentation, err := cred.Present(serverPublic, r3)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}

	// server: verify.
	if err := presentation.Verify(redemptionTime, serverParams); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// ---- Call link flow ---------------------------------------------------------

// TestZkgroupFlow_CallLinkCreateCredential mirrors
// call_link_flow.rs::test_create_call_link_request_response.
// Uses seeds: r0=[0x42;32], r1=[0x43;32], r2=[0x44;32], r3=[0x45;32], r4=[0x46;32],
// user_id=[0x04;16], room_id="a very special room".
func TestZkgroupFlow_CallLinkCreateCredential(t *testing.T) {
	var r0, r1, r2, r3, r4 [32]byte
	fill32(&r0, 0x42)
	fill32(&r1, 0x43)
	fill32(&r2, 0x44)
	fill32(&r3, 0x45)
	fill32(&r4, 0x46)

	var userIDBytes [16]byte
	fill16(&userIDBytes, 0x04)
	clientUserID := zkgroup.NewACI(userIDBytes)

	timestamp := zkgroup.NewTimestamp(dayAlignedTimestamp)
	roomID := []byte("a very special room")

	// client: create request context.
	reqCtx, err := zkgroup.NewCreateCallLinkCredentialRequestContext(roomID, r0)
	if err != nil {
		t.Fatalf("NewCreateCallLinkCredentialRequestContext: %v", err)
	}
	req := reqCtx.GetRequest()

	// server: issue.
	serverParams := zkgroup.GenerateGenericServerSecretParams(r1)
	resp, err := req.Issue(clientUserID, timestamp, serverParams, r2)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// client: receive.
	serverPublic := serverParams.GetPublicParams()
	cred, err := reqCtx.Receive(resp, clientUserID, serverPublic)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}

	// client: derive call link params and present.
	callLinkParams, err := zkgroup.DeriveCallLinkSecretParams(r3[:])
	if err != nil {
		t.Fatalf("DeriveCallLinkSecretParams: %v", err)
	}

	presentation, err := cred.Present(roomID, clientUserID, serverPublic, callLinkParams, r4)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}

	// server: verify.
	callLinkPublic := callLinkParams.GetPublicParams()
	if err := presentation.Verify(roomID, timestamp, serverParams, callLinkPublic); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// server: verify with time too early (sub_seconds(1) = one second before issue time).
	earlyTime := zkgroup.NewTimestamp(dayAlignedTimestamp - 1)
	if err := presentation.Verify(roomID, earlyTime, serverParams, callLinkPublic); err == nil {
		t.Fatal("Verify should fail before issue timestamp")
	}

	// server: verify with time too late (30 hours after issue = 108000s).
	lateTime := zkgroup.NewTimestamp(dayAlignedTimestamp + 30*60*60)
	if err := presentation.Verify(roomID, lateTime, serverParams, callLinkPublic); err == nil {
		t.Fatal("Verify should fail 30 hours after expiration")
	}

	// server: verify with wrong room ID.
	if err := presentation.Verify([]byte("a much more boring room"), timestamp, serverParams, callLinkPublic); err == nil {
		t.Fatal("Verify should fail for different room")
	}

	// client: decrypt user ID from presentation.
	recovered, err := callLinkParams.DecryptUID(presentation.GetUserID())
	if err != nil {
		t.Fatalf("DecryptUID: %v", err)
	}
	if recovered != clientUserID {
		t.Errorf("decrypted user ID %v != original %v", recovered, clientUserID)
	}
}

// TestZkgroupFlow_CallLinkCreateEnforcesTimestamp mirrors
// call_link_flow.rs::test_create_call_link_enforces_timestamp_granularity.
func TestZkgroupFlow_CallLinkCreateEnforcesTimestamp(t *testing.T) {
	var r0, r1, r2 [32]byte
	fill32(&r0, 0x42)
	fill32(&r1, 0x43)
	fill32(&r2, 0x44)

	var userIDBytes [16]byte
	fill16(&userIDBytes, 0x04)
	clientUserID := zkgroup.NewACI(userIDBytes)

	// Not on a day boundary: dayAligned + 1 hour.
	timestamp := zkgroup.NewTimestamp(dayAlignedTimestamp + 60*60)
	roomID := []byte("a very special room")

	reqCtx, err := zkgroup.NewCreateCallLinkCredentialRequestContext(roomID, r0)
	if err != nil {
		t.Fatalf("NewCreateCallLinkCredentialRequestContext: %v", err)
	}
	req := reqCtx.GetRequest()

	serverParams := zkgroup.GenerateGenericServerSecretParams(r1)
	resp, err := req.Issue(clientUserID, timestamp, serverParams, r2)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	serverPublic := serverParams.GetPublicParams()
	_, err = reqCtx.Receive(resp, clientUserID, serverPublic)
	if err == nil {
		t.Fatal("Receive should reject non-day-aligned timestamp")
	}
}

// TestZkgroupFlow_CallLinkAuthCredential mirrors
// call_link_flow.rs::test_auth_credential.
func TestZkgroupFlow_CallLinkAuthCredential(t *testing.T) {
	var r1, r2, r3, r4 [32]byte
	fill32(&r1, 0x43)
	fill32(&r2, 0x44)
	fill32(&r3, 0x45)
	fill32(&r4, 0x46)

	var userIDBytes [16]byte
	fill16(&userIDBytes, 0x04)
	clientUserID := zkgroup.NewACI(userIDBytes)

	timestamp := zkgroup.NewTimestamp(dayAlignedTimestamp)

	// server: issue.
	serverParams := zkgroup.GenerateGenericServerSecretParams(r1)
	resp, err := zkgroup.IssueCallLinkAuthCredential(clientUserID, timestamp, serverParams, r2)
	if err != nil {
		t.Fatalf("IssueCallLinkAuthCredential: %v", err)
	}

	// client: receive.
	serverPublic := serverParams.GetPublicParams()
	cred, err := zkgroup.ReceiveCallLinkAuthCredential(resp, clientUserID, timestamp, serverPublic)
	if err != nil {
		t.Fatalf("ReceiveCallLinkAuthCredential: %v", err)
	}

	callLinkParams, err := zkgroup.DeriveCallLinkSecretParams(r3[:])
	if err != nil {
		t.Fatalf("DeriveCallLinkSecretParams: %v", err)
	}

	// client: present.
	presentation, err := cred.Present(clientUserID, timestamp, serverPublic, callLinkParams, r4)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}

	callLinkPublic := callLinkParams.GetPublicParams()

	// server: verify at issue time — valid.
	if err := presentation.Verify(timestamp, serverParams, callLinkPublic); err != nil {
		t.Fatalf("Verify at issue time: %v", err)
	}

	// server: verify one day later — still valid (window is 2 days).
	oneDayLater := zkgroup.NewTimestamp(dayAlignedTimestamp + zkgroup.SecondsPerDay)
	if err := presentation.Verify(oneDayLater, serverParams, callLinkPublic); err != nil {
		t.Fatalf("Verify one day later: %v", err)
	}

	// server: verify more than two days + 1s later — must reject.
	tooLate := zkgroup.NewTimestamp(dayAlignedTimestamp + 2*zkgroup.SecondsPerDay + 1)
	if err := presentation.Verify(tooLate, serverParams, callLinkPublic); err == nil {
		t.Fatal("Verify should fail more than two days later")
	}

	// server: verify more than one day before — must reject.
	tooEarly := zkgroup.NewTimestamp(dayAlignedTimestamp - zkgroup.SecondsPerDay - 1)
	if err := presentation.Verify(tooEarly, serverParams, callLinkPublic); err == nil {
		t.Fatal("Verify should fail more than one day early")
	}

	// client: decrypt user ID from presentation.
	recovered, err := callLinkParams.DecryptUID(presentation.GetUserID())
	if err != nil {
		t.Fatalf("DecryptUID: %v", err)
	}
	if recovered != clientUserID {
		t.Errorf("decrypted user ID %v != original %v", recovered, clientUserID)
	}
}

// TestZkgroupFlow_CallLinkAuthEnforcesTimestamp mirrors
// call_link_flow.rs::test_auth_credential_enforces_timestamp_granularity.
func TestZkgroupFlow_CallLinkAuthEnforcesTimestamp(t *testing.T) {
	var r1, r2 [32]byte
	fill32(&r1, 0x43)
	fill32(&r2, 0x44)

	var userIDBytes [16]byte
	fill16(&userIDBytes, 0x04)
	clientUserID := zkgroup.NewACI(userIDBytes)

	// Not on a day boundary: dayAligned + 1 hour.
	timestamp := zkgroup.NewTimestamp(dayAlignedTimestamp + 60*60)

	serverParams := zkgroup.GenerateGenericServerSecretParams(r1)
	resp, err := zkgroup.IssueCallLinkAuthCredential(clientUserID, timestamp, serverParams, r2)
	if err != nil {
		t.Fatalf("IssueCallLinkAuthCredential: %v", err)
	}

	serverPublic := serverParams.GetPublicParams()
	_, err = zkgroup.ReceiveCallLinkAuthCredential(resp, clientUserID, timestamp, serverPublic)
	if err == nil {
		t.Fatal("ReceiveCallLinkAuthCredential should reject non-day-aligned timestamp")
	}
}

// ---- Group send endorsement flow -------------------------------------------

// groupSendMoxieUUID and groupSendBrianUUID match the UUIDs in
// group_send_endorsements.rs::test_endorsement.
var (
	groupSendMoxieUUID = [16]byte{
		0xe3, 0x6f, 0xdc, 0xe7, 0x36, 0xda, 0x4c, 0x6f,
		0xa2, 0x1b, 0x9a, 0xfe, 0x2b, 0x75, 0x46, 0x50,
	}
	groupSendBrianUUID = [16]byte{
		0x8c, 0x78, 0xcd, 0x2a, 0x16, 0xff, 0x42, 0x7d,
		0x83, 0xdc, 0x1a, 0x5e, 0x36, 0xce, 0x71, 0x3d,
	}
)

// TestZkgroupFlow_GroupSendEndorsement mirrors
// group_send_endorsements.rs::test_endorsement.
// Tests both receive_with_service_ids and receive_with_ciphertexts paths.
func TestZkgroupFlow_GroupSendEndorsement(t *testing.T) {
	var r1, r2, r3 [32]byte
	fill32(&r1, 0x43)
	fill32(&r2, 0x44)
	fill32(&r3, 0x45)

	var clientUUIDBuf [16]byte
	fill16(&clientUUIDBuf, 0x04)
	clientUserID := zkgroup.NewACI(clientUUIDBuf)
	moxieUserID := zkgroup.NewACI(groupSendMoxieUUID)
	brianUserID := zkgroup.NewACI(groupSendBrianUUID)

	groupMembers := []zkgroup.ServiceID{
		clientUserID,
		moxieUserID,
		brianUserID,
	}

	groupParams, err := zkgroup.GenerateGroupSecretParams(r1)
	if err != nil {
		t.Fatalf("GenerateGroupSecretParams: %v", err)
	}

	ciphertexts := make([]*zkgroup.UUIDCiphertext, len(groupMembers))
	for i, m := range groupMembers {
		ciphertexts[i] = groupParams.EncryptServiceID(m)
	}

	serverParams, err := zkgroup.GenerateServerSecretParams(r2)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}

	// Expiration = dayAligned + 1 day (matches Rust: DAY_ALIGNED_TIMESTAMP.add_seconds(SECONDS_PER_DAY)).
	expiration := zkgroup.NewTimestamp(dayAlignedTimestamp + zkgroup.SecondsPerDay)
	todaysKey, err := zkgroup.ForExpiration(expiration, serverParams.EndorsementKeyPair)
	if err != nil {
		t.Fatalf("ForExpiration: %v", err)
	}

	serverPublic := serverParams.GetPublicParams()

	// Test receive_with_service_ids path.
	t.Run("receive_with_service_ids", func(t *testing.T) {
		resp, err := zkgroup.IssueGroupSendEndorsements(ciphertexts, todaysKey, r3)
		if err != nil {
			t.Fatalf("IssueGroupSendEndorsements: %v", err)
		}

		now := zkgroup.NewTimestamp(dayAlignedTimestamp)
		received, err := resp.ReceiveWithServiceIDs(groupMembers, now, serverPublic.EndorsementPublicKey, groupParams)
		if err != nil {
			t.Fatalf("ReceiveWithServiceIDs: %v", err)
		}
		if len(received) != len(groupMembers) {
			t.Fatalf("received %d endorsements, want %d", len(received), len(groupMembers))
		}

		decompressed := make([]*zkgroup.GroupSendEndorsement, len(received))
		for i, r := range received {
			decompressed[i] = r.Decompressed
		}

		// combine, remove client, to_token, into_full_token.
		combined := zkgroup.CombineGroupSendEndorsements(decompressed).Remove(decompressed[0])
		token := combined.ToToken(groupParams.UIDEncKeyPair).IntoFullToken(resp.Expiration)

		if token.GetExpiration() != resp.Expiration {
			t.Errorf("token expiration %v != response expiration %v", token.GetExpiration(), resp.Expiration)
		}

		// Verify against the group members without the requester (client removed).
		membersWithoutClient := []zkgroup.ServiceID{brianUserID, moxieUserID}
		if err := token.Verify(membersWithoutClient, now, todaysKey); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	})

	// Test receive_with_ciphertexts path.
	t.Run("receive_with_ciphertexts", func(t *testing.T) {
		resp, err := zkgroup.IssueGroupSendEndorsements(ciphertexts, todaysKey, r3)
		if err != nil {
			t.Fatalf("IssueGroupSendEndorsements: %v", err)
		}

		now := zkgroup.NewTimestamp(dayAlignedTimestamp)
		received, err := resp.ReceiveWithCiphertexts(ciphertexts, now, serverPublic.EndorsementPublicKey)
		if err != nil {
			t.Fatalf("ReceiveWithCiphertexts: %v", err)
		}
		if len(received) != len(groupMembers) {
			t.Fatalf("received %d endorsements, want %d", len(received), len(groupMembers))
		}

		decompressed := make([]*zkgroup.GroupSendEndorsement, len(received))
		for i, r := range received {
			decompressed[i] = r.Decompressed
		}

		combined := zkgroup.CombineGroupSendEndorsements(decompressed).Remove(decompressed[0])
		token := combined.ToToken(groupParams.UIDEncKeyPair).IntoFullToken(resp.Expiration)

		if token.GetExpiration() != resp.Expiration {
			t.Errorf("token expiration %v != response expiration %v", token.GetExpiration(), resp.Expiration)
		}

		membersWithoutClient := []zkgroup.ServiceID{brianUserID, moxieUserID}
		now = zkgroup.NewTimestamp(dayAlignedTimestamp)
		if err := token.Verify(membersWithoutClient, now, todaysKey); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	})
}

// TestZkgroupFlow_GroupSendSingleMember mirrors
// group_send_endorsements.rs::test_single_member_group.
func TestZkgroupFlow_GroupSendSingleMember(t *testing.T) {
	var r1, r2, r3 [32]byte
	fill32(&r1, 0x43)
	fill32(&r2, 0x44)
	fill32(&r3, 0x45)

	var clientUUIDBuf [16]byte
	fill16(&clientUUIDBuf, 0x04)
	clientUserID := zkgroup.NewACI(clientUUIDBuf)

	groupParams, err := zkgroup.GenerateGroupSecretParams(r1)
	if err != nil {
		t.Fatalf("GenerateGroupSecretParams: %v", err)
	}
	ct := groupParams.EncryptServiceID(clientUserID)

	serverParams, err := zkgroup.GenerateServerSecretParams(r2)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}

	expiration := zkgroup.NewTimestamp(dayAlignedTimestamp + zkgroup.SecondsPerDay)
	todaysKey, err := zkgroup.ForExpiration(expiration, serverParams.EndorsementKeyPair)
	if err != nil {
		t.Fatalf("ForExpiration: %v", err)
	}

	resp, err := zkgroup.IssueGroupSendEndorsements([]*zkgroup.UUIDCiphertext{ct}, todaysKey, r3)
	if err != nil {
		t.Fatalf("IssueGroupSendEndorsements: %v", err)
	}

	serverPublic := serverParams.GetPublicParams()
	now := zkgroup.NewTimestamp(dayAlignedTimestamp)
	received, err := resp.ReceiveWithServiceIDs(
		[]zkgroup.ServiceID{clientUserID},
		now,
		serverPublic.EndorsementPublicKey,
		groupParams,
	)
	if err != nil {
		t.Fatalf("ReceiveWithServiceIDs: %v", err)
	}
	if len(received) != 1 {
		t.Fatalf("received %d endorsements, want 1", len(received))
	}
}

// TestZkgroupFlow_GroupSendRejectsExpiration mirrors
// group_send_endorsements.rs::test_client_rejects_bad_expirations.
func TestZkgroupFlow_GroupSendRejectsExpiration(t *testing.T) {
	var r1, r2, r3 [32]byte
	fill32(&r1, 0x43)
	fill32(&r2, 0x44)
	fill32(&r3, 0x45)

	var clientUUIDBuf [16]byte
	fill16(&clientUUIDBuf, 0x04)
	clientUserID := zkgroup.NewACI(clientUUIDBuf)

	moxieUserID := zkgroup.NewACI(groupSendMoxieUUID)
	brianUserID := zkgroup.NewACI(groupSendBrianUUID)

	groupMembers := []zkgroup.ServiceID{clientUserID, moxieUserID, brianUserID}

	groupParams, err := zkgroup.GenerateGroupSecretParams(r1)
	if err != nil {
		t.Fatalf("GenerateGroupSecretParams: %v", err)
	}
	ciphertexts := make([]*zkgroup.UUIDCiphertext, len(groupMembers))
	for i, m := range groupMembers {
		ciphertexts[i] = groupParams.EncryptServiceID(m)
	}

	serverParams, err := zkgroup.GenerateServerSecretParams(r2)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}
	serverPublic := serverParams.GetPublicParams()

	now := zkgroup.NewTimestamp(dayAlignedTimestamp)

	expectReject := func(t *testing.T, nowTS, expirationTS zkgroup.Timestamp) {
		t.Helper()
		key, err := zkgroup.ForExpiration(expirationTS, serverParams.EndorsementKeyPair)
		if err != nil {
			t.Fatalf("ForExpiration: %v", err)
		}
		resp, err := zkgroup.IssueGroupSendEndorsements(ciphertexts, key, r3)
		if err != nil {
			t.Fatalf("IssueGroupSendEndorsements: %v", err)
		}
		_, err = resp.ReceiveWithServiceIDs(
			[]zkgroup.ServiceID{clientUserID},
			nowTS,
			serverPublic.EndorsementPublicKey,
			groupParams,
		)
		if err == nil {
			t.Errorf("ReceiveWithServiceIDs should reject now=%v expiration=%v",
				nowTS.EpochSeconds(), expirationTS.EpochSeconds())
		}
	}

	// Rust cases: expiration == now (not strictly after now), expiration < now,
	// expiration = now + 1s (not day aligned), expiration = now + 8 days,
	// expiration = now + 1000 days.
	expectReject(t, now, now)
	expectReject(t, now, zkgroup.NewTimestamp(dayAlignedTimestamp-zkgroup.SecondsPerDay))
	expectReject(t, now, zkgroup.NewTimestamp(dayAlignedTimestamp+1))
	expectReject(t, now, zkgroup.NewTimestamp(dayAlignedTimestamp+8*zkgroup.SecondsPerDay))
	expectReject(t, now, zkgroup.NewTimestamp(dayAlignedTimestamp+1000*zkgroup.SecondsPerDay))
}

// ---- Receipt flow -----------------------------------------------------------

// TestZkgroupFlow_ReceiptApi mirrors receipt_flow.rs::test_api.
// Uses seeds: r0=[0x42;32], r1=[0x43;32], r2=[0x44;32], r3=[0x45;32],
// serial=[0x84;16], expiration=31337 days, level=3.
func TestZkgroupFlow_ReceiptApi(t *testing.T) {
	var r0, r1, r2, r3 [32]byte
	fill32(&r0, 0x42)
	fill32(&r1, 0x43)
	fill32(&r2, 0x44)
	fill32(&r3, 0x45)

	var serial [16]byte
	fill16(&serial, 0x84)

	serverParams, err := zkgroup.GenerateServerSecretParams(r0)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}
	serverPublic := serverParams.GetPublicParams()

	// client: create context.
	ctx := serverPublic.CreateReceiptCredentialRequestContext(r1, serial)
	req := ctx.GetRequest()

	// server: issue response.
	receiptExpiration := zkgroup.NewTimestamp(31337 * zkgroup.SecondsPerDay)
	const receiptLevel zkgroup.ReceiptLevel = 3
	resp, err := serverParams.IssueReceiptCredential(r2, req, receiptExpiration, receiptLevel)
	if err != nil {
		t.Fatalf("IssueReceiptCredential: %v", err)
	}

	// client: receive.
	cred, err := serverPublic.ReceiveReceiptCredential(ctx, resp)
	if err != nil {
		t.Fatalf("ReceiveReceiptCredential: %v", err)
	}

	// client: present.
	presentation, err := serverPublic.CreateReceiptCredentialPresentation(r3, cred)
	if err != nil {
		t.Fatalf("CreateReceiptCredentialPresentation: %v", err)
	}

	// server: verify.
	if err := serverParams.VerifyReceiptCredentialPresentation(presentation); err != nil {
		t.Fatalf("VerifyReceiptCredentialPresentation: %v", err)
	}

	// Assert presentation properties match Rust constants.
	if presentation.GetReceiptLevel() != receiptLevel {
		t.Errorf("receipt level: got %v, want %v", presentation.GetReceiptLevel(), receiptLevel)
	}
	if presentation.GetReceiptExpirationTime() != receiptExpiration {
		t.Errorf("receipt expiration: got %v, want %v",
			presentation.GetReceiptExpirationTime().EpochSeconds(),
			receiptExpiration.EpochSeconds())
	}

	// Tamper with the presentation: flip a byte and expect verification to fail.
	// Rust does: presentation_bytes[i] += 1 where i = len - 17.
	serialized := zkgroup.SerializeReceiptCredentialPresentation(presentation)
	if len(serialized) < 17 {
		t.Fatalf("presentation too short: %d bytes", len(serialized))
	}
	tampered := make([]byte, len(serialized))
	copy(tampered, serialized)
	tampered[len(tampered)-17] ^= 0x01
	badPresentation, err := zkgroup.DeserializeReceiptCredentialPresentation(tampered)
	if err != nil {
		t.Fatalf("DeserializeReceiptCredentialPresentation tampered: %v", err)
	}
	if err := serverParams.VerifyReceiptCredentialPresentation(badPresentation); err == nil {
		t.Fatal("VerifyReceiptCredentialPresentation should reject tampered presentation")
	}
}

// TestZkgroupFlow_ReceiptRejectsNonDayAligned mirrors
// receipt_flow.rs::test_api_rejects_non_day_aligned_receipt_expiration_time.
// Uses seeds: r0=[0x52;32], r1=[0x53;32], r2=[0x54;32], serial=[0x94;16],
// expiration=42 (seconds — not day-aligned), level=3.
func TestZkgroupFlow_ReceiptRejectsNonDayAligned(t *testing.T) {
	var r0, r1, r2 [32]byte
	fill32(&r0, 0x52)
	fill32(&r1, 0x53)
	fill32(&r2, 0x54)

	var serial [16]byte
	fill16(&serial, 0x94)

	serverParams, err := zkgroup.GenerateServerSecretParams(r0)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}
	serverPublic := serverParams.GetPublicParams()

	ctx := serverPublic.CreateReceiptCredentialRequestContext(r1, serial)
	req := ctx.GetRequest()

	notDayAligned := zkgroup.NewTimestamp(42) // 42 seconds is NOT day-aligned
	const receiptLevel zkgroup.ReceiptLevel = 3
	resp, err := serverParams.IssueReceiptCredential(r2, req, notDayAligned, receiptLevel)
	if err != nil {
		t.Fatalf("IssueReceiptCredential: %v", err)
	}

	_, err = serverPublic.ReceiveReceiptCredential(ctx, resp)
	if err == nil {
		t.Fatal("ReceiveReceiptCredential should reject non-day-aligned expiration")
	}
}

// ---- helpers ----------------------------------------------------------------

func fill32(b *[32]byte, v byte) {
	for i := range b {
		b[i] = v
	}
}

func fill16(b *[16]byte, v byte) {
	for i := range b {
		b[i] = v
	}
}
