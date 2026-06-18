// Conformance test: zkgroup AuthCredentialWithPniZkc end-to-end byte-identical
// to Rust.
//
// Mirrors rust/zkgroup/tests/integration_tests.rs::test_integration_auth_zkc:
//
//   1. server_secret = ServerSecretParams::generate(TEST_ARRAY_32).
//   2. master_key    = GroupMasterKey::new(TEST_ARRAY_32_1).
//   3. group         = GroupSecretParams::derive_from_master_key(master_key).
//   4. aci           = Aci::from(TEST_ARRAY_16).
//   5. pni           = Pni::from(TEST_ARRAY_16_1).
//   6. redemption    = Timestamp::from_epoch_seconds(123456 * SECONDS_PER_DAY).
//   7. response      = AuthCredentialWithPniZkcResponse::issue_credential(
//                          aci, pni, redemption, &server_secret, TEST_ARRAY_32_2).
//   8. credential    = response.receive(aci, pni, redemption, &server_public).
//   9. presentation  = credential.present(&server_public, &group, TEST_ARRAY_32_5).
//  10. bincode::serialize(&presentation) == AUTH_CREDENTIAL_PRESENTATION_V4_RESULT.
//
// This is the only KAT we have today that exercises the *full* auth zkc round
// trip — IssuanceProof generation, Receive verification, PresentationProof
// generation, attribute encryption, and the bincode wire format that goes
// over the wire to the chat service.

package interop

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

type authCredentialWithPniZkcFixture struct {
	ExpectedPresentationV4Hex string `json:"expected_presentation_v4_hex"`
	RedemptionTimeDays        uint64 `json:"redemption_time_days"`
}

// TestZkgroup_AuthCredentialWithPniZkc_KAT proves Go's full auth credential
// zkc round trip (issue → receive → present → serialize) produces a
// PresentationV4 byte sequence byte-identical to Rust libsignal under the
// canonical test_integration_auth_zkc seeds.
func TestZkgroup_AuthCredentialWithPniZkc_KAT(t *testing.T) {
	raw := loader.MustRead("zkgroup/auth_credential_with_pni_zkc_known_answers.json")
	var fx authCredentialWithPniZkcFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	want, err := hex.DecodeString(fx.ExpectedPresentationV4Hex)
	if err != nil {
		t.Fatalf("decode expected presentation: %v", err)
	}

	// Step 1: server params from TEST_ARRAY_32.
	serverSeed := fillRange(0)
	serverSecret, err := zkgroup.GenerateServerSecretParams(serverSeed)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}
	serverPublic := serverSecret.GetPublicParams()

	// Step 2-3: group params derived from TEST_ARRAY_32_1.
	masterKeySeed := fillRange(100)
	masterKey := zkgroup.NewGroupMasterKey(masterKeySeed)
	groupSecret, err := zkgroup.DeriveGroupSecretParams(masterKey)
	if err != nil {
		t.Fatalf("DeriveGroupSecretParams: %v", err)
	}
	groupPublic := groupSecret.GetPublicParams()

	// Step 4-5: ACI(TEST_ARRAY_16), PNI(TEST_ARRAY_16_1).
	aci := zkgroup.NewACI(fillRange16(0))
	pni := zkgroup.NewPNI(fillRange16(100))

	// Step 6: day-aligned redemption time.
	redemption := zkgroup.NewTimestamp(fx.RedemptionTimeDays * zkgroup.SecondsPerDay)
	if !redemption.IsDayAligned() {
		t.Fatal("redemption time not day-aligned (fixture bug)")
	}

	// Step 7: issue credential with TEST_ARRAY_32_2 randomness.
	issueRand := fillRange(200)
	response, err := serverSecret.IssueAuthCredentialWithPniZkc(
		aci, pni, redemption, issueRand,
	)
	if err != nil {
		t.Fatalf("IssueAuthCredentialWithPniZkc: %v", err)
	}

	// Step 8: client receives credential.
	credential, err := serverPublic.ReceiveAuthCredentialWithPniZkc(
		aci, pni, redemption, response,
	)
	if err != nil {
		t.Fatalf("ReceiveAuthCredentialWithPniZkc: %v", err)
	}

	// Step 9: present with TEST_ARRAY_32_5 randomness.
	// TEST_ARRAY_32_5 = [3, 4, 5, ..., 34] — i.e. start byte 3.
	var presRand [32]byte
	for i := range presRand {
		presRand[i] = byte(3 + i)
	}
	presentation, err := serverPublic.CreateAuthCredentialWithPniZkcPresentation(
		credential, groupSecret, presRand,
	)
	if err != nil {
		t.Fatalf("CreateAuthCredentialWithPniZkcPresentation: %v", err)
	}

	// Step 10: serialize and compare byte-for-byte with Rust output.
	got := zkgroup.SerializeAuthCredentialWithPniZkcPresentation(presentation)
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("AuthCredentialWithPniZkc V4 presentation mismatch:\n  got  %s\n  want %s",
			hex.EncodeToString(got), hex.EncodeToString(want))
	}

	// Cross-check: the server can verify the wire-format presentation we
	// just produced, against the same redemption time.
	parsed, err := zkgroup.DeserializeAnyAuthCredentialPresentation(got)
	if err != nil {
		t.Fatalf("DeserializeAnyAuthCredentialPresentation round trip: %v", err)
	}
	if err := serverSecret.VerifyAuthCredentialWithPniZkcPresentation(
		groupPublic, parsed.Presentation, redemption,
	); err != nil {
		t.Fatalf("VerifyAuthCredentialWithPniZkcPresentation: %v", err)
	}

	// Sanity: the parsed PNI ciphertext must match a fresh group encryption
	// of the PNI service id (mirrors Rust's get_pni_ciphertext assertion).
	want2 := groupSecret.EncryptServiceID(pni)
	if !parsed.Presentation.PNICiphertext.Ciphertext.Equal(want2.Ciphertext) {
		t.Fatal("parsed PNI ciphertext differs from group_secret.encrypt(PNI)")
	}
}
