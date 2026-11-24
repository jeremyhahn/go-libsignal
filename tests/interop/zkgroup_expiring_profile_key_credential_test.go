// Conformance: the ExpiringProfileKeyCredential flow with Rust test_integration_expiring_profile inputs serializes to the V3 and V4 presentation results; V4 adds the C_y5 clause.

package interop

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

type expiringProfileKeyCredentialFixture struct {
	ExpectedPresentationV3Hex string `json:"expected_presentation_v3_hex"`
	ExpectedPresentationV4Hex string `json:"expected_presentation_v4_hex"`
	ExpirationSeconds         uint64 `json:"expiration_seconds"`
	CurrentTimeSeconds        uint64 `json:"current_time_seconds"`
}

// TestZkgroup_ExpiringProfileKeyCredentialV3_KAT proves Go's full V3 round
// trip produces a presentation byte-identical to Rust libsignal under the
// canonical test_integration_expiring_profile_v1 seeds.
func TestZkgroup_ExpiringProfileKeyCredentialV3_KAT(t *testing.T) {
	checkExpiringProfileKeyCredentialKAT(t, zkgroup.PresentationVersion3)
}

// TestZkgroup_ExpiringProfileKeyCredentialV4_KAT proves Go's full V4 round
// trip produces a presentation byte-identical to Rust libsignal under the
// canonical test_integration_expiring_profile_v2 seeds. V4 differs from V3
// in the inner PoKShO statement (extra C_y5 = z * G_y5 clause).
func TestZkgroup_ExpiringProfileKeyCredentialV4_KAT(t *testing.T) {
	checkExpiringProfileKeyCredentialKAT(t, zkgroup.PresentationVersion4)
}

func checkExpiringProfileKeyCredentialKAT(t *testing.T, version byte) {
	t.Helper()

	raw := loader.MustRead("zkgroup/expiring_profile_key_credential_known_answers.json")
	var fx expiringProfileKeyCredentialFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	var wantHex string
	switch version {
	case zkgroup.PresentationVersion3:
		wantHex = fx.ExpectedPresentationV3Hex
	case zkgroup.PresentationVersion4:
		wantHex = fx.ExpectedPresentationV4Hex
	default:
		t.Fatalf("unsupported version 0x%02x", version)
	}
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatalf("decode expected presentation: %v", err)
	}

	// Step 1: server params from TEST_ARRAY_32.
	serverSecret, err := zkgroup.GenerateServerSecretParams(fillRange(0))
	if err != nil {
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}
	serverPublic := serverSecret.GetPublicParams()

	// Step 2-3: group derived from TEST_ARRAY_32_1.
	masterKey := zkgroup.NewGroupMasterKey(fillRange(100))
	groupSecret, err := zkgroup.DeriveGroupSecretParams(masterKey)
	if err != nil {
		t.Fatalf("DeriveGroupSecretParams: %v", err)
	}
	groupPublic := groupSecret.GetPublicParams()

	// Step 4-5: aci, profile key.
	aci := zkgroup.NewACI(fillRange16(0))
	profileKey := zkgroup.NewProfileKey(fillRange(100)) // TEST_ARRAY_32_1
	commitment := profileKey.GetCommitment(aci)

	// Step 6: request context with TEST_ARRAY_32_3 randomness.
	// TEST_ARRAY_32_3 = [1, 2, 3, ..., 32] — start byte 1.
	var reqRand [32]byte
	for i := range reqRand {
		reqRand[i] = byte(1 + i)
	}
	ctx, err := serverPublic.CreateProfileKeyCredentialRequestContext(reqRand, aci, profileKey)
	if err != nil {
		t.Fatalf("CreateProfileKeyCredentialRequestContext: %v", err)
	}

	// Step 7: server issues with TEST_ARRAY_32_4 randomness.
	// TEST_ARRAY_32_4 = [2, 3, 4, ..., 33] — start byte 2.
	var issueRand [32]byte
	for i := range issueRand {
		issueRand[i] = byte(2 + i)
	}
	expiration := zkgroup.NewTimestamp(fx.ExpirationSeconds)
	currentTime := zkgroup.NewTimestamp(fx.CurrentTimeSeconds)
	response, err := serverSecret.IssueExpiringProfileKeyCredential(
		issueRand, ctx.GetRequest(), aci, commitment, expiration,
	)
	if err != nil {
		t.Fatalf("IssueExpiringProfileKeyCredential: %v", err)
	}

	// Step 8: client receives.
	credential, err := serverPublic.ReceiveExpiringProfileKeyCredential(
		ctx, response, currentTime,
	)
	if err != nil {
		t.Fatalf("ReceiveExpiringProfileKeyCredential: %v", err)
	}

	// Step 9: present with TEST_ARRAY_32_5 randomness.
	// TEST_ARRAY_32_5 = [3, 4, 5, ..., 34] — start byte 3.
	var presRand [32]byte
	for i := range presRand {
		presRand[i] = byte(3 + i)
	}
	presentation, err := serverPublic.CreateExpiringProfileKeyCredentialPresentation(
		presRand, groupSecret, credential, version,
	)
	if err != nil {
		t.Fatalf("CreateExpiringProfileKeyCredentialPresentation: %v", err)
	}

	// Step 10: serialize and compare byte-for-byte with Rust output.
	got := zkgroup.SerializeExpiringProfileKeyCredentialPresentation(version, presentation)
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("V%d presentation mismatch:\n  got  %s\n  want %s",
			versionNum(version),
			hex.EncodeToString(got), hex.EncodeToString(want))
	}

	// Cross-check: server can verify the presentation we just produced.
	if err := serverSecret.VerifyExpiringProfileKeyCredentialPresentation(
		groupPublic, presentation, currentTime, version,
	); err != nil {
		t.Fatalf("VerifyExpiringProfileKeyCredentialPresentation: %v", err)
	}

	// Cross-check: AnyProfileKeyCredentialPresentation parses our wire bytes
	// to the right version arm.
	any, err := zkgroup.DeserializeAnyProfileKeyCredentialPresentation(got)
	if err != nil {
		t.Fatalf("DeserializeAnyProfileKeyCredentialPresentation: %v", err)
	}
	if any.Version != version {
		t.Fatalf("parsed version 0x%02x, want 0x%02x", any.Version, version)
	}
}

func versionNum(v byte) int {
	switch v {
	case zkgroup.PresentationVersion3:
		return 3
	case zkgroup.PresentationVersion4:
		return 4
	default:
		return -1
	}
}
