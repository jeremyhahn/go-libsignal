// Conformance test: GroupSendEndorsementsResponse wire parity vs Rust libsignal.
//
// This test loads the Rust-emitted fixture and:
//   1. Deserializes the response_hex bytes into a GroupSendEndorsementsResponse
//      using Go's DeserializeGroupSendEndorsementsResponse.
//   2. Regenerates the server public params and group secret params from the
//      pinned seeds recorded in the fixture (deterministic, no RNG).
//   3. Calls ReceiveWithServiceIDs([Alice, Bob, Carol], now, server_public_key,
//      group_params) and asserts all three endorsements are received.
//
// A fixture only has value if Rust genuinely emits it and Go independently
// consumes and verifies it. The endorsement proof is a Schnorr-style DLEQ
// proof over the three members' ciphertext points; a mismatch in any byte of
// the R vector or proof would cause Receive to fail its poksho verification.
//
// Rust source: rust/zkgroup/src/api/groups/group_send_endorsement.rs
//              GroupSendDerivedKeyPair::for_expiration + GroupSendEndorsementsResponse::issue
//              (libsignal v0.92.2, RUST_REV 98915c442d)

package interop

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

// groupSendEndorsementsWireFixture is the JSON schema for
// tests/interop/fixtures/wire/group_send_endorsements.json.
type groupSendEndorsementsWireFixture struct {
	Source  string `json:"source"`
	RustRev string `json:"rust_rev"`
	Purpose string `json:"purpose"`
	Vectors []struct {
		Name   string `json:"name"`
		Inputs struct {
			ServerRandomnessHex string `json:"server_randomness_hex"`
			GroupRandomnessHex  string `json:"group_randomness_hex"`
			ExpirationSecs      uint64 `json:"expiration_secs"`
			AliceUUID           string `json:"alice_uuid"`
			BobUUID             string `json:"bob_uuid"`
			CarolUUID           string `json:"carol_uuid"`
		} `json:"inputs"`
		Expected struct {
			ResponseHex    string `json:"response_hex"`
			ExpirationSecs uint64 `json:"expiration_secs"`
		} `json:"expected"`
	} `json:"vectors"`
}

// TestGroupSendEndorsementsResponse_WireInterop proves that Go's
// DeserializeGroupSendEndorsementsResponse produces a structurally valid
// response from bytes emitted by Rust's zkgroup::serialize, and that
// ReceiveWithServiceIDs independently validates the embedded proof.
func TestGroupSendEndorsementsResponse_WireInterop(t *testing.T) {
	raw := loader.MustRead("wire/group_send_endorsements.json")
	var fx groupSendEndorsementsWireFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	if len(fx.Vectors) == 0 {
		t.Fatal("fixture has no vectors")
	}
	v := fx.Vectors[0]

	// Decode the Rust-emitted wire bytes.
	responseBytes, err := hex.DecodeString(v.Expected.ResponseHex)
	if err != nil {
		t.Fatalf("decode response_hex: %v", err)
	}

	// Step 1: Deserialize the wire bytes into a GroupSendEndorsementsResponse.
	resp, err := zkgroup.DeserializeGroupSendEndorsementsResponse(responseBytes)
	if err != nil {
		t.Fatalf("DeserializeGroupSendEndorsementsResponse: %v", err)
	}

	// Verify the expiration round-trips correctly.
	if resp.Expiration.EpochSeconds() != v.Expected.ExpirationSecs {
		t.Errorf("expiration mismatch: got %d, want %d",
			resp.Expiration.EpochSeconds(), v.Expected.ExpirationSecs)
	}

	// Step 2: Decode the pinned seeds and regenerate server+group params.
	serverRandomnessBin, err := hex.DecodeString(v.Inputs.ServerRandomnessHex)
	if err != nil {
		t.Fatalf("decode server_randomness_hex: %v", err)
	}
	groupRandomnessBin, err := hex.DecodeString(v.Inputs.GroupRandomnessHex)
	if err != nil {
		t.Fatalf("decode group_randomness_hex: %v", err)
	}

	var serverRandomness [32]byte
	copy(serverRandomness[:], serverRandomnessBin)
	var groupRandomness zkgroup.RandomnessBytes
	copy(groupRandomness[:], groupRandomnessBin)

	serverSecret, err := zkgroup.GenerateServerSecretParams(serverRandomness)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}
	serverPublicKey := serverSecret.GetPublicParams().EndorsementPublicKey

	groupParams, err := zkgroup.GenerateGroupSecretParams(groupRandomness)
	if err != nil {
		t.Fatalf("GenerateGroupSecretParams: %v", err)
	}

	// Step 3: Build the three ServiceIDs from the fixture UUIDs.
	aliceUUID := mustParseUUID(t, v.Inputs.AliceUUID)
	bobUUID := mustParseUUID(t, v.Inputs.BobUUID)
	carolUUID := mustParseUUID(t, v.Inputs.CarolUUID)

	serviceIDs := []zkgroup.ServiceID{
		zkgroup.NewACI(aliceUUID),
		zkgroup.NewACI(bobUUID),
		zkgroup.NewACI(carolUUID),
	}

	// Step 4: Choose a `now` within the valid window.
	// Expiration is 2 days = 172800 seconds; the window requires:
	//   remaining > 2h  ⟹  now < expiration - 2h
	//   remaining < 7d  ⟹  now > expiration - 7d (trivially satisfied here)
	// We pick now = 1 day = 86400 seconds.
	now := zkgroup.NewTimestamp(zkgroup.SecondsPerDay)

	// Step 5: Verify the endorsements — this validates the embedded proof.
	received, err := resp.ReceiveWithServiceIDs(serviceIDs, now, serverPublicKey, groupParams)
	if err != nil {
		t.Fatalf("ReceiveWithServiceIDs: %v — wire proof verification failed", err)
	}
	if len(received) != len(serviceIDs) {
		t.Errorf("received count: got %d, want %d", len(received), len(serviceIDs))
	}
	for i, r := range received {
		if r == nil {
			t.Errorf("received[%d] is nil", i)
			continue
		}
		if r.Compressed == nil {
			t.Errorf("received[%d].Compressed is nil", i)
		}
		if r.Decompressed == nil {
			t.Errorf("received[%d].Decompressed is nil", i)
		}
	}

	// Step 6: Re-serialize and assert the bytes are byte-identical to the fixture.
	// This is the core of the wire-compat claim: Go's serializer must reproduce
	// the exact same byte sequence that Rust emitted.
	reserialized := zkgroup.SerializeGroupSendEndorsementsResponse(resp)
	if hex.EncodeToString(reserialized) != v.Expected.ResponseHex {
		t.Errorf("re-serialized bytes differ from Rust-emitted bytes:\n  got  %s\n  want %s",
			hex.EncodeToString(reserialized), v.Expected.ResponseHex)
	}
}

// mustParseUUID parses a UUID string into a [16]byte, failing the test on error.
func mustParseUUID(t *testing.T, uuidStr string) [16]byte {
	t.Helper()
	// UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	// Strip dashes and hex-decode.
	stripped := ""
	for _, ch := range uuidStr {
		if ch != '-' {
			stripped += string(ch)
		}
	}
	b, err := hex.DecodeString(stripped)
	if err != nil || len(b) != 16 {
		t.Fatalf("parse UUID %q: %v", uuidStr, err)
	}
	var arr [16]byte
	copy(arr[:], b)
	return arr
}
