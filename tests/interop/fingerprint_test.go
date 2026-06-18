// Conformance test: Fingerprint generation vs Rust libsignal-protocol.
//
// Mirrors rust/protocol/src/fingerprint.rs::test::{
//   fingerprint_test_v1,
//   fingerprint_test_v2,
//   fingerprint_encodings,
// }.
//
// Validates that Go's NumericFingerprintGenerator.CreateFor with the
// canonical Alice/Bob inputs produces:
//   1. The exact 60-digit displayable string (Rust: DISPLAYABLE_FINGERPRINT_V1).
//   2. The exact v1 scannable protobuf encoding for both Alice and Bob.
//   3. The exact v2 scannable protobuf encoding for both Alice and Bob.

package interop

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/fingerprint"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

type fingerprintFixture struct {
	AliceIdentityHex    string `json:"alice_identity_hex"`
	BobIdentityHex      string `json:"bob_identity_hex"`
	AliceStableID       string `json:"alice_stable_id"`
	BobStableID         string `json:"bob_stable_id"`
	Iterations          uint32 `json:"iterations"`
	DisplayableV1       string `json:"displayable_v1"`
	AliceScannableV1Hex string `json:"alice_scannable_v1_hex"`
	BobScannableV1Hex   string `json:"bob_scannable_v1_hex"`
	AliceScannableV2Hex string `json:"alice_scannable_v2_hex"`
	BobScannableV2Hex   string `json:"bob_scannable_v2_hex"`
}

func loadFingerprintFixture(t *testing.T) fingerprintFixture {
	t.Helper()
	raw := loader.MustRead("protocol/fingerprint_known_answers.json")
	var fx fingerprintFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("decode fingerprint fixture: %v", err)
	}
	return fx
}

func decodeIdentity(t *testing.T, hexStr string) *identity.Key {
	t.Helper()
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("decode identity hex: %v", err)
	}
	pk, err := ecc.DecodePoint(raw, 0)
	if err != nil {
		t.Fatalf("DecodePoint: %v", err)
	}
	return identity.NewKey(pk)
}

// TestFingerprint_V1_KAT generates Alice's and Bob's V1 fingerprints with
// the canonical inputs and asserts byte-identical scannable encodings AND
// the exact 60-digit displayable string.
func TestFingerprint_V1_KAT(t *testing.T) {
	fx := loadFingerprintFixture(t)

	aliceKey := decodeIdentity(t, fx.AliceIdentityHex)
	bobKey := decodeIdentity(t, fx.BobIdentityHex)

	gen, err := fingerprint.NewNumericFingerprintGenerator(fx.Iterations)
	if err != nil {
		t.Fatalf("NewNumericFingerprintGenerator: %v", err)
	}

	const v1 = uint32(1)

	aliceFP, err := gen.CreateFor(v1, []byte(fx.AliceStableID), aliceKey, []byte(fx.BobStableID), bobKey)
	if err != nil {
		t.Fatalf("Alice CreateFor v1: %v", err)
	}
	bobFP, err := gen.CreateFor(v1, []byte(fx.BobStableID), bobKey, []byte(fx.AliceStableID), aliceKey)
	if err != nil {
		t.Fatalf("Bob CreateFor v1: %v", err)
	}

	if got := aliceFP.Display().DisplayText(); got != fx.DisplayableV1 {
		t.Errorf("Alice displayable v1 mismatch:\n  got  %s\n  want %s", got, fx.DisplayableV1)
	}
	if got := bobFP.Display().DisplayText(); got != fx.DisplayableV1 {
		t.Errorf("Bob displayable v1 mismatch (should equal Alice's, fingerprint is symmetric):\n  got  %s\n  want %s", got, fx.DisplayableV1)
	}

	aliceV1Bytes, err := aliceFP.Scannable().Serialize()
	if err != nil {
		t.Fatalf("Alice Scannable Serialize v1: %v", err)
	}
	if got := hex.EncodeToString(aliceV1Bytes); !strings.EqualFold(got, fx.AliceScannableV1Hex) {
		t.Errorf("Alice scannable v1 mismatch:\n  got  %s\n  want %s", got, fx.AliceScannableV1Hex)
	}

	bobV1Bytes, err := bobFP.Scannable().Serialize()
	if err != nil {
		t.Fatalf("Bob Scannable Serialize v1: %v", err)
	}
	if got := hex.EncodeToString(bobV1Bytes); !strings.EqualFold(got, fx.BobScannableV1Hex) {
		t.Errorf("Bob scannable v1 mismatch:\n  got  %s\n  want %s", got, fx.BobScannableV1Hex)
	}
}

// TestFingerprint_V2_KAT generates Alice's and Bob's V2 fingerprints and
// asserts the v2 scannable wire bytes match Rust upstream.
func TestFingerprint_V2_KAT(t *testing.T) {
	fx := loadFingerprintFixture(t)

	aliceKey := decodeIdentity(t, fx.AliceIdentityHex)
	bobKey := decodeIdentity(t, fx.BobIdentityHex)

	gen, err := fingerprint.NewNumericFingerprintGenerator(fx.Iterations)
	if err != nil {
		t.Fatalf("NewNumericFingerprintGenerator: %v", err)
	}

	const v2 = uint32(2)

	aliceFP, err := gen.CreateFor(v2, []byte(fx.AliceStableID), aliceKey, []byte(fx.BobStableID), bobKey)
	if err != nil {
		t.Fatalf("Alice CreateFor v2: %v", err)
	}
	bobFP, err := gen.CreateFor(v2, []byte(fx.BobStableID), bobKey, []byte(fx.AliceStableID), aliceKey)
	if err != nil {
		t.Fatalf("Bob CreateFor v2: %v", err)
	}

	aliceV2Bytes, err := aliceFP.Scannable().Serialize()
	if err != nil {
		t.Fatalf("Alice Scannable Serialize v2: %v", err)
	}
	if got := hex.EncodeToString(aliceV2Bytes); !strings.EqualFold(got, fx.AliceScannableV2Hex) {
		t.Errorf("Alice scannable v2 mismatch:\n  got  %s\n  want %s", got, fx.AliceScannableV2Hex)
	}

	bobV2Bytes, err := bobFP.Scannable().Serialize()
	if err != nil {
		t.Fatalf("Bob Scannable Serialize v2: %v", err)
	}
	if got := hex.EncodeToString(bobV2Bytes); !strings.EqualFold(got, fx.BobScannableV2Hex) {
		t.Errorf("Bob scannable v2 mismatch:\n  got  %s\n  want %s", got, fx.BobScannableV2Hex)
	}
}
