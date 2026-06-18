// Conformance test: Fingerprint wire-format parity vs Rust libsignal.
//
// Drives pkg/fingerprint with the seeded inputs the Rust emitter used in
// tests/interop/rust/src/bin/wire_emitter.rs and asserts byte-equality of
// the Displayable text and Scannable serialized bytes for both v1 and v2.
//
// Rust upstream: rust/protocol/src/fingerprint.rs (libsignal v0.92.2)

package interop

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/fingerprint"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

type fingerprintWireFixture struct {
	Source  string `json:"source"`
	RustRev string `json:"rust_rev"`
	Purpose string `json:"purpose"`
	Vectors []struct {
		Name   string `json:"name"`
		Inputs struct {
			AliceIdentityPublic string `json:"alice_identity_public"`
			AliceStableID       string `json:"alice_stable_id"`
			BobIdentityPublic   string `json:"bob_identity_public"`
			BobStableID         string `json:"bob_stable_id"`
			Iterations          uint32 `json:"iterations"`
		} `json:"inputs"`
		Expected struct {
			DisplayableV1    string `json:"displayable_v1"`
			DisplayableV2    string `json:"displayable_v2"`
			AliceScannableV1 string `json:"alice_scannable_v1_hex"`
			AliceScannableV2 string `json:"alice_scannable_v2_hex"`
			BobScannableV1   string `json:"bob_scannable_v1_hex"`
			BobScannableV2   string `json:"bob_scannable_v2_hex"`
		} `json:"expected"`
	} `json:"vectors"`
}

func decodeIdentityKey(t *testing.T, hexStr string) *identity.Key {
	t.Helper()
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("hex decode identity key: %v", err)
	}
	pub, err := ecc.DecodePoint(raw, 0)
	if err != nil {
		t.Fatalf("DecodePoint identity key: %v", err)
	}
	return identity.NewKey(pub)
}

func TestFingerprintWire(t *testing.T) {
	raw := loader.MustRead("wire/fingerprint.json")
	var fix fingerprintWireFixture
	if err := json.Unmarshal(raw, &fix); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if len(fix.Vectors) == 0 {
		t.Fatalf("fixture has no vectors")
	}

	for _, v := range fix.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			aliceKey := decodeIdentityKey(t, v.Inputs.AliceIdentityPublic)
			bobKey := decodeIdentityKey(t, v.Inputs.BobIdentityPublic)
			aliceID := []byte(v.Inputs.AliceStableID)
			bobID := []byte(v.Inputs.BobStableID)

			gen, err := fingerprint.NewNumericFingerprintGenerator(v.Inputs.Iterations)
			if err != nil {
				t.Fatalf("NewNumericFingerprintGenerator: %v", err)
			}

			// Per the Rust upstream, the displayable fingerprint is independent
			// of the version, so v1 and v2 must produce the same string.
			aliceFpV1, err := gen.CreateFor(1, aliceID, aliceKey, bobID, bobKey)
			if err != nil {
				t.Fatalf("CreateFor alice v1: %v", err)
			}
			aliceFpV2, err := gen.CreateFor(2, aliceID, aliceKey, bobID, bobKey)
			if err != nil {
				t.Fatalf("CreateFor alice v2: %v", err)
			}

			gotDisplayV1 := aliceFpV1.Display().DisplayText()
			if gotDisplayV1 != v.Expected.DisplayableV1 {
				t.Errorf("displayable_v1 mismatch:\n got  %s\n want %s", gotDisplayV1, v.Expected.DisplayableV1)
			}
			gotDisplayV2 := aliceFpV2.Display().DisplayText()
			if gotDisplayV2 != v.Expected.DisplayableV2 {
				t.Errorf("displayable_v2 mismatch:\n got  %s\n want %s", gotDisplayV2, v.Expected.DisplayableV2)
			}

			aliceScanV1, err := aliceFpV1.Scannable().Serialize()
			if err != nil {
				t.Fatalf("Scannable.Serialize alice v1: %v", err)
			}
			wantAliceV1, err := hex.DecodeString(v.Expected.AliceScannableV1)
			if err != nil {
				t.Fatalf("hex decode alice_scannable_v1: %v", err)
			}
			if !bytes.Equal(aliceScanV1, wantAliceV1) {
				t.Errorf("alice scannable v1 mismatch:\n got  %s\n want %s",
					hex.EncodeToString(aliceScanV1), v.Expected.AliceScannableV1)
			}

			aliceScanV2, err := aliceFpV2.Scannable().Serialize()
			if err != nil {
				t.Fatalf("Scannable.Serialize alice v2: %v", err)
			}
			wantAliceV2, err := hex.DecodeString(v.Expected.AliceScannableV2)
			if err != nil {
				t.Fatalf("hex decode alice_scannable_v2: %v", err)
			}
			if !bytes.Equal(aliceScanV2, wantAliceV2) {
				t.Errorf("alice scannable v2 mismatch:\n got  %s\n want %s",
					hex.EncodeToString(aliceScanV2), v.Expected.AliceScannableV2)
			}

			// Bob-as-local: arguments swapped.
			bobFpV1, err := gen.CreateFor(1, bobID, bobKey, aliceID, aliceKey)
			if err != nil {
				t.Fatalf("CreateFor bob v1: %v", err)
			}
			bobFpV2, err := gen.CreateFor(2, bobID, bobKey, aliceID, aliceKey)
			if err != nil {
				t.Fatalf("CreateFor bob v2: %v", err)
			}

			bobScanV1, err := bobFpV1.Scannable().Serialize()
			if err != nil {
				t.Fatalf("Scannable.Serialize bob v1: %v", err)
			}
			wantBobV1, err := hex.DecodeString(v.Expected.BobScannableV1)
			if err != nil {
				t.Fatalf("hex decode bob_scannable_v1: %v", err)
			}
			if !bytes.Equal(bobScanV1, wantBobV1) {
				t.Errorf("bob scannable v1 mismatch:\n got  %s\n want %s",
					hex.EncodeToString(bobScanV1), v.Expected.BobScannableV1)
			}

			bobScanV2, err := bobFpV2.Scannable().Serialize()
			if err != nil {
				t.Fatalf("Scannable.Serialize bob v2: %v", err)
			}
			wantBobV2, err := hex.DecodeString(v.Expected.BobScannableV2)
			if err != nil {
				t.Fatalf("hex decode bob_scannable_v2: %v", err)
			}
			if !bytes.Equal(bobScanV2, wantBobV2) {
				t.Errorf("bob scannable v2 mismatch:\n got  %s\n want %s",
					hex.EncodeToString(bobScanV2), v.Expected.BobScannableV2)
			}
		})
	}
}
