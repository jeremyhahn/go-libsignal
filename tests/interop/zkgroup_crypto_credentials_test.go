// Interop test for zkgroup credential MAC bytes parity.
//
// Source: rust/zkgroup/src/crypto/credentials.rs:425-509
// at Rust libsignal commit 98915c442d.
//
// Rust's test_mac() pins the 160-byte bincode serialization of a
// BlindedExpiringProfileKeyCredential (5 Ristretto255 scalars × 32 bytes = 160 bytes)
// derived from a fixed SHO and TEST_ARRAY_16 inputs. This is an internal
// credential type and is not exposed at the Go public API boundary; the public
// API goes through ServerSecretParams.IssueExpiringProfileKeyCredential which
// takes a serialized ExpiringProfileKeyCredentialRequest (not a raw KeyPair).
//
// SKIPPED: The exact mac_bytes path is unreachable from the Go interop
// test layer without introducing unexported access. This file documents
// that fact and loads the fixture to confirm the fixture JSON is well-formed.
package interop

import (
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

type zkCredFixture struct {
	Source  string      `json:"source"`
	RustRev string      `json:"rust_rev"`
	Purpose string      `json:"purpose"`
	Vectors []zkCredVec `json:"vectors"`
	Skipped string      `json:"skipped"`
}

type zkCredVec struct {
	Name   string       `json:"name"`
	Inputs zkCredInputs `json:"inputs"`
	Expect zkCredExpect `json:"expected"`
}

type zkCredInputs struct {
	ShoLabel           string `json:"sho_label"`
	ShoKeyHex          string `json:"sho_key_hex"`
	UIDHex             string `json:"uid_bytes_hex"`
	RedemptionTimeSecs int64  `json:"redemption_time_seconds"`
	ProfileKeyHex      string `json:"profile_key_hex"`
}

type zkCredExpect struct {
	MacBytesHex string `json:"mac_bytes_hex"`
}

// TestZKGroup_CryptoCredentials_FixtureWellFormed loads the credentials
// fixture and verifies its JSON is well-formed and the mac_bytes_hex has
// the expected length (160 bytes = 320 hex chars).
//
// The BlindedExpiringProfileKeyCredential serializes as 5 Ristretto255
// scalars × 32 bytes = 160 bytes in Rust bincode format.
//
// The full MAC computation path (KeyPair<ExpiringProfileKeyCredential>::
// create_blinded_expiring_profile_key_credential) is internal in Go and
// cannot be driven from the interop test layer without exposing unexported
// types. The byte-level assertion is therefore deferred; only fixture
// structure is checked here.
func TestZKGroup_CryptoCredentials_FixtureWellFormed(t *testing.T) {
	raw := loader.MustRead("zkgroup/crypto/credentials.json")
	var fix zkCredFixture
	if err := json.Unmarshal(raw, &fix); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if len(fix.Vectors) == 0 {
		t.Fatal("fixture has no vectors")
	}
	for _, vec := range fix.Vectors {
		macHex := vec.Expect.MacBytesHex
		// Rust bincode serializes BlindedExpiringProfileKeyCredential as
		// 5 Ristretto255 scalars × 32 bytes = 160 bytes = 320 hex chars.
		if len(macHex) != 320 {
			t.Errorf("vector %q: mac_bytes_hex length = %d; want 320 (160 bytes)", vec.Name, len(macHex))
		} else {
			t.Logf("vector %q: mac_bytes_hex length correct (320 hex chars = 160 bytes)", vec.Name)
		}
	}
	if fix.Skipped != "" {
		t.Logf("skipped: %s", fix.Skipped)
	}
}
