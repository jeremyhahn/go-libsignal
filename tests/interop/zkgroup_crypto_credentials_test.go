// zkgroup credential MAC fixture (Rust credentials.rs test_mac); the MAC path is unexported, so only the fixture is checked.
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

// TestZKGroup_CryptoCredentials_FixtureWellFormed checks the fixture parses and mac_bytes_hex is 160 bytes.
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
