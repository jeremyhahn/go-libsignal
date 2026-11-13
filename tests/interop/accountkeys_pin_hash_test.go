//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 1 test in this file exercises HKDF-SHA256 under an eight-byte key. FIPS
// 140-3 does not approve that, but the key is the username, which Rust
// PinHash::make_salt (rust/account-keys/src/hash.rs) feeds to HKDF as input
// key material, and the vector pins it to "username", so the fips140only
// build tag drops this file from the FIPS gate. `make test` and `make
// coverage` still run it.

// Conformance test: PIN hashing and salt derivation against Rust libsignal.
//
// Mirrors the inline tests in rust/account-keys/src/hash.rs:
//   - known_hash, known_hash2 → PinHash::create (Argon2id 16MiB / t=32 / out=64)
//   - known_salt              → PinHash::make_salt (HKDF-SHA-256 over username + group_id)
//   - known_phc_string        → local_pin_hash_with_salt (Argon2i 512KiB / t=64 / out=32)
//
// All hex constants are tracked by MANIFEST.toml and the drift detector
// fails CI if any literal disappears from the upstream Rust source.

package interop

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/accountkeys"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret/secrettest"
)

type pinHashCase struct {
	Name              string `json:"name"`
	Pin               string `json:"pin"`
	SaltHex           string `json:"salt_hex"`
	ExpectedAccessKey string `json:"expected_access_key_hex"`
}

type makeSaltCase struct {
	Username        string `json:"username"`
	GroupID         uint64 `json:"group_id"`
	ExpectedSaltHex string `json:"expected_salt_hex"`
}

type localPHCCase struct {
	Pin         string `json:"pin"`
	SaltHex     string `json:"salt_hex"`
	ExpectedPHC string `json:"expected_phc"`
}

type pinHashFixture struct {
	Argon2idPinHash []pinHashCase `json:"argon2id_pin_hash"`
	MakeSalt        makeSaltCase  `json:"make_salt"`
	LocalPinPHC     localPHCCase  `json:"local_pin_phc"`
}

func loadPinHashFixture(t *testing.T) pinHashFixture {
	t.Helper()
	raw := loader.MustRead("accountkeys/pin_hash_known_answers.json")
	var fx pinHashFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("decode pin_hash fixture: %v", err)
	}
	if len(fx.Argon2idPinHash) == 0 {
		t.Fatal("fixture has no argon2id cases")
	}
	return fx
}

// TestAccountKeys_PinHash_AccessKey_KAT exercises every Argon2id KAT.
// Rust splits the 64-byte hash into [encryption_key=first 32 || access_key=last 32];
// the test asserts the access_key half byte-matches.
func TestAccountKeys_PinHash_AccessKey_KAT(t *testing.T) {
	fx := loadPinHashFixture(t)

	for _, c := range fx.Argon2idPinHash {
		t.Run(c.Name, func(t *testing.T) {
			salt, err := hex.DecodeString(c.SaltHex)
			if err != nil {
				t.Fatalf("decode salt: %v", err)
			}
			want, err := hex.DecodeString(c.ExpectedAccessKey)
			if err != nil {
				t.Fatalf("decode expected access key: %v", err)
			}

			ph, err := accountkeys.HashPin(c.Pin, salt)
			if err != nil {
				t.Fatalf("HashPin: %v", err)
			}
			defer ph.Zeroize()

			if !secrettest.Matches(t, ph.AccessKey, want) {
				t.Fatalf("access key mismatch")
			}
		})
	}
}

// TestAccountKeys_MakeSalt_KAT verifies that PinHash::make_salt's HKDF-SHA-256
// derivation produces byte-identical output to Rust for the canonical
// (username, group_id) input.
func TestAccountKeys_MakeSalt_KAT(t *testing.T) {
	fx := loadPinHashFixture(t)

	want, err := hex.DecodeString(fx.MakeSalt.ExpectedSaltHex)
	if err != nil {
		t.Fatalf("decode expected salt: %v", err)
	}

	got := accountkeys.MakeSalt(fx.MakeSalt.Username, fx.MakeSalt.GroupID)
	if !bytes.Equal(got[:], want) {
		t.Fatalf("MakeSalt mismatch:\n  got  %x\n  want %x", got, want)
	}
}

// TestAccountKeys_LocalPinPHC_KAT exercises the deterministic local-pin-hash
// PHC string format. Argon2i parameters (m=512, t=64, p=1, output=32) are
// embedded in the PHC string itself, so a byte-identical PHC string proves
// the Argon2i parameter set, salt encoding, and output encoding all match
// Rust libsignal-account-keys.
func TestAccountKeys_LocalPinPHC_KAT(t *testing.T) {
	fx := loadPinHashFixture(t)

	// Go's accountkeys.LocalPinHash uses a random salt, so we cannot
	// deterministically rebuild the exact PHC string from a public API.
	// Instead, assert the *verifier* round-trips on the Rust-produced PHC
	// string: a successful verify proves Go's Argon2i implementation
	// (algorithm, version, m, t, p, output_len, salt encoding, hash
	// encoding) is byte-compatible with Rust's.
	ok, err := accountkeys.VerifyLocalPinHash(fx.LocalPinPHC.Pin, fx.LocalPinPHC.ExpectedPHC)
	if err != nil {
		t.Fatalf("VerifyLocalPinHash on Rust PHC: %v", err)
	}
	if !ok {
		t.Fatalf("VerifyLocalPinHash returned false on Rust-produced PHC %q", fx.LocalPinPHC.ExpectedPHC)
	}

	// Negative case: a different pin must NOT verify.
	ok2, err := accountkeys.VerifyLocalPinHash("wrongpin", fx.LocalPinPHC.ExpectedPHC)
	if err != nil {
		t.Fatalf("VerifyLocalPinHash(wrongpin): %v", err)
	}
	if ok2 {
		t.Fatal("expected wrong pin to fail verification")
	}

	// Sanity: the PHC string we expect from Rust starts with the canonical
	// $argon2i$ prefix; if the upstream changes algorithm or m/t/p, the
	// drift detector will already have failed before this test runs, but
	// assert here too for in-process clarity.
	if !strings.HasPrefix(fx.LocalPinPHC.ExpectedPHC, "$argon2i$v=19$m=512,t=64,p=1$") {
		t.Fatalf("expected PHC parameter prefix did not match: %q", fx.LocalPinPHC.ExpectedPHC)
	}
}
