//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// MakeSalt feeds the username to HKDF as input key material, matching Rust
// PinHash::make_salt (rust/account-keys/src/hash.rs); the known-answer vector
// uses the eight-byte username "username". crypto/hkdf rejects keys shorter
// than 112 bits under GODEBUG=fips140=only, so this test is excluded from the
// FIPS gate by the fips140only build tag. Everything else in this package
// stays gated.

package accountkeys

import (
	"testing"
)

func TestMakeSalt(t *testing.T) {
	t.Run("known test vector from Rust", func(t *testing.T) {
		// From Rust known_salt test
		username := "username"
		groupID := uint64(3862621253427332054)
		expected := mustDecodeHex("d6159ba30f90b6eb6ccf1ec844427f052baaf0705da849767471744cdb3f8a5e")

		result := MakeSalt(username, groupID)
		if !bytesEqual(result[:], expected) {
			t.Fatalf("salt mismatch\ngot:  %x\nwant: %x", result[:], expected)
		}
	})

	t.Run("different usernames produce different salts", func(t *testing.T) {
		s1 := MakeSalt("alice", 1)
		s2 := MakeSalt("bob", 1)
		if s1 == s2 {
			t.Fatal("different usernames should produce different salts")
		}
	})

	t.Run("different group IDs produce different salts", func(t *testing.T) {
		s1 := MakeSalt("alice", 1)
		s2 := MakeSalt("alice", 2)
		if s1 == s2 {
			t.Fatal("different group IDs should produce different salts")
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		s1 := MakeSalt("test", 42)
		s2 := MakeSalt("test", 42)
		if s1 != s2 {
			t.Fatal("same inputs should produce same salt")
		}
	})
}
