//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 3 tests in this file exercise X25519. FIPS 140-3 does not approve that,
// but the X3DH key agreement specification (section 2.1) requires it, so the
// fips140only build tag drops this file from the FIPS gate. `make test` and
// `make coverage` still run it.

// M4: Sesame device-list serialization interop fixture.
//
// SCOPE DETERMINATION: Sesame is NOT a standalone protocol in Rust libsignal.
// The Rust codebase references "Sesame" as a session management pattern in
// rust/protocol/src/session_management.rs but there is no separate serialization
// format, dedicated crate, or Sesame-specific wire fixture emitter in Rust
// libsignal at the pinned commit (98915c44).
//
// The Go pkg/sesame package implements a multi-device manager on top of the
// Signal protocol session primitives.  Its internal state (DeviceRecord,
// UserRecord, SessionWrapper) is Go-only and has no Rust counterpart to compare
// against byte-for-byte.
//
// CONCLUSION: No Rust-emitted Sesame fixture can be produced.  This file
// contains Go-only round-trip consistency tests that verify the Go Sesame
// data model is self-consistent without cross-language comparison.
//
// If Rust libsignal ever adds a dedicated Sesame serialization format at the
// wire level, this file should be replaced with a Rust fixture loader and a
// `make interop-wire-emit` workflow entry.

package interop_test

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/sesame"
)

// TestSesameDeviceRecord_IdentityKeyRoundTrip verifies that identity key data
// assigned to a DeviceRecord survives an in-memory lifecycle (set, get, compare).
// This is a Go-only consistency test since no Rust Sesame wire fixture exists.
func TestSesameDeviceRecord_IdentityKeyRoundTrip(t *testing.T) {
	kp, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	idKey := identity.NewKey(kp.PublicKey())
	record := sesame.NewDeviceRecordWithIdentity(1, idKey)

	// DeviceID must be preserved.
	if record.DeviceID() != 1 {
		t.Errorf("DeviceID = %d, want 1", record.DeviceID())
	}

	// Identity key public bytes must be identical.
	got := record.IdentityKey().PublicKey().Serialize()
	want := kp.PublicKey().Serialize()
	if len(got) != len(want) {
		t.Fatalf("identity key length: got %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("identity key byte %d: got 0x%02x, want 0x%02x", i, got[i], want[i])
		}
	}
}

// TestSesameDeviceRecord_UniquePerDevice verifies that two DeviceRecords with
// distinct device IDs are distinct objects.
func TestSesameDeviceRecord_UniquePerDevice(t *testing.T) {
	kp1, _ := ecc.GenerateKeyPair()
	kp2, _ := ecc.GenerateKeyPair()

	r1 := sesame.NewDeviceRecordWithIdentity(1, identity.NewKey(kp1.PublicKey()))
	r2 := sesame.NewDeviceRecordWithIdentity(2, identity.NewKey(kp2.PublicKey()))

	if r1.DeviceID() == r2.DeviceID() {
		t.Error("two records with distinct device IDs must not share a device ID")
	}

	s1 := r1.IdentityKey().PublicKey().Serialize()
	s2 := r2.IdentityKey().PublicKey().Serialize()
	same := len(s1) == len(s2)
	if same {
		for i := range s1 {
			if s1[i] != s2[i] {
				same = false
				break
			}
		}
	}
	if same {
		t.Error("two DeviceRecords with different keys have identical identity key serializations")
	}
}

// TestSesameUserRecord_AddDeviceAndRetrieve verifies that adding a device to a
// UserRecord and retrieving it by device ID returns the same record.
func TestSesameUserRecord_AddDeviceAndRetrieve(t *testing.T) {
	record := sesame.NewUserRecord("user-123")

	kp, _ := ecc.GenerateKeyPair()
	idKey := identity.NewKey(kp.PublicKey())

	got, err := record.AddDeviceWithIdentity(42, idKey, 0)
	if err != nil {
		t.Fatalf("AddDeviceWithIdentity: %v", err)
	}
	if got == nil {
		t.Fatal("AddDeviceWithIdentity returned nil device")
	}
	if got.DeviceID() != 42 {
		t.Errorf("DeviceID = %d, want 42", got.DeviceID())
	}

	retrieved := record.GetDevice(42)
	if retrieved == nil {
		t.Fatal("GetDevice(42) returned nil after AddDeviceWithIdentity")
	}
	if retrieved.DeviceID() != 42 {
		t.Errorf("retrieved DeviceID = %d, want 42", retrieved.DeviceID())
	}
}
