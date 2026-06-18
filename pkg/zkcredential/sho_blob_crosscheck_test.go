package zkcredential

// INFO-1: SHO hardcoded-blob cross-check tests.
//
// The Go zkcredential package has two categories of system parameters:
//
//  1. MODERN SystemParams — derived deterministically from a SHO using the
//     "Signal_ZKCredential_ConstantSystemParams_generate_20230410" label.
//     generateSystemParams() is the Go implementation; the constants are
//     never stored as a hardcoded byte blob in Go.
//
//  2. LEGACY LegacySystemParams — parsed from legacyCredentialSystemHardcoded,
//     a verbatim copy of the 544-byte blob emitted by the Rust zkgroup crate's
//     SYSTEM_PARAMS constant (rust/zkgroup/src/crypto/credentials.rs,
//     "Signal_ZKGroup_20200424_Constant_Credentials_SystemParams_Generate").
//     Go does not re-derive these from a SHO; it parses the blob directly and
//     relies on the Rust blob being correct.
//
// These tests prove:
//  a. generateSystemParams() is deterministic and every call produces
//     byte-identical point encodings (no non-determinism in the SHO pipeline).
//  b. legacyCredentialSystemHardcoded decodes to 17 valid ristretto255 points
//     that re-encode to the SAME bytes, confirming blob integrity.
//  c. The cached GetSystemParams() singleton matches a fresh generateSystemParams()
//     call byte-for-byte, confirming the lazy-init path is correct.
//
// If (b) fails it is a bug: either the blob has been corrupted or the parser
// is reading at the wrong offset. If (a) fails it indicates the SHO PRNG is
// not deterministic for this label.

import (
	"encoding/hex"
	"testing"

	"github.com/gtank/ristretto255"
)

// newRistrettoElement returns a new identity ristretto255.Element.
func newRistrettoElement() *ristretto255.Element {
	return ristretto255.NewIdentityElement()
}

// TestSystemParams_SHODerived_Deterministic asserts that generateSystemParams()
// produces byte-identical point encodings across two calls.
// This is the SHO cross-check for the MODERN parameters: both calls run the
// same SHO pipeline and must emit the same points.
func TestSystemParams_SHODerived_Deterministic(t *testing.T) {
	p1 := generateSystemParams()
	p2 := generateSystemParams()

	check := func(name string, a, b interface{ Bytes() []byte }) {
		t.Helper()
		if string(a.Bytes()) != string(b.Bytes()) {
			t.Errorf("point %s differs between two generateSystemParams() calls:\n  first:  %s\n  second: %s",
				name, hex.EncodeToString(a.Bytes()), hex.EncodeToString(b.Bytes()))
		}
	}

	check("Gw", p1.Gw, p2.Gw)
	check("Gwprime", p1.Gwprime, p2.Gwprime)
	check("Gx0", p1.Gx0, p2.Gx0)
	check("Gx1", p1.Gx1, p2.Gx1)
	check("GV", p1.GV, p2.GV)
	check("Gz", p1.Gz, p2.Gz)
	for i := range p1.Gy {
		check(
			string([]byte{'G', 'y', '[', byte('0' + i), ']'}),
			p1.Gy[i], p2.Gy[i],
		)
	}
}

// TestSystemParams_Singleton_MatchesFresh asserts that the lazy-init singleton
// returned by GetSystemParams() produces the same encodings as a fresh
// generateSystemParams() call.
func TestSystemParams_Singleton_MatchesFresh(t *testing.T) {
	singleton := GetSystemParams()
	fresh := generateSystemParams()

	if string(singleton.Gw.Bytes()) != string(fresh.Gw.Bytes()) {
		t.Errorf("singleton Gw != fresh Gw:\n  singleton: %s\n  fresh:     %s",
			hex.EncodeToString(singleton.Gw.Bytes()),
			hex.EncodeToString(fresh.Gw.Bytes()))
	}
	if string(singleton.Gz.Bytes()) != string(fresh.Gz.Bytes()) {
		t.Errorf("singleton Gz != fresh Gz:\n  singleton: %s\n  fresh:     %s",
			hex.EncodeToString(singleton.Gz.Bytes()),
			hex.EncodeToString(fresh.Gz.Bytes()))
	}
	for i := range singleton.Gy {
		if string(singleton.Gy[i].Bytes()) != string(fresh.Gy[i].Bytes()) {
			t.Errorf("singleton Gy[%d] != fresh Gy[%d]", i, i)
		}
	}
}

// TestLegacySystemParams_BlobIntegrity verifies that legacyCredentialSystemHardcoded
// (the verbatim Rust blob) decodes to 17 valid ristretto255 points, each of which
// re-encodes to the SAME bytes. This is the "hardcoded blob cross-check" for the
// LEGACY parameters: parseLegacySystemParams() is the only derivation we have in Go,
// so we verify the blob is self-consistent.
//
// Rust source: rust/zkgroup/src/crypto/credentials.rs
// (Signal_ZKGroup_20200424_Constant_Credentials_SystemParams_Generate)
func TestLegacySystemParams_BlobIntegrity(t *testing.T) {
	blob := legacyCredentialSystemHardcoded[:]

	// There are 17 points in the blob:
	// G_w, G_wprime, G_x0, G_x1, G_y1..G_y6 (6), G_m1..G_m5 (5), G_V, G_z
	const numPoints = 17
	if len(blob) != numPoints*32 {
		t.Fatalf("blob length = %d, want %d", len(blob), numPoints*32)
	}

	for i := 0; i < numPoints; i++ {
		raw := blob[i*32 : (i+1)*32]

		// Parse the point.
		p := newRistrettoElement()
		if _, err := p.SetCanonicalBytes(raw); err != nil {
			t.Errorf("point[%d] (offset %d): invalid ristretto255 encoding: %v\n  bytes: %s",
				i, i*32, err, hex.EncodeToString(raw))
			continue
		}

		// Re-encode and assert byte-equality with the original bytes.
		reEncoded := p.Bytes()
		for j, b := range reEncoded {
			if b != raw[j] {
				t.Errorf("point[%d] (offset %d): round-trip mismatch at byte %d: "+
					"original=0x%02x re-encoded=0x%02x\n  original:   %s\n  re-encoded: %s",
					i, i*32, j, raw[j], b,
					hex.EncodeToString(raw), hex.EncodeToString(reEncoded))
				break
			}
		}
	}
}

// TestLegacySystemParams_AllPointsNonIdentity verifies that no hardcoded point
// in the legacy blob is the identity element. The identity is a degenerate
// generator and would indicate a derivation bug.
func TestLegacySystemParams_AllPointsNonIdentity(t *testing.T) {
	params := GetLegacySystemParams()

	identity := newRistrettoElement() // zero-value is identity

	if params.Gw.Equal(identity) == 1 {
		t.Error("Gw is the identity element")
	}
	if params.Gwprime.Equal(identity) == 1 {
		t.Error("Gwprime is the identity element")
	}
	if params.Gx0.Equal(identity) == 1 {
		t.Error("Gx0 is the identity element")
	}
	if params.Gx1.Equal(identity) == 1 {
		t.Error("Gx1 is the identity element")
	}
	if params.GV.Equal(identity) == 1 {
		t.Error("GV is the identity element")
	}
	if params.Gz.Equal(identity) == 1 {
		t.Error("Gz is the identity element")
	}
	for i, gy := range params.Gy {
		if gy.Equal(identity) == 1 {
			t.Errorf("Gy[%d] is the identity element", i)
		}
	}
	for i, gm := range params.Gm {
		if gm.Equal(identity) == 1 {
			t.Errorf("Gm[%d] is the identity element", i)
		}
	}
}
