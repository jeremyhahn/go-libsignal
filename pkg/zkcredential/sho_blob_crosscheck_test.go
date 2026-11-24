package zkcredential

// System parameter cross-checks: generateSystemParams is deterministic and equals the cached GetSystemParams, and the 544-byte legacy blob from Rust zkgroup decodes to 17 valid points that re-encode identically.

import (
	"encoding/hex"
	"testing"

	"github.com/gtank/ristretto255"
)

// newRistrettoElement returns a new identity ristretto255.Element.
func newRistrettoElement() *ristretto255.Element {
	return ristretto255.NewIdentityElement()
}

// TestSystemParams_SHODerived_Deterministic checks two generateSystemParams calls give identical points.
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

// TestLegacySystemParams_BlobIntegrity checks legacyCredentialSystemHardcoded decodes to 17 valid points that re-encode to the same bytes.
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
