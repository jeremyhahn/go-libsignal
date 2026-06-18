// Conformance test: ServiceId binary encodings vs Rust libsignal_core.
//
// The variable-width binary form is what Rust libsignal uses inside HKDF
// info strings (e.g. derive_backup_id concatenates AccountEntropyPool ||
// ACI::service_id_binary), so byte-equality here is critical for cross-
// implementation key derivation interop.
//
// Mirrors rust/core/src/address.rs::tests::{
//   round_trip_service_id_binary,
//   accepts_ios_system_story_aci,
// }.

package interop

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

type serviceIdVector struct {
	Name                  string `json:"name"`
	Kind                  string `json:"kind"`
	UUID                  string `json:"uuid"`
	ExpectedBinaryHex     string `json:"expected_binary_hex"`
	ExpectedFixedWidthHex string `json:"expected_fixed_width_hex"`
}

type serviceIdFixture struct {
	Vectors []serviceIdVector `json:"vectors"`
}

// uuidStringToBytes parses a hyphenated UUID string into a 16-byte array,
// matching uuid::Uuid::parse_str on the Rust side.
func uuidStringToBytes(t *testing.T, s string) [16]byte {
	t.Helper()
	clean := ""
	for _, r := range s {
		if r == '-' {
			continue
		}
		clean += string(r)
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		t.Fatalf("decode uuid hex: %v", err)
	}
	if len(b) != 16 {
		t.Fatalf("uuid must be 16 bytes; got %d", len(b))
	}
	var arr [16]byte
	copy(arr[:], b)
	return arr
}

// TestServiceId_BinaryEncodings_KAT runs every vector in the fixture
// through both ServiceIdBinary (variable width) and FixedWidthBinary,
// comparing byte for byte against the Rust expected hex.
func TestServiceId_BinaryEncodings_KAT(t *testing.T) {
	raw := loader.MustRead("core/service_id_binary.json")
	var fx serviceIdFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if len(fx.Vectors) == 0 {
		t.Fatal("fixture has no vectors")
	}

	for _, v := range fx.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			uuidBytes := uuidStringToBytes(t, v.UUID)

			var sid protocol.ServiceId
			switch v.Kind {
			case "aci":
				sid = protocol.NewACI(uuidBytes)
			case "pni":
				sid = protocol.NewPNI(uuidBytes)
			default:
				t.Fatalf("unknown kind %q", v.Kind)
			}

			// Variable-width binary: ACI=16 bytes, PNI=17 bytes.
			gotVarHex := hex.EncodeToString(sid.ServiceIdBinary())
			if gotVarHex != v.ExpectedBinaryHex {
				t.Errorf("ServiceIdBinary mismatch:\n  got  %s\n  want %s", gotVarHex, v.ExpectedBinaryHex)
			}

			// Fixed-width binary: always 17 bytes.
			fixed := sid.FixedWidthBinary()
			gotFixedHex := hex.EncodeToString(fixed[:])
			if gotFixedHex != v.ExpectedFixedWidthHex {
				t.Errorf("FixedWidthBinary mismatch:\n  got  %s\n  want %s", gotFixedHex, v.ExpectedFixedWidthHex)
			}

			// Round trip through ServiceIdFromBinary.
			parsed, err := protocol.ServiceIdFromBinary(sid.ServiceIdBinary())
			if err != nil {
				t.Fatalf("ServiceIdFromBinary: %v", err)
			}
			if parsed.Kind() != sid.Kind() {
				t.Errorf("kind round-trip mismatch: got %v want %v", parsed.Kind(), sid.Kind())
			}
			gotUUID := parsed.UUID()
			if !bytes.Equal(gotUUID[:], uuidBytes[:]) {
				t.Errorf("uuid round-trip mismatch:\n  got  %x\n  want %x", gotUUID, uuidBytes)
			}
		})
	}
}

// TestServiceId_FromBinary_RejectsBadLengths mirrors Rust's
// rejects_invalid_binary_lengths test.
func TestServiceId_FromBinary_RejectsBadLengths(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		{0x01},           // single byte
		make([]byte, 15), // one short
		make([]byte, 18), // one long
	}
	for i, c := range cases {
		if _, err := protocol.ServiceIdFromBinary(c); err == nil {
			t.Errorf("case %d (len=%d) accepted; want error", i, len(c))
		}
	}
}

// TestServiceId_FromBinary_RejectsUnknownKind ensures the 17-byte form
// rejects a leading byte that is neither 0x00 (ACI) nor 0x01 (PNI).
func TestServiceId_FromBinary_RejectsUnknownKind(t *testing.T) {
	bad := make([]byte, 17)
	bad[0] = 0xFF
	if _, err := protocol.ServiceIdFromBinary(bad); err == nil {
		t.Fatal("expected error for unknown kind byte 0xFF")
	}
}
