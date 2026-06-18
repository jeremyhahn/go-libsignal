package protocol

import (
	"errors"
	"strings"
	"testing"
)

func TestNewServiceId(t *testing.T) {
	uuid := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}

	sid := NewServiceId(ServiceIdKindACI, uuid)

	if sid.Kind() != ServiceIdKindACI {
		t.Fatalf("expected ACI kind, got %v", sid.Kind())
	}
	if sid.UUID() != uuid {
		t.Fatalf("UUID mismatch")
	}
}

func TestNewACI(t *testing.T) {
	uuid := [16]byte{0xaa, 0xbb, 0xcc, 0xdd}
	sid := NewACI(uuid)

	if sid.Kind() != ServiceIdKindACI {
		t.Fatal("expected ACI kind")
	}
	if sid.UUID() != uuid {
		t.Fatal("UUID mismatch")
	}
}

func TestNewPNI(t *testing.T) {
	uuid := [16]byte{0x11, 0x22, 0x33, 0x44}
	sid := NewPNI(uuid)

	if sid.Kind() != ServiceIdKindPNI {
		t.Fatal("expected PNI kind")
	}
	if sid.UUID() != uuid {
		t.Fatal("UUID mismatch")
	}
}

func TestServiceIdUUIDString(t *testing.T) {
	uuid := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	sid := NewServiceId(ServiceIdKindACI, uuid)

	expected := "01020304-0506-0708-090a-0b0c0d0e0f10"
	if got := sid.UUIDString(); got != expected {
		t.Fatalf("expected %q, got %q", expected, got)
	}
}

func TestServiceIdString(t *testing.T) {
	// ACI prints as a bare UUID (no prefix); PNI prints as "PNI:<uuid>".
	// This matches Rust libsignal_core ServiceId::service_id_string.
	tests := []struct {
		name           string
		kind           ServiceIdKind
		expectPrefix   string
		expectNoPrefix string
	}{
		{
			name:           "ACI is bare UUID with no prefix",
			kind:           ServiceIdKindACI,
			expectNoPrefix: "ACI:",
		},
		{
			name:         "PNI has PNI: prefix",
			kind:         ServiceIdKindPNI,
			expectPrefix: "PNI:",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uuid := [16]byte{}
			sid := NewServiceId(tc.kind, uuid)
			got := sid.String()
			if tc.expectPrefix != "" && !strings.HasPrefix(got, tc.expectPrefix) {
				t.Fatalf("expected %q to have prefix %q", got, tc.expectPrefix)
			}
			if tc.expectNoPrefix != "" && strings.HasPrefix(got, tc.expectNoPrefix) {
				t.Fatalf("ACI String() must not have %q prefix, got %q", tc.expectNoPrefix, got)
			}
		})
	}
}

func TestServiceIdFixedWidthBinary(t *testing.T) {
	uuid := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	sid := NewServiceId(ServiceIdKindPNI, uuid)

	binary := sid.FixedWidthBinary()
	if binary[0] != byte(ServiceIdKindPNI) {
		t.Fatalf("expected PNI kind byte, got %v", binary[0])
	}
	for i := 0; i < 16; i++ {
		if binary[i+1] != uuid[i] {
			t.Fatalf("byte %d mismatch", i)
		}
	}
}

func TestServiceIdFromFixedWidthBinary(t *testing.T) {
	t.Run("valid ACI", func(t *testing.T) {
		uuid := [16]byte{0xaa, 0xbb}
		sid := NewServiceId(ServiceIdKindACI, uuid)
		binary := sid.FixedWidthBinary()

		parsed, err := ServiceIdFromFixedWidthBinary(binary)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if parsed.Kind() != ServiceIdKindACI {
			t.Fatal("kind mismatch")
		}
		if parsed.UUID() != uuid {
			t.Fatal("UUID mismatch")
		}
	})

	t.Run("valid PNI", func(t *testing.T) {
		uuid := [16]byte{0xcc, 0xdd}
		sid := NewServiceId(ServiceIdKindPNI, uuid)
		binary := sid.FixedWidthBinary()

		parsed, err := ServiceIdFromFixedWidthBinary(binary)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if parsed.Kind() != ServiceIdKindPNI {
			t.Fatal("kind mismatch")
		}
	})

	t.Run("unknown kind", func(t *testing.T) {
		data := [17]byte{0xFF}
		_, err := ServiceIdFromFixedWidthBinary(data)
		if err == nil {
			t.Fatal("expected error for unknown kind")
		}
	})
}

func TestServiceIdFromString(t *testing.T) {
	t.Run("standard format with dashes", func(t *testing.T) {
		sid, err := ServiceIdFromString(ServiceIdKindACI, "01020304-0506-0708-090a-0b0c0d0e0f10")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
		if sid.UUID() != expected {
			t.Fatal("UUID mismatch")
		}
	})

	t.Run("plain hex without dashes", func(t *testing.T) {
		sid, err := ServiceIdFromString(ServiceIdKindPNI, "0102030405060708090a0b0c0d0e0f10")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if sid.Kind() != ServiceIdKindPNI {
			t.Fatal("kind mismatch")
		}
	})

	t.Run("invalid length", func(t *testing.T) {
		_, err := ServiceIdFromString(ServiceIdKindACI, "0102")
		if err == nil {
			t.Fatal("expected error for invalid length")
		}
	})

	t.Run("invalid hex", func(t *testing.T) {
		_, err := ServiceIdFromString(ServiceIdKindACI, "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")
		if err == nil {
			t.Fatal("expected error for invalid hex")
		}
	})
}

// TestServiceIdFromBinary_17ByteACIRejected verifies that a 17-byte buffer
// carrying the ACI kind byte (0x00) is rejected. Rust parse_from_service_id_binary
// returns None in this case because ACI must be encoded as exactly 16 bytes.
func TestServiceIdFromBinary_17ByteACIRejected(t *testing.T) {
	// Build a 17-byte buffer: [0x00 (ACI tag)][16 UUID bytes].
	data := make([]byte, 17)
	data[0] = byte(ServiceIdKindACI)
	for i := 1; i < 17; i++ {
		data[i] = byte(i)
	}
	_, err := ServiceIdFromBinary(data)
	if err == nil {
		t.Fatal("expected error for 17-byte ACI binary, got nil")
	}
	var parseErr *ServiceIdParseError
	if !errors.As(err, &parseErr) {
		t.Fatalf("expected *ServiceIdParseError, got %T: %v", err, err)
	}
}

// TestServiceIdFromBinary_17BytePNIAccepted verifies that a 17-byte PNI
// buffer (0x01 tag || 16-byte UUID) is accepted.
func TestServiceIdFromBinary_17BytePNIAccepted(t *testing.T) {
	data := make([]byte, 17)
	data[0] = byte(ServiceIdKindPNI)
	for i := 1; i < 17; i++ {
		data[i] = byte(i)
	}
	sid, err := ServiceIdFromBinary(data)
	if err != nil {
		t.Fatalf("unexpected error for valid 17-byte PNI: %v", err)
	}
	if sid.Kind() != ServiceIdKindPNI {
		t.Fatalf("expected PNI kind, got %v", sid.Kind())
	}
}

// TestServiceIdFromServiceIdString_LegacyACIPrefix tests Postel's law: the legacy
// "ACI:<uuid>" form (emitted by older Go releases) is accepted leniently while
// String() always emits the Rust-canonical bare UUID.
func TestServiceIdFromServiceIdString_LegacyACIPrefix(t *testing.T) {
	const rawUUID = "550e8400-e29b-41d4-a716-446655440000"

	t.Run("ACI prefix accepted", func(t *testing.T) {
		sid, err := ServiceIdFromServiceIdString("ACI:" + rawUUID)
		if err != nil {
			t.Fatalf("expected success for legacy ACI:-prefixed input, got error: %v", err)
		}
		if sid.Kind() != ServiceIdKindACI {
			t.Fatalf("expected ACI kind, got %v", sid.Kind())
		}
		if sid.UUIDString() != rawUUID {
			t.Fatalf("UUID mismatch: got %q, want %q", sid.UUIDString(), rawUUID)
		}
	})

	t.Run("bare UUID accepted as ACI", func(t *testing.T) {
		sid, err := ServiceIdFromServiceIdString(rawUUID)
		if err != nil {
			t.Fatalf("expected success for bare UUID, got error: %v", err)
		}
		if sid.Kind() != ServiceIdKindACI {
			t.Fatalf("expected ACI kind, got %v", sid.Kind())
		}
	})

	t.Run("round-trip: ACI prefix in, bare UUID out", func(t *testing.T) {
		sid, err := ServiceIdFromServiceIdString("ACI:" + rawUUID)
		if err != nil {
			t.Fatalf("unexpected parse error: %v", err)
		}
		got := sid.String()
		if got != rawUUID {
			t.Fatalf("String() must emit bare UUID, got %q", got)
		}
		if strings.HasPrefix(got, "ACI:") {
			t.Fatalf("String() must not emit ACI: prefix, got %q", got)
		}
	})

	t.Run("lowercase aci prefix rejected", func(t *testing.T) {
		_, err := ServiceIdFromServiceIdString("aci:" + rawUUID)
		if err == nil {
			t.Fatal("expected error for lowercase aci:-prefixed input, got nil")
		}
		var parseErr *ServiceIdParseError
		if !errors.As(err, &parseErr) {
			t.Fatalf("expected *ServiceIdParseError, got %T: %v", err, err)
		}
	})

	t.Run("ACI prefix with malformed UUID rejected", func(t *testing.T) {
		_, err := ServiceIdFromServiceIdString("ACI:not-a-valid-uuid")
		if err == nil {
			t.Fatal("expected error for ACI: prefix with malformed UUID, got nil")
		}
		var parseErr *ServiceIdParseError
		if !errors.As(err, &parseErr) {
			t.Fatalf("expected *ServiceIdParseError, got %T: %v", err, err)
		}
	})
}

// TestServiceIdFromServiceIdString_UnhyphenatedRejected verifies that a
// 32-character unhyphenated UUID is rejected by the canonical parser.
func TestServiceIdFromServiceIdString_UnhyphenatedRejected(t *testing.T) {
	_, err := ServiceIdFromServiceIdString("550e8400e29b41d4a716446655440000")
	if err == nil {
		t.Fatal("expected error for unhyphenated UUID, got nil")
	}
	var parseErr *ServiceIdParseError
	if !errors.As(err, &parseErr) {
		t.Fatalf("expected *ServiceIdParseError, got %T: %v", err, err)
	}
}

func TestServiceIdRoundtrip(t *testing.T) {
	uuid := [16]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}

	original := NewServiceId(ServiceIdKindACI, uuid)

	// Roundtrip through string
	str := original.UUIDString()
	parsed, err := ServiceIdFromString(ServiceIdKindACI, str)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.UUID() != original.UUID() {
		t.Fatal("roundtrip through string failed")
	}

	// Roundtrip through binary
	binary := original.FixedWidthBinary()
	parsed2, err := ServiceIdFromFixedWidthBinary(binary)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed2.UUID() != original.UUID() || parsed2.Kind() != original.Kind() {
		t.Fatal("roundtrip through binary failed")
	}
}

// TestServiceIdBinary_ACI verifies that an ACI encodes as 16 raw UUID bytes.
func TestServiceIdBinary_ACI(t *testing.T) {
	uuid := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	sid := NewACI(uuid)
	bin := sid.ServiceIdBinary()
	if len(bin) != 16 {
		t.Fatalf("ACI ServiceIdBinary: len = %d, want 16", len(bin))
	}
	for i, b := range uuid {
		if bin[i] != b {
			t.Errorf("byte[%d] = 0x%02x, want 0x%02x", i, bin[i], b)
		}
	}
}

// TestServiceIdBinary_PNI verifies that a PNI encodes as 17 bytes: 0x01 tag + UUID.
func TestServiceIdBinary_PNI(t *testing.T) {
	uuid := [16]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	sid := NewPNI(uuid)
	bin := sid.ServiceIdBinary()
	if len(bin) != 17 {
		t.Fatalf("PNI ServiceIdBinary: len = %d, want 17", len(bin))
	}
	if bin[0] != byte(ServiceIdKindPNI) {
		t.Errorf("PNI tag = 0x%02x, want 0x%02x", bin[0], byte(ServiceIdKindPNI))
	}
	for i, b := range uuid {
		if bin[i+1] != b {
			t.Errorf("uuid byte[%d] = 0x%02x, want 0x%02x", i, bin[i+1], b)
		}
	}
}
