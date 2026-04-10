package protocol

import (
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
	tests := []struct {
		name     string
		kind     ServiceIdKind
		expected string
	}{
		{"ACI", ServiceIdKindACI, "ACI:"},
		{"PNI", ServiceIdKindPNI, "PNI:"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uuid := [16]byte{}
			sid := NewServiceId(tc.kind, uuid)
			got := sid.String()
			if got[:4] != tc.expected {
				t.Fatalf("expected prefix %q, got %q", tc.expected, got[:4])
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
