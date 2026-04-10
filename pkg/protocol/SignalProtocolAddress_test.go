package protocol

import (
	"testing"
)

func TestNewSignalAddress(t *testing.T) {
	addr := NewSignalAddress("Alice", 1)

	if addr.Name() != "Alice" {
		t.Fatalf("expected name Alice, got %s", addr.Name())
	}
	if addr.DeviceID() != 1 {
		t.Fatalf("expected device ID 1, got %d", addr.DeviceID())
	}
}

func TestSignalAddressString(t *testing.T) {
	tests := []struct {
		name     string
		deviceID uint32
		expected string
	}{
		{"Alice", 1, "Alice~1"},
		{"Bob", 42, "Bob~42"},
		{"", 0, "~0"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			addr := NewSignalAddress(tc.name, tc.deviceID)
			if got := addr.String(); got != tc.expected {
				t.Fatalf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}

func TestSignalAddressFields(t *testing.T) {
	addr := NewSignalAddress("Charlie", 99)

	if addr.Name() != "Charlie" {
		t.Fatal("name mismatch")
	}
	if addr.DeviceID() != 99 {
		t.Fatal("device ID mismatch")
	}
}
