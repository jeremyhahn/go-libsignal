package zkgroup

import (
	"testing"
)

// TestMustDecodeHex_ValidInput ensures mustDecodeHex returns the correct bytes
// for a valid lowercase hex string.
func TestMustDecodeHex_ValidInput(t *testing.T) {
	got := mustDecodeHex("000102ff")
	want := []byte{0x00, 0x01, 0x02, 0xff}
	if len(got) != len(want) {
		t.Fatalf("len mismatch: got %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("byte %d: got %02x, want %02x", i, got[i], want[i])
		}
	}
}

// TestMustDecodeHex_PanicsOnInvalidInput ensures mustDecodeHex panics when the
// input is not valid hex, rather than silently returning garbage.
func TestMustDecodeHex_PanicsOnInvalidInput(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("mustDecodeHex with invalid hex did not panic")
		}
	}()
	mustDecodeHex("zz")
}

// TestPresentationConstants verifies that the exported presentation byte
// constants have the expected first-byte version prefix and are non-empty.
// This guards against accidental truncation or hex typos in the literals.
func TestPresentationConstants(t *testing.T) {
	cases := []struct {
		name   string
		data   []byte
		prefix byte
	}{
		{"AuthCredentialPresentationV1Bytes", AuthCredentialPresentationV1Bytes, 0x00},
		{"AuthCredentialPresentationV4ResultBytes", AuthCredentialPresentationV4ResultBytes, 0x03},
		{"ProfileKeyCredentialPresentationV1Bytes", ProfileKeyCredentialPresentationV1Bytes, 0x00},
		{"ProfileKeyCredentialPresentationV2ResultBytes", ProfileKeyCredentialPresentationV2ResultBytes, 0x01},
		{"ProfileKeyCredentialPresentationV3ResultBytes", ProfileKeyCredentialPresentationV3ResultBytes, 0x02},
		{"ProfileKeyCredentialPresentationV4ResultBytes", ProfileKeyCredentialPresentationV4ResultBytes, 0x03},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.data) == 0 {
				t.Fatal("constant is empty")
			}
			if tc.data[0] != tc.prefix {
				t.Errorf("first byte: got %02x, want %02x", tc.data[0], tc.prefix)
			}
		})
	}
}
