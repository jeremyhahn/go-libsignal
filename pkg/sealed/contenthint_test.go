package sealed

import "testing"

func TestContentHintConstants(t *testing.T) {
	tests := []struct {
		name     string
		hint     ContentHint
		expected uint32
	}{
		{"Default", ContentHintDefault, 0},
		{"Resendable", ContentHintResendable, 1},
		{"Implicit", ContentHintImplicit, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if uint32(tt.hint) != tt.expected {
				t.Errorf("ContentHint%s = %d, want %d", tt.name, tt.hint, tt.expected)
			}
		})
	}
}

func TestContentHintDistinct(t *testing.T) {
	hints := []ContentHint{ContentHintDefault, ContentHintResendable, ContentHintImplicit}
	seen := make(map[ContentHint]bool)
	for _, h := range hints {
		if seen[h] {
			t.Errorf("ContentHint %d is duplicated", h)
		}
		seen[h] = true
	}
}

// TestContentHintFromRaw verifies that known values round-trip and that
// unknown values are preserved rather than discarded (forward-compat parity
// with Rust's ContentHint::Unknown(u32)).
func TestContentHintFromRaw(t *testing.T) {
	tests := []struct {
		name    string
		raw     uint32
		want    ContentHint
		isKnown bool
	}{
		{"Default", 0, ContentHintDefault, true},
		{"Resendable", 1, ContentHintResendable, true},
		{"Implicit", 2, ContentHintImplicit, true},
		{"Unknown3", 3, ContentHint(3), false},
		{"UnknownLarge", 0xFF, ContentHint(0xFF), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ContentHintFromRaw(tt.raw)
			if got != tt.want {
				t.Errorf("ContentHintFromRaw(%d) = %d, want %d", tt.raw, got, tt.want)
			}
			if got.IsKnown() != tt.isKnown {
				t.Errorf("ContentHintFromRaw(%d).IsKnown() = %v, want %v", tt.raw, got.IsKnown(), tt.isKnown)
			}
			if got.Raw() != tt.raw {
				t.Errorf("ContentHintFromRaw(%d).Raw() = %d, want %d", tt.raw, got.Raw(), tt.raw)
			}
		})
	}
}

// TestContentHintIsKnownKnownValues ensures the three named constants all
// report IsKnown() = true.
func TestContentHintIsKnownKnownValues(t *testing.T) {
	for _, h := range []ContentHint{ContentHintDefault, ContentHintResendable, ContentHintImplicit} {
		if !h.IsKnown() {
			t.Errorf("ContentHint(%d).IsKnown() = false, want true", h)
		}
	}
}

// TestContentHintRawPreservesUnknown ensures Raw() round-trips an unknown value,
// confirming no information is discarded (Rust Unknown(u32) parity).
func TestContentHintRawPreservesUnknown(t *testing.T) {
	const unknownRaw = uint32(99)
	h := ContentHint(unknownRaw)
	if h.Raw() != unknownRaw {
		t.Errorf("ContentHint(99).Raw() = %d, want %d", h.Raw(), unknownRaw)
	}
	if h.IsKnown() {
		t.Error("ContentHint(99).IsKnown() = true, want false")
	}
}
