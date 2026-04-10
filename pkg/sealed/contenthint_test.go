package sealed

import "testing"

func TestContentHintConstants(t *testing.T) {
	tests := []struct {
		name     string
		hint     ContentHint
		expected int
	}{
		{"Default", ContentHintDefault, 0},
		{"Resendable", ContentHintResendable, 1},
		{"Implicit", ContentHintImplicit, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if int(tt.hint) != tt.expected {
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
