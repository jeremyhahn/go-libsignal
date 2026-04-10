package session

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/spqr"
)

// TestNewOldCounterError exercises the newOldCounterError constructor directly,
// verifying the returned error has correct kind and fields.
func TestNewOldCounterError(t *testing.T) {
	err := newOldCounterError(10, 5)
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	msg := err.Error()
	if msg == "" {
		t.Fatal("Error() returned empty string")
	}
	// Verify it matches the sentinel via errors.Is.
	if !err.Is(ErrOldCounter) {
		t.Fatalf("expected error to match ErrOldCounter, got: %v", err)
	}
	// Verify the fields are stored correctly in the error message.
	if err.index != 10 || err.counter != 5 {
		t.Fatalf("expected index=10 counter=5, got index=%d counter=%d", err.index, err.counter)
	}
}

// TestIsSpqrDuplicateErr verifies the isSpqrDuplicateErr function returns
// true for SPQR duplicate error types and false for other errors.
func TestIsSpqrDuplicateErr(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "ErrKeyAlreadyRequested returns true",
			err:  &spqr.ErrKeyAlreadyRequested{Counter: 5},
			want: true,
		},
		{
			name: "ErrKeyTrimmed returns true",
			err:  &spqr.ErrKeyTrimmed{Counter: 3},
			want: true,
		},
		{
			name: "non-SPQR error returns false",
			err:  &Error{kind: errDuplicateMessage},
			want: false,
		},
		{
			name: "nil-like via typed nil pointer",
			err:  (*spqr.ErrMaxJump)(nil),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSpqrDuplicateErr(tt.err)
			if got != tt.want {
				t.Errorf("isSpqrDuplicateErr(%T) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestMax(t *testing.T) {
	tests := []struct {
		name     string
		x, y     uint32
		expected uint32
	}{
		{"x greater", 10, 5, 10},
		{"y greater", 3, 7, 7},
		{"equal", 4, 4, 4},
		{"zero and nonzero", 0, 1, 1},
		{"nonzero and zero", 1, 0, 1},
		{"both zero", 0, 0, 0},
		{"max uint32", ^uint32(0), 1, ^uint32(0)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := max(tt.x, tt.y)
			if got != tt.expected {
				t.Errorf("max(%d, %d) = %d, want %d", tt.x, tt.y, got, tt.expected)
			}
		})
	}
}
