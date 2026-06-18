package keytrans

import (
	"testing"
)

func TestLog2(t *testing.T) {
	tests := []struct {
		name string
		n    uint64
		want uint32
	}{
		{"zero", 0, 0},
		{"one", 1, 0},
		{"two", 2, 1},
		{"three", 3, 1},
		{"four", 4, 2},
		{"eight", 8, 3},
		{"fifteen", 15, 3},
		{"sixteen", 16, 4},
		{"large", 1 << 20, 20},
		{"max power of 2", 1 << 62, 62},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := log2(tt.n)
			if got != tt.want {
				t.Errorf("log2(%d) = %d, want %d", tt.n, got, tt.want)
			}
		})
	}
}

func TestIsLeaf(t *testing.T) {
	tests := []struct {
		x    uint64
		want bool
	}{
		{0, true},
		{1, false},
		{2, true},
		{3, false},
		{4, true},
		{5, false},
		{6, true},
		{7, false},
	}

	for _, tt := range tests {
		got := isLeaf(tt.x)
		if got != tt.want {
			t.Errorf("isLeaf(%d) = %v, want %v", tt.x, got, tt.want)
		}
	}
}

func TestLevel(t *testing.T) {
	tests := []struct {
		x    uint64
		want int
	}{
		{0, 0}, // leaf
		{1, 1}, // level 1
		{2, 0}, // leaf
		{3, 2}, // level 2
		{4, 0}, // leaf
		{5, 1}, // level 1
		{6, 0}, // leaf
		{7, 3}, // level 3
	}

	for _, tt := range tests {
		got := level(tt.x)
		if got != tt.want {
			t.Errorf("level(%d) = %d, want %d", tt.x, got, tt.want)
		}
	}
}

func TestLeftStep(t *testing.T) {
	// Node 1 (level 1): left child should be 0
	got, err := leftStep(1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 0 {
		t.Errorf("leftStep(1) = %d, want 0", got)
	}
	// Node 3 (level 2): left child should be 1
	got, err = leftStep(3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 1 {
		t.Errorf("leftStep(3) = %d, want 1", got)
	}
	// Node 7 (level 3): left child should be 3
	got, err = leftStep(7)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 3 {
		t.Errorf("leftStep(7) = %d, want 3", got)
	}
}

func TestLeftStep_ErrorOnLeaf(t *testing.T) {
	_, err := leftStep(0)
	if err != ErrLeafNodeHasNoChildren {
		t.Errorf("leftStep on leaf should return ErrLeafNodeHasNoChildren, got %v", err)
	}
}

func TestRightStep(t *testing.T) {
	// Node 1 (level 1): right child should be 2
	got, err := rightStep(1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 2 {
		t.Errorf("rightStep(1) = %d, want 2", got)
	}
	// Node 3 (level 2): right child should be 5
	got, err = rightStep(3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 5 {
		t.Errorf("rightStep(3) = %d, want 5", got)
	}
	// Node 7 (level 3): right child should be 11
	got, err = rightStep(7)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 11 {
		t.Errorf("rightStep(7) = %d, want 11", got)
	}
}

func TestRightStep_ErrorOnLeaf(t *testing.T) {
	_, err := rightStep(0)
	if err != ErrLeafNodeHasNoChildren {
		t.Errorf("rightStep on leaf should return ErrLeafNodeHasNoChildren, got %v", err)
	}
}

func TestParentStep(t *testing.T) {
	// Node 0: parent should be 1
	if got := parentStep(0); got != 1 {
		t.Errorf("parentStep(0) = %d, want 1", got)
	}
	// Node 2: parent should be 1
	if got := parentStep(2); got != 1 {
		t.Errorf("parentStep(2) = %d, want 1", got)
	}
	// Node 1: parent should be 3
	if got := parentStep(1); got != 3 {
		t.Errorf("parentStep(1) = %d, want 3", got)
	}
	// Node 5: parent should be 3
	if got := parentStep(5); got != 3 {
		t.Errorf("parentStep(5) = %d, want 3", got)
	}
}
