package keytrans

import (
	"testing"
)

func TestImplicitRoot(t *testing.T) {
	tests := []struct {
		name  string
		start uint64
		n     uint64
	}{
		{"single element", 0, 1},
		{"two elements", 0, 2},
		{"four elements", 0, 4},
		{"eight elements", 0, 8},
		{"non-power-of-two", 0, 5},
		{"with offset", 2, 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, err := implicitRoot(tt.start, tt.n)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if root < tt.start || root >= tt.n {
				t.Errorf("implicitRoot(%d, %d) = %d, out of range [%d, %d)", tt.start, tt.n, root, tt.start, tt.n)
			}
		})
	}
}

func TestImplicitLeft(t *testing.T) {
	// For a tree with n=8 starting at 0, root=7
	// left of 7 should be 3
	root, err := implicitRoot(0, 8)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	left, err := implicitLeft(root, 0, 8)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if left >= root {
		t.Errorf("left child %d should be less than root %d", left, root)
	}
	if left >= 8 {
		t.Errorf("left child %d out of range", left)
	}
}

func TestImplicitRight(t *testing.T) {
	// Use a tree with enough nodes to have a non-leaf root with valid right child
	// For n=10, start=0: root should be a non-leaf with both children valid
	n := uint64(10)
	root, err := implicitRoot(0, n)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Only test if root is not n-1 (otherwise right child may not exist)
	if root < n-1 {
		right, err := implicitRight(root, 0, n)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if right >= n {
			t.Errorf("right child %d out of range [0, %d)", right, n)
		}
	}
}

func TestImplicitParent(t *testing.T) {
	// In a tree with 8 nodes
	// parentStep of leaf 0 should give a valid parent within the tree
	p := implicitParent(0, 8)
	if p >= 8 {
		t.Errorf("implicitParent(0, 8) = %d, should be < 8", p)
	}
}

func TestImplicitDirectPath(t *testing.T) {
	t.Run("leaf to root", func(t *testing.T) {
		path, err := implicitDirectPath(0, 0, 8)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(path) == 0 {
			t.Error("path from leaf to root should not be empty for non-trivial tree")
		}
		// Last element should be the root
		root, err := implicitRoot(0, 8)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if path[len(path)-1] != root {
			t.Errorf("path should end at root %d, got %d", root, path[len(path)-1])
		}
	})

	t.Run("root to itself", func(t *testing.T) {
		root, err := implicitRoot(0, 8)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		path, err := implicitDirectPath(root, 0, 8)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(path) != 0 {
			t.Errorf("path from root to itself should be empty, got %v", path)
		}
	})
}

func TestImplicitFrontier(t *testing.T) {
	t.Run("power of two", func(t *testing.T) {
		frontier, err := implicitFrontier(0, 4)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(frontier) == 0 {
			t.Error("frontier should not be empty")
		}
		// First element should be root
		root, err := implicitRoot(0, 4)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if frontier[0] != root {
			t.Errorf("first frontier element should be root %d, got %d", root, frontier[0])
		}
		// Last element should be n-1
		if frontier[len(frontier)-1] != 3 {
			t.Errorf("last frontier element should be 3, got %d", frontier[len(frontier)-1])
		}
	})

	t.Run("non-power of two", func(t *testing.T) {
		frontier, err := implicitFrontier(0, 5)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(frontier) == 0 {
			t.Error("frontier should not be empty")
		}
		if frontier[len(frontier)-1] != 4 {
			t.Errorf("last frontier element should be 4, got %d", frontier[len(frontier)-1])
		}
	})
}

func TestMonitoringPath(t *testing.T) {
	t.Run("returns only parents greater than x", func(t *testing.T) {
		path, err := monitoringPath(0, 0, 8)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		for _, p := range path {
			if p <= 0 {
				t.Errorf("monitoring path element %d should be > 0", p)
			}
		}
	})

	t.Run("root has empty path", func(t *testing.T) {
		root, err := implicitRoot(0, 8)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		path, err := monitoringPath(root, 0, 8)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(path) != 0 {
			t.Errorf("root should have empty monitoring path, got %v", path)
		}
	})
}

func TestMonitoringFrontier(t *testing.T) {
	t.Run("no entries found", func(t *testing.T) {
		frontier := []uint64{1, 3, 5}
		entries := map[uint64]struct{}{}
		_, err := monitoringFrontier(frontier, entries)
		if err == nil {
			t.Error("expected error for no matching entries, got nil")
		}
	})

	t.Run("last entry is in frontier", func(t *testing.T) {
		frontier := []uint64{1, 3, 5}
		entries := map[uint64]struct{}{5: {}}
		result, err := monitoringFrontier(frontier, entries)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) != 0 {
			t.Errorf("expected empty result when last frontier entry is matched, got %v", result)
		}
	})

	t.Run("first entry is in frontier", func(t *testing.T) {
		frontier := []uint64{1, 3, 5}
		entries := map[uint64]struct{}{1: {}}
		result, err := monitoringFrontier(frontier, entries)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) != 2 {
			t.Errorf("expected 2 remaining frontier elements, got %d: %v", len(result), result)
		}
	})
}

func TestFullMonitoringPath(t *testing.T) {
	t.Run("returns non-empty path for leaf", func(t *testing.T) {
		path, err := fullMonitoringPath(0, 0, 8)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Should have some elements (monitoring path + frontier remainder)
		if len(path) == 0 {
			t.Error("full monitoring path should not be empty for leaf in non-trivial tree")
		}
	})

	t.Run("no duplicate entries", func(t *testing.T) {
		path, err := fullMonitoringPath(0, 0, 8)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		seen := make(map[uint64]struct{})
		for _, p := range path {
			if _, ok := seen[p]; ok {
				t.Errorf("duplicate entry %d in full monitoring path", p)
			}
			seen[p] = struct{}{}
		}
	})
}

func TestFirstParentToTheRight(t *testing.T) {
	tests := []struct {
		entry uint64
		want  uint64
	}{
		{0, 2},  // parentStep(0)=1, 1>0 so out=1+1=2
		{2, 4},  // parentStep(2)=1, 1<2 so parentStep(1)=3, 3>2 so out=3+1=4
	}

	for _, tt := range tests {
		got := firstParentToTheRight(tt.entry)
		if got != tt.want {
			t.Errorf("firstParentToTheRight(%d) = %d, want %d", tt.entry, got, tt.want)
		}
	}
}

func TestNextMonitor(t *testing.T) {
	t.Run("empty entries", func(t *testing.T) {
		got := nextMonitor(nil)
		if got != 0 {
			t.Errorf("nextMonitor(nil) = %d, want 0", got)
		}
	})

	t.Run("single entry", func(t *testing.T) {
		got := nextMonitor([]uint64{0})
		expected := firstParentToTheRight(0)
		if got != expected {
			t.Errorf("nextMonitor([0]) = %d, want %d", got, expected)
		}
	})

	t.Run("multiple entries picks minimum", func(t *testing.T) {
		entries := []uint64{0, 4, 8}
		got := nextMonitor(entries)
		// Should be the minimum of firstParentToTheRight for each
		min := firstParentToTheRight(entries[0])
		for _, e := range entries[1:] {
			v := firstParentToTheRight(e)
			if v < min {
				min = v
			}
		}
		if got != min {
			t.Errorf("nextMonitor(%v) = %d, want %d", entries, got, min)
		}
	})
}

func TestImplicitMoveWithin(t *testing.T) {
	tests := []struct {
		name  string
		x     uint64
		start uint64
		n     uint64
	}{
		{"already in range", 3, 0, 8},
		{"at start", 0, 0, 8},
		{"at end-1", 7, 0, 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := implicitMoveWithin(tt.x, tt.start, tt.n)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result < tt.start || result >= tt.n {
				t.Errorf("implicitMoveWithin(%d, %d, %d) = %d, out of range [%d, %d)",
					tt.x, tt.start, tt.n, result, tt.start, tt.n)
			}
		})
	}
}
