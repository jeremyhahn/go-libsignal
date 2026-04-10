package keytrans

import (
	"errors"
	"testing"
)

func TestNewProofGuide(t *testing.T) {
	t.Run("nil version creates frontier guide", func(t *testing.T) {
		g, err := NewProofGuide(nil, 0, 8)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if g == nil {
			t.Fatal("expected non-nil guide")
		}
		if !g.isFrontier {
			t.Error("nil version should create frontier guide")
		}
	})

	t.Run("non-nil version creates version guide", func(t *testing.T) {
		v := uint32(5)
		g, err := NewProofGuide(&v, 0, 8)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if g == nil {
			t.Fatal("expected non-nil guide")
		}
		if g.isFrontier {
			t.Error("non-nil version should not create frontier guide")
		}
		if g.version != 5 {
			t.Errorf("expected version 5, got %d", g.version)
		}
	})
}

func TestProofGuide_Insert(t *testing.T) {
	v := uint32(5)
	g, err := NewProofGuide(&v, 0, 8)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	g.Insert(3, 2)
	if len(g.sorted) != 1 {
		t.Fatalf("expected 1 sorted entry, got %d", len(g.sorted))
	}
	if g.sorted[0].id != 3 || g.sorted[0].version != 2 {
		t.Error("Insert should add the id-version pair")
	}
}

func TestProofGuide_NextID(t *testing.T) {
	v := uint32(5)
	g, err := NewProofGuide(&v, 0, 8)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// After creation, ids has one element (the root), sorted has none
	id := g.nextID()
	if id != g.ids[0] {
		t.Errorf("nextID should return first id %d, got %d", g.ids[0], id)
	}
}

func TestProofGuide_Consume(t *testing.T) {
	t.Run("step returns error", func(t *testing.T) {
		v := uint32(0)
		g, err := NewProofGuide(&v, 0, 4)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		testErr := errors.New("test error")
		_, _, _, err = g.Consume(func(guide *ProofGuide, id uint64) error {
			guide.Insert(id, 0)
			return testErr
		})
		if err != testErr {
			t.Errorf("expected test error, got %v", err)
		}
	})

	t.Run("simple search completes", func(t *testing.T) {
		v := uint32(0)
		g, err := NewProofGuide(&v, 0, 4)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		_, _, _, err = g.Consume(func(guide *ProofGuide, id uint64) error {
			guide.Insert(id, 0)
			return nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestProofGuide_Result(t *testing.T) {
	t.Run("empty sorted returns false", func(t *testing.T) {
		v := uint32(0)
		g, err := NewProofGuide(&v, 0, 4)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		_, _, ok := g.result()
		if ok {
			t.Error("empty sorted should return false")
		}
	})
}

func TestProofGuide_PollMonotonic(t *testing.T) {
	v := uint32(5)
	g, err := NewProofGuide(&v, 0, 8)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	root := g.ids[0]
	// Insert a valid entry for the root: small id gets small version (monotonic)
	g.Insert(root, 3)

	done, err := g.poll()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = done
}

func TestProofGuide_PollNonMonotonic(t *testing.T) {
	v := uint32(5)
	g, err := NewProofGuide(&v, 0, 8)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	root := g.ids[0]
	// Create non-monotonic: entry with smaller id has higher version
	g.sorted = []versionedID{
		{id: root - 1, version: 10},
		{id: root, version: 3},
	}
	g.ids = []uint64{root - 1, root}

	_, err = g.poll()
	if err != ErrInvalidGuideState {
		t.Errorf("expected ErrInvalidGuideState, got %v", err)
	}
}
