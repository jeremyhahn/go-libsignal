package optional

import (
	"testing"
)

func TestNewOptionalUint32_HasValue(t *testing.T) {
	opt := NewOptionalUint32(42)
	if opt == nil {
		t.Fatal("expected non-nil optional")
	}
	if opt.Value != 42 {
		t.Fatalf("expected value 42, got %d", opt.Value)
	}
	if opt.IsEmpty {
		t.Fatal("expected IsEmpty to be false")
	}
}

func TestNewOptionalUint32_ZeroValue(t *testing.T) {
	opt := NewOptionalUint32(0)
	if opt.Value != 0 {
		t.Fatalf("expected value 0, got %d", opt.Value)
	}
	if opt.IsEmpty {
		t.Fatal("expected IsEmpty to be false for zero value")
	}
}

func TestNewOptionalUint32_MaxValue(t *testing.T) {
	opt := NewOptionalUint32(^uint32(0))
	if opt.Value != ^uint32(0) {
		t.Fatalf("expected max uint32 value, got %d", opt.Value)
	}
	if opt.IsEmpty {
		t.Fatal("expected IsEmpty to be false")
	}
}

func TestNewEmptyUint32(t *testing.T) {
	opt := NewEmptyUint32()
	if opt == nil {
		t.Fatal("expected non-nil optional")
	}
	if !opt.IsEmpty {
		t.Fatal("expected IsEmpty to be true")
	}
	if opt.Value != 0 {
		t.Fatalf("expected zero value for empty optional, got %d", opt.Value)
	}
}

func TestNewEmptyUint32_DiffersFromZeroValue(t *testing.T) {
	empty := NewEmptyUint32()
	zero := NewOptionalUint32(0)

	if empty.IsEmpty == zero.IsEmpty {
		t.Fatal("empty and zero-value optionals should differ in IsEmpty")
	}
}
