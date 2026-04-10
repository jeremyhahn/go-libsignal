package errorhelper

import (
	"errors"
	"testing"
)

func TestNewMultiError_Empty(t *testing.T) {
	me := NewMultiError()
	if me == nil {
		t.Fatal("expected non-nil MultiError")
	}
	if me.HasErrors() {
		t.Fatal("new MultiError should have no errors")
	}
}

func TestMultiError_AddNilError(t *testing.T) {
	me := NewMultiError()
	me.Add(nil)
	if me.HasErrors() {
		t.Fatal("adding nil error should not register as an error")
	}
}

func TestMultiError_AddRealError(t *testing.T) {
	me := NewMultiError()
	me.Add(errors.New("test error"))
	if !me.HasErrors() {
		t.Fatal("expected HasErrors to return true after adding an error")
	}
}

func TestMultiError_ErrorReturnsFirstError(t *testing.T) {
	me := NewMultiError()
	me.Add(errors.New("first error"))
	me.Add(errors.New("second error"))
	if me.Error() != "first error" {
		t.Fatalf("expected 'first error', got %q", me.Error())
	}
}

func TestMultiError_ErrorReturnsEmptyStringWhenNoErrors(t *testing.T) {
	me := NewMultiError()
	if me.Error() != "" {
		t.Fatalf("expected empty string, got %q", me.Error())
	}
}

func TestMultiError_MultipleAdds(t *testing.T) {
	me := NewMultiError()
	me.Add(nil)
	me.Add(errors.New("one"))
	me.Add(nil)
	me.Add(errors.New("two"))

	if !me.HasErrors() {
		t.Fatal("expected HasErrors to be true")
	}
	if me.Error() != "one" {
		t.Fatalf("expected first non-nil error 'one', got %q", me.Error())
	}
}
