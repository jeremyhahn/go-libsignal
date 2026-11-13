package secret

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-enclave"
)

// failingDestroy wraps a live enclave and reports a release failure from
// Destroy, as go-enclave does for a corrupted canary or a refused munlock.
type failingDestroy struct {
	enclave.ByteAccess
	err error
}

func (f *failingDestroy) Destroy() error {
	_ = f.ByteAccess.Destroy()
	return f.err
}

// TestDestroy_PanicsOnReleaseFailure checks that a release failure the
// enclave reports is never dropped: Destroy panics with it wrapped.
func TestDestroy_PanicsOnReleaseFailure(t *testing.T) {
	s, err := New([]byte("release-failure-material"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	injected := errors.New("canary corrupted")
	s.enc = &failingDestroy{ByteAccess: s.enc, err: injected}

	defer func() {
		r := recover()
		perr, ok := r.(error)
		if !ok || !errors.Is(perr, injected) {
			t.Fatalf("want a panic wrapping %v, got %v", injected, r)
		}
	}()
	s.Destroy()
	t.Fatal("Destroy returned after a release failure")
}

// TestDestroy_SuccessDoesNotPanic checks that a clean release, and a second
// idempotent Destroy, do not panic.
func TestDestroy_SuccessDoesNotPanic(t *testing.T) {
	s, err := New([]byte("clean-release-material"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.Destroy()
	s.Destroy()
	if !s.IsDestroyed() {
		t.Fatal("want destroyed")
	}
}
