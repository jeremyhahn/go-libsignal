// Package secrettest lets tests assert on the material a locked secret holds
// from inside its WithBytes borrow: equal to an expected value, equal to or
// different from another secret, or zeroed. Borrow failures fail the test.
//
// No helper returns the material: tests may not copy secrets out of protected
// storage into plain memory to assert on them.
package secrettest

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// Borrower is any locked secret that lends its material through WithBytes,
// such as *secret.Secret, *secret.Secret32 and the key types built on them.
type Borrower interface {
	WithBytes(fn func([]byte) error) error
}

// With runs fn on the borrowed view of s and fails the test if the borrow
// fails. fn must not retain the view or copy it out.
func With(t testing.TB, s Borrower, fn func(b []byte)) {
	t.Helper()
	if err := s.WithBytes(func(b []byte) error { fn(b); return nil }); err != nil {
		t.Fatalf("secrettest: borrow failed: %v", err)
	}
}

// Len reports the length of the material s holds.
func Len(t testing.TB, s Borrower) int {
	t.Helper()
	n := 0
	With(t, s, func(b []byte) { n = len(b) })
	return n
}

// Empty reports whether s lends no material, because it holds none or
// because it has been destroyed.
func Empty(s Borrower) bool {
	n := 0
	if err := s.WithBytes(func(b []byte) error { n = len(b); return nil }); err != nil {
		return true
	}
	return n == 0
}

// Digest returns the SHA-256 digest of the material s holds, taken inside the
// borrow, so a test can check later that the material is unchanged without
// keeping a copy of it.
func Digest(t testing.TB, s Borrower) [sha256.Size]byte {
	t.Helper()
	var d [sha256.Size]byte
	With(t, s, func(b []byte) { d = sha256.Sum256(b) })
	return d
}

// Matches reports whether s holds exactly want, comparing inside the borrow.
func Matches(t testing.TB, s Borrower, want []byte) bool {
	t.Helper()
	ok := false
	With(t, s, func(b []byte) { ok = bytes.Equal(b, want) })
	return ok
}

// Same reports whether a and b hold the same bytes, comparing inside both
// borrows.
func Same(t testing.TB, a, b Borrower) bool {
	t.Helper()
	if a == b {
		return true
	}
	ok := false
	With(t, a, func(x []byte) {
		With(t, b, func(y []byte) { ok = bytes.Equal(x, y) })
	})
	return ok
}

// IsZero reports whether every byte s holds is zero.
func IsZero(t testing.TB, s Borrower) bool {
	t.Helper()
	ok := true
	With(t, s, func(b []byte) {
		for _, c := range b {
			if c != 0 {
				ok = false
				return
			}
		}
	})
	return ok
}

// Equal fails the test unless s holds exactly want.
func Equal(t testing.TB, s Borrower, want []byte) {
	t.Helper()
	if !Matches(t, s, want) {
		t.Errorf("secrettest: secret does not hold the expected %d bytes", len(want))
	}
}

// NotEqual fails the test if s holds exactly other.
func NotEqual(t testing.TB, s Borrower, other []byte) {
	t.Helper()
	if Matches(t, s, other) {
		t.Errorf("secrettest: secret unexpectedly holds the given %d bytes", len(other))
	}
}

// SameAs fails the test unless a and b hold the same bytes.
func SameAs(t testing.TB, a, b Borrower) {
	t.Helper()
	if !Same(t, a, b) {
		t.Errorf("secrettest: secrets differ")
	}
}

// Differ fails the test if a and b hold the same bytes.
func Differ(t testing.TB, a, b Borrower) {
	t.Helper()
	if Same(t, a, b) {
		t.Errorf("secrettest: secrets are equal")
	}
}

// Zeroed fails the test unless every byte s holds is zero.
func Zeroed(t testing.TB, s Borrower) {
	t.Helper()
	if !IsZero(t, s) {
		t.Errorf("secrettest: secret is not zeroed")
	}
}
