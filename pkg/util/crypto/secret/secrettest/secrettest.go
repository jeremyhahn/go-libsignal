// Package secrettest gives tests a copy of the material a locked secret
// holds, so that a test can compare it or check that it was wiped.
//
// It is for tests only. Production code reads a secret inside its WithBytes
// borrow and never holds the material outside it; a copy taken here lives on
// the ordinary heap.
package secrettest

// Borrower is any locked secret that lends its material through WithBytes,
// such as *secret.Secret, *secret.Secret32 and the key types built on them.
type Borrower interface {
	WithBytes(fn func([]byte) error) error
}

// Bytes returns a copy of s's material, or nil when s holds none or has been
// destroyed.
func Bytes(s Borrower) []byte {
	var out []byte
	if err := s.WithBytes(func(b []byte) error {
		if b != nil {
			out = append([]byte{}, b...)
		}
		return nil
	}); err != nil {
		return nil
	}
	return out
}

// Array returns a copy of the first 32 bytes of s's material, or the zero
// array when s holds none or has been destroyed.
func Array(s Borrower) [32]byte {
	var out [32]byte
	copy(out[:], Bytes(s))
	return out
}
