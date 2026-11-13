package ratchet

import "fmt"

// MissingKeyError indicates that a serializable structure carried no material
// for a field that must have some. It is returned rather than tolerated because
// every path that reaches it has decoded persisted or wire-supplied state, and
// a sender chain key or message key with no material cannot ratchet, encrypt or
// authenticate anything.
//
// Field names what was missing ("sender chain key", "structure").
type MissingKeyError struct {
	Field string
}

func (e *MissingKeyError) Error() string {
	return "ratchet: sender key structure is missing its " + e.Field
}

// KeyLengthError indicates that a key component held the wrong number of
// bytes when it was copied out of guarded memory. A short or long key is
// refused rather than used.
type KeyLengthError struct {
	Field string
	Got   int
	Want  int
}

func (e *KeyLengthError) Error() string {
	return fmt.Sprintf("ratchet: %s is %d bytes, want %d", e.Field, e.Got, e.Want)
}
