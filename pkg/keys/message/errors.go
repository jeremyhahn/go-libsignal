package message

import "fmt"

// MissingKeyError indicates that a KeysStructure in derived-keys form was
// missing one of the components that form requires. It is returned rather than
// tolerated because the three are only meaningful together: a Keys holding two
// of them cannot encrypt or authenticate anything, and every path that reaches
// here has decoded persisted or wire-supplied state that must be rejected
// outright when a component is absent.
//
// Field names the missing component ("cipher key", "mac key", "iv"), or
// "structure" when no structure was supplied at all.
type MissingKeyError struct {
	Field string
}

func (e *MissingKeyError) Error() string {
	return "message: key structure is missing its " + e.Field
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
	return fmt.Sprintf("message: %s is %d bytes, want %d", e.Field, e.Got, e.Want)
}
