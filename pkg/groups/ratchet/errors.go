package ratchet

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
