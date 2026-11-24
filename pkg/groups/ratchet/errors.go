package ratchet

// MissingKeyError reports a decoded structure with no material for a required field, named by Field.
type MissingKeyError struct {
	Field string
}

func (e *MissingKeyError) Error() string {
	return "ratchet: sender key structure is missing its " + e.Field
}
