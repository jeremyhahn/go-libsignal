package message

// MissingKeyError indicates a derived-keys KeysStructure missing the component named by Field.
type MissingKeyError struct {
	Field string
}

func (e *MissingKeyError) Error() string {
	return "message: key structure is missing its " + e.Field
}
