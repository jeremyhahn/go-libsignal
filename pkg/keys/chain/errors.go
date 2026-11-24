package chain

// MissingKeyError indicates a KeyStructure with no chain key material.
type MissingKeyError struct{}

func (e *MissingKeyError) Error() string {
	return "chain: key structure carries no chain key material"
}
