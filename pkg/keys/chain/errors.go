package chain

// MissingKeyError indicates that a KeyStructure carried no chain key material,
// so there is nothing to build a Key from. It is returned rather than tolerated
// because a chain key is mandatory: a Key with no material cannot ratchet, and
// every path that reaches it has decoded persisted or wire-supplied state that
// must be rejected outright when the key is absent.
type MissingKeyError struct{}

func (e *MissingKeyError) Error() string {
	return "chain: key structure carries no chain key material"
}
