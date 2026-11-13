package ratchet

import "errors"

// mustCopy unwraps an accessor's (copy, error) pair for tests whose state is
// known to be live; a copy error is a test bug, so it panics.
func mustCopy(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

// absent is mustCopy for a field that may be missing: a MissingKeyError
// becomes nil, any other error still panics.
func absent(b []byte, err error) []byte {
	var missing *MissingKeyError
	if errors.As(err, &missing) {
		return nil
	}
	return mustCopy(b, err)
}
