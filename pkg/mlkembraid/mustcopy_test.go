package mlkembraid

// mustCopy unwraps an accessor's (copy, error) pair for tests whose state is
// known to be live; a copy error is a test bug, so it panics.
func mustCopy(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}
