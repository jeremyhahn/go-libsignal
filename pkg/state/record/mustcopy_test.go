package record_test

import "github.com/jeremyhahn/go-libsignal/pkg/keys/message"

// mustCopy unwraps an accessor's (copy, error) pair for tests whose state is
// known to be live; a copy error is a test bug, so it panics.
func mustCopy(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

// fixedKey pads label with zeros to n bytes, giving a recognisable test key
// of the length the accessors require.
func fixedKey(label string, n int) []byte {
	b := make([]byte, n)
	copy(b, label)
	return b
}

// mustKeys is mustCopy for RemoveMessageKeys.
func mustKeys(k *message.Keys, err error) *message.Keys {
	if err != nil {
		panic(err)
	}
	return k
}
