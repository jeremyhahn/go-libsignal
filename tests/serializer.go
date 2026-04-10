package tests

import (
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
)

// newSerializer will return a JSON serializer for testing.
func newSerializer() *serialize.Serializer {
	serializer := serialize.NewJSONSerializer()

	return serializer
}
