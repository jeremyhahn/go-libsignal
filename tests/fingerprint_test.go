package tests

import (
	"fmt"
	"github.com/jeremyhahn/go-libsignal/pkg/fingerprint"
	"testing"
)

// TestFingerprint will test printing key fingerprints.
func TestFingerprint(t *testing.T) {

	// Create a serializer object that will be used to encode/decode data.
	serializer := newSerializer()

	// Create our users who will talk to each other.
	alice := newUser("Alice", 1, serializer)
	bob := newUser("Bob", 2, serializer)

	fp, err := fingerprint.NewDisplay(
		alice.identityKeyPair.PublicKey().Serialize(),
		bob.identityKeyPair.PublicKey().Serialize(),
	)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(fp.DisplayText())

}
