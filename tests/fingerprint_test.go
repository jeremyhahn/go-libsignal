//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 1 test in this file exercises X25519. FIPS 140-3 does not approve that,
// but the X3DH specification (section 2.1) and the Double Ratchet
// specification (section 5.2) require it, so the fips140only build tag drops
// this file from the FIPS gate. `make test` and `make coverage` still run
// it.

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
