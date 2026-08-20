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
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/util/keyhelper"
	"testing"
)

// TestPreKeys checks generating prekeys.
func TestPreKeys(t *testing.T) {

	// Create a serializer object that will be used to encode/decode data.
	serializer := serialize.NewSerializer()
	serializer.SignalMessage = &serialize.JSONSignalMessageSerializer{}
	serializer.PreKeySignalMessage = &serialize.JSONPreKeySignalMessageSerializer{}
	serializer.SignedPreKeyRecord = &serialize.JSONSignedPreKeyRecordSerializer{}

	identityKeyPair, err := keyhelper.GenerateIdentityKeyPair()
	if err != nil {
		t.Error(err)
	}

	preKeys, _ := keyhelper.GeneratePreKeys(1, 100, serializer.PreKeyRecord)
	if len(preKeys) == 0 {
		t.Fatal("expected generated prekeys")
	}

	signedPreKey, _ := keyhelper.GenerateSignedPreKey(identityKeyPair, 1, serializer.SignedPreKeyRecord)
	if signedPreKey == nil {
		t.Fatal("expected generated signed prekey")
	}
}
