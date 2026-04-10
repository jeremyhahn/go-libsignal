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
