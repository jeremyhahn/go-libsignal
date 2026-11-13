//go:build !fips140only

package protocol

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret/secrettest"
)

// TestSenderKeyDistributionMessage_ReleaseWipesSeed checks that the message
// keeps its chain key seed guarded, serializes it from inside the borrow,
// and that Release destroys it so no copy of the seed is left behind.
func TestSenderKeyDistributionMessage_ReleaseWipesSeed(t *testing.T) {
	serializer := &jsonSenderKeyDistributionMessageSerializer{}
	signingKey := newTestKeyPair(t)
	chainKey := validChainKey()
	want := append([]byte(nil), chainKey...)

	msg := NewSenderKeyDistributionMessage([16]byte{}, 1, 10, chainKey, signingKey.PublicKey(), serializer, SenderKeyCurrentVersion)
	if !bytes.Equal(chainKey, want) {
		t.Fatal("the constructor wiped the caller's chain key")
	}
	if msg.chainKey.IsDestroyed() {
		t.Fatal("the seed is not held guarded")
	}
	if !secrettest.Matches(t, msg.chainKey, want) {
		t.Fatal("the guarded seed does not match the input chain key")
	}
	out, err := msg.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	parsed, err := NewSenderKeyDistributionMessageFromBytes(out, serializer)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	defer parsed.Release()
	if !secrettest.Matches(t, parsed.chainKey, want) {
		t.Fatal("the round-tripped seed does not match the input chain key")
	}

	msg.Release()
	if !msg.chainKey.IsDestroyed() {
		t.Fatal("Release left the seed alive")
	}
	if !secrettest.Empty(msg.chainKey) {
		t.Fatal("the seed still lends material after Release")
	}
	if msg.ChainKey() != nil {
		t.Fatal("ChainKey after Release: want nil")
	}
	if _, err := msg.Serialize(); err == nil {
		t.Fatal("Serialize after Release: want an error")
	}
	msg.Release() // idempotent
	(*SenderKeyDistributionMessage)(nil).Release()
}
