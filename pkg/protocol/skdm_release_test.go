//go:build !fips140only

package protocol

import (
	"bytes"
	"testing"
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
	if got := msg.ChainKey(); !bytes.Equal(got, want) {
		t.Fatalf("ChainKey = %x, want %x", got, want)
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
	if got := parsed.ChainKey(); !bytes.Equal(got, want) {
		t.Fatalf("round-tripped chain key = %x, want %x", got, want)
	}

	msg.Release()
	if !msg.chainKey.IsDestroyed() {
		t.Fatal("Release left the seed alive")
	}
	if got := msg.ChainKey(); got != nil {
		t.Fatalf("ChainKey after Release = %x, want nil", got)
	}
	if _, err := msg.Serialize(); err == nil {
		t.Fatal("Serialize after Release: want an error")
	}
	msg.Release() // idempotent
	(*SenderKeyDistributionMessage)(nil).Release()
}
