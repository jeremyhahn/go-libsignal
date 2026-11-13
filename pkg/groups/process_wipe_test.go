package groups

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
)

// TestSessionBuilderProcess_WipesChainKeyCopy checks that Process wipes the
// owned plaintext copy ChainKey() returns, while the receiver still stores
// the sender's seed. The test keeps only a reference to the copy Process
// makes and checks it after the wipe; the seeds are compared by digest
// inside the borrow.
func TestSessionBuilderProcess_WipesChainKeyCopy(t *testing.T) {
	sender := newInMemorySenderKeyStore()
	name := protocol.NewSenderKeyName("process-wipe-group", protocol.NewSignalAddress("alice", 1))
	skdm, err := NewGroupSessionBuilder(sender, newTestSerializer()).Create([16]byte{}, name)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer skdm.Release()

	var handed []byte
	orig := distributionChainKey
	distributionChainKey = func(msg *protocol.SenderKeyDistributionMessage) []byte {
		handed = orig(msg)
		return handed
	}
	defer func() { distributionChainKey = orig }()

	receiver := newInMemorySenderKeyStore()
	if err := NewGroupSessionBuilder(receiver, newTestSerializer()).Process(name, skdm); err != nil {
		t.Fatalf("Process: %v", err)
	}

	if len(handed) != 32 {
		t.Fatalf("Process took a %d-byte chain key copy, want 32", len(handed))
	}
	for i, v := range handed {
		if v != 0 {
			t.Fatalf("Process left the chain key copy unwiped at byte %d", i)
		}
	}
	if storedSeedDigest(t, receiver, name) != storedSeedDigest(t, sender, name) {
		t.Fatal("the receiver did not store the sender's seed")
	}
}
