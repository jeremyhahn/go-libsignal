//go:build !fips140only

package groups

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
)

// TestSessionBuilderCreate_ReleaseWipesSeed checks that the message Create
// returns carries the sender chain seed guarded, serializes it, and that
// Release destroys the message's seed while the stored state keeps its own.
func TestSessionBuilderCreate_ReleaseWipesSeed(t *testing.T) {
	store := newInMemorySenderKeyStore()
	builder := NewGroupSessionBuilder(store, newTestSerializer())
	name := protocol.NewSenderKeyName("release-group", protocol.NewSignalAddress("alice", 1))

	skdm, err := builder.Create([16]byte{}, name)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer skdm.Release()

	rec, err := store.LoadSenderKey(name)
	if err != nil {
		t.Fatalf("LoadSenderKey: %v", err)
	}
	state, err := rec.SenderKeyState()
	if err != nil {
		t.Fatalf("SenderKeyState: %v", err)
	}
	stored := state.SenderChainKey().Seed()
	if got := skdm.ChainKey(); len(stored) != 32 || !bytes.Equal(got, stored) {
		t.Fatalf("message seed %x does not match the stored seed %x", got, stored)
	}
	if _, err := skdm.Serialize(); err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	skdm.Release()
	if got := skdm.ChainKey(); got != nil {
		t.Fatalf("seed still readable after Release: %x", got)
	}
	if _, err := skdm.Serialize(); err == nil {
		t.Fatal("Serialize after Release: want an error")
	}
	if got := state.SenderChainKey().Seed(); !bytes.Equal(got, stored) {
		t.Fatal("Release changed the stored sender chain seed")
	}
}
