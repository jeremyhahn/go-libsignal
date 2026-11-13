//go:build !fips140only

package groups

import (
	"crypto/sha256"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret/secrettest"
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

	stored := storedSeedDigest(t, store, name)

	// The message carries the stored seed: a receiver that processes it
	// stores the same seed. Both sides are compared by digest inside the
	// borrow, so the test holds no copy of the seed.
	receiver := newInMemorySenderKeyStore()
	if err := NewGroupSessionBuilder(receiver, newTestSerializer()).Process(name, skdm); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if storedSeedDigest(t, receiver, name) != stored {
		t.Fatal("message seed does not match the stored seed")
	}
	if _, err := skdm.Serialize(); err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	skdm.Release()
	if skdm.ChainKey() != nil {
		t.Fatal("seed still readable after Release")
	}
	if _, err := skdm.Serialize(); err == nil {
		t.Fatal("Serialize after Release: want an error")
	}
	if storedSeedDigest(t, store, name) != stored {
		t.Fatal("Release changed the stored sender chain seed")
	}
}

// storedSeedDigest returns the SHA-256 of the sender chain seed stored for
// name, computed inside the borrow of a guarded clone. It fails the test if
// the seed is not 32 bytes.
func storedSeedDigest(t *testing.T, store *inMemorySenderKeyStore, name *protocol.SenderKeyName) [sha256.Size]byte {
	t.Helper()
	rec, err := store.LoadSenderKey(name)
	if err != nil {
		t.Fatalf("LoadSenderKey: %v", err)
	}
	state, err := rec.SenderKeyState()
	if err != nil {
		t.Fatalf("SenderKeyState: %v", err)
	}
	seed, err := state.SenderChainKey().SeedSecret()
	if err != nil {
		t.Fatalf("SeedSecret: %v", err)
	}
	defer seed.Destroy()
	if n := secrettest.Len(t, seed); n != 32 {
		t.Fatalf("stored seed length = %d, want 32", n)
	}
	return secrettest.Digest(t, seed)
}
