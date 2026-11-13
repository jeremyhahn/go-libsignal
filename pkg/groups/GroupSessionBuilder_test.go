//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 4 tests in this file exercise X25519. FIPS 140-3 does not approve that,
// but the X3DH key agreement specification (section 2.1) requires it, so the
// fips140only build tag drops this file from the FIPS gate. `make test` and
// `make coverage` still run it.

package groups

import (
	"testing"

	groupRecord "github.com/jeremyhahn/go-libsignal/pkg/groups/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
)

// inMemorySenderKeyStore is a minimal in-memory store for testing.
type inMemorySenderKeyStore struct {
	store map[string]*groupRecord.SenderKey
}

func newInMemorySenderKeyStore() *inMemorySenderKeyStore {
	return &inMemorySenderKeyStore{
		store: make(map[string]*groupRecord.SenderKey),
	}
}

func (s *inMemorySenderKeyStore) StoreSenderKey(name *protocol.SenderKeyName, record *groupRecord.SenderKey) error {
	s.store[name.GroupID()+name.Sender().String()] = record
	return nil
}

func (s *inMemorySenderKeyStore) LoadSenderKey(name *protocol.SenderKeyName) (*groupRecord.SenderKey, error) {
	return s.store[name.GroupID()+name.Sender().String()], nil
}

func newTestSerializer() *serialize.Serializer {
	return serialize.NewJSONSerializer()
}

func TestNewGroupSessionBuilder(t *testing.T) {
	store := newInMemorySenderKeyStore()
	serializer := newTestSerializer()

	builder := NewGroupSessionBuilder(store, serializer)
	if builder == nil {
		t.Fatal("NewGroupSessionBuilder() returned nil")
	}
}

func TestSessionBuilderCreate(t *testing.T) {
	store := newInMemorySenderKeyStore()
	serializer := newTestSerializer()
	builder := NewGroupSessionBuilder(store, serializer)

	address := protocol.NewSignalAddress("alice", 1)
	senderKeyName := protocol.NewSenderKeyName("test-group", address)

	skdm, err := builder.Create([16]byte{}, senderKeyName)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	defer skdm.Release()
	if skdm == nil {
		t.Fatal("Create() returned nil SKDM")
	}
	if skdm.SignatureKey() == nil {
		t.Error("SKDM SignatureKey() should not be nil")
	}
}

func TestSessionBuilderCreateIdempotent(t *testing.T) {
	store := newInMemorySenderKeyStore()
	serializer := newTestSerializer()
	builder := NewGroupSessionBuilder(store, serializer)

	address := protocol.NewSignalAddress("alice", 1)
	senderKeyName := protocol.NewSenderKeyName("test-group", address)

	// First create generates new keys
	skdm1, err := builder.Create([16]byte{}, senderKeyName)
	if err != nil {
		t.Fatalf("First Create() error: %v", err)
	}
	defer skdm1.Release()

	// Second create should return same state (not regenerate)
	skdm2, err := builder.Create([16]byte{}, senderKeyName)
	if err != nil {
		t.Fatalf("Second Create() error: %v", err)
	}
	defer skdm2.Release()

	if skdm1.ID() != skdm2.ID() {
		t.Errorf("Second Create should reuse existing state: ID %d vs %d", skdm1.ID(), skdm2.ID())
	}
}

func TestSessionBuilderProcess(t *testing.T) {
	aliceStore := newInMemorySenderKeyStore()
	bobStore := newInMemorySenderKeyStore()
	serializer := newTestSerializer()

	aliceBuilder := NewGroupSessionBuilder(aliceStore, serializer)
	bobBuilder := NewGroupSessionBuilder(bobStore, serializer)

	aliceAddress := protocol.NewSignalAddress("alice", 1)
	senderKeyName := protocol.NewSenderKeyName("test-group", aliceAddress)

	// Alice creates the group session
	skdm, err := aliceBuilder.Create([16]byte{}, senderKeyName)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	defer skdm.Release()

	// Serialize and deserialize the SKDM to simulate network transfer
	skdmBytes, err := skdm.Serialize()
	if err != nil {
		t.Fatalf("SKDM Serialize() error: %v", err)
	}
	receivedSkdm, err := protocol.NewSenderKeyDistributionMessageFromBytes(skdmBytes, serializer.SenderKeyDistributionMessage)
	if err != nil {
		t.Fatalf("NewSenderKeyDistributionMessageFromBytes() error: %v", err)
	}
	defer receivedSkdm.Release()

	// Bob processes the received SKDM
	if err := bobBuilder.Process(senderKeyName, receivedSkdm); err != nil {
		t.Fatalf("Process() error: %v", err)
	}

	// Verify Bob now has the sender key
	record, err := bobStore.LoadSenderKey(senderKeyName)
	if err != nil {
		t.Fatalf("LoadSenderKey() error: %v", err)
	}
	if record == nil {
		t.Fatal("Bob's store should have sender key after Process")
	}
	if record.IsEmpty() {
		t.Error("Bob's sender key record should not be empty")
	}
}

func TestSessionBuilderProcessNilRecord(t *testing.T) {
	store := newInMemorySenderKeyStore()
	serializer := newTestSerializer()
	builder := NewGroupSessionBuilder(store, serializer)

	// Create a SKDM from another builder
	otherStore := newInMemorySenderKeyStore()
	otherBuilder := NewGroupSessionBuilder(otherStore, serializer)
	address := protocol.NewSignalAddress("sender", 1)
	senderKeyName := protocol.NewSenderKeyName("group1", address)

	skdm, err := otherBuilder.Create([16]byte{}, senderKeyName)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	defer skdm.Release()

	// Process on builder with nil record in store (store returns nil)
	if err := builder.Process(senderKeyName, skdm); err != nil {
		t.Fatalf("Process() error: %v", err)
	}

	// Should now have a record
	record, err := store.LoadSenderKey(senderKeyName)
	if err != nil {
		t.Fatalf("LoadSenderKey() error: %v", err)
	}
	if record == nil {
		t.Fatal("Store should have record after Process with nil initial record")
	}
}
