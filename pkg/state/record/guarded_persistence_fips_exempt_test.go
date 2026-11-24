//go:build !fips140only

// FIPS 140-3 exemption (docs/FIPS.md): these guarded-persistence fixtures carry Curve25519 keys, which X3DH requires; the rest stay in guarded_persistence_test.go.

package record_test

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/keys/chain"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/util/bytehelper"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// Serializing twice must give identical bytes, proving the structure does not share the record's guarded key.

func TestPreKeySerializeIsRepeatable(t *testing.T) {
	s := newSerializer()
	kp := genKP(t)
	pk := record.NewPreKey(5, kp, s.PreKeyRecord)

	first, err := pk.Serialize()
	if err != nil {
		t.Fatalf("first Serialize: %v", err)
	}
	second, err := pk.Serialize()
	if err != nil {
		t.Fatalf("second Serialize: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("serialization is not repeatable:\nfirst  %s\nsecond %s", first, second)
	}

	// The record's own key material must be untouched by serialization.
	privateKey := pk.KeyPair().PrivateKey().Serialize()
	if bytes.Equal(privateKey[:], make([]byte, 32)) {
		t.Error("private key was zeroized by serialization")
	}
}

func TestSignedPreKeySerializeIsRepeatable(t *testing.T) {
	s := newSerializer()
	kp := genKP(t)
	var sig [64]byte
	copy(sig[:], bytes.Repeat([]byte{0x0A}, 64))
	spk := record.NewSignedPreKey(3, 1000, kp, sig, s.SignedPreKeyRecord)

	first, err := spk.Serialize()
	if err != nil {
		t.Fatalf("first Serialize: %v", err)
	}
	second, err := spk.Serialize()
	if err != nil {
		t.Fatalf("second Serialize: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("serialization is not repeatable:\nfirst  %s\nsecond %s", first, second)
	}

	restored, err := record.NewSignedPreKeyFromBytes(second, s.SignedPreKeyRecord)
	if err != nil {
		t.Fatalf("NewSignedPreKeyFromBytes: %v", err)
	}
	want := kp.PrivateKey().Serialize()
	got := restored.KeyPair().PrivateKey().Serialize()
	if !bytes.Equal(got[:], want[:]) {
		t.Error("private key did not survive the round trip")
	}
	if restored.Signature() != sig {
		t.Error("signature did not survive the round trip")
	}
}

func TestSessionSerializeIsRepeatable(t *testing.T) {
	s := newSerializer()

	structure := makeFullStateStructure(t)
	structure.PqRatchetState = mustGuard(t, []byte{0x01, 0x02, 0x03})

	state, err := record.NewStateFromStructure(structure, s.State)
	if err != nil {
		t.Fatalf("NewStateFromStructure: %v", err)
	}
	session := record.NewSessionFromState(state, s.Session)

	first, err := session.Serialize()
	if err != nil {
		t.Fatalf("first Serialize: %v", err)
	}
	second, err := session.Serialize()
	if err != nil {
		t.Fatalf("second Serialize: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("serialization is not repeatable:\nfirst  %s\nsecond %s", first, second)
	}

	restored, err := record.NewSessionFromBytes(second, s.Session, s.State)
	if err != nil {
		t.Fatalf("NewSessionFromBytes: %v", err)
	}
	restoredState := restored.SessionState()
	if !bytes.Equal(restoredState.RootKey().Bytes(), state.RootKey().Bytes()) {
		t.Error("root key did not survive the round trip")
	}
	if !bytes.Equal(restoredState.PqRatchetState(), []byte{0x01, 0x02, 0x03}) {
		t.Error("PQ ratchet state did not survive the round trip")
	}
	if restoredState.SenderRatchetKeyPair().PrivateKey() == nil {
		t.Fatal("sender ratchet private key did not survive the round trip")
	}
}

// TestStateStructureZeroizeDestroysGuardedMaterial checks the storage-boundary
// contract: once a caller has Zeroized a deserialized structure, no guarded
// key material is left alive anywhere in it.
func TestStateStructureZeroizeDestroysGuardedMaterial(t *testing.T) {
	kp := genKP(t)
	privateKey := kp.PrivateKey().Serialize()

	structure := &record.StateStructure{
		SessionVersion: 4,
		RootKey:        mustGuard(t, bytes.Repeat([]byte{0x07}, 32)),
		PqRatchetState: mustGuard(t, []byte{0x01, 0x02}),
		SenderChain: &record.ChainStructure{
			SenderRatchetKeyPublic:  kp.PublicKey().Serialize(),
			SenderRatchetKeyPrivate: mustGuard(t, bytehelper.ArrayToSlice(privateKey)),
		},
		PendingKeyExchange: &record.PendingKeyExchangeStructure{
			LocalIdentityKeyPrivate: mustGuard(t, bytehelper.ArrayToSlice(privateKey)),
		},
		ReceiverChains: []*record.ChainStructure{
			{SenderRatchetKeyPrivate: mustGuard(t, bytehelper.ArrayToSlice(privateKey))},
			nil,
		},
	}

	structure.Zeroize()

	for name, guarded := range map[string]*secret.Secret{
		"root key":             &structure.RootKey,
		"pq ratchet state":     &structure.PqRatchetState,
		"sender ratchet key":   &structure.SenderChain.SenderRatchetKeyPrivate,
		"local identity key":   &structure.PendingKeyExchange.LocalIdentityKeyPrivate,
		"receiver ratchet key": &structure.ReceiverChains[0].SenderRatchetKeyPrivate,
	} {
		if !guarded.IsDestroyed() {
			t.Errorf("%s survived Zeroize", name)
		}
	}

	// Zeroize is idempotent: a second call on the same structure is a no-op.
	structure.Zeroize()
}

// TestChainStructureAbsentPrivateKey covers a receiver chain persisted without
// a sender ratchet private key, which is the shape of every chain deserialized
// from a peer's ratchet step.
func TestChainStructureAbsentPrivateKey(t *testing.T) {
	kp := genKP(t)
	structure := &record.ChainStructure{
		SenderRatchetKeyPublic:  kp.PublicKey().Serialize(),
		SenderRatchetKeyPrivate: secret.Secret{},
		ChainKey:                &chain.KeyStructure{Key: mustGuard(t, make([]byte, 32)), Index: 0},
	}

	chainState, err := record.NewChainFromStructure(structure)
	if err != nil {
		t.Fatalf("NewChainFromStructure: %v", err)
	}
	if chainState.SenderRatchetKey().PrivateKey() != nil {
		t.Error("expected no private key for a chain persisted without one")
	}
	structure.Zeroize()
}

// TestStatePqRatchetStateStaysGuarded checks a restored SPQR state is guarded and independent of its source structure.
func TestStatePqRatchetStateStaysGuarded(t *testing.T) {
	s := newSerializer()
	want := []byte{0x0a, 0x0b, 0x0c}

	structure := makeFullStateStructure(t)
	structure.PqRatchetState = mustGuard(t, want)

	state, err := record.NewStateFromStructure(structure, s.State)
	if err != nil {
		t.Fatalf("NewStateFromStructure: %v", err)
	}
	structure.Zeroize()

	if !bytes.Equal(state.PqRatchetState(), want) {
		t.Fatalf("PqRatchetState() = %x, want %x", state.PqRatchetState(), want)
	}
}

// TestCopyFromAdoptsClonedPqRatchetState checks the clone's SPQR state replaces the original on commit.
func TestCopyFromAdoptsClonedPqRatchetState(t *testing.T) {
	s := newSerializer()

	structure := makeFullStateStructure(t)
	structure.PqRatchetState = mustGuard(t, []byte{0x01})
	state, err := record.NewStateFromStructure(structure, s.State)
	if err != nil {
		t.Fatalf("NewStateFromStructure: %v", err)
	}
	structure.Zeroize()

	working, err := state.Clone()
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	if err := working.SetPqRatchetState([]byte{0x02, 0x03}); err != nil {
		t.Fatalf("SetPqRatchetState: %v", err)
	}

	state.CopyFrom(working)

	if got := state.PqRatchetState(); !bytes.Equal(got, []byte{0x02, 0x03}) {
		t.Fatalf("PqRatchetState() = %x, want %x", got, []byte{0x02, 0x03})
	}
}
