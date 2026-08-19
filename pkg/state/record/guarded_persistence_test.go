package record_test

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/kem"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/chain"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/util/bytehelper"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// The records below build their serializable structure on demand and destroy
// its guarded private key once the serializer is done with it. Serializing
// twice therefore has to produce identical bytes: if a record ever went back to
// sharing the guarded key with the structure it hands to the serializer, the
// first Serialize would destroy the record's own key and the second would
// return zeros or panic.

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

func TestKyberPreKeySerializeIsRepeatable(t *testing.T) {
	keyPair, err := kem.NewGuardedKyber1024().Generate()
	if err != nil {
		t.Fatalf("kem Generate: %v", err)
	}
	serializer := &kyberPreKeySerializer{}
	kpk := record.NewKyberPreKey(9, 2000, keyPair, []byte("sig"), serializer)

	first, err := kpk.Serialize()
	if err != nil {
		t.Fatalf("first Serialize: %v", err)
	}
	second, err := kpk.Serialize()
	if err != nil {
		t.Fatalf("second Serialize: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("serialization is not repeatable")
	}

	structure, err := serializer.Deserialize(second)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	defer structure.Zeroize()

	if !structure.PrivateKey.EqualTo(keyPair.Secret.Data()) {
		t.Error("secret key did not survive the round trip")
	}
	structure.Zeroize()
	if !structure.PrivateKey.IsDestroyed() {
		t.Error("Zeroize left the guarded secret key alive")
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
		ChainKey:                &chain.KeyStructure{Key: make([]byte, 32), Index: 0},
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

// The live representations below are the other half of the storage boundary:
// deserialization must not hand the material it decoded into guarded memory
// back to the plain Go heap, because the record and the session state outlive
// the structure by the whole lifetime of the key.

// TestKyberPreKeyRoundTripStaysGuarded checks that a Kyber pre-key read back
// from storage holds its secret key in guarded memory, independent of the
// structure it was decoded from.
func TestKyberPreKeyRoundTripStaysGuarded(t *testing.T) {
	keyPair, err := kem.NewGuardedKyber1024().Generate()
	if err != nil {
		t.Fatalf("kem Generate: %v", err)
	}
	want := append([]byte(nil), keyPair.Secret.Data()...)

	serializer := &kyberPreKeySerializer{}
	serialized, err := record.NewKyberPreKey(3, 1000, keyPair, []byte("sig"), serializer).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	structure, err := serializer.Deserialize(serialized)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}

	rebuilt, err := record.NewKyberPreKeyFromStructure(*structure, serializer)
	if err != nil {
		t.Fatalf("NewKyberPreKeyFromStructure: %v", err)
	}

	// The record owns its own guarded copy: releasing the structure at the
	// storage boundary must not disturb it.
	structure.Zeroize()

	guarded, err := rebuilt.GuardedKeyPair()
	if err != nil {
		t.Fatalf("GuardedKeyPair: %v", err)
	}
	defer guarded.Destroy()

	if guarded.Secret.IsDestroyed() {
		t.Fatal("secret key was destroyed with the structure")
	}
	if !bytes.Equal(guarded.Secret.Data(), want) {
		t.Error("secret key did not survive the round trip")
	}
}

// TestKyberPreKeyGuardedKeyPairIsIndependent checks that the caller-owned copy
// handed out by GuardedKeyPair can be destroyed without disturbing the record,
// which is what every PQXDH decrypt does.
func TestKyberPreKeyGuardedKeyPairIsIndependent(t *testing.T) {
	keyPair, err := kem.NewGuardedKyber1024().Generate()
	if err != nil {
		t.Fatalf("kem Generate: %v", err)
	}
	kpk := record.NewKyberPreKey(4, 1000, keyPair, []byte("sig"), &kyberPreKeySerializer{})

	guarded, err := kpk.GuardedKeyPair()
	if err != nil {
		t.Fatalf("GuardedKeyPair: %v", err)
	}
	guarded.Destroy()

	again, err := kpk.GuardedKeyPair()
	if err != nil {
		t.Fatalf("GuardedKeyPair after Destroy: %v", err)
	}
	defer again.Destroy()
	if again.Secret.IsDestroyed() {
		t.Error("destroying the handed-out copy destroyed the record's own key")
	}
}

// TestKyberPreKeyDestroyReleasesSecret checks the record lifecycle: once the
// record is destroyed its key material is gone and it can no longer be used.
func TestKyberPreKeyDestroyReleasesSecret(t *testing.T) {
	keyPair, err := kem.NewGuardedKyber1024().Generate()
	if err != nil {
		t.Fatalf("kem Generate: %v", err)
	}
	kpk := record.NewKyberPreKey(5, 1000, keyPair, []byte("sig"), &kyberPreKeySerializer{})

	kpk.Destroy()
	kpk.Destroy() // idempotent

	if _, err := kpk.GuardedKeyPair(); err == nil {
		t.Error("GuardedKeyPair should fail once the record has been destroyed")
	}
	if _, err := kpk.Serialize(); err == nil {
		t.Error("Serialize should fail once the record has been destroyed")
	}
	if kpk.PublicKey() == nil {
		t.Error("the public key should remain available after Destroy")
	}
}

// TestNewKyberPreKeyFromStructureRejectsWrongKeyLength checks that a persisted
// private key whose length does not match the public key's algorithm is
// rejected rather than loaded as a mismatched key pair.
func TestNewKyberPreKeyFromStructureRejectsWrongKeyLength(t *testing.T) {
	publicKey := kem.NewPublicKey(kem.KeyTypeKyber1024, make([]byte, 1568))
	structure := record.KyberPreKeyStructure{
		ID:         6,
		PublicKey:  publicKey.Serialize(),
		PrivateKey: mustGuard(t, make([]byte, 32)),
		Signature:  []byte("sig"),
		Timestamp:  1000,
	}
	defer structure.Zeroize()

	if _, err := record.NewKyberPreKeyFromStructure(structure, &kyberPreKeySerializer{}); err == nil {
		t.Fatal("expected a truncated private key to be rejected")
	}
}

// TestNewKyberPreKeyFromStructureRejectsAbsentPrivateKey checks that a record
// persisted without a private key is rejected: a Kyber pre-key that cannot
// decapsulate is not a usable record.
func TestNewKyberPreKeyFromStructureRejectsAbsentPrivateKey(t *testing.T) {
	publicKey := kem.NewPublicKey(kem.KeyTypeKyber1024, make([]byte, 1568))
	structure := record.KyberPreKeyStructure{
		ID:        7,
		PublicKey: publicKey.Serialize(),
		Signature: []byte("sig"),
		Timestamp: 1000,
	}

	if _, err := record.NewKyberPreKeyFromStructure(structure, &kyberPreKeySerializer{}); err == nil {
		t.Fatal("expected a structure with no private key to be rejected")
	}
}

// TestStatePqRatchetStateStaysGuarded checks that the SPQR state a session was
// restored with lives in guarded memory rather than in a plain slice, and that
// it is independent of the structure it was decoded from.
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

// TestSetPqRatchetStateReplacesPreviousState checks the replacement path used
// on every SPQR send and receive: the new state is readable and the old one is
// gone rather than left behind.
func TestSetPqRatchetStateReplacesPreviousState(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)

	if err := state.SetPqRatchetState([]byte{0x01, 0x02}); err != nil {
		t.Fatalf("SetPqRatchetState: %v", err)
	}
	if err := state.SetPqRatchetState([]byte{0x03, 0x04, 0x05}); err != nil {
		t.Fatalf("SetPqRatchetState (replacement): %v", err)
	}

	if got := state.PqRatchetState(); !bytes.Equal(got, []byte{0x03, 0x04, 0x05}) {
		t.Fatalf("PqRatchetState() = %x, want %x", got, []byte{0x03, 0x04, 0x05})
	}
}

// TestCopyFromKeepsPqRatchetStateOnSelfCopy checks that committing a state onto
// itself does not destroy the guarded SPQR state it is about to keep.
func TestCopyFromKeepsPqRatchetStateOnSelfCopy(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)
	if err := state.SetPqRatchetState([]byte{0x09, 0x08}); err != nil {
		t.Fatalf("SetPqRatchetState: %v", err)
	}

	state.CopyFrom(state)

	if got := state.PqRatchetState(); !bytes.Equal(got, []byte{0x09, 0x08}) {
		t.Fatalf("PqRatchetState() = %x, want %x", got, []byte{0x09, 0x08})
	}
}

// TestCopyFromAdoptsClonedPqRatchetState checks the decrypt commit path: the
// state advanced on a clone replaces the original's SPQR state.
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
