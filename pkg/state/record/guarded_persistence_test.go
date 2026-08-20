// Guarded-persistence tests that stay inside the FIPS gate.
//
// These build their key material byte by byte, or use Kyber, and reach no
// primitive the Go Cryptographic Module rejects. The seven tests whose
// fixtures carry a real Curve25519 key pair live in
// guarded_persistence_fips_exempt_test.go -- see docs/FIPS.md.

package record_test

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/kem"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
)

// A record builds its serializable structure on demand and destroys its
// guarded private key once the serializer is done with it. Serializing twice
// therefore has to produce identical bytes: if a record ever went back to
// sharing the guarded key with the structure it hands to the serializer, the
// first Serialize would destroy the record's own key and the second would
// return zeros or panic.

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
