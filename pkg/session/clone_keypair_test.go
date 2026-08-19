package session

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/kdf"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/chain"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
)

// heapBackedKeyPair builds a key pair whose private half is an unprotected
// *ecc.DjbECPrivateKey, the representation the public constructors
// (ecc.NewDjbECPrivateKey, record.NewSignedPreKey) still accept.
func heapBackedKeyPair(t *testing.T) *ecc.ECKeyPair {
	t.Helper()
	generated, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	material := generated.PrivateKey().Serialize()
	generated.ZeroizePrivateKey()
	return ecc.NewECKeyPair(generated.PublicKey(), ecc.NewDjbECPrivateKey(material))
}

// TestCloneKeyPairForStateCopiesHeapBackedKey covers the pre-key store's
// contract: a signed pre-key handed to a session state must survive the state
// destroying the chain it was placed in.
func TestCloneKeyPairForStateCopiesHeapBackedKey(t *testing.T) {
	storeOwned := heapBackedKeyPair(t)
	original := storeOwned.PrivateKey().Serialize()

	cloned, err := cloneKeyPairForState(storeOwned)
	if err != nil {
		t.Fatalf("cloneKeyPairForState: %v", err)
	}
	if cloned.PrivateKey() == storeOwned.PrivateKey() {
		t.Fatal("clone shares the caller's private key")
	}
	if got := cloned.PrivateKey().Serialize(); !bytes.Equal(got[:], original[:]) {
		t.Fatal("clone does not carry the same key material")
	}
	if !bytes.Equal(cloned.PublicKey().Serialize(), storeOwned.PublicKey().Serialize()) {
		t.Fatal("clone does not carry the same public key")
	}

	// Hand the clone to a state and let a ratchet step supersede it, which is
	// the path that destroys the chain's private key.
	state := record.NewState(serialize.NewJSONSerializer().State)
	state.SetSenderChain(cloned, chain.NewKey(kdf.DeriveSecrets, make([]byte, 32), 0))
	state.SetSenderChain(heapBackedKeyPair(t), chain.NewKey(kdf.DeriveSecrets, make([]byte, 32), 1))

	if got := storeOwned.PrivateKey().Serialize(); !bytes.Equal(got[:], original[:]) {
		t.Fatal("session state zeroized the store's signed pre-key")
	}

	// The store's key must still be usable for the operations a later handshake
	// performs with it.
	shared, agreeErr := kdf.CalculateSharedSecret(
		storeOwned.PublicKey().PublicKey(),
		storeOwned.PrivateKey().Serialize(),
	)
	if agreeErr != nil {
		t.Fatalf("CalculateSharedSecret with the store's key: %v", agreeErr)
	}
	if bytes.Equal(shared[:], make([]byte, len(shared))) {
		t.Fatal("agreement with the store's key produced an all-zero secret")
	}
}

// TestCloneKeyPairForStateClonesGuardedKey covers the guarded representation:
// the state must receive its own locked buffer, and destroying it must leave
// the caller's key intact.
func TestCloneKeyPairForStateClonesGuardedKey(t *testing.T) {
	storeOwned, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	defer storeOwned.ZeroizePrivateKey()
	original := storeOwned.PrivateKey().Serialize()

	cloned, cloneErr := cloneKeyPairForState(storeOwned)
	if cloneErr != nil {
		t.Fatalf("cloneKeyPairForState: %v", cloneErr)
	}
	clonedPrivate, ok := cloned.PrivateKey().(*ecc.GuardedECPrivateKey)
	if !ok {
		t.Fatalf("clone is %T, want *ecc.GuardedECPrivateKey", cloned.PrivateKey())
	}
	if got := clonedPrivate.Serialize(); !bytes.Equal(got[:], original[:]) {
		t.Fatal("clone does not carry the same key material")
	}

	clonedPrivate.Destroy()
	if !clonedPrivate.IsDestroyed() {
		t.Fatal("clone was not destroyed")
	}
	if got := storeOwned.PrivateKey().Serialize(); !bytes.Equal(got[:], original[:]) {
		t.Fatal("destroying the clone disturbed the caller's key")
	}
}

// TestCloneKeyPairForStateRejectsDestroyedKey exercises the error path: a
// guarded key whose buffer is already gone cannot be cloned, and the failure
// must surface rather than yield a key pair with unusable material.
func TestCloneKeyPairForStateRejectsDestroyedKey(t *testing.T) {
	keyPair, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	keyPair.ZeroizePrivateKey()

	cloned, cloneErr := cloneKeyPairForState(keyPair)
	if cloneErr == nil {
		t.Fatal("expected an error cloning a destroyed guarded key")
	}
	if cloned != nil {
		t.Fatal("expected no key pair alongside the error")
	}
}
