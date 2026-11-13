package record

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/kdf"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/chain"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/message"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/root"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// These tests live in the record package because the cleanup they cover is
// deliberately unexported: it may only be applied to objects a constructor is
// abandoning. See destroy.go.

// released reports whether the guarded material behind an accessor is gone.
// A destroyed secret.Secret panics on access rather than returning zeros, so
// both outcomes count as released.
func released(read func() []byte) (gone bool) {
	defer func() {
		if recover() != nil {
			gone = true
		}
	}()
	return len(read()) == 0
}

// releasedCopy is released for an accessor that reports a destroyed key as
// an error rather than an empty copy.
func releasedCopy(read func() ([]byte, error)) bool {
	b, err := read()
	return err != nil || len(b) == 0
}

func newFilledPrivateKey(t *testing.T, fill byte) *ecc.GuardedECPrivateKey {
	t.Helper()
	var raw [32]byte
	for i := range raw {
		raw[i] = fill
	}
	key, err := ecc.NewGuardedECPrivateKey(raw)
	if err != nil {
		t.Fatalf("ecc.NewGuardedECPrivateKey: %v", err)
	}
	return key
}

func guardedKeyPair(t *testing.T, fill byte) (*ecc.ECKeyPair, *ecc.GuardedECPrivateKey) {
	t.Helper()
	privateKey := newFilledPrivateKey(t, fill)
	var public [32]byte
	public[0] = fill
	return ecc.NewECKeyPair(ecc.NewDjbECPublicKey(public), privateKey), privateKey
}

func testChain(t *testing.T, fill byte) (*Chain, *ecc.GuardedECPrivateKey) {
	t.Helper()
	keyPair, privateKey := guardedKeyPair(t, fill)
	chainKey := chain.NewKey(kdf.DeriveSecrets, bytes.Repeat([]byte{fill}, 32), 0)
	messageKeys := []*message.Keys{
		message.NewKeys(bytes.Repeat([]byte{fill}, 32), bytes.Repeat([]byte{fill}, 32), bytes.Repeat([]byte{fill}, 16), 0),
	}
	return NewChain(keyPair, chainKey, messageKeys), privateKey
}

func TestDestroyPartialChainReleasesEveryGuardedComponent(t *testing.T) {
	chainState, privateKey := testChain(t, 0x11)
	messageKeys := chainState.MessageKeys()[0]

	destroyChain(chainState)

	if !privateKey.IsDestroyed() {
		t.Error("sender ratchet private key was left in locked memory")
	}
	if !released(chainState.ChainKey().Key) {
		t.Error("chain key was left in locked memory")
	}
	if !releasedCopy(messageKeys.CipherKey) {
		t.Error("message cipher key was left in locked memory")
	}
	if !releasedCopy(messageKeys.MacKey) {
		t.Error("message mac key was left in locked memory")
	}
	if !releasedCopy(messageKeys.Iv) {
		t.Error("message iv was left in locked memory")
	}

	// A constructor may unwind through the cleanup more than once — the outer
	// state releases the chain the inner call already released.
	destroyChain(chainState)
}

func TestDestroyPartialChainToleratesAbsentComponents(t *testing.T) {
	destroyChain(nil)

	// The shapes a chain can have part-way through NewChainFromStructure: no
	// key pair at all, and a key pair whose private half was never decoded.
	destroyChain(NewChain(nil, nil, nil))
	destroyChain(NewChain(ecc.NewECKeyPair(nil, nil), nil, []*message.Keys{nil}))
}

func TestDestroyPartialPendingKeyExchangeReleasesEveryPrivateKey(t *testing.T) {
	baseKeyPair, basePrivate := guardedKeyPair(t, 0x21)
	ratchetKeyPair, ratchetPrivate := guardedKeyPair(t, 0x22)
	identityKeyPair, identityPrivate := guardedKeyPair(t, 0x23)
	pendingKeyExchange := NewPendingKeyExchange(7, baseKeyPair, ratchetKeyPair,
		identity.NewKeyPair(identity.NewKey(identityKeyPair.PublicKey()), identityPrivate))

	destroyPendingKeyExchange(pendingKeyExchange)

	if !basePrivate.IsDestroyed() {
		t.Error("local base private key was left in locked memory")
	}
	if !ratchetPrivate.IsDestroyed() {
		t.Error("local ratchet private key was left in locked memory")
	}
	if !identityPrivate.IsDestroyed() {
		t.Error("long-term identity private key was left in locked memory")
	}

	destroyPendingKeyExchange(pendingKeyExchange)
}

func TestDestroyPartialPendingKeyExchangeToleratesPartialConstruction(t *testing.T) {
	destroyPendingKeyExchange(nil)

	// The shape NewPendingKeyExchangeFromStruct leaves behind when the ratchet
	// key fails to decode: a base key pair and nothing after it.
	baseKeyPair, basePrivate := guardedKeyPair(t, 0x31)
	destroyPendingKeyExchange(NewPendingKeyExchange(1, baseKeyPair, nil, nil))
	if !basePrivate.IsDestroyed() {
		t.Error("local base private key was left in locked memory")
	}
}

func TestDestroyPartialStateReleasesEveryGuardedComponent(t *testing.T) {
	senderChain, senderPrivate := testChain(t, 0x41)
	receiverChain, receiverPrivate := testChain(t, 0x42)
	baseKeyPair, basePrivate := guardedKeyPair(t, 0x43)
	rootKey := root.NewKey(kdf.DeriveSecrets, bytes.Repeat([]byte{0x44}, 32))
	pqRatchetState, err := secret.New(bytes.Repeat([]byte{0x45}, 64))
	if err != nil {
		t.Fatalf("secret.New: %v", err)
	}

	state := &State{
		senderChain:        senderChain,
		receiverChains:     []*Chain{receiverChain, nil},
		pendingKeyExchange: NewPendingKeyExchange(1, baseKeyPair, nil, nil),
		rootKey:            rootKey,
		pqRatchetState:     pqRatchetState,
	}

	destroyState(state)

	if !senderPrivate.IsDestroyed() {
		t.Error("sender chain private key was left in locked memory")
	}
	if !receiverPrivate.IsDestroyed() {
		t.Error("receiver chain private key was left in locked memory")
	}
	if !basePrivate.IsDestroyed() {
		t.Error("pending key exchange private key was left in locked memory")
	}
	if !releasedCopy(rootKey.Bytes) {
		t.Error("root key was left in locked memory")
	}
	if !pqRatchetState.IsDestroyed() {
		t.Error("PQ ratchet state was left in locked memory")
	}

	destroyState(state)
}

func TestDestroyPartialStateToleratesAbsentComponents(t *testing.T) {
	destroyState(nil)
	destroyState(&State{})
}

func TestDestroyPrivateKeyOverwritesHeapBackedKey(t *testing.T) {
	var raw [32]byte
	for i := range raw {
		raw[i] = 0x51
	}
	heapKey := ecc.NewDjbECPrivateKey(raw)

	destroyPrivateKey(heapKey)

	if serialized := heapKey.Serialize(); !bytes.Equal(serialized[:], make([]byte, 32)) {
		t.Error("heap-backed private key was not overwritten")
	}
}

func TestDestroyPrivateKeyToleratesMissingKeys(t *testing.T) {
	destroyPrivateKey(nil)
	destroyPrivateKey((*ecc.GuardedECPrivateKey)(nil))
	destroyPrivateKey((*ecc.DjbECPrivateKey)(nil))
	destroyKeyPairPrivate(nil)
}

// testState returns a session state carrying guarded material in every place a
// live state can carry it, for the archive-eviction test below.
func testState(t *testing.T, fill byte) *State {
	t.Helper()
	senderChain, _ := testChain(t, fill)
	receiverChain, _ := testChain(t, fill+1)
	baseKeyPair, _ := guardedKeyPair(t, fill+2)
	pqRatchetState, err := secret.New(bytes.Repeat([]byte{fill + 3}, 64))
	if err != nil {
		t.Fatalf("secret.New: %v", err)
	}
	return &State{
		sessionVersion:     3,
		senderChain:        senderChain,
		receiverChains:     []*Chain{receiverChain},
		pendingKeyExchange: NewPendingKeyExchange(1, baseKeyPair, nil, nil),
		rootKey:            root.NewKey(kdf.DeriveSecrets, bytes.Repeat([]byte{fill + 4}, 32)),
		pqRatchetState:     pqRatchetState,
	}
}

// An archive that has reached its bound drops its oldest state, which the
// record was the only owner of.
func TestPromoteStateReleasesTheEvictedArchivedState(t *testing.T) {
	session := NewSession(nil, nil)

	// The oldest state ends up at the tail of the archive and is the first to
	// be evicted; keep hold of it so its material can be checked afterwards.
	oldest := testState(t, 0x61)
	session.SetState(oldest)

	retained := make([]*State, 0, archivedStatesMaxLength)
	for i := 0; i < archivedStatesMaxLength; i++ {
		state := testState(t, byte(0x70+i))
		retained = append(retained, state)
		session.PromoteState(state)
	}

	// The archive is exactly full and still holds the oldest state.
	if got := len(session.PreviousSessionStates()); got != archivedStatesMaxLength {
		t.Fatalf("archive holds %d states, want %d", got, archivedStatesMaxLength)
	}
	if releasedCopy(oldest.rootKey.Bytes) {
		t.Fatal("the oldest state was released before it was evicted")
	}

	// One more promotion pushes it over the bound and evicts it.
	session.PromoteState(testState(t, 0x51))

	if !releasedCopy(oldest.rootKey.Bytes) {
		t.Error("evicted state's root key was left in locked memory")
	}
	if !released(oldest.senderChain.ChainKey().Key) {
		t.Error("evicted state's sender chain key was left in locked memory")
	}
	if !oldest.pqRatchetState.IsDestroyed() {
		t.Error("evicted state's PQ ratchet state was left in locked memory")
	}

	// Everything still in the archive has to be untouched.
	for i, state := range retained {
		if releasedCopy(state.rootKey.Bytes) {
			t.Errorf("retained state %d was released along with the evicted one", i)
		}
	}
}
