package record

import (
	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
)

// Guarded key material is not reclaimed by the garbage collector: memguard
// registers no finalizer and keeps every live buffer in a process-global list
// until it is explicitly destroyed, so an abandoned buffer stays mlock'd for
// the life of the process. A deserialization constructor that fails part-way
// through has therefore stranded every guarded allocation it already made, and
// a peer able to feed the store malformed persisted records can repeat that
// path until the process exhausts its RLIMIT_MEMLOCK allowance.
//
// The helpers below release those allocations. They may only be applied to an
// object the caller owns outright, and there are exactly two such objects: one
// a constructor built and is about to abandon, which no caller has ever seen,
// and a clone that will not be committed, which Clone built out of its own
// guarded buffers (see State.DiscardClone). That restriction is what makes them
// safe. Ordinary live objects are shared by design — State.CopyFrom moves the
// clone's chains, root key and PQ ratchet state into the state committed into,
// so the two then own the same guarded objects — and destroying a reachable
// object would be a use-after-free. Giving the record layer a general
// destruction model means settling that ownership question first; nothing here
// depends on it.
//
// Every helper is nil-safe and idempotent, so a partially populated object is
// as safe to pass as a complete one.

// destroyState releases the guarded material held by a session state.
func destroyState(state *State) {
	if state == nil {
		return
	}
	destroyChain(state.senderChain)
	for _, receiverChain := range state.receiverChains {
		destroyChain(receiverChain)
	}
	destroyPendingKeyExchange(state.pendingKeyExchange)
	if state.rootKey != nil {
		state.rootKey.Zeroize()
	}
	state.pqRatchetState.Destroy()
}

// destroyChain releases the guarded material held by a ratchet chain
// that failed to finish construction: the sender ratchet private key, the
// chain key, and every message key cached on the chain.
func destroyChain(chainState *Chain) {
	if chainState == nil {
		return
	}
	destroyKeyPairPrivate(chainState.senderRatchetKeyPair)
	if chainState.chainKey != nil {
		chainState.chainKey.Zeroize()
	}
	for _, messageKeys := range chainState.messageKeys {
		if messageKeys != nil {
			messageKeys.Zeroize()
		}
	}
}

// destroyPendingKeyExchange releases the three private keys held by a
// pending key exchange that failed to finish construction, including the
// long-term identity private key.
func destroyPendingKeyExchange(pendingKeyExchange *PendingKeyExchange) {
	if pendingKeyExchange == nil {
		return
	}
	destroyKeyPairPrivate(pendingKeyExchange.localBaseKeyPair)
	destroyKeyPairPrivate(pendingKeyExchange.localRatchetKeyPair)
	if pendingKeyExchange.localIdentityKeyPair != nil {
		destroyPrivateKey(pendingKeyExchange.localIdentityKeyPair.PrivateKey())
	}
}

// destroyKeyPairPrivate releases the private half of an EC key pair. The
// public half holds no secret and is left for the garbage collector.
func destroyKeyPairPrivate(keyPair *ecc.ECKeyPair) {
	if keyPair == nil {
		return
	}
	destroyPrivateKey(keyPair.PrivateKey())
}

// destroyPrivateKey releases an EC private key in whichever representation it
// arrived in: a guarded key gives up its locked buffer, a heap-backed key is
// overwritten in place. A nil key is a key that was never built.
func destroyPrivateKey(privateKey ecc.ECPrivateKeyable) {
	switch key := privateKey.(type) {
	case *ecc.GuardedECPrivateKey:
		if key != nil {
			key.Destroy()
		}
	case *ecc.DjbECPrivateKey:
		if key != nil {
			key.Zeroize()
		}
	}
}
