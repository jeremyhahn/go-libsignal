package record

import (
	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/util/bytehelper"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// NewPendingKeyExchange will return a new PendingKeyExchange object.
func NewPendingKeyExchange(sequence uint32, localBaseKeyPair, localRatchetKeyPair *ecc.ECKeyPair,
	localIdentityKeyPair *identity.KeyPair) *PendingKeyExchange {

	return &PendingKeyExchange{
		sequence:             sequence,
		localBaseKeyPair:     localBaseKeyPair,
		localRatchetKeyPair:  localRatchetKeyPair,
		localIdentityKeyPair: localIdentityKeyPair,
	}
}

// NewPendingKeyExchangeFromStruct returns a PendingKeyExchange with each private key in guarded memory; on failure it releases them.
func NewPendingKeyExchangeFromStruct(structure *PendingKeyExchangeStructure) (*PendingKeyExchange, error) {
	// Return nil if no structure was provided.
	if structure == nil {
		return nil, nil
	}

	// Alias the SliceToArray method.
	getArray := bytehelper.SliceToArray

	// Populate the exchange in place so that every guarded key built so far is
	// reachable by the cleanup below, whichever step fails.
	pendingKeyExchange := &PendingKeyExchange{sequence: structure.Sequence}
	handedOver := false
	defer func() {
		if !handedOver {
			destroyPendingKeyExchange(pendingKeyExchange)
		}
	}()

	// Convert the bytes in the given structure to ECC objects using guarded keys.
	localBaseKeyPrivate, err := guardedPrivateKey(&structure.LocalBaseKeyPrivate)
	if err != nil {
		return nil, err
	}
	pendingKeyExchange.localBaseKeyPair = ecc.NewECKeyPair(
		ecc.NewDjbECPublicKey(getArray(structure.LocalBaseKeyPublic)),
		localBaseKeyPrivate,
	)

	localRatchetKeyPrivate, err := guardedPrivateKey(&structure.LocalRatchetKeyPrivate)
	if err != nil {
		return nil, err
	}
	pendingKeyExchange.localRatchetKeyPair = ecc.NewECKeyPair(
		ecc.NewDjbECPublicKey(getArray(structure.LocalRatchetKeyPublic)),
		localRatchetKeyPrivate,
	)

	localIdentityKeyPrivate, err := guardedPrivateKey(&structure.LocalIdentityKeyPrivate)
	if err != nil {
		return nil, err
	}
	pendingKeyExchange.localIdentityKeyPair = identity.NewKeyPair(
		identity.NewKey(ecc.NewDjbECPublicKey(getArray(structure.LocalIdentityKeyPublic))),
		localIdentityKeyPrivate,
	)

	// Return the PendingKeyExchange with the deserialized keys.
	handedOver = true
	return pendingKeyExchange, nil
}

// PendingKeyExchangeStructure is the stored form of a pending key exchange; private keys are guarded values, not pointers, so JSON null cannot orphan them.
type PendingKeyExchangeStructure struct {
	Sequence                uint32
	LocalBaseKeyPublic      []byte
	LocalBaseKeyPrivate     secret.Secret
	LocalRatchetKeyPublic   []byte
	LocalRatchetKeyPrivate  secret.Secret
	LocalIdentityKeyPublic  []byte
	LocalIdentityKeyPrivate secret.Secret
}

// Zeroize destroys all guarded private key material in the structure.
// Call this (via defer) after the structure has been serialized to prevent
// private key bytes from outliving the serialization.
func (p *PendingKeyExchangeStructure) Zeroize() {
	p.LocalBaseKeyPrivate.Destroy()
	p.LocalRatchetKeyPrivate.Destroy()
	p.LocalIdentityKeyPrivate.Destroy()
}

// PendingKeyExchange is a structure for storing a pending
// key exchange for a session state.
type PendingKeyExchange struct {
	sequence             uint32
	localBaseKeyPair     *ecc.ECKeyPair
	localRatchetKeyPair  *ecc.ECKeyPair
	localIdentityKeyPair *identity.KeyPair
}

// structure returns a serializable pending key exchange the caller must Zeroize; on failure it releases what it built.
func (p *PendingKeyExchange) structure() (_ *PendingKeyExchangeStructure, err error) {
	getSlice := bytehelper.ArrayToSlice

	structure := &PendingKeyExchangeStructure{
		Sequence:               p.sequence,
		LocalBaseKeyPublic:     getSlice(p.localBaseKeyPair.PublicKey().PublicKey()),
		LocalRatchetKeyPublic:  getSlice(p.localRatchetKeyPair.PublicKey().PublicKey()),
		LocalIdentityKeyPublic: getSlice(p.localIdentityKeyPair.PublicKey().PublicKey().PublicKey()),
	}

	// Release the partially built structure if any step below fails, so that
	// no guarded allocation outlives the failed call.
	defer func() {
		if err != nil {
			structure.Zeroize()
		}
	}()

	if structure.LocalBaseKeyPrivate, err = ecc.GuardPrivateKey(p.localBaseKeyPair.PrivateKey()); err != nil {
		return nil, err
	}
	if structure.LocalRatchetKeyPrivate, err = ecc.GuardPrivateKey(p.localRatchetKeyPair.PrivateKey()); err != nil {
		return nil, err
	}
	if structure.LocalIdentityKeyPrivate, err = ecc.GuardPrivateKey(p.localIdentityKeyPair.PrivateKey()); err != nil {
		return nil, err
	}

	return structure, nil
}
