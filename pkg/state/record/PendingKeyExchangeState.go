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

// NewPendingKeyExchangeFromStruct will return a PendingKeyExchange object from
// the given structure. This is used to get a deserialized pending prekey exchange
// fetched from persistent storage.
//
// Each private key is moved into its own guarded buffer as it is decoded. If a
// later key cannot be built, the ones already built are released before
// returning, so a failed call leaves no locked memory behind.
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
	localBaseKeyPrivate, err := ecc.NewGuardedECPrivateKey(getArray(structure.LocalBaseKeyPrivate.BytesOrNil()))
	if err != nil {
		return nil, err
	}
	pendingKeyExchange.localBaseKeyPair = ecc.NewECKeyPair(
		ecc.NewDjbECPublicKey(getArray(structure.LocalBaseKeyPublic)),
		localBaseKeyPrivate,
	)

	localRatchetKeyPrivate, err := ecc.NewGuardedECPrivateKey(getArray(structure.LocalRatchetKeyPrivate.BytesOrNil()))
	if err != nil {
		return nil, err
	}
	pendingKeyExchange.localRatchetKeyPair = ecc.NewECKeyPair(
		ecc.NewDjbECPublicKey(getArray(structure.LocalRatchetKeyPublic)),
		localRatchetKeyPrivate,
	)

	localIdentityKeyPrivate, err := ecc.NewGuardedECPrivateKey(getArray(structure.LocalIdentityKeyPrivate.BytesOrNil()))
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

// PendingKeyExchangeStructure is a serializable structure for pending
// key exchanges. This structure is used for persistent storage of the
// key exchange state.
//
// The private keys — including the long-term identity private key — are held
// in guarded memory rather than on the Go heap, so that the plaintext window
// while state crosses the storage boundary is mlock'd, guard-paged and
// excluded from core dumps, matching the protection the live session state
// already has.
//
// The guarded fields are held by value, not by pointer: encoding/json replaces
// a pointer field with nil for a JSON null without calling the codec, which
// would abandon a guarded allocation made for an earlier occurrence of the
// same field. See secret.NewValue.
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

// structure will return a serializable structure of a pending key exchange
// so it can be persistently stored. The caller owns the returned structure and
// must Zeroize it once the serializer is done with it; on failure everything
// built so far is released before returning.
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

	if structure.LocalBaseKeyPrivate, err = guardECPrivateKey(p.localBaseKeyPair.PrivateKey()); err != nil {
		return nil, err
	}
	if structure.LocalRatchetKeyPrivate, err = guardECPrivateKey(p.localRatchetKeyPair.PrivateKey()); err != nil {
		return nil, err
	}
	if structure.LocalIdentityKeyPrivate, err = guardECPrivateKey(p.localIdentityKeyPair.PrivateKey()); err != nil {
		return nil, err
	}

	return structure, nil
}
