package record

import (
	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/util/bytehelper"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
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
func NewPendingKeyExchangeFromStruct(structure *PendingKeyExchangeStructure) (*PendingKeyExchange, error) {
	// Return nil if no structure was provided.
	if structure == nil {
		return nil, nil
	}

	// Alias the SliceToArray method.
	getArray := bytehelper.SliceToArray

	// Convert the bytes in the given structure to ECC objects using guarded keys.
	localBaseKeyPrivate, err := ecc.NewGuardedECPrivateKey(getArray(structure.LocalBaseKeyPrivate))
	if err != nil {
		return nil, err
	}
	localBaseKeyPair := ecc.NewECKeyPair(
		ecc.NewDjbECPublicKey(getArray(structure.LocalBaseKeyPublic)),
		localBaseKeyPrivate,
	)

	localRatchetKeyPrivate, err := ecc.NewGuardedECPrivateKey(getArray(structure.LocalRatchetKeyPrivate))
	if err != nil {
		return nil, err
	}
	localRatchetKeyPair := ecc.NewECKeyPair(
		ecc.NewDjbECPublicKey(getArray(structure.LocalRatchetKeyPublic)),
		localRatchetKeyPrivate,
	)

	localIdentityKeyPrivate, err := ecc.NewGuardedECPrivateKey(getArray(structure.LocalIdentityKeyPrivate))
	if err != nil {
		return nil, err
	}
	localIdentityKeyPair := identity.NewKeyPair(
		identity.NewKey(ecc.NewDjbECPublicKey(getArray(structure.LocalIdentityKeyPublic))),
		localIdentityKeyPrivate,
	)

	// Return the PendingKeyExchange with the deserialized keys.
	return &PendingKeyExchange{
		sequence:             structure.Sequence,
		localBaseKeyPair:     localBaseKeyPair,
		localRatchetKeyPair:  localRatchetKeyPair,
		localIdentityKeyPair: localIdentityKeyPair,
	}, nil
}

// PendingKeyExchangeStructure is a serializable structure for pending
// key exchanges. This structure is used for persistent storage of the
// key exchange state.
type PendingKeyExchangeStructure struct {
	Sequence                uint32
	LocalBaseKeyPublic      []byte
	LocalBaseKeyPrivate     []byte
	LocalRatchetKeyPublic   []byte
	LocalRatchetKeyPrivate  []byte
	LocalIdentityKeyPublic  []byte
	LocalIdentityKeyPrivate []byte
}

// Zeroize overwrites all private key material in the structure with zeros.
// Call this (via defer) after the structure has been serialized to prevent
// private key bytes from lingering in heap memory.
func (p *PendingKeyExchangeStructure) Zeroize() {
	crypto.Zeroize(p.LocalBaseKeyPrivate)
	crypto.Zeroize(p.LocalRatchetKeyPrivate)
	crypto.Zeroize(p.LocalIdentityKeyPrivate)
}

// PendingKeyExchange is a structure for storing a pending
// key exchange for a session state.
type PendingKeyExchange struct {
	sequence             uint32
	localBaseKeyPair     *ecc.ECKeyPair
	localRatchetKeyPair  *ecc.ECKeyPair
	localIdentityKeyPair *identity.KeyPair
}

// structre will return a serializable structure of a pending key exchange
// so it can be persistently stored.
func (p *PendingKeyExchange) structure() *PendingKeyExchangeStructure {
	getSlice := bytehelper.ArrayToSlice
	return &PendingKeyExchangeStructure{
		Sequence:                p.sequence,
		LocalBaseKeyPublic:      getSlice(p.localBaseKeyPair.PublicKey().PublicKey()),
		LocalBaseKeyPrivate:     getSlice(p.localBaseKeyPair.PrivateKey().Serialize()),
		LocalRatchetKeyPublic:   getSlice(p.localRatchetKeyPair.PublicKey().PublicKey()),
		LocalRatchetKeyPrivate:  getSlice(p.localRatchetKeyPair.PrivateKey().Serialize()),
		LocalIdentityKeyPublic:  getSlice(p.localIdentityKeyPair.PublicKey().PublicKey().PublicKey()),
		LocalIdentityKeyPrivate: getSlice(p.localIdentityKeyPair.PrivateKey().Serialize()),
	}
}
