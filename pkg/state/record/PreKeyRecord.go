package record

import (
	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
	"github.com/jeremyhahn/go-libsignal/pkg/util/optional"
)

// PreKeySerializer is an interface for serializing and deserializing
// PreKey objects into bytes. An implementation of this interface should be
// used to encode/decode the object into JSON, Protobuffers, etc.
type PreKeySerializer interface {
	Serialize(preKey *PreKeyStructure) ([]byte, error)
	Deserialize(serialized []byte) (*PreKeyStructure, error)
}

// NewPreKeyFromBytes will return a prekey record from the given bytes using the given serializer.
func NewPreKeyFromBytes(serialized []byte, serializer PreKeySerializer) (*PreKey, error) {
	// Use the given serializer to decode the signal message.
	preKeyStructure, err := serializer.Deserialize(serialized)
	if err != nil {
		return nil, err
	}
	// The structure decoded here is ours; release its guarded private key once
	// the record has taken its own copy.
	defer preKeyStructure.Zeroize()

	return NewPreKeyFromStruct(preKeyStructure, serializer)
}

// NewPreKeyFromStruct returns a PreKey record using the given serializable structure.
// The record copies the private key into its own guarded memory; the caller
// keeps ownership of the structure and should Zeroize it when done.
func NewPreKeyFromStruct(structure *PreKeyStructure, serializer PreKeySerializer) (*PreKey, error) {
	// Create the prekey record from the structure.
	preKey := &PreKey{
		id:         structure.ID,
		serializer: serializer,
	}

	// Decode the 33-byte serialized EC public key ([0x05 || 32 key bytes]).
	// Using ecc.DecodePoint rather than bytehelper.SliceToArray + NewDjbECPublicKey
	// is required because SliceToArray truncates the 33-byte form to [32]byte,
	// keeping the 0x05 type byte and discarding the last key byte, producing a
	// corrupted public key.
	// Mirrors the Rust approach of decoding from the stored bytes directly.
	publicKey, err := ecc.DecodePoint(structure.PublicKey, 0)
	if err != nil {
		return nil, err
	}
	privateKey, gErr := guardedPrivateKey(&structure.PrivateKey)
	if gErr != nil {
		return nil, gErr
	}
	keyPair := ecc.NewECKeyPair(publicKey, privateKey)
	preKey.keyPair = keyPair

	return preKey, nil
}

// NewPreKey record returns a new pre key record that can
// be stored in a PreKeyStore.
func NewPreKey(id uint32, keyPair *ecc.ECKeyPair, serializer PreKeySerializer) *PreKey {
	return &PreKey{
		id:         id,
		keyPair:    keyPair,
		serializer: serializer,
	}
}

// PreKeyStructure is a structure for serializing PreKey records. The private
// key is held in guarded memory for the crossing of the storage boundary; see
// PendingKeyExchangeStructure for the rationale.
type PreKeyStructure struct {
	ID         uint32
	PublicKey  []byte
	PrivateKey secret.Secret
}

// Zeroize destroys the guarded private key material in the structure.
// Call this (via defer) after the structure has been serialized.
func (p *PreKeyStructure) Zeroize() {
	p.PrivateKey.Destroy()
}

// PreKey record is a structure for storing pre keys inside
// a PreKeyStore. The private key lives only in the guarded memory of the
// record's key pair; the serializable structure is built on demand.
type PreKey struct {
	id         uint32
	keyPair    *ecc.ECKeyPair
	serializer PreKeySerializer
}

// ID returns the pre key record's id.
func (p *PreKey) ID() *optional.Uint32 {
	return optional.NewOptionalUint32(p.id)
}

// KeyPair returns the pre key record's key pair.
func (p *PreKey) KeyPair() *ecc.ECKeyPair {
	return p.keyPair
}

// Serialize uses the PreKey serializer to return the PreKey
// as serialized bytes.
func (p *PreKey) Serialize() ([]byte, error) {
	structure, err := p.structure()
	if err != nil {
		return nil, err
	}
	defer structure.Zeroize()
	return p.serializer.Serialize(structure)
}

// structure builds the serializable form of the record, copying the private
// key out of the key pair into guarded memory. The caller owns the returned
// structure and must Zeroize it once the serializer is done with it.
func (p *PreKey) structure() (*PreKeyStructure, error) {
	privateKey, err := ecc.GuardPrivateKey(p.keyPair.PrivateKey())
	if err != nil {
		return nil, err
	}
	return &PreKeyStructure{
		ID:         p.id,
		PublicKey:  p.keyPair.PublicKey().Serialize(),
		PrivateKey: privateKey,
	}, nil
}
