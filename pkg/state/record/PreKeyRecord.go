package record

import (
	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/util/bytehelper"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
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

	return NewPreKeyFromStruct(preKeyStructure, serializer)
}

// NewPreKeyFromStruct returns a PreKey record using the given serializable structure.
func NewPreKeyFromStruct(structure *PreKeyStructure, serializer PreKeySerializer) (*PreKey, error) {
	// Create the prekey record from the structure.
	preKey := &PreKey{
		structure:  *structure,
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
	privateKey, gErr := ecc.NewGuardedECPrivateKey(bytehelper.SliceToArray(structure.PrivateKey))
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
		structure: PreKeyStructure{
			ID:         id,
			PublicKey:  keyPair.PublicKey().Serialize(),
			PrivateKey: bytehelper.ArrayToSlice(keyPair.PrivateKey().Serialize()),
		},
		keyPair:    keyPair,
		serializer: serializer,
	}
}

// PreKeyStructure is a structure for serializing PreKey records.
type PreKeyStructure struct {
	ID         uint32
	PublicKey  []byte
	PrivateKey []byte
}

// Zeroize overwrites the private key material in the structure with zeros.
// Call this (via defer) after the structure has been serialized.
func (p *PreKeyStructure) Zeroize() {
	crypto.Zeroize(p.PrivateKey)
}

// PreKey record is a structure for storing pre keys inside
// a PreKeyStore.
type PreKey struct {
	structure  PreKeyStructure
	keyPair    *ecc.ECKeyPair
	serializer PreKeySerializer
}

// ID returns the pre key record's id.
func (p *PreKey) ID() *optional.Uint32 {
	return optional.NewOptionalUint32(p.structure.ID)
}

// KeyPair returns the pre key record's key pair.
func (p *PreKey) KeyPair() *ecc.ECKeyPair {
	return p.keyPair
}

// Serialize uses the PreKey serializer to return the PreKey
// as serialized bytes.
func (p *PreKey) Serialize() ([]byte, error) {
	structure := p.structure
	return p.serializer.Serialize(&structure)
}
