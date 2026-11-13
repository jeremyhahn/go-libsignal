package record

import (
	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/util/bytehelper"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// SignedPreKeySerializer is an interface for serializing and deserializing
// SignedPreKey objects into bytes. An implementation of this interface should be
// used to encode/decode the object into JSON, Protobuffers, etc.
type SignedPreKeySerializer interface {
	Serialize(signedPreKey *SignedPreKeyStructure) ([]byte, error)
	Deserialize(serialized []byte) (*SignedPreKeyStructure, error)
}

// NewSignedPreKeyFromBytes will return a signed prekey record from the given
// bytes using the given serializer.
func NewSignedPreKeyFromBytes(serialized []byte, serializer SignedPreKeySerializer) (*SignedPreKey, error) {
	// Use the given serializer to decode the signal message.
	signedPreKeyStructure, err := serializer.Deserialize(serialized)
	if err != nil {
		return nil, err
	}
	// The structure decoded here is ours; release its guarded private key once
	// the record has taken its own copy.
	defer signedPreKeyStructure.Zeroize()

	return NewSignedPreKeyFromStruct(signedPreKeyStructure, serializer)
}

// NewSignedPreKeyFromStruct returns a SignedPreKey record using the given
// serializable structure. The record copies the private key into its own
// guarded memory; the caller keeps ownership of the structure and should
// Zeroize it when done.
func NewSignedPreKeyFromStruct(structure *SignedPreKeyStructure,
	serializer SignedPreKeySerializer) (*SignedPreKey, error) {

	// Create the signed prekey record from the structure.
	signedPreKey := &SignedPreKey{
		id:         structure.ID,
		timestamp:  structure.Timestamp,
		serializer: serializer,
		signature:  bytehelper.SliceToArray64(structure.Signature),
	}

	// Decode the 33-byte serialized EC public key ([0x05 || 32 key bytes]).
	// Using ecc.DecodePoint rather than bytehelper.SliceToArray + NewDjbECPublicKey
	// is required because SliceToArray truncates the 33-byte form to [32]byte,
	// keeping the 0x05 type byte and discarding the last key byte, producing a
	// corrupted public key. A corrupted SPK public key causes signature
	// verification of the SPK to fail with valid signatures.
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
	signedPreKey.keyPair = keyPair

	return signedPreKey, nil
}

// NewSignedPreKey record creates a new signed pre key record
// with the given properties.
func NewSignedPreKey(id uint32, timestamp int64, keyPair *ecc.ECKeyPair,
	sig [64]byte, serializer SignedPreKeySerializer) *SignedPreKey {

	return &SignedPreKey{
		id:         id,
		timestamp:  timestamp,
		keyPair:    keyPair,
		signature:  sig,
		serializer: serializer,
	}
}

// SignedPreKeyStructure is a flat structure of a signed pre key, used
// for serialization and deserialization. The private key is held in guarded
// memory for the crossing of the storage boundary; see
// PendingKeyExchangeStructure for the rationale.
type SignedPreKeyStructure struct {
	ID         uint32
	PublicKey  []byte
	PrivateKey secret.Secret
	Signature  []byte
	Timestamp  int64
}

// Zeroize destroys the guarded private key material in the structure.
// Call this (via defer) after the structure has been serialized.
func (s *SignedPreKeyStructure) Zeroize() {
	s.PrivateKey.Destroy()
}

// SignedPreKey record is a structure for storing a signed
// pre key in a SignedPreKey store. The private key lives only in the guarded
// memory of the record's key pair; the serializable structure is built on
// demand.
type SignedPreKey struct {
	id         uint32
	timestamp  int64
	keyPair    *ecc.ECKeyPair
	signature  [64]byte
	serializer SignedPreKeySerializer
}

// ID returns the record's id.
func (s *SignedPreKey) ID() uint32 {
	return s.id
}

// Timestamp returns the record's timestamp
func (s *SignedPreKey) Timestamp() int64 {
	return s.timestamp
}

// KeyPair returns the signed pre key record's key pair.
func (s *SignedPreKey) KeyPair() *ecc.ECKeyPair {
	return s.keyPair
}

// Signature returns the record's signed prekey signature.
func (s *SignedPreKey) Signature() [64]byte {
	return s.signature
}

// SignatureBytes returns the signature as a plain byte slice.
// It delegates to Signature() to satisfy the GenericSignedPreKey interface
// without altering the [64]byte return type that existing callers rely on.
func (s *SignedPreKey) SignatureBytes() []byte {
	sig := s.signature
	out := make([]byte, len(sig))
	copy(out, sig[:])
	return out
}

// SerializedPublicKey returns the type-prefixed serialized EC public key bytes.
// This satisfies the GenericSignedPreKey interface and gives polymorphic
// callers access to the raw bytes without depending on ECPublicKeyable.
func (s *SignedPreKey) SerializedPublicKey() []byte {
	return s.keyPair.PublicKey().Serialize()
}

// Serialize uses the SignedPreKey serializer to return the SignedPreKey
// as serialized bytes.
func (s *SignedPreKey) Serialize() ([]byte, error) {
	structure, err := s.structure()
	if err != nil {
		return nil, err
	}
	defer structure.Zeroize()
	return s.serializer.Serialize(structure)
}

// structure builds the serializable form of the record, copying the private
// key out of the key pair into guarded memory. The caller owns the returned
// structure and must Zeroize it once the serializer is done with it.
func (s *SignedPreKey) structure() (*SignedPreKeyStructure, error) {
	privateKey, err := ecc.GuardPrivateKey(s.keyPair.PrivateKey())
	if err != nil {
		return nil, err
	}
	return &SignedPreKeyStructure{
		ID:         s.id,
		Timestamp:  s.timestamp,
		PublicKey:  s.keyPair.PublicKey().Serialize(),
		PrivateKey: privateKey,
		Signature:  bytehelper.ArrayToSlice64(s.signature),
	}, nil
}
