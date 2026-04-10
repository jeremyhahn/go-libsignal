package record

import (
	"github.com/jeremyhahn/go-libsignal/pkg/kem"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
)

// KyberPreKeyID is a type alias for Kyber pre-key identifiers.
type KyberPreKeyID uint32

// KyberPreKeySerializer is an interface for serializing and deserializing
// KyberPreKey records into bytes. An implementation of this interface should
// be used to encode/decode the object into JSON, Protobuffers, etc.
type KyberPreKeySerializer interface {
	Serialize(preKey *KyberPreKeyStructure) ([]byte, error)
	Deserialize(serialized []byte) (*KyberPreKeyStructure, error)
}

// KyberPreKeyStructure is a flat, serializable structure for Kyber pre-key records.
type KyberPreKeyStructure struct {
	ID         uint32
	PublicKey  []byte // Serialized KEM public key (with type prefix)
	PrivateKey []byte // Raw KEM secret key bytes
	Signature  []byte // Identity key signature over the public key
	Timestamp  int64
}

// Zeroize overwrites the private key material in the structure with zeros.
// Call this (via defer) after the structure has been serialized.
func (k *KyberPreKeyStructure) Zeroize() {
	crypto.Zeroize(k.PrivateKey)
}

// KyberPreKey stores a Kyber pre-key with its associated metadata.
type KyberPreKey struct {
	structure  KyberPreKeyStructure
	keyPair    *kem.KeyPair
	signature  []byte
	serializer KyberPreKeySerializer
}

// NewKyberPreKey creates a new KyberPreKey record with the given properties.
func NewKyberPreKey(id uint32, timestamp int64, keyPair *kem.KeyPair, signature []byte, serializer KyberPreKeySerializer) *KyberPreKey {
	sig := make([]byte, len(signature))
	copy(sig, signature)

	return &KyberPreKey{
		structure: KyberPreKeyStructure{
			ID:         id,
			PublicKey:  keyPair.Public.Serialize(),
			PrivateKey: keyPair.Secret.Data(),
			Signature:  sig,
			Timestamp:  timestamp,
		},
		keyPair:    keyPair,
		signature:  sig,
		serializer: serializer,
	}
}

// NewKyberPreKeyFromStructure reconstructs a KyberPreKey from a serializable structure.
func NewKyberPreKeyFromStructure(structure KyberPreKeyStructure, serializer KyberPreKeySerializer) (*KyberPreKey, error) {
	publicKey, err := kem.DeserializePublicKey(structure.PublicKey)
	if err != nil {
		return nil, &KyberPreKeyDeserializeError{Operation: "failed to deserialize kyber pre-key public key", Err: err}
	}

	secretKey, skErr := kem.NewSecretKey(publicKey.Type(), structure.PrivateKey)
	if skErr != nil {
		return nil, &KyberPreKeyDeserializeError{Operation: "failed to create kyber pre-key secret key", Err: skErr}
	}

	sig := make([]byte, len(structure.Signature))
	copy(sig, structure.Signature)

	return &KyberPreKey{
		structure: structure,
		keyPair: &kem.KeyPair{
			Public: publicKey,
			Secret: secretKey,
		},
		signature:  sig,
		serializer: serializer,
	}, nil
}

// ID returns the record's identifier.
func (k *KyberPreKey) ID() uint32 {
	return k.structure.ID
}

// KeyPair returns the KEM key pair for this record.
func (k *KyberPreKey) KeyPair() *kem.KeyPair {
	return k.keyPair
}

// Signature returns the identity key signature over the public key.
func (k *KyberPreKey) Signature() []byte {
	sig := make([]byte, len(k.signature))
	copy(sig, k.signature)
	return sig
}

// GuardedKeyPair creates a GuardedKeyPair from this record's key material.
// The secret key bytes are moved into memguard-protected memory. The caller
// is responsible for calling Destroy() on the returned GuardedKeyPair when
// it is no longer needed.
func (k *KyberPreKey) GuardedKeyPair() (*kem.GuardedKeyPair, error) {
	skData := k.keyPair.Secret.Data() // returns a copy
	defer crypto.Zeroize(skData)

	guardedSK, err := kem.NewGuardedSecretKey(k.keyPair.Public.Type(), skData)
	if err != nil {
		return nil, &KyberPreKeyDeserializeError{Operation: "failed to create guarded kyber key pair", Err: err}
	}

	return &kem.GuardedKeyPair{
		Public: k.keyPair.Public,
		Secret: guardedSK,
	}, nil
}

// Timestamp returns the record's creation timestamp.
func (k *KyberPreKey) Timestamp() int64 {
	return k.structure.Timestamp
}

// Serialize uses the KyberPreKey serializer to return the record as serialized bytes.
func (k *KyberPreKey) Serialize() ([]byte, error) {
	structure := k.structure
	return k.serializer.Serialize(&structure)
}
