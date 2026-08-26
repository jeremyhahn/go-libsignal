package record

import (
	"github.com/jeremyhahn/go-libsignal/pkg/kem"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// KyberPreKeyID is a typed identifier for Kyber pre-key records at the storage
// layer. It mirrors the Rust KyberPreKeyId newtype at
// rust/protocol/src/state/kyber_prekey.rs:18.
//
// Note: the protocol layer (pkg/protocol) also defines a KyberPreKeyID over the
// same underlying uint32. Both represent the same wire value; they are separate
// declarations to avoid a circular import between the protocol and record packages.
type KyberPreKeyID uint32

// KyberPreKeySerializer is an interface for serializing and deserializing
// KyberPreKey records into bytes. An implementation of this interface should
// be used to encode/decode the object into JSON, Protobuffers, etc.
type KyberPreKeySerializer interface {
	Serialize(preKey *KyberPreKeyStructure) ([]byte, error)
	Deserialize(serialized []byte) (*KyberPreKeyStructure, error)
}

// KyberPreKeyStructure is a flat, serializable structure for Kyber pre-key
// records. The private key is held in guarded memory for the crossing of the
// storage boundary; see PendingKeyExchangeStructure for the rationale.
type KyberPreKeyStructure struct {
	ID         uint32
	PublicKey  []byte        // Serialized KEM public key (with type prefix)
	PrivateKey secret.Secret // Raw KEM secret key bytes
	Signature  []byte        // Identity key signature over the public key
	Timestamp  int64
}

// Zeroize destroys the guarded private key material in the structure.
// Call this (via defer) after the structure has been serialized.
func (k *KyberPreKeyStructure) Zeroize() {
	k.PrivateKey.Destroy()
}

// KyberPreKey stores a Kyber pre-key with its associated metadata. The secret
// key lives in locked memory for the whole lifetime of the record,
// both when the record is generated and when it is read back from storage; the
// serializable structure is built on demand and destroyed by the caller.
type KyberPreKey struct {
	id         uint32
	timestamp  int64
	keyPair    *kem.GuardedKeyPair
	signature  []byte
	serializer KyberPreKeySerializer
}

// NewKyberPreKey creates a new KyberPreKey record with the given properties.
// The record takes ownership of keyPair: the caller must not destroy it, and
// must not use it after the record itself is destroyed.
func NewKyberPreKey(id uint32, timestamp int64, keyPair *kem.GuardedKeyPair, signature []byte, serializer KyberPreKeySerializer) *KyberPreKey {
	sig := make([]byte, len(signature))
	copy(sig, signature)

	return &KyberPreKey{
		id:         id,
		timestamp:  timestamp,
		keyPair:    keyPair,
		signature:  sig,
		serializer: serializer,
	}
}

// NewKyberPreKeyFromStructure reconstructs a KyberPreKey from a serializable structure.
// It asserts that the public-key type tag in structure.PublicKey matches the
// secret-key type, guarding against cross-type key pair loading.
//
// The secret key is cloned from the structure's guarded memory straight into
// the record's own guarded memory, so it never reaches the Go heap. The caller
// keeps ownership of the structure and should Zeroize it when done.
func NewKyberPreKeyFromStructure(structure KyberPreKeyStructure, serializer KyberPreKeySerializer) (*KyberPreKey, error) {
	publicKey, err := kem.DeserializePublicKey(structure.PublicKey)
	if err != nil {
		return nil, &KyberPreKeyDeserializeError{Operation: "failed to deserialize kyber pre-key public key", Err: err}
	}

	guardedSecret, cloneErr := structure.PrivateKey.Clone()
	if cloneErr != nil {
		return nil, &KyberPreKeyDeserializeError{Operation: "failed to clone kyber pre-key secret key", Err: cloneErr}
	}

	// NewGuardedSecretKeyFromSecret takes ownership of guardedSecret, and
	// destroys it itself if the type or length check fails.
	secretKey, skErr := kem.NewGuardedSecretKeyFromSecret(publicKey.Type(), guardedSecret)
	if skErr != nil {
		return nil, &KyberPreKeyDeserializeError{Operation: "failed to create kyber pre-key secret key", Err: skErr}
	}

	// Guard: the type tag embedded in the serialized public key must match the
	// type used to construct the secret key. NewGuardedSecretKeyFromSecret
	// receives publicKey.Type() explicitly, so secretKey.Type() == publicKey.Type()
	// is always true here; this assertion catches future API changes that could
	// break the invariant.
	if secretKey.Type() != publicKey.Type() {
		secretKey.Destroy()
		return nil, &ErrKyberPreKeyTypeMismatch{
			PublicKeyType: publicKey.Type(),
			SecretKeyType: secretKey.Type(),
		}
	}

	sig := make([]byte, len(structure.Signature))
	copy(sig, structure.Signature)

	return &KyberPreKey{
		id:        structure.ID,
		timestamp: structure.Timestamp,
		keyPair: &kem.GuardedKeyPair{
			Public: publicKey,
			Secret: secretKey,
		},
		signature:  sig,
		serializer: serializer,
	}, nil
}

// ID returns the record's identifier.
func (k *KyberPreKey) ID() uint32 {
	return k.id
}

// PublicKey returns the KEM public key for this record. The secret half is
// never handed out unguarded; use GuardedKeyPair for operations that need it.
func (k *KyberPreKey) PublicKey() *kem.PublicKey {
	return k.keyPair.Public
}

// Destroy releases the guarded secret key held by the record. It is idempotent,
// and the record must not be used for KEM operations afterwards.
func (k *KyberPreKey) Destroy() {
	k.keyPair.Destroy()
}

// Signature returns the identity key signature over the public key.
func (k *KyberPreKey) Signature() []byte {
	sig := make([]byte, len(k.signature))
	copy(sig, k.signature)
	return sig
}

// GuardedKeyPair returns an independent guarded copy of this record's key
// material, cloned from guarded memory into guarded memory. The caller is
// responsible for calling Destroy() on the returned GuardedKeyPair when it is
// no longer needed; destroying it leaves the record's own key intact.
func (k *KyberPreKey) GuardedKeyPair() (*kem.GuardedKeyPair, error) {
	guardedSK, err := k.keyPair.Secret.Clone()
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
	return k.timestamp
}

// SignatureBytes returns the signature as a plain byte slice, satisfying the
// GenericSignedPreKey interface.  KyberPreKey already stores the signature as
// []byte, so this delegates directly to Signature().
func (k *KyberPreKey) SignatureBytes() []byte {
	return k.Signature()
}

// SerializedPublicKey returns the type-prefixed serialized KEM public key bytes.
// This satisfies the GenericSignedPreKey interface and gives polymorphic callers
// access to the raw bytes without depending on *kem.PublicKey.
func (k *KyberPreKey) SerializedPublicKey() []byte {
	return k.keyPair.Public.Serialize()
}

// Serialize uses the KyberPreKey serializer to return the record as serialized bytes.
func (k *KyberPreKey) Serialize() ([]byte, error) {
	structure, err := k.structure()
	if err != nil {
		return nil, err
	}
	defer structure.Zeroize()
	return k.serializer.Serialize(structure)
}

// structure builds the serializable form of the record, cloning the secret key
// from the record's guarded memory into the structure's own guarded memory.
// The caller owns the returned structure and must Zeroize it once the
// serializer is done with it.
func (k *KyberPreKey) structure() (*KyberPreKeyStructure, error) {
	cloned, err := k.keyPair.Secret.CloneSecret()
	if err != nil {
		return nil, &KyberPreKeyDeserializeError{Operation: "failed to guard kyber pre-key secret key", Err: err}
	}
	privateKey := secret.FromSecret(cloned)
	return &KyberPreKeyStructure{
		ID:         k.id,
		PublicKey:  k.keyPair.Public.Serialize(),
		PrivateKey: privateKey,
		Signature:  k.Signature(),
		Timestamp:  k.timestamp,
	}, nil
}
