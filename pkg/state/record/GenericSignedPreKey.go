// Package record provides Signal Protocol session and key record types.
package record

// GenericSignedPreKey is the common interface shared by both EC signed
// pre-keys (SignedPreKey) and Kyber signed pre-keys (KyberPreKey).  It
// mirrors the Rust libsignal GenericSignedPreKey trait
// (rust/protocol/src/state/signed_prekey.rs) and enables callers to work
// with either key type without knowing the concrete kind.
//
// Design notes:
//   - ID and Timestamp use the same types as the existing concrete types
//     so no conversion is required at call sites.
//   - SerializedPublicKey returns the type-prefixed serialized public key
//     for both EC (33 bytes: type byte + 32-byte point) and Kyber (variable
//     length, type byte + raw key bytes).  This is the polymorphic analogue
//     of the Rust KeyPairSerde::PublicKey::serialize() call.
//   - SignatureBytes returns the signature as a plain byte slice.
//     SignedPreKey keeps its existing Signature() [64]byte method intact so
//     that existing callers that depend on the array type are not broken;
//     SignatureBytes is added as a delegating alias.
//   - Serialize returns the fully serialized record (protobuf or JSON
//     depending on the concrete type's serializer).
type GenericSignedPreKey interface {
	// ID returns the numeric identifier for this pre-key record.
	ID() uint32

	// Timestamp returns the creation timestamp of this record in
	// milliseconds since the Unix epoch.
	Timestamp() int64

	// SignatureBytes returns the identity-key signature over the serialized
	// public key as a plain byte slice.
	SignatureBytes() []byte

	// SerializedPublicKey returns the serialized public key bytes
	// (type-prefixed) for this pre-key record.  For EC keys this is the
	// 33-byte DJB encoding; for Kyber keys this is the KEM public key
	// encoding.
	SerializedPublicKey() []byte

	// Serialize encodes the entire pre-key record for storage.
	Serialize() ([]byte, error)
}

// Compile-time interface assertions.  If either concrete type ever stops
// satisfying GenericSignedPreKey these will produce a build error.
var _ GenericSignedPreKey = (*SignedPreKey)(nil)
var _ GenericSignedPreKey = (*KyberPreKey)(nil)
