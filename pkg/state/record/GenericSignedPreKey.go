// Package record provides Signal Protocol session and key record types.
package record

// GenericSignedPreKey is the interface shared by SignedPreKey and KyberPreKey (Rust GenericSignedPreKey).
type GenericSignedPreKey interface {
	// ID returns the numeric identifier for this pre-key record.
	ID() uint32

	// Timestamp returns the creation timestamp of this record in
	// milliseconds since the Unix epoch.
	Timestamp() int64

	// SignatureBytes returns the identity-key signature over the serialized
	// public key as a plain byte slice.
	SignatureBytes() []byte

	// SerializedPublicKey returns the type-prefixed public key: 33 bytes for EC, the KEM encoding for Kyber.
	SerializedPublicKey() []byte

	// Serialize encodes the entire pre-key record for storage.
	Serialize() ([]byte, error)
}

// Compile-time interface assertions.  If either concrete type ever stops
// satisfying GenericSignedPreKey these will produce a build error.
var _ GenericSignedPreKey = (*SignedPreKey)(nil)
var _ GenericSignedPreKey = (*KyberPreKey)(nil)
