package identity

import "fmt"

// ErrInvalidIdentityKeyPairProtoType is the typed error for an invalid
// IdentityKeyPairStructure protobuf encoding.
//
// Rust source: rust/protocol/src/identity_key.rs — TryFrom<&[u8]> for IdentityKeyPair
type ErrInvalidIdentityKeyPairProtoType struct{}

func (e *ErrInvalidIdentityKeyPairProtoType) Error() string {
	return "identity: invalid IdentityKeyPairStructure protobuf encoding"
}

// ErrInvalidIdentityKeyPairProto is returned when proto.Unmarshal fails.
var ErrInvalidIdentityKeyPairProto error = &ErrInvalidIdentityKeyPairProtoType{}

// ErrInvalidIdentityKeyPairPublicKeyType is the typed error for an invalid
// public key inside an IdentityKeyPairStructure.
//
// Rust source: rust/protocol/src/identity_key.rs — TryFrom<&[u8]> for IdentityKeyPair
type ErrInvalidIdentityKeyPairPublicKeyType struct {
	Err error
}

func (e *ErrInvalidIdentityKeyPairPublicKeyType) Error() string {
	return fmt.Sprintf("identity: invalid public key in IdentityKeyPairStructure: %v", e.Err)
}

func (e *ErrInvalidIdentityKeyPairPublicKeyType) Unwrap() error {
	return e.Err
}

// ErrInvalidIdentityKeyPairPrivateKeyType is the typed error for an invalid
// private key inside an IdentityKeyPairStructure.
//
// Rust source: rust/protocol/src/identity_key.rs — TryFrom<&[u8]> for IdentityKeyPair
type ErrInvalidIdentityKeyPairPrivateKeyType struct {
	Got int
}

func (e *ErrInvalidIdentityKeyPairPrivateKeyType) Error() string {
	return fmt.Sprintf("identity: invalid private key in IdentityKeyPairStructure: expected 32 bytes, got %d", e.Got)
}
