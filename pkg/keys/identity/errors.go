package identity

import "fmt"

// ErrInvalidIdentityKeyPairProtoType is returned for an invalid IdentityKeyPairStructure encoding.
type ErrInvalidIdentityKeyPairProtoType struct{}

func (e *ErrInvalidIdentityKeyPairProtoType) Error() string {
	return "identity: invalid IdentityKeyPairStructure protobuf encoding"
}

// ErrInvalidIdentityKeyPairProto is returned when proto.Unmarshal fails.
var ErrInvalidIdentityKeyPairProto error = &ErrInvalidIdentityKeyPairProtoType{}

// ErrInvalidIdentityKeyPairPublicKeyType is returned for an invalid public key in an IdentityKeyPairStructure.
type ErrInvalidIdentityKeyPairPublicKeyType struct {
	Err error
}

func (e *ErrInvalidIdentityKeyPairPublicKeyType) Error() string {
	return fmt.Sprintf("identity: invalid public key in IdentityKeyPairStructure: %v", e.Err)
}

func (e *ErrInvalidIdentityKeyPairPublicKeyType) Unwrap() error {
	return e.Err
}

// ErrInvalidIdentityKeyPairPrivateKeyType is returned for an invalid private key in an IdentityKeyPairStructure.
type ErrInvalidIdentityKeyPairPrivateKeyType struct {
	Got int
}

func (e *ErrInvalidIdentityKeyPairPrivateKeyType) Error() string {
	return fmt.Sprintf("identity: invalid private key in IdentityKeyPairStructure: expected 32 bytes, got %d", e.Got)
}
