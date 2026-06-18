package record

import (
	"fmt"

	"github.com/jeremyhahn/go-libsignal/pkg/kem"
)

// ErrKyberPreKeyTypeMismatch is returned when the serialized public-key type
// tag in a KyberPreKeyStructure does not match the type tag of the secret key.
// This prevents silently loading a key pair where the public and secret key
// were generated with different KEM algorithms.
type ErrKyberPreKeyTypeMismatch struct {
	PublicKeyType kem.KeyType
	SecretKeyType kem.KeyType
}

func (e *ErrKyberPreKeyTypeMismatch) Error() string {
	return fmt.Sprintf(
		"record: kyber pre-key type mismatch: public key type 0x%02x != secret key type 0x%02x",
		e.PublicKeyType, e.SecretKeyType,
	)
}

// RootKeyTypeError indicates that the provided RootKeyable value is not the
// expected concrete type (*root.Key).
type RootKeyTypeError struct {
	Got interface{}
}

func (e *RootKeyTypeError) Error() string {
	return fmt.Sprintf("record: SetRootKey: expected *root.Key, got %T", e.Got)
}

// KyberPreKeyDeserializeError indicates a failure deserializing a Kyber pre-key record.
type KyberPreKeyDeserializeError struct {
	Operation string
	Err       error
}

func (e *KyberPreKeyDeserializeError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("record: %s: %v", e.Operation, e.Err)
	}
	return fmt.Sprintf("record: %s", e.Operation)
}

func (e *KyberPreKeyDeserializeError) Unwrap() error {
	return e.Err
}

// ReceiverChainNotFoundError indicates no receiver chain was found for the given
// sender ephemeral key.
type ReceiverChainNotFoundError struct {
	Operation string
}

func (e *ReceiverChainNotFoundError) Error() string {
	return fmt.Sprintf("record: %s: no receiver chain for sender ephemeral key", e.Operation)
}

// SessionCopyError indicates a failure while copying a session record.
type SessionCopyError struct {
	Err error
}

func (e *SessionCopyError) Error() string {
	return fmt.Sprintf("record: session copy failed: %v", e.Err)
}

func (e *SessionCopyError) Unwrap() error {
	return e.Err
}

// SignedPreKeyPublicKeyLengthError indicates that the public key bytes passed
// to a SignedPreKey constructor have an unexpected length.
type SignedPreKeyPublicKeyLengthError struct {
	Got  int
	Want int
}

func (e *SignedPreKeyPublicKeyLengthError) Error() string {
	return fmt.Sprintf("record: signed pre-key public key: expected %d bytes, got %d", e.Want, e.Got)
}
