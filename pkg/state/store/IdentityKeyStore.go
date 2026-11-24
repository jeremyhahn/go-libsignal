package store

import (
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
)

// Direction indicates whether the operation is for sending or receiving.
type Direction int

const (
	// DirectionSending is used when encrypting a message to send.
	DirectionSending Direction = 1
	// DirectionReceiving is used when decrypting a received message.
	DirectionReceiving Direction = 2
)

// IdentityChange reports whether saving an identity replaced a different trusted key (Rust IdentityChange).
type IdentityChange int

const (
	// IdentityChangeNewOrUnchanged indicates the protocol address did not have
	// an identity key, or the saved key matched the one being recorded.
	IdentityChangeNewOrUnchanged IdentityChange = 0
	// IdentityChangeReplacedExisting indicates the new identity key replaced a
	// different key for the protocol address. Callers may treat this as a
	// trust event (e.g. show a safety-number-changed banner).
	IdentityChangeReplacedExisting IdentityChange = 1
)

// IdentityChangeFromChanged returns IdentityChangeReplacedExisting when
// changed is true, otherwise IdentityChangeNewOrUnchanged. Mirrors Rust's
// IdentityChange::from_changed in rust/protocol/src/storage/traits.rs.
func IdentityChangeFromChanged(changed bool) IdentityChange {
	if changed {
		return IdentityChangeReplacedExisting
	}
	return IdentityChangeNewOrUnchanged
}

// IdentityKey stores identity keys and returns storage errors (Rust IdentityKeyStore).
type IdentityKey interface {
	// GetIdentityKeyPair returns the local client's identity key pair.
	GetIdentityKeyPair() *identity.KeyPair

	// GetLocalRegistrationId returns the registration ID, a random 1..16380 chosen at install.
	GetLocalRegistrationId() uint32

	// SaveIdentity stores a remote identity key, returning IdentityChangeReplacedExisting if it replaced a different key (Rust save_identity).
	SaveIdentity(address *protocol.SignalAddress, identityKey *identity.Key) (IdentityChange, error)

	// IsTrustedIdentity reports whether identityKey is trusted on first use for address; direction allows stricter sending policies.
	IsTrustedIdentity(address *protocol.SignalAddress, identityKey *identity.Key, direction Direction) (bool, error)

	// GetIdentity returns the saved identity key for address, or nil.
	GetIdentity(address *protocol.SignalAddress) (*identity.Key, error)
}
