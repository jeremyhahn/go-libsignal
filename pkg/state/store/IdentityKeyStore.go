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

// IdentityChange is the result of saving a new identity key for a protocol
// address. It mirrors the Rust libsignal type at
// rust/protocol/src/storage/traits.rs::IdentityChange so callers can detect
// whether an existing trusted identity was replaced (a security-relevant
// event) versus simply recording a new or unchanged identity.
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

// IdentityKey provides an interface to identity information.
//
// Every method that can fail returns an error so that storage backend
// failures propagate to callers rather than being silently swallowed.
//
// Mirrors the Rust libsignal trait IdentityKeyStore at
// rust/protocol/src/storage/traits.rs.
type IdentityKey interface {
	// GetIdentityKeyPair returns the local client's identity key pair.
	GetIdentityKeyPair() *identity.KeyPair

	// GetLocalRegistrationId returns the local client's registration ID.
	//
	// Clients should maintain a registration ID, a random number between 1 and 16380
	// that's generated once at install time.
	GetLocalRegistrationId() uint32

	// SaveIdentity records a remote client's identity key in the local
	// identity store. It returns IdentityChangeReplacedExisting when the new
	// key replaced a different existing key for the address, and
	// IdentityChangeNewOrUnchanged otherwise. Mirrors Rust
	// IdentityKeyStore::save_identity.
	SaveIdentity(address *protocol.SignalAddress, identityKey *identity.Key) (IdentityChange, error)

	// IsTrustedIdentity determines whether a remote client's identity is trusted.
	// Trust is based on 'trust on first use': an identity key is considered
	// 'trusted' if there is no entry for the recipient in the local store, or
	// if it matches the saved key for a recipient in the local store.
	//
	// The direction parameter indicates whether this check is for a sending or
	// receiving operation. Implementations may apply stricter policies for
	// sending (e.g., blocking on key change) versus receiving (e.g., trust on
	// first use).
	IsTrustedIdentity(address *protocol.SignalAddress, identityKey *identity.Key, direction Direction) (bool, error)

	// GetIdentity returns a previously saved identity key for an address,
	// or nil if no identity has been saved for the address.
	GetIdentity(address *protocol.SignalAddress) (*identity.Key, error)
}
