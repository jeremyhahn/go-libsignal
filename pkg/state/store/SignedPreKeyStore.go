package store

import (
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
)

// SignedPreKey store is an interface that describes how to persistently
// store signed PreKeys.
//
// Every method returns an error so that storage backend failures propagate to
// callers. A nil record with a nil error from Load methods means "not found".
//
// Mirrors the Rust libsignal trait SignedPreKeyStore at
// rust/protocol/src/storage/traits.rs.
type SignedPreKey interface {
	// LoadSignedPreKey loads a local SignedPreKeyRecord, returning (nil, nil) if not found.
	LoadSignedPreKey(signedPreKeyID uint32) (*record.SignedPreKey, error)

	// LoadSignedPreKeys loads all local SignedPreKeyRecords.
	LoadSignedPreKeys() ([]*record.SignedPreKey, error)

	// StoreSignedPreKey persists a local SignedPreKeyRecord.
	StoreSignedPreKey(signedPreKeyID uint32, record *record.SignedPreKey) error

	// ContainsSignedPreKey returns true if the store contains a SignedPreKeyRecord.
	ContainsSignedPreKey(signedPreKeyID uint32) (bool, error)

	// RemoveSignedPreKey deletes a SignedPreKeyRecord from local storage.
	RemoveSignedPreKey(signedPreKeyID uint32) error
}
