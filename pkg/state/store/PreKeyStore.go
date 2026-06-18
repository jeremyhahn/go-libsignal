package store

import (
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
)

// PreKey store is an interface describing the local storage of PreKeyRecords.
//
// Every method returns an error so that storage backend failures propagate to
// callers. A nil record with a nil error from LoadPreKey means "not found".
//
// Mirrors the Rust libsignal trait PreKeyStore at
// rust/protocol/src/storage/traits.rs.
type PreKey interface {
	// LoadPreKey loads a local PreKeyRecord, returning (nil, nil) if not found.
	LoadPreKey(preKeyID uint32) (*record.PreKey, error)

	// StorePreKey persists a local PreKeyRecord.
	StorePreKey(preKeyID uint32, preKeyRecord *record.PreKey) error

	// ContainsPreKey returns true if the store contains a PreKeyRecord.
	ContainsPreKey(preKeyID uint32) (bool, error)

	// RemovePreKey deletes a PreKeyRecord from local storage.
	RemovePreKey(preKeyID uint32) error
}
