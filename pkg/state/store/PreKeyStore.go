package store

import (
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
)

// PreKey stores PreKeyRecords; LoadPreKey returns nil, nil when not found (Rust PreKeyStore).
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
