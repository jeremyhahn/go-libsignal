package store

import (
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
)

// SignedPreKey persists signed pre-keys; a nil record with a nil error means not found.
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
