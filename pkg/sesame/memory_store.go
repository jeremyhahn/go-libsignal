package sesame

import (
	"fmt"
	"sync"
)

// MemoryStore is an in-memory implementation of the Store interface,
// suitable for testing. It clones records on load and store to prevent
// external mutation from corrupting stored state, preserving rollback
// semantics on decryption failure.
type MemoryStore struct {
	mu      sync.RWMutex
	records map[string]*UserRecord
}

// NewMemoryStore creates a new empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		records: make(map[string]*UserRecord),
	}
}

// LoadUserRecord returns a deep clone of the UserRecord for the given user ID,
// or nil if no record exists. The clone prevents mutations from affecting
// stored state, which is essential for rollback semantics on decryption failure.
// Returns an error if the record exists but cloning fails, rather than falling
// back to the raw pointer which would break rollback guarantees.
func (s *MemoryStore) LoadUserRecord(userID string) (*UserRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.records[userID]
	if !ok {
		return nil, nil
	}
	cloned, err := rec.Clone()
	if err != nil {
		return nil, &SesameError{
			Kind:    ErrorKindStoreCloneFailed,
			Message: fmt.Sprintf("failed to clone user record for %s on load", userID),
			Cause:   err,
		}
	}
	return cloned, nil
}

// StoreUserRecord persists a deep clone of the UserRecord for the given user ID.
// The clone prevents external mutation from corrupting stored state.
// Returns an error if cloning fails, rather than storing the raw pointer
// which would break isolation guarantees.
func (s *MemoryStore) StoreUserRecord(userID string, record *UserRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cloned, err := record.Clone()
	if err != nil {
		return &SesameError{
			Kind:    ErrorKindStoreCloneFailed,
			Message: fmt.Sprintf("failed to clone user record for %s on store", userID),
			Cause:   err,
		}
	}
	s.records[userID] = cloned
	return nil
}

// DeleteUserRecord removes the UserRecord for the given user ID.
func (s *MemoryStore) DeleteUserRecord(userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, userID)
}

// ContainsUserRecord returns true if a UserRecord exists for the given user ID.
func (s *MemoryStore) ContainsUserRecord(userID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.records[userID]
	return ok
}

// AllUserIDs returns the IDs of all stored users.
func (s *MemoryStore) AllUserIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.records))
	for id := range s.records {
		ids = append(ids, id)
	}
	return ids
}
