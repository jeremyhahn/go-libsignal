package sesame

import (
	"fmt"
	"sync"
)

// MemoryStore is an in-memory Store for tests that clones records on load and store.
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

// LoadUserRecord returns a clone of the user's record, nil if none, or an error if cloning fails.
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

// StoreUserRecord stores a clone of record, or returns an error if cloning fails.
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
