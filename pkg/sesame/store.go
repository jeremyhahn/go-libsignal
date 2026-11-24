package sesame

// Store persists Sesame sessions; it must be concurrency-safe if the Manager is shared and must never call back into the Manager, which holds its lock during every Store call.
type Store interface {
	// LoadUserRecord returns the UserRecord for the given user ID, or nil
	// if no record exists. Returns an error if the record exists but cannot
	// be safely loaded (e.g., clone failure).
	LoadUserRecord(userID string) (*UserRecord, error)

	// StoreUserRecord persists the UserRecord for the given user ID.
	// Returns an error if the record cannot be safely stored (e.g., clone failure).
	StoreUserRecord(userID string, record *UserRecord) error

	// DeleteUserRecord removes the UserRecord for the given user ID.
	DeleteUserRecord(userID string)

	// ContainsUserRecord returns true if a UserRecord exists for the given user ID.
	ContainsUserRecord(userID string) bool

	// AllUserIDs returns the IDs of all stored users. This is used by
	// CleanupExpired to iterate over all records for maintenance.
	AllUserIDs() []string
}
