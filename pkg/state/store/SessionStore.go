package store

import (
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
)

// Session store is an interface for the persistent storage of session
// state information for remote clients.
//
// Every method returns an error so that storage backend failures propagate
// to callers rather than being silently swallowed. A nil record with a nil
// error from Load methods means "not found"; a nil record with a non-nil
// error means an I/O failure occurred.
//
// Mirrors the Rust libsignal trait SessionStore at
// rust/protocol/src/storage/traits.rs.
type Session interface {
	// LoadSession loads the session record for the given address, or
	// returns (nil, nil) if no session exists.
	LoadSession(address *protocol.SignalAddress) (*record.Session, error)

	// GetSubDeviceSessions returns all sub-device IDs (device ID != 1)
	// that have sessions for the given name.
	GetSubDeviceSessions(name string) ([]uint32, error)

	// StoreSession persists the session record for the given address.
	StoreSession(remoteAddress *protocol.SignalAddress, record *record.Session) error

	// ContainsSession returns true if a session exists for the given address.
	ContainsSession(remoteAddress *protocol.SignalAddress) (bool, error)

	// DeleteSession removes the session for the given address.
	DeleteSession(remoteAddress *protocol.SignalAddress) error

	// DeleteAllSessions removes all stored sessions.
	DeleteAllSessions() error
}
