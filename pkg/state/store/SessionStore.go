package store

import (
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
)

// Session persists session records; a nil record with a nil error means not found.
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
