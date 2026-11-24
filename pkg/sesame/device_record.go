package sesame

import (
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
)

// DeviceRecord holds a device's active session and inactive sessions, keyed by DeviceID in a UserRecord (Sesame §3.1).
type DeviceRecord struct {
	deviceID         uint32
	identityKey      *identity.Key
	activeSession    *SessionWrapper
	inactiveSessions []*SessionWrapper
	stale            bool
	staledAt         time.Time
}

// NewDeviceRecord creates a new DeviceRecord for the given device ID.
func NewDeviceRecord(deviceID uint32) *DeviceRecord {
	return &DeviceRecord{
		deviceID:         deviceID,
		inactiveSessions: make([]*SessionWrapper, 0),
	}
}

// NewDeviceRecordWithIdentity creates a new DeviceRecord for the given device ID
// and remote identity key.
func NewDeviceRecordWithIdentity(deviceID uint32, identityKey *identity.Key) *DeviceRecord {
	return &DeviceRecord{
		deviceID:         deviceID,
		identityKey:      identityKey,
		inactiveSessions: make([]*SessionWrapper, 0),
	}
}

// DeviceID returns the device identifier.
func (d *DeviceRecord) DeviceID() uint32 {
	return d.deviceID
}

// IdentityKey returns the remote identity key associated with this device record.
func (d *DeviceRecord) IdentityKey() *identity.Key {
	return d.identityKey
}

// SetIdentityKey sets the remote identity key for this device record.
func (d *DeviceRecord) SetIdentityKey(key *identity.Key) {
	d.identityKey = key
}

// ActiveSession returns the current active session, or nil if none exists.
func (d *DeviceRecord) ActiveSession() *SessionWrapper {
	return d.activeSession
}

// InactiveSessions returns the ordered list of inactive sessions.
func (d *DeviceRecord) InactiveSessions() []*SessionWrapper {
	return d.inactiveSessions
}

// IsStale returns whether this device record has been marked stale.
func (d *DeviceRecord) IsStale() bool {
	return d.stale
}

// StaledAt returns the time when this device was marked stale.
func (d *DeviceRecord) StaledAt() time.Time {
	return d.staledAt
}

// InsertSession makes session active, moving any active one to the front of the inactive list, trimmed by config.
func (d *DeviceRecord) InsertSession(session *SessionWrapper, config *Config, now time.Time) {
	if d.activeSession != nil {
		d.inactiveSessions = append([]*SessionWrapper{d.activeSession}, d.inactiveSessions...)
	}
	d.activeSession = session
	d.trimInactive(config)
}

// ActivateSession makes session active unless it is past MAXSEND (Sesame §4.2), and reports whether it did.
func (d *DeviceRecord) ActivateSession(session *SessionWrapper, config *Config, now time.Time) bool {
	if config != nil && session.IsSendExpired(config, now) {
		return false
	}

	if d.activeSession != nil {
		d.inactiveSessions = append([]*SessionWrapper{d.activeSession}, d.inactiveSessions...)
	}
	d.activeSession = session
	d.trimInactive(config)
	return true
}

// DeactivateSession moves the active session to the front of the inactive
// sessions list and clears the active session slot. The inactive list is
// trimmed if config is provided.
func (d *DeviceRecord) DeactivateSession(config *Config) {
	if d.activeSession == nil {
		return
	}
	d.inactiveSessions = append([]*SessionWrapper{d.activeSession}, d.inactiveSessions...)
	d.activeSession = nil
	d.trimInactive(config)
}

// trimInactive trims the inactive sessions list to MaxInactiveSessions if
// config is provided.
func (d *DeviceRecord) trimInactive(config *Config) {
	if config != nil && config.MaxInactiveSessions > 0 && len(d.inactiveSessions) > config.MaxInactiveSessions {
		d.inactiveSessions = d.inactiveSessions[:config.MaxInactiveSessions]
	}
}

// MarkStale marks this device record as stale at the given time.
func (d *DeviceRecord) MarkStale(now time.Time) {
	d.stale = true
	d.staledAt = now
}

// ClearStale resets the stale flag and timestamp.
func (d *DeviceRecord) ClearStale() {
	d.stale = false
	d.staledAt = time.Time{}
}

// IsExpired returns true if any of the device's sessions have expired
// according to the provided config and current time.
func (d *DeviceRecord) IsExpired(config *Config, now time.Time) bool {
	if d.activeSession != nil && d.activeSession.IsSendExpired(config, now) {
		return true
	}
	return false
}

// IsStaleExpired returns true if the device has been stale for at least
// MaxLatency. Per Sesame spec, expiry is inclusive (>=).
func (d *DeviceRecord) IsStaleExpired(config *Config, now time.Time) bool {
	if !d.stale {
		return false
	}
	return now.Sub(d.staledAt) >= config.MaxLatency
}

// CleanExpiredSessions removes sessions that have exceeded MaxRecv and
// deactivates the active session if it has exceeded MaxSend.
func (d *DeviceRecord) CleanExpiredSessions(config *Config, now time.Time) {
	// Deactivate the active session if it has exceeded MaxSend.
	if d.activeSession != nil && d.activeSession.IsSendExpired(config, now) {
		d.DeactivateSession(config)
	}

	// Remove inactive sessions that have exceeded MaxRecv.
	kept := make([]*SessionWrapper, 0, len(d.inactiveSessions))
	for _, s := range d.inactiveSessions {
		if !s.IsRecvExpired(config, now) {
			kept = append(kept, s)
		}
	}
	d.inactiveSessions = kept
}

// IsEmpty returns true if the device has no active or inactive sessions.
func (d *DeviceRecord) IsEmpty() bool {
	return d.activeSession == nil && len(d.inactiveSessions) == 0
}

// Clone creates a deep copy of the DeviceRecord. SessionWrappers are
// deep-cloned to prevent mutable state leakage.
func (d *DeviceRecord) Clone() (*DeviceRecord, error) {
	inactive := make([]*SessionWrapper, len(d.inactiveSessions))
	for i, sw := range d.inactiveSessions {
		c, err := sw.Clone()
		if err != nil {
			return nil, err
		}
		inactive[i] = c
	}
	var activeClone *SessionWrapper
	if d.activeSession != nil {
		var err error
		activeClone, err = d.activeSession.Clone()
		if err != nil {
			return nil, err
		}
	}
	return &DeviceRecord{
		deviceID:         d.deviceID,
		identityKey:      d.identityKey,
		activeSession:    activeClone,
		inactiveSessions: inactive,
		stale:            d.stale,
		staledAt:         d.staledAt,
	}, nil
}

// SessionCount returns the total number of sessions (active + inactive).
func (d *DeviceRecord) SessionCount() int {
	count := len(d.inactiveSessions)
	if d.activeSession != nil {
		count++
	}
	return count
}

// PromoteInactiveSession activates inactive session index unless it is past MAXSEND, and reports whether it did.
func (d *DeviceRecord) PromoteInactiveSession(index int, config *Config, now time.Time) bool {
	if index < 0 || index >= len(d.inactiveSessions) {
		return false
	}
	promoted := d.inactiveSessions[index]

	// Check expiry before removing it from the inactive list.
	if config != nil && promoted.IsSendExpired(config, now) {
		return false
	}

	// Remove from inactive list.
	d.inactiveSessions = append(d.inactiveSessions[:index], d.inactiveSessions[index+1:]...)

	// Push current active to inactive and set the promoted session.
	// Use InsertSession since we already validated expiry and this is a
	// promote operation that should always succeed at this point.
	d.InsertSession(promoted, config, now)
	return true
}
