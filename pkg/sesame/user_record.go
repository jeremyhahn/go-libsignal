package sesame

import (
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
)

// UserRecord represents the session state for a single user across all their
// devices. Per Sesame spec section 3.1, a UserRecord is keyed by UserID and
// contains a map of DeviceRecords plus stale tracking.
type UserRecord struct {
	userID      string
	identityKey *identity.Key
	devices     map[uint32]*DeviceRecord
	stale       bool
	staledAt    time.Time
}

// NewUserRecord creates a new UserRecord for the given user ID.
func NewUserRecord(userID string) *UserRecord {
	return &UserRecord{
		userID:  userID,
		devices: make(map[uint32]*DeviceRecord),
	}
}

// NewUserRecordWithIdentity creates a new UserRecord for the given user ID
// and remote identity key.
func NewUserRecordWithIdentity(userID string, identityKey *identity.Key) *UserRecord {
	return &UserRecord{
		userID:      userID,
		identityKey: identityKey,
		devices:     make(map[uint32]*DeviceRecord),
	}
}

// UserID returns the user identifier.
func (u *UserRecord) UserID() string {
	return u.userID
}

// IdentityKey returns the remote identity key associated with this user record.
func (u *UserRecord) IdentityKey() *identity.Key {
	return u.identityKey
}

// SetIdentityKey sets the remote identity key for this user record.
func (u *UserRecord) SetIdentityKey(key *identity.Key) {
	u.identityKey = key
}

// IsStale returns whether this user record has been marked stale.
func (u *UserRecord) IsStale() bool {
	return u.stale
}

// StaledAt returns the time when this user was marked stale.
func (u *UserRecord) StaledAt() time.Time {
	return u.staledAt
}

// GetDevice returns the DeviceRecord for the given device ID, or nil if
// no record exists.
func (u *UserRecord) GetDevice(deviceID uint32) *DeviceRecord {
	return u.devices[deviceID]
}

// AddDevice creates and adds a new DeviceRecord for the given device ID.
// If a record already exists for that device, it is returned unchanged.
// The maxDevices parameter limits the total number of devices per user;
// a value of 0 disables the limit.
func (u *UserRecord) AddDevice(deviceID uint32, maxDevices int) (*DeviceRecord, error) {
	if existing, ok := u.devices[deviceID]; ok {
		return existing, nil
	}
	if maxDevices > 0 && len(u.devices) >= maxDevices {
		return nil, NewMaxDevicesExceededError(u.userID, maxDevices)
	}
	device := NewDeviceRecord(deviceID)
	u.devices[deviceID] = device
	return device, nil
}

// AddDeviceWithIdentity creates and adds a new DeviceRecord for the given
// device ID and identity key. If a record already exists for that device,
// it is returned unchanged. The maxDevices parameter limits the total number
// of devices per user; a value of 0 disables the limit.
func (u *UserRecord) AddDeviceWithIdentity(deviceID uint32, identityKey *identity.Key, maxDevices int) (*DeviceRecord, error) {
	if existing, ok := u.devices[deviceID]; ok {
		return existing, nil
	}
	if maxDevices > 0 && len(u.devices) >= maxDevices {
		return nil, NewMaxDevicesExceededError(u.userID, maxDevices)
	}
	device := NewDeviceRecordWithIdentity(deviceID, identityKey)
	u.devices[deviceID] = device
	return device, nil
}

// RemoveDevice removes the DeviceRecord for the given device ID.
func (u *UserRecord) RemoveDevice(deviceID uint32) {
	delete(u.devices, deviceID)
}

// DeviceIDs returns a slice of all device IDs in this user record.
func (u *UserRecord) DeviceIDs() []uint32 {
	ids := make([]uint32, 0, len(u.devices))
	for id := range u.devices {
		ids = append(ids, id)
	}
	return ids
}

// Devices returns the underlying device map.
func (u *UserRecord) Devices() map[uint32]*DeviceRecord {
	return u.devices
}

// MarkStale marks this user record as stale at the given time.
func (u *UserRecord) MarkStale(now time.Time) {
	u.stale = true
	u.staledAt = now
}

// ClearStale resets the stale flag and timestamp.
func (u *UserRecord) ClearStale() {
	u.stale = false
	u.staledAt = time.Time{}
}

// IsStaleExpired returns true if the user has been stale for at least
// MaxLatency. Per Sesame spec, expiry is inclusive (>=).
func (u *UserRecord) IsStaleExpired(config *Config, now time.Time) bool {
	if !u.stale {
		return false
	}
	return now.Sub(u.staledAt) >= config.MaxLatency
}

// RemoveStaleDevices removes devices that have been stale past MaxLatency
// and cleans expired sessions on all remaining devices. Empty devices are
// removed after cleanup (cascade deletion per spec).
func (u *UserRecord) RemoveStaleDevices(config *Config, now time.Time) {
	for id, device := range u.devices {
		// Remove devices stale past MaxLatency.
		if device.IsStaleExpired(config, now) {
			delete(u.devices, id)
			continue
		}
		// Clean expired sessions on remaining devices.
		device.CleanExpiredSessions(config, now)
		// Cascade: remove empty devices (last session deleted -> delete DeviceRecord).
		if device.IsEmpty() {
			delete(u.devices, id)
		}
	}
}

// IsEmpty returns true if the user has no device records.
func (u *UserRecord) IsEmpty() bool {
	return len(u.devices) == 0
}

// Clone creates a deep copy of the UserRecord suitable for snapshot/restore.
// DeviceRecords and their SessionWrappers are deep-copied to prevent
// mutable state leakage.
func (u *UserRecord) Clone() (*UserRecord, error) {
	clone := &UserRecord{
		userID:      u.userID,
		identityKey: u.identityKey,
		devices:     make(map[uint32]*DeviceRecord, len(u.devices)),
		stale:       u.stale,
		staledAt:    u.staledAt,
	}
	for id, device := range u.devices {
		c, err := device.Clone()
		if err != nil {
			return nil, err
		}
		clone.devices[id] = c
	}
	return clone, nil
}
